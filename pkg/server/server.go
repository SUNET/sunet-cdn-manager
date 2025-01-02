package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/components"
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	zlog "github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
)

func init() {
	gob.Register(authData{})

	// Withouth this the decoder will fail on "error":"schema: invalid path \"gorilla.csrf.Token\""" when using gorilla/csrf
	schemaDecoder.IgnoreUnknownKeys(true)
}

var (
	errForbidden     = errors.New("access to resource is not allowed")
	errNotFound      = errors.New("resource not found")
	errUnprocessable = errors.New("resource not processable")
	errAlreadyExists = errors.New("resource already exists")
	errBadPassword   = errors.New("bad password")

	// Set a Decoder instance as a package global, because it caches
	// meta-data about structs, and an instance can be shared safely.
	schemaDecoder = schema.NewDecoder()

	// use a single instance of Validate, it caches struct info
	validate = validator.New(validator.WithRequiredStructEnabled())

	returnToKey = "return_to"
)

// Small struct that implements io.Writer so we can pass it to net/http server
// for error logging
type zerologErrorWriter struct {
	logger *zerolog.Logger
}

func (zew *zerologErrorWriter) Write(p []byte) (n int, err error) {
	zew.logger.Error().Msg(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	// http.Redirect(w, r, "/console", http.StatusFound)
	validatedRedirect("/console", w, r)
}

func consoleHandler(cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		session, err := cookieStore.Get(r, cookieName)
		if err != nil {
			logger.Err(err).Msg("console: bad session cookie")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Err(err).Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		err = renderConsolePage(w, r, ad)
		if err != nil {
			logger.Err(err).Msg("unable to render console page")
			return
		}
	}
}

// Login page/form for browser based (not API) requests
func renderConsolePage(w http.ResponseWriter, r *http.Request, ad authData) error {
	component := components.ConsolePage(ad.Username)
	err := component.Render(r.Context(), w)
	return err
}

// Return user to content of return_to query parameter but only if it points to a place we control
// https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
func validatedRedirect(returnTo string, w http.ResponseWriter, r *http.Request) {
	logger := hlog.FromRequest(r)
	returnToURL, err := url.Parse(returnTo)
	if err != nil {
		logger.Err(err).Msg("unable to parse return_to content as URL")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Make sure the URL does not point to anything outside this server
	if r.URL.Host != returnToURL.Host {
		logger.Err(err).Msg("return_to does not point to this service, not redirecting")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	logger.Info().Str("return_to", returnToURL.String()).Msg("redirecting user")
	http.Redirect(w, r, returnToURL.String(), http.StatusFound)
}

type loginForm struct {
	// Username length validation needs to be kept in sync with the CHECK
	// constraints in the user table, see the migrations module.
	Username string `schema:"username" validate:"min=1,max=63"`
	// Password length validation needs to be kept in sync with the
	// /api/v1/users POST endpoint for user creation
	Password string `schema:"password" validate:"min=15,max=64"`
	ReturnTo string `schema:"return_to"`
}

// Endpoint used for console login
func loginHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore, devMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()
		switch r.Method {
		case "GET":
			q := r.URL.Query()
			returnTo := q.Get(returnToKey)
			_, ok := ctx.Value(authDataKey{}).(authData)
			if ok {
				switch returnTo {
				case "":
					logger.Info().Msg("login: session already has ad data but no return_to, redirecting to console")
					// http.Redirect(w, r, "/console", http.StatusFound)
					validatedRedirect("/console", w, r)
					return
				default:
					logger.Info().Msg("login: session already has ad data and return_to, redirecting to return_to")
					validatedRedirect(returnTo, w, r)
					return
				}
			}

			// No existing login session, show login form
			err := renderLoginPage(w, r, returnTo, false)
			if err != nil {
				logger.Err(err).Msg("unable to render login page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		case "POST":
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse login POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := loginForm{}

			err = schemaDecoder.Decode(&formData, r.PostForm)
			if err != nil {
				logger.Err(err).Msg("unable to decode POST form data")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			err = validate.Struct(formData)
			if err != nil {
				logger.Err(err).Msg("unable to validate POST login form data, treating as failed login")
				err := renderLoginPage(w, r, formData.ReturnTo, true)
				if err != nil {
					logger.Err(err).Msg("unable to render login page")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				return
			}

			ad, err := dbUserLogin(dbPool, formData.Username, formData.Password)
			if err != nil {
				switch err {
				case pgx.ErrNoRows:
					// The user does not exist etc, try again
					err := renderLoginPage(w, r, formData.ReturnTo, true)
					if err != nil {
						logger.Err(err).Msg("unable to render bad password page for non-existant user")
					}
					return
				case errBadPassword:
					// Bad password, try again
					err := renderLoginPage(w, r, formData.ReturnTo, true)
					if err != nil {
						logger.Err(err).Msg("unable to render bad password page for bad password")
					}
					return
				}

				logger.Err(err).Msg("db request to handle POST login request failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			session, err := cookieStore.Get(r, cookieName)
			if err != nil {
				logger.Err(err).Msg("login: unable to decode existing session, using new one for session saving")
			}

			if session.IsNew {
				session.Options = &sessions.Options{
					Path:     "/",
					Secure:   true,
					HttpOnly: true,
				}
				if devMode {
					session.Options.Secure = false
				}
			}

			logger.Info().Msg("saving login session")
			session.Values["ad"] = ad
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Login is successful at this point, send the now authenticated user to their original location (or /console if no such hint is available)
			if formData.ReturnTo != "" {
				u, err := url.Parse(formData.ReturnTo)
				if err != nil {
					logger.Err(err).Msg("unable to parse form return_to as URL")
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					return
				}

				logger.Info().Msg("redirecting logged in user to return_to found in POSTed form")
				validatedRedirect(u.String(), w, r)
				return
			} else {
				logger.Info().Msg("no return_to in POST data, redirecting logged in user to /console")
				validatedRedirect("/console", w, r)
				return
			}
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for login handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

// Endpoint used for console logout
func logoutHandler(cookieStore *sessions.CookieStore, devMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		q := r.URL.Query()
		returnTo := q.Get(returnToKey)

		_, ok := ctx.Value(authDataKey{}).(authData)
		if ok {
			switch returnTo {
			case "":
				logger.Info().Msg("login: session already has ad data but no return_to, redirecting to console")
				// http.Redirect(w, r, "/console", http.StatusFound)
				validatedRedirect("/console", w, r)
				return
			default:
				logger.Info().Msg("login: session already has ad data and return_to, redirecting to return_to")
				validatedRedirect(returnTo, w, r)
				return
			}
		}

		session, err := cookieStore.Get(r, cookieName)
		if err != nil {
			logger.Err(err).Msg("logout: unable to decode existing session, overriding with logout session anyway")
		}

		// Individual sessions can be deleted by setting Options.MaxAge = -1 for that session.
		session.Options = &sessions.Options{
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			MaxAge:   -1,
		}
		if devMode {
			session.Options.Secure = false
		}

		logger.Info().Msg("logout: saving expired login session")
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// User should be logged out at this point, send them to where they were originally headed (which will in turn probably redirect them to /login).
		if returnTo != "" {
			u, err := url.Parse(returnTo)
			if err != nil {
				logger.Err(err).Msg("unable to parse returnTo in logout handler")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			validatedRedirect(u.String(), w, r)
			return
		}

		// No return_to hint, just send them to the console
		validatedRedirect("/console", w, r)
	}
}

type argon2Settings struct {
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
	argonTagSize uint32
}

func newArgon2DefaultSettings() argon2Settings {
	argon2Settings := argon2Settings{}
	// https://datatracker.ietf.org/doc/rfc9106/
	// ===
	// If much less memory is available, a uniformly safe option is
	// Argon2id with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of
	// RAM), 128-bit salt, and 256-bit tag size.  This is the SECOND
	// RECOMMENDED option.
	// [...]
	// The Argon2id variant with t=1 and 2 GiB memory is the FIRST
	// RECOMMENDED option and is suggested as a default setting for
	// all environments.  This setting is secure against
	// side-channel attacks and maximizes adversarial costs on
	// dedicated brute-force hardware. The Argon2id variant with t=3
	// and 64 MiB memory is the SECOND RECOMMENDED option and is
	// suggested as a default setting for memory- constrained
	// environments.
	// ===
	//
	// Use the "SECOND RECOMMENDED" settings because we are
	// probably running in a memory constrained container:
	// t=3 iterations
	argon2Settings.argonTime = uint32(3)

	// p=4 lanes
	// const ArgonThreads = uint8(4)
	argon2Settings.argonThreads = uint8(4)

	// m=2^(16) (64 MiB of RAM)
	argon2Settings.argonMemory = uint32(64 * 1024)

	// 256-bit tag size (== 32 bytes)
	argon2Settings.argonTagSize = uint32(32)
	return argon2Settings
}

type authDataKey struct{}

type authData struct {
	Username  string
	UserID    pgtype.UUID
	OrgID     *pgtype.UUID
	OrgName   *string
	Superuser bool
	RoleID    pgtype.UUID
	RoleName  string
}

func sendBasicAuth(w http.ResponseWriter) {
	realm := "SUNET CDN Manager"
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}

// Login page/form for browser based (not API) requests
func renderLoginPage(w http.ResponseWriter, r *http.Request, returnTo string, loginFailed bool) error {
	component := components.LoginPage(returnTo, loginFailed)
	err := component.Render(r.Context(), w)
	return err
}

func redirectToLoginPage(w http.ResponseWriter, r *http.Request) error {
	redirectURL, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		return fmt.Errorf("unable to parse RequestURI: %w", err)
	}

	// Remember where we wanted to go, but only overwrite it if it is not already set
	q := r.URL.Query()
	if !q.Has(returnToKey) {
		q.Set(returnToKey, r.URL.String())
		redirectURL.RawQuery = q.Encode()
	}

	// Redirect to the login handler
	redirectURL.Path = "/login"

	// http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	validatedRedirect(redirectURL.String(), w, r)

	return nil
}

func dbUserLogin(dbPool *pgxpool.Pool, username string, password string) (authData, error) {
	var userID, roleID pgtype.UUID
	var orgID *pgtype.UUID // can be nil if not belonging to a organization
	var orgName *string    // same as above
	var argon2Key, argon2Salt []byte
	var argon2Time, argon2Memory, argon2TagSize uint32
	var argon2Threads uint8
	var superuser bool
	var roleName string

	err := dbPool.QueryRow(
		context.Background(),
		`SELECT
				users.id,
				users.org_id,
				organizations.name,
				users.role_id,
				roles.name,
				roles.superuser,
				user_argon2keys.key,
				user_argon2keys.salt,
				user_argon2keys.time,
				user_argon2keys.memory,
				user_argon2keys.threads,
				user_argon2keys.tag_size
			FROM users
			JOIN user_argon2keys ON users.id = user_argon2keys.user_id
			JOIN roles ON users.role_id = roles.id
			LEFT JOIN organizations ON users.org_id = organizations.id
			WHERE users.name=$1`,
		username,
	).Scan(
		&userID,
		&orgID,
		&orgName,
		&roleID,
		&roleName,
		&superuser,
		&argon2Key,
		&argon2Salt,
		&argon2Time,
		&argon2Memory,
		&argon2Threads,
		&argon2TagSize,
	)
	if err != nil {
		return authData{}, err
	}

	loginKey := argon2.IDKey([]byte(password), argon2Salt, argon2Time, argon2Memory, argon2Threads, argon2TagSize)
	// Use subtle.ConstantTimeCompare() in an attempt to
	// not leak password contents via timing attack
	passwordMatch := (subtle.ConstantTimeCompare(loginKey, argon2Key) == 1)

	if !passwordMatch {
		return authData{}, errBadPassword
	}

	return authData{
		Username:  username,
		UserID:    userID,
		OrgID:     orgID,
		OrgName:   orgName,
		RoleID:    roleID,
		RoleName:  roleName,
		Superuser: superuser,
	}, nil
}

// This handler writes any data to the client as well as logging errors etc. If everything went well *authData is not nil.
func handleBasicAuth(dbPool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) *authData {
	logger := hlog.FromRequest(r)
	username, password, ok := r.BasicAuth()
	if !ok {
		sendBasicAuth(w)
		return nil
	}

	ad, err := dbUserLogin(dbPool, username, password)
	if err != nil {
		switch err {
		case pgx.ErrNoRows:
			// The user does not exist etc, try again
			sendBasicAuth(w)
			return nil
		case errBadPassword:
			// Bad password, try again
			sendBasicAuth(w)
			return nil
		}

		logger.Err(err).Msg("failed looking up username for authentication")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	return &ad
}

func apiAuth(dbPool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) *authData {
	return handleBasicAuth(dbPool, w, r)
}

const cookieName = "sunet-cdn-manager"

func authFromSession(logger *zerolog.Logger, cookieStore *sessions.CookieStore, w http.ResponseWriter, r *http.Request) *authData {
	if r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return nil
	}

	session, err := cookieStore.Get(r, cookieName)
	if err != nil {
		logger.Err(err).Msg("unable to decode existing session, using new one")
	}

	adInt, ok := session.Values["ad"]
	if !ok {
		return nil
	}

	logger.Info().Msg("using authentication data from session")
	ad := adInt.(authData)
	return &ad
}

func apiAuthMiddleware(dbPool *pgxpool.Pool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adRef := apiAuth(dbPool, w, r)
			if adRef == nil {
				return
			}

			ctx := context.WithValue(r.Context(), authDataKey{}, *adRef)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func consoleAuthMiddleware(cookieStore *sessions.CookieStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			adRef := authFromSession(logger, cookieStore, w, r)
			if adRef == nil {
				logger.Info().Msg("consoleAuthMiddleware: redirecting to login page")
				err := redirectToLoginPage(w, r)
				if err != nil {
					logger.Err(err).Msg("unable to redirect to login page")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				return
			}

			ctx := context.WithValue(r.Context(), authDataKey{}, *adRef)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func selectUsers(dbPool *pgxpool.Pool, logger *zerolog.Logger, ad authData) ([]user, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT users.id, users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id ORDER BY users.ts")
		if err != nil {
			logger.Err(err).Msg("unable to query for users")
			return nil, fmt.Errorf("unable to query for users")
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT users.id, users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.id=$1 ORDER BY users.ts", ad.UserID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for users for organization: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[user])
	if err != nil {
		logger.Err(err).Msg("unable to CollectRows for users")
		return nil, errors.New("unable to get rows for users")
	}

	return users, nil
}

func selectUserByID(dbPool *pgxpool.Pool, logger *zerolog.Logger, inputID string, ad authData) (user, error) {
	u := user{}
	userIdent, err := parseNameOrID(inputID)
	if err != nil {
		return user{}, fmt.Errorf("unable to parse name or id")
	}

	var roleName string
	var superuser bool
	if userIdent.isID() {
		if !ad.Superuser && (ad.UserID != *userIdent.id) {
			return user{}, errNotFound
		}

		var userName string
		err := dbPool.QueryRow(context.Background(), "SELECT users.name, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.id=$1", *userIdent.id).Scan(&userName, &roleName, &superuser)
		if err != nil {
			return user{}, fmt.Errorf("unable to SELECT user by id: %w", err)
		}
		u.ID = *userIdent.id
		u.Name = userName
	} else {
		if !ad.Superuser && (ad.Username != inputID) {
			return user{}, errNotFound
		}

		var userID pgtype.UUID
		err := dbPool.QueryRow(context.Background(), "SELECT users.id, roles.name as role_name, roles.superuser FROM users JOIN roles ON users.role_id=roles.id WHERE users.name=$1", inputID).Scan(&userID, &roleName, &superuser)
		if err != nil {
			logger.Err(err).Str("id", inputID).Msg("unable to SELECT user by name")
			return user{}, fmt.Errorf("unable to SELECT user by name")
		}
		u.ID = userID
		u.Name = *userIdent.name
	}

	u.RoleName = roleName
	u.Superuser = superuser

	return u, nil
}

type argon2Data struct {
	key  []byte
	salt []byte
	argon2Settings
}

func passwordToArgon2(password string) (argon2Data, error) {
	argonSettings := newArgon2DefaultSettings()

	// Generate 16 byte (128 bit) salt as
	// recommended for argon2 in RFC 9106
	saltLen := 16

	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return argon2Data{}, fmt.Errorf("unable to create argon2 salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonSettings.argonTime, argonSettings.argonMemory, argonSettings.argonThreads, argonSettings.argonTagSize)

	return argon2Data{
		key:            key,
		salt:           salt,
		argon2Settings: argonSettings,
	}, nil
}

func insertUserWithArgon2Tx(tx pgx.Tx, name string, orgID *pgtype.UUID, roleID pgtype.UUID, a2Data argon2Data) (pgtype.UUID, error) {
	var userID pgtype.UUID

	err := tx.QueryRow(context.Background(), "INSERT INTO users (name, org_id, role_id) VALUES ($1, $2, $3) RETURNING id", name, orgID, roleID).Scan(&userID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT user with IDs: %w", err)
	}

	err = tx.QueryRow(context.Background(), "INSERT INTO user_argon2keys (user_id, key, salt, time, memory, threads, tag_size) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", userID, a2Data.key, a2Data.salt, a2Data.argonTime, a2Data.argonMemory, a2Data.argonThreads, a2Data.argonTagSize).Scan(&userID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT user argon2 data with IDs: %w", err)
	}

	return userID, nil
}

func insertUser(dbPool *pgxpool.Pool, name string, password string, role string, organization string, ad authData) (pgtype.UUID, error) {
	if !ad.Superuser {
		return pgtype.UUID{}, errForbidden
	}

	orgIdent, err := parseNameOrID(organization)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to parse organization for user INSERT: %w", err)
	}

	roleIdent, err := parseNameOrID(role)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to parse role for user INSERT: %w", err)
	}

	a2Data, err := passwordToArgon2(password)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to create password data for user INSERT: %w", err)
	}

	var userID pgtype.UUID
	// If we already have all the IDs needed just insert them via VALUES
	if orgIdent.isID() && roleIdent.isID() {
		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			userID, err = insertUserWithArgon2Tx(tx, name, orgIdent.id, *roleIdent.id, a2Data)
			if err != nil {
				return fmt.Errorf("unable to INSERT user with IDs: %w", err)
			}

			return nil
		})
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("user with IDs INSERT transaction failed: %w", err)
		}
	} else {
		var roleID pgtype.UUID
		var orgID pgtype.UUID
		// Fetch the missing IDs based on names instead where necessary
		// Use single transaction with FOR SHARE selects to make sure
		// the INSERT uses consistent data. To avoid deadlocks make
		// sure all code performans FOR SHARE selects in the same
		// order (alphabetical).
		err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			if !orgIdent.isID() {
				err := tx.QueryRow(
					context.Background(),
					`SELECT id FROM organizations WHERE name=$1 FOR SHARE`, *orgIdent.name,
				).Scan(
					&orgID,
				)
				if err != nil {
					return fmt.Errorf("unable to lookup organization ID from name for user INSERT: %w", err)
				}
			} else {
				orgID = *orgIdent.id
			}

			if !roleIdent.isID() {
				err := tx.QueryRow(
					context.Background(),
					`SELECT id FROM roles WHERE name=$1 FOR SHARE`, *roleIdent.name,
				).Scan(
					&roleID,
				)
				if err != nil {
					return fmt.Errorf("unable to lookup role ID from name for user INSERT: %w", err)
				}
			} else {
				roleID = *roleIdent.id
			}

			userID, err = insertUserWithArgon2Tx(tx, name, &orgID, roleID, a2Data)
			if err != nil {
				return fmt.Errorf("unable to INSERT user after looking up IDs: %w", err)
			}

			return nil
		})
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("user INSERT transaction failed: %w", err)
		}
	}

	return userID, nil
}

func selectOrganizations(dbPool *pgxpool.Pool, ad authData) ([]organization, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM organizations ORDER BY ts")
		if err != nil {
			return nil, fmt.Errorf("unable to query for organizations: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM organizations WHERE id=$1 ORDER BY ts", *ad.OrgID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for organizations: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	organizations, err := pgx.CollectRows(rows, pgx.RowToStructByName[organization])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for organizations: %w", err)
	}

	return organizations, nil
}

func selectOrganizationByID(dbPool *pgxpool.Pool, inputID string, ad authData) (organization, error) {
	o := organization{}
	orgIdent, err := parseNameOrID(inputID)
	if err != nil {
		return organization{}, fmt.Errorf("unable to parse name or id")
	}
	if orgIdent.isID() {
		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != *orgIdent.id) {
			return organization{}, errNotFound
		}

		var name string
		err := dbPool.QueryRow(context.Background(), "SELECT name FROM organizations WHERE id=$1", *orgIdent.id).Scan(&name)
		if err != nil {
			return organization{}, fmt.Errorf("unable to SELECT organization by id")
		}
		o.Name = name
		o.ID = *orgIdent.id
	} else {
		if !ad.Superuser && (ad.OrgName == nil || *ad.OrgName != inputID) {
			return organization{}, errNotFound
		}
		var id pgtype.UUID
		err := dbPool.QueryRow(context.Background(), "SELECT id FROM organizations WHERE name=$1", inputID).Scan(&id)
		if err != nil {
			return organization{}, fmt.Errorf("unable to SELECT organization by name: %w", err)
		}
		o.Name = inputID
		o.ID = id
	}

	return o, nil
}

func insertOrganization(dbPool *pgxpool.Pool, name string, ad authData) (pgtype.UUID, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return pgtype.UUID{}, errForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO organizations (name) VALUES ($1) RETURNING id", name).Scan(&id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT organization: %w", err)
	}

	return id, nil
}

func selectServices(dbPool *pgxpool.Pool, ad authData) ([]service, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services ORDER BY ts")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services WHERE org_id=$1 ORDER BY ts", *ad.OrgID)
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	services := []service{}
	var serviceID pgtype.UUID
	var serviceName string
	_, err = pgx.ForEachRow(rows, []any{&serviceID, &serviceName}, func() error {
		services = append(
			services,
			service{
				ID:   serviceID,
				Name: serviceName,
			},
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to ForEachRow over services in API GET: %w", err)
	}

	return services, nil
}

func selectServiceByID(dbPool *pgxpool.Pool, inputID string, ad authData) (service, error) {
	s := service{}
	var serviceName string
	var serviceID pgtype.UUID

	serviceIdent, err := parseNameOrID(inputID)
	if err != nil {
		return service{}, fmt.Errorf("unable to parse name or id")
	}
	if serviceIdent.isID() {
		if ad.Superuser {
			err := dbPool.QueryRow(context.Background(), "SELECT name FROM services WHERE id=$1", *serviceIdent.id).Scan(&serviceName)
			if err != nil {
				return service{}, fmt.Errorf("unable to SELECT service by id for superuser")
			}
			s.Name = serviceName
			s.ID = *serviceIdent.id
		} else if ad.OrgID != nil {
			err := dbPool.QueryRow(context.Background(), "SELECT services.name FROM services JOIN organizations ON services.org_id = organizations.id WHERE services.id=$1 AND organizations.id=$2", *serviceIdent.id, ad.OrgID).Scan(&serviceName)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return service{}, errNotFound
				}
				return service{}, fmt.Errorf("unable to SELECT service by id for organization")
			}
			s.Name = serviceName
			s.ID = *serviceIdent.id
		} else {
			return service{}, errNotFound
		}
	} else {
		if ad.Superuser {
			err := dbPool.QueryRow(context.Background(), "SELECT id FROM services WHERE name=$1", inputID).Scan(&serviceID)
			if err != nil {
				return service{}, fmt.Errorf("unable to SELECT service by name for superuser")
			}
			s.Name = inputID
			s.ID = serviceID
		} else if ad.OrgID != nil {
			err := dbPool.QueryRow(context.Background(), "SELECT services.id FROM services JOIN organizations ON services.org_id = organizations.id WHERE services.name=$1 AND organizations.id=$2", inputID, ad.OrgID).Scan(&serviceID)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return service{}, errNotFound
				}
				return service{}, fmt.Errorf("unable to SELECT service by name for organization")
			}
			s.Name = inputID
			s.ID = serviceID
		} else {
			return service{}, errNotFound
		}
	}

	return s, nil
}

type identifier struct {
	name *string
	id   *pgtype.UUID
}

func parseNameOrID(inputID string) (identifier, error) {
	if inputID == "" {
		return identifier{}, errors.New("input id is empty")
	}

	id := new(pgtype.UUID)
	err := id.Scan(inputID)
	if err == nil {
		// This is a UUID, treat it as an ID
		return identifier{
			id: id,
		}, nil
	}

	// This is not a UUID, treat it as a name
	return identifier{
		name: &inputID,
	}, nil
}

func (i identifier) isID() bool {
	return i.id != nil
}

func (i identifier) isValid() bool {
	return i.id != nil || i.name != nil
}

func (i identifier) String() string {
	if i.name != nil {
		return *i.name
	}

	if i.id != nil {
		// We can drop the uuid module when
		// https://github.com/jackc/pgx/commit/8723855d957fc7a076a0e6998a016d8c4b138dca
		// is available in a release.
		u, err := uuid.FromBytes(i.id.Bytes[:])
		if err != nil {
			// Should not happen as parseNameOrID() would have errored out if it was unable to parse the UUID
			panic(err)
		}
		return u.String()
	}

	return ""
}

func insertService(dbPool *pgxpool.Pool, name string, orgNameOrID *string, ad authData) (pgtype.UUID, error) {
	var serviceID pgtype.UUID

	var orgIdent identifier
	var err error

	if orgNameOrID != nil {
		orgIdent, err = parseNameOrID(*orgNameOrID)
		if err != nil {
			return pgtype.UUID{}, errUnprocessable
		}
	}

	if ad.Superuser {
		if !orgIdent.isValid() {
			return pgtype.UUID{}, errUnprocessable
		}
		if orgIdent.isID() {
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) VALUES ($1, $2) RETURNING id", name, *orgIdent.id).Scan(&serviceID)
			if err != nil {
				return pgtype.UUID{}, fmt.Errorf("unable to INSERT service for superuser with organizaiton id: %w", err)
			}
		} else {
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) SELECT $1, organizations.id FROM organizations WHERE organizations.name=$2 returning id", name, *orgIdent.name).Scan(&serviceID)
			if err != nil {
				return pgtype.UUID{}, fmt.Errorf("unable to INSERT service for superuser with organization name: %w", err)
			}
		}
	} else {
		if ad.OrgID == nil {
			return pgtype.UUID{}, errForbidden
		}

		// If a user is trying to supply an org id for an org they are
		// not part of just error out to signal they are sending bad
		// data.
		if orgIdent.isValid() {
			if orgIdent.isID() {
				if *ad.OrgID != *orgIdent.id {
					return pgtype.UUID{}, errForbidden
				}
			} else {
				if *ad.OrgName != *orgIdent.name {
					return pgtype.UUID{}, errForbidden
				}
			}
		}

		err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) VALUES ($1, $2) RETURNING id", name, ad.OrgID).Scan(&serviceID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				// https://www.postgresql.org/docs/current/errcodes-appendix.html
				// unique_violation: 23505
				if pgErr.Code == "23505" {
					return pgtype.UUID{}, errAlreadyExists
				}
			}
			return pgtype.UUID{}, fmt.Errorf("unable to INSERT service for organization with id: %w", err)
		}
	}

	return serviceID, nil
}

func selectServiceVersions(dbPool *pgxpool.Pool, ad authData) ([]serviceVersion, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT service_versions.id, service_versions.version, service_versions.active, services.name FROM service_versions JOIN services ON service_versions.service_id = services.id ORDER BY service_versions.version")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for service versions as superuser: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT service_versions.id, service_versions.version, service_versions.active, services.name FROM service_versions JOIN services ON service_versions.service_id = services.id WHERE services.org_id=$1 ORDER BY service_versions.version", ad.OrgID)
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	serviceVersions := []serviceVersion{}
	var id pgtype.UUID
	var version int64
	// active can be NULL in the database so that we can force uniqeness on
	// the TRUE value. Treat NULL as false in the API.
	var active *bool
	var serviceName string
	_, err = pgx.ForEachRow(rows, []any{&id, &version, &active, &serviceName}, func() error {
		if active == nil {
			b := false
			active = &b
		}
		serviceVersions = append(
			serviceVersions,
			serviceVersion{
				ID:          id,
				ServiceName: serviceName,
				Version:     version,
				Active:      *active,
			},
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to ForEachRow over services in API GET: %w", err)
	}

	return serviceVersions, nil
}

type serviceVersionInsertResult struct {
	versionID     pgtype.UUID
	version       int64
	active        bool
	domainIDs     []pgtype.UUID
	originIDs     []pgtype.UUID
	deactivatedID pgtype.UUID
}

func insertServiceVersionTx(tx pgx.Tx, serviceID pgtype.UUID, orgID pgtype.UUID, domains []domainString, origins []origin, active *bool) (serviceVersionInsertResult, error) {
	var serviceVersionID pgtype.UUID
	var versionCounter int64
	var deactivatedServiceVersion pgtype.UUID

	err := tx.QueryRow(
		context.Background(),
		"UPDATE services SET version_counter=version_counter+1 WHERE id=$1 AND org_id=$2 RETURNING version_counter",
		serviceID,
		orgID,
	).Scan(&versionCounter)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to UPDATE version_counter for service version: %w", err)
	}

	err = tx.QueryRow(
		context.Background(),
		"INSERT INTO service_versions (service_id, version, active) VALUES ($1, $2, $3) RETURNING id",
		serviceID,
		versionCounter,
		active,
	).Scan(&serviceVersionID)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
	}

	// If the new version is expected to be active we need to unset the currently active version
	if active != nil && *active {
		err := tx.QueryRow(
			context.Background(),
			"UPDATE service_versions SET active=NULL WHERE service_id=$1 AND active=true returning id",
			serviceID,
		).Scan(&deactivatedServiceVersion)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to UPDATE active status for previous service version: %w", err)
		}
	}

	var serviceDomainIDs []pgtype.UUID
	for _, domain := range domains {
		var serviceDomainID pgtype.UUID
		err = tx.QueryRow(
			context.Background(),
			"INSERT INTO service_domains (service_version_id, domain) VALUES ($1, $2) RETURNING id",
			serviceVersionID,
			domain,
		).Scan(&serviceDomainID)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
		}
		serviceDomainIDs = append(serviceDomainIDs, serviceDomainID)
	}

	var serviceOriginIDs []pgtype.UUID
	for _, origin := range origins {
		var serviceOriginID pgtype.UUID
		err = tx.QueryRow(
			context.Background(),
			"INSERT INTO service_origins (service_version_id, host, port, tls) VALUES ($1, $2, $3, $4) RETURNING id",
			serviceVersionID,
			origin.Host,
			origin.Port,
			origin.TLS,
		).Scan(&serviceOriginID)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
		}
		serviceOriginIDs = append(serviceOriginIDs, serviceOriginID)
	}

	res := serviceVersionInsertResult{
		versionID:     serviceVersionID,
		version:       versionCounter,
		domainIDs:     serviceDomainIDs,
		originIDs:     serviceOriginIDs,
		deactivatedID: deactivatedServiceVersion,
	}

	if active != nil && *active {
		res.active = *active
	}

	return res, nil
}

func insertServiceVersion(dbPool *pgxpool.Pool, serviceID pgtype.UUID, orgNameOrID *string, domains []domainString, origins []origin, active *bool, ad authData) (serviceVersionInsertResult, error) {
	var serviceVersionResult serviceVersionInsertResult

	var orgIdent identifier
	var err error

	// The "active" column in the database uses NULL to represent "false"
	// so we can have a UNIQUE constraint for "true". For this reason,
	// translate boolean "false" to nil if necessary:
	if active != nil && !*active {
		active = nil
	}

	if orgNameOrID != nil {
		orgIdent, err = parseNameOrID(*orgNameOrID)
		if err != nil {
			return serviceVersionInsertResult{}, errUnprocessable
		}
	}

	if ad.Superuser {
		if !orgIdent.isValid() {
			return serviceVersionInsertResult{}, errUnprocessable
		}
		if orgIdent.isID() {
			err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
				serviceVersionResult, err = insertServiceVersionTx(tx, serviceID, *orgIdent.id, domains, origins, active)
				if err != nil {
					return fmt.Errorf("unable to INSERT service version with org ID for superuser: %w", err)
				}

				return nil
			})
			if err != nil {
				return serviceVersionInsertResult{}, fmt.Errorf("service version with ID INSERT transaction failed: %w", err)
			}
		} else {
			err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
				var orgID pgtype.UUID
				err := tx.QueryRow(context.Background(), "SELECT id FROM organizations WHERE name=$1 FOR UPDATE", *orgIdent.name).Scan(&orgID)
				if err != nil {
					return fmt.Errorf("unable to SELECT org ID based on name for superuser: %w", err)
				}

				serviceVersionResult, err = insertServiceVersionTx(tx, serviceID, orgID, domains, origins, active)
				if err != nil {
					return fmt.Errorf("unable to INSERT service version with org name: %w", err)
				}

				return nil
			})
			if err != nil {
				return serviceVersionInsertResult{}, fmt.Errorf("service version with name INSERT transaction failed: %w", err)
			}
		}
	} else {
		if ad.OrgID == nil {
			return serviceVersionInsertResult{}, errForbidden
		}

		// If a user is trying to supply an org id for an org they are
		// not part of just error out to signal they are sending bad
		// data.
		if orgIdent.isValid() {
			if orgIdent.isID() {
				if *ad.OrgID != *orgIdent.id {
					return serviceVersionInsertResult{}, errForbidden
				}
			} else {
				if *ad.OrgName != *orgIdent.name {
					return serviceVersionInsertResult{}, errForbidden
				}
			}
		}

		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			serviceVersionResult, err = insertServiceVersionTx(tx, serviceID, *ad.OrgID, domains, origins, active)
			if err != nil {
				return fmt.Errorf("unable to INSERT service version with org ID for user: %w", err)
			}

			return nil
		})
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("service version with INSERT transaction for user failed: %w", err)
		}
	}

	return serviceVersionResult, nil
}

func generateCompleteVcl(sv selectVcl) (string, error) {
	var b strings.Builder

	b.WriteString("vcl 4.1;\n")
	b.WriteString("import std;\n")
	b.WriteString("import proxy;\n")
	b.WriteString("\n")
	b.WriteString("backend haproxy_https {\n")
	b.WriteString("  .path = \"/shared/haproxy_https\"\n")
	b.WriteString("}\n")
	b.WriteString("backend haproxy_http {\n")
	b.WriteString("  .path = \"/shared/haproxy_http\"\n")
	b.WriteString("}\n")
	b.WriteString("\n")

	for i, origin := range sv.Origins {
		b.WriteString(fmt.Sprintf("backend backend_%d {\n", i))
		b.WriteString(fmt.Sprintf("  .host = \"%s\";\n", origin.Host))
		b.WriteString(fmt.Sprintf("  .port = \"%d\";\n", origin.Port))
		if origin.TLS {
			b.WriteString("  .via = haproxy_https;\n")
		} else {
			b.WriteString("  .via = haproxy_http;\n")
		}
		b.WriteString("}\n")
	}
	if len(sv.Origins) > 0 {
		b.WriteString("\n")
	}

	b.WriteString("sub vcl_recv {\n")
	if len(sv.Domains) > 0 {
		b.WriteString("  if ")
		for i, domain := range sv.Domains {
			if i > 0 {
				b.WriteString(" && ")
			}
			b.WriteString(fmt.Sprintf("req.http.host != \"%s\"", domain))
		}
		b.WriteString(" {\n")
		b.WriteString("    return(synth(400,\"Unknown Host header.\"));\n")
		b.WriteString("  }\n")
	}

	if sv.VclRecvContent != "" {
		b.WriteString("  # vcl_recv content from database\n")
		scanner := bufio.NewScanner(strings.NewReader(sv.VclRecvContent))
		for scanner.Scan() {
			if scanner.Text() != "" {
				b.WriteString("  " + scanner.Text() + "\n")
			} else {
				b.WriteString("\n")
			}
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("scanning VclRecvContent failed: %w", err)
		}
	}
	b.WriteString("}\n")

	return b.String(), nil
}

func selectVcls(dbPool *pgxpool.Pool, ad authData) ([]completeVcl, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		// Usage of JOIN with subqueries based on
		// https://stackoverflow.com/questions/27622398/multiple-array-agg-calls-in-a-single-query
		// (including separate version when having WHERE statement based on org).
		rows, err = dbPool.Query(
			context.Background(),
			`SELECT
				organizations.id AS org_id,
				services.id AS service_id,
				service_versions.version,
				service_versions.active,
				service_vcl_recv.content AS vcl_recv_content,
				agg_domains.domains,
				agg_origins.origins
			FROM
				organizations
				JOIN services ON organizations.id = services.org_id
				JOIN service_versions ON services.id = service_versions.service_id
				JOIN service_vcl_recv ON service_versions.id = service_vcl_recv.service_version_id
				JOIN (
					SELECT service_version_id, array_agg(domain ORDER BY domain) AS domains
					FROM service_domains
					GROUP BY service_version_id
				) AS agg_domains ON agg_domains.service_version_id = service_versions.id
				JOIN (
					SELECT service_version_id, array_agg((host, port, tls) ORDER BY host, port) AS origins
					FROM service_origins
					GROUP BY service_version_id
				) AS agg_origins ON agg_origins.service_version_id = service_versions.id
			ORDER BY organizations.name`,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to query for vcls as superuser: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(
			context.Background(),
			`SELECT
				organizations.id AS org_id,
				services.id AS service_id,
				service_versions.version,
				service_versions.active,
				service_vcl_recv.content AS vcl_recv_content,
				(SELECT
					array_agg(domain ORDER BY domain)
					FROM service_domains
					WHERE service_version_id = service_versions.id
				) AS domains,
				(SELECT
					array_agg((host, port, tls) ORDER BY host, port)
					FROM service_origins
					WHERE service_version_id = service_versions.id
				) AS origins
			FROM
				organizations
				JOIN services ON organizations.id = services.org_id
				JOIN service_versions ON services.id = service_versions.service_id
				JOIN service_vcl_recv ON service_versions.id = service_vcl_recv.service_version_id
			WHERE organizations.id=$1
			ORDER BY organizations.name`,
			*ad.OrgID,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to query for vcls as normal user: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	selectedVcls, err := pgx.CollectRows(rows, pgx.RowToStructByName[selectVcl])
	if err != nil {
		return nil, fmt.Errorf("unable to get rows for vcls: %w", err)
	}

	var completeVcls []completeVcl
	for _, sv := range selectedVcls {
		vclContent, err := generateCompleteVcl(sv)
		if err != nil {
			return nil, fmt.Errorf("unable to generate complete vcl for selected vcl: %w", err)
		}
		completeVcls = append(completeVcls, completeVcl{
			OrgID:     sv.OrgID,
			ServiceID: sv.ServiceID,
			Active:    sv.Active,
			Version:   sv.Version,
			Content:   vclContent,
		})
	}

	return completeVcls, nil
}

func newChiRouter(devMode bool, logger zerolog.Logger, dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore, csrfMiddleware func(http.Handler) http.Handler) *chi.Mux {
	router := chi.NewMux()

	hlogChain := chi.Chain(
		hlog.NewHandler(logger),
		hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			hlog.FromRequest(r).Info().
				Str("method", r.Method).
				Stringer("url", r.URL).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg("")
		}),
		hlog.RemoteAddrHandler("ip"),
		hlog.UserAgentHandler("user_agent"),
		hlog.RefererHandler("referer"),
		hlog.RequestIDHandler("req_id", "Request-Id"),
	)
	router.Use(hlogChain...)

	router.Get("/", rootHandler)

	// Authenticated console releated routes
	router.Group(func(r chi.Router) {
		r.Use(csrfMiddleware)
		r.Use(consoleAuthMiddleware(cookieStore))
		r.Get("/console", consoleHandler(cookieStore))
	})

	// Console login related routes
	router.Group(func(r chi.Router) {
		r.Use(csrfMiddleware)
		r.Get("/login", loginHandler(dbPool, cookieStore, devMode))
		r.Post("/login", loginHandler(dbPool, cookieStore, devMode))
		r.Get("/logout", logoutHandler(cookieStore, devMode))
	})

	return router
}

func Ptr[T any](v T) *T {
	return &v
}

type domainString string

func (ds domainString) Schema(_ huma.Registry) *huma.Schema {
	return &huma.Schema{
		Type:      "string",
		MinLength: Ptr(1),
		MaxLength: Ptr(253),
	}
}

func setupHumaAPI(router chi.Router, dbPool *pgxpool.Pool) error {
	router.Route("/api", func(r chi.Router) {
		r.Use(apiAuthMiddleware(dbPool))

		config := huma.DefaultConfig("SUNET CDN API", "0.0.1")
		config.Servers = []*huma.Server{
			{URL: "https://manager.cdn.example.se/api"},
		}

		api := humachi.New(r, config)

		huma.Get(api, "/v1/users", func(ctx context.Context, _ *struct{},
		) (*usersOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				logger.Error().Msg("unable to read auth data from users handler")
				return nil, errors.New("unable to read auth data from users handler")
			}

			users, err := selectUsers(dbPool, logger, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query users")
				return nil, err
			}

			resp := &usersOutput{
				Body: users,
			}
			return resp, nil
		})

		huma.Get(api, "/v1/users/{user}", func(ctx context.Context, input *struct {
			User string `path:"user" example:"1" doc:"User ID or name" minLength:"1" maxLength:"63"`
		},
		) (*userOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from user GET handler")
			}

			org, err := selectUserByID(dbPool, logger, input.User, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				} else if errors.Is(err, errNotFound) {
					return nil, huma.Error404NotFound("user not found")
				}
				logger.Err(err).Msg("unable to query users")
				return nil, err
			}
			resp := &userOutput{}
			resp.Body.ID = org.ID
			resp.Body.Name = org.Name
			return resp, nil
		})

		// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
		postUsersPath := "/v1/users"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postUsersPath, &userOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postUsersPath, &userOutput{}),
				Method:        http.MethodPost,
				Path:          postUsersPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Name         string `json:"name" example:"you@example.com" doc:"The username" minLength:"1" maxLength:"63"`
					Role         string `json:"role" example:"customer" doc:"Role ID or name" minLength:"1" maxLength:"63"`
					Organization string `json:"organization" example:"Some name" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
					Password     string `json:"password" example:"verysecretpassword" doc:"The user password" minLength:"15" maxLength:"64"`
				}
			},
			) (*userOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from users POST handler")
				}

				id, err := insertUser(dbPool, input.Body.Name, input.Body.Password, input.Body.Role, input.Body.Organization, ad)
				if err != nil {
					if errors.Is(err, errForbidden) {
						return nil, huma.Error403Forbidden("not allowed to add resource")
					}
					logger.Err(err).Msg("unable to add user")
					return nil, err
				}
				resp := &userOutput{}
				resp.Body.ID = id
				resp.Body.Name = input.Body.Name
				return resp, nil
			},
		)

		huma.Get(api, "/v1/organizations", func(ctx context.Context, _ *struct{},
		) (*organizationsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from organizations GET handler")
			}

			orgs, err := selectOrganizations(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query organizations")
				return nil, err
			}

			resp := &organizationsOutput{
				Body: orgs,
			}
			return resp, nil
		})

		huma.Get(api, "/v1/organizations/{organization}", func(ctx context.Context, input *struct {
			Organization string `path:"organization" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*organizationOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization GET handler")
			}

			org, err := selectOrganizationByID(dbPool, input.Organization, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				} else if errors.Is(err, errNotFound) {
					return nil, huma.Error404NotFound("organization not found")
				}
				logger.Err(err).Msg("unable to query organization")
				return nil, err
			}
			resp := &organizationOutput{}
			resp.Body.ID = org.ID
			resp.Body.Name = org.Name
			return resp, nil
		})

		// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
		postOrganizationsPath := "/v1/organizations"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postOrganizationsPath, &organizationOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postOrganizationsPath, &organizationOutput{}),
				Method:        http.MethodPost,
				Path:          postOrganizationsPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Name string `json:"name" example:"Some name" doc:"Organization name" minLength:"1" maxLength:"63"`
				}
			},
			) (*organizationOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from organization POST handler: %w")
				}

				id, err := insertOrganization(dbPool, input.Body.Name, ad)
				if err != nil {
					if errors.Is(err, errForbidden) {
						return nil, huma.Error403Forbidden("not allowed to add resource")
					}
					logger.Err(err).Msg("unable to add organization")
					return nil, err
				}
				resp := &organizationOutput{}
				resp.Body.ID = id
				resp.Body.Name = input.Body.Name
				return resp, nil
			},
		)

		huma.Get(api, "/v1/services", func(ctx context.Context, _ *struct{},
		) (*servicesOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from services GET handler")
			}

			services, err := selectServices(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to query for services")
				}
				logger.Err(err).Msg("unable to query services")
				return nil, err
			}

			resp := &servicesOutput{
				Body: services,
			}
			return resp, nil
		})

		huma.Get(api, "/v1/services/{service}", func(ctx context.Context, input *struct {
			Service string `path:"service" example:"1" doc:"Service ID or name" minLength:"1" maxLength:"63"`
		},
		) (*serviceOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service GET handler")
			}

			services, err := selectServiceByID(dbPool, input.Service, ad)
			if err != nil {
				if errors.Is(err, errNotFound) {
					return nil, huma.Error404NotFound("service not found")
				} else if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("access to this service is not allowed")
				}
				logger.Err(err).Msg("unable to query service by ID")
				return nil, err
			}

			resp := &serviceOutput{
				Body: services,
			}
			return resp, nil
		})

		postServicesPath := "/v1/services"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postServicesPath, &serviceOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postServicesPath, &serviceOutput{}),
				Method:        http.MethodPost,
				Path:          postServicesPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Name         string  `json:"name" example:"Some name" doc:"Service name" minLength:"1" maxLength:"63"`
					Organization *string `json:"organization,omitempty" example:"Name or ID of organization" doc:"org1" minLength:"1" maxLength:"63"`
				}
			},
			) (*organizationOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from service GET handler")
				}

				id, err := insertService(dbPool, input.Body.Name, input.Body.Organization, ad)
				if err != nil {
					if errors.Is(err, errUnprocessable) {
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add service")
					} else if errors.Is(err, errAlreadyExists) {
						return nil, huma.Error400BadRequest("service already exists")
					} else if errors.Is(err, errForbidden) {
						return nil, huma.Error403Forbidden("not allowed to create this service")
					}
					logger.Err(err).Msg("unable to add service")
					return nil, err
				}
				resp := &organizationOutput{}
				resp.Body.ID = id
				resp.Body.Name = input.Body.Name
				return resp, nil
			},
		)

		huma.Get(api, "/v1/service-versions", func(ctx context.Context, _ *struct{},
		) (*serviceVersionsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service-versions GET handler")
			}

			serviceVersions, err := selectServiceVersions(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query service-versions")
				return nil, err
			}

			resp := &serviceVersionsOutput{
				Body: serviceVersions,
			}
			return resp, nil
		})

		postServiceVersionsPath := "/v1/service-versions"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postServiceVersionsPath, &serviceVersionOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postServiceVersionsPath, &serviceVersionOutput{}),
				Method:        http.MethodPost,
				Path:          postServiceVersionsPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					ServiceID    uuid.UUID      `json:"service_id" doc:"Service ID"`
					Organization *string        `json:"organization,omitempty" example:"Name or ID of organization" doc:"Name or ID of the organization" minLength:"1" maxLength:"63"`
					Domains      []domainString `json:"domains" doc:"List of domains handled by the service" minItems:"1" maxItems:"10"`
					Origins      []origin       `json:"origins" doc:"List of origin hosts for this service" minItems:"1" maxItems:"10"`
					Active       *bool          `json:"active,omitempty" doc:"If the submitted config should be activated or not"`
				}
			},
			) (*serviceVersionOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from service GET handler")
				}

				// Seems we can not use pgtype.UUID as the type in the
				// input body directly, so go via google/uuid module
				// instead and convert here.
				//
				// Might be possible to make this work with pgtype.UUID
				// directly if it would implement
				// encoding.TextUnmarshaler as described here:
				// https://github.com/danielgtaylor/huma/issues/654
				var pgServiceID pgtype.UUID
				err := pgServiceID.Scan(input.Body.ServiceID.String())
				if err != nil {
					return nil, errors.New("unable to convert uuid to pgtype")
				}

				serviceVersionInsertRes, err := insertServiceVersion(dbPool, pgServiceID, input.Body.Organization, input.Body.Domains, input.Body.Origins, input.Body.Active, ad)
				if err != nil {
					if errors.Is(err, errUnprocessable) {
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add service version")
					} else if errors.Is(err, errAlreadyExists) {
						return nil, huma.Error400BadRequest("service version already exists")
					} else if errors.Is(err, errForbidden) {
						return nil, huma.Error403Forbidden("not allowed to create this service version")
					}
					logger.Err(err).Msg("unable to add service")
					return nil, err
				}
				resp := &serviceVersionOutput{}
				resp.Body.ID = serviceVersionInsertRes.versionID
				resp.Body.Version = serviceVersionInsertRes.version
				resp.Body.Active = serviceVersionInsertRes.active
				return resp, nil
			},
		)

		huma.Get(api, "/v1/vcls", func(ctx context.Context, _ *struct{},
		) (*completeVclsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				logger.Error().Msg("unable to read auth data from vcls handler")
				return nil, errors.New("unable to read auth data from vcls handler")
			}

			vcls, err := selectVcls(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query vcls")
				return nil, err
			}

			resp := &completeVclsOutput{
				Body: vcls,
			}
			return resp, nil
		})
	})

	return nil
}

type user struct {
	ID        pgtype.UUID `json:"id" doc:"ID of user"`
	Name      string      `json:"name" example:"user1" doc:"name of user"`
	RoleName  string      `json:"role_name" example:"customer"`
	Superuser bool        `json:"superuser" example:"true" doc:"if user is a superuser"`
}

type userOutput struct {
	Body user
}

type usersOutput struct {
	Body []user
}

type organization struct {
	ID   pgtype.UUID `json:"id" doc:"ID of organization, UUIDv4"`
	Name string      `json:"name" example:"organization 1" doc:"name of organization"`
}

type organizationOutput struct {
	Body organization
}

type organizationsOutput struct {
	Body []organization
}

type service struct {
	ID   pgtype.UUID `json:"id" doc:"ID of service"`
	Name string      `json:"name" example:"service 1" doc:"name of service"`
}

type serviceOutput struct {
	Body service
}

type servicesOutput struct {
	Body []service
}

type serviceVersion struct {
	ID          pgtype.UUID `json:"id"`
	Version     int64       `json:"version"`
	Active      bool        `json:"active"`
	ServiceName string      `json:"service_name,omitempty"`
}

type serviceVersionOutput struct {
	Body serviceVersion
}

type serviceVersionsOutput struct {
	Body []serviceVersion
}

type origin struct {
	Host string `json:"host" minLength:"1" maxLength:"253"`
	Port int    `json:"port" minimum:"1" maximum:"65535"`
	TLS  bool   `json:"tls"`
}

type selectVcl struct {
	OrgID          pgtype.UUID `json:"org_id" doc:"ID of organization"`
	ServiceID      pgtype.UUID `json:"service_id" doc:"ID of service"`
	Active         bool        `json:"active" example:"true" doc:"If the VCL is active"`
	Version        int64       `json:"version" example:"1" doc:"Version of the service"`
	Domains        []string    `json:"domains" doc:"The domains used by the VCL"`
	Origins        []origin    `json:"origins" doc:"The origins used by the VCL"`
	VclRecvContent string      `json:"vcl_recv_content" doc:"The vcl_recv content for the service"`
}

type completeVcl struct {
	OrgID     pgtype.UUID `json:"org_id" doc:"ID of organization"`
	ServiceID pgtype.UUID `json:"service_id" doc:"ID of service"`
	Active    bool        `json:"active" example:"true" doc:"If the VCL is active"`
	Version   int64       `json:"version" example:"1" doc:"Version of the service"`
	Content   string      `json:"content" doc:"The complete VCL loaded by varnish"`
}

type completeVclsOutput struct {
	Body []completeVcl
}

// Generate a random password containing A-Z, a-z and 0-9
func generatePassword(length int) (string, error) {
	minLength := 15

	if length < minLength {
		return "", fmt.Errorf("the password must be at least %d characters", minLength)
	}

	var chars []rune
	// 0-9
	for c := '0'; c <= '9'; c++ {
		chars = append(chars, c)
	}

	// A-Z
	for c := 'A'; c <= 'Z'; c++ {
		chars = append(chars, c)
	}

	// a-z
	for c := 'a'; c <= 'z'; c++ {
		chars = append(chars, c)
	}

	maxBigInt := big.NewInt(int64(len(chars)))

	var b strings.Builder
	for i := 0; i < length; i++ {
		bigI, err := rand.Int(rand.Reader, maxBigInt)
		if err != nil {
			return "", fmt.Errorf("rand.Int failed: %w", err)
		}

		if !bigI.IsInt64() {
			return "", errors.New("rand.Int can not be represented as int64")
		}

		b.WriteRune(chars[int(bigI.Int64())])
	}
	return b.String(), nil
}

type InitUser struct {
	ID       pgtype.UUID
	Name     string
	Role     string
	Password string
}

func Init(logger zerolog.Logger, pgConfig *pgxpool.Config, encryptedSessionKey bool) (InitUser, error) {
	err := migrations.Up(logger, pgConfig)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to run initial migration: %w", err)
	}

	dbPool, err := pgxpool.NewWithConfig(context.Background(), pgConfig)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to create database pool: %w", err)
	}
	defer dbPool.Close()

	password, err := generatePassword(30)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to generate password: %w", err)
	}

	a2Data, err := passwordToArgon2(password)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to create password data for initial user: %w", err)
	}

	u := InitUser{
		Name:     "admin",
		Role:     "admin",
		Password: password,
	}

	var gorillaSessionEncKey []byte

	gorillaSessionAuthKey, err := generateRandomKey(32)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to create random gorilla session auth key: %w", err)
	}

	if encryptedSessionKey {
		gorillaSessionEncKey, err = generateRandomKey(32)
		if err != nil {
			return InitUser{}, fmt.Errorf("unable to create random gorilla session encryption key: %w", err)
		}
	}

	gorillaCSRFAuthKey, err := generateRandomKey(32)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to create random gorilla CSRF key: %w", err)
	}

	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		// Verify there are no roles present
		var rolesExists bool
		err := tx.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM roles)").Scan(&rolesExists)
		if err != nil {
			return fmt.Errorf("checking if there are any roles failed: %w", err)
		}

		if rolesExists {
			return fmt.Errorf("we do not expect there to be any roles, is the database already initialized?")
		}

		// Because of the NOT NULL role_id required for users, if there are no
		// roles there are no users either. So now we can create an initial
		// admin role and user.
		var roleID pgtype.UUID
		err = tx.QueryRow(context.Background(), "INSERT INTO roles (name, superuser) VALUES ($1, TRUE) RETURNING id", u.Role).Scan(&roleID)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial superuser role '%s': %w", u.Role, err)
		}

		userID, err := insertUserWithArgon2Tx(tx, u.Name, nil, roleID, a2Data)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user: %w", err)
		}

		u.ID = userID

		_, err = insertGorillaSessionKey(tx, gorillaSessionAuthKey, gorillaSessionEncKey)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user session key: %w", err)
		}

		_, _, err = insertGorillaCSRFKey(tx, gorillaCSRFAuthKey, true)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial CSRF key: %w", err)
		}

		return nil
	})
	if err != nil {
		return InitUser{}, fmt.Errorf("initial user transaction failed: %w", err)
	}

	return u, nil
}

func generateRandomKey(length int) ([]byte, error) {
	b := make([]byte, length)

	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	return b, nil
}

func insertGorillaSessionKey(tx pgx.Tx, authKey []byte, encKey []byte) (pgtype.UUID, error) {
	var sessionKeyID pgtype.UUID

	// key_order is either the current max key_order value + 1 or 0 if no rows exist
	err := tx.QueryRow(
		context.Background(),
		"INSERT INTO gorilla_session_keys (auth_key, enc_key, key_order) SELECT $1, $2, COALESCE(MAX(key_order)+1,0) FROM gorilla_session_keys RETURNING id",
		authKey,
		encKey,
	).Scan(&sessionKeyID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT gorilla session key: %w", err)
	}

	return sessionKeyID, nil
}

func insertGorillaCSRFKey(tx pgx.Tx, authKey []byte, active bool) (pgtype.UUID, pgtype.UUID, error) {
	var prevCSRFKeyID, csrfKeyID pgtype.UUID

	if active {
		err := tx.QueryRow(context.Background(), "UPDATE gorilla_csrf_keys SET active = NULL WHERE active = TRUE RETURNING id").Scan(&prevCSRFKeyID)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return pgtype.UUID{}, pgtype.UUID{}, fmt.Errorf("unable to deactivate previous gorilla CSRF key: %w", err)
			}
		}
	}

	// If active is false we actually want to insert NULL in the database
	// since the UNIQUE constraint will error out if we try to store
	// multiple FALSE entries at the same time. So only actually set the
	// pointer to a bool value if true.
	var activePtr *bool
	if active {
		activePtr = &active
	}

	err := tx.QueryRow(
		context.Background(),
		"INSERT INTO gorilla_csrf_keys (active, auth_key) VALUES ($1, $2) RETURNING id",
		activePtr,
		authKey,
	).Scan(&csrfKeyID)
	if err != nil {
		return pgtype.UUID{}, pgtype.UUID{}, fmt.Errorf("unable to INSERT gorilla csrf key: %w", err)
	}

	return csrfKeyID, prevCSRFKeyID, nil
}

type sessionKey struct {
	TS      time.Time `db:"ts"`
	AuthKey []byte    `db:"auth_key"`
	EncKey  []byte    `db:"enc_key"`
}

func getSessionKeys(dbPool *pgxpool.Pool) ([]sessionKey, error) {
	rows, err := dbPool.Query(context.Background(), "SELECT ts, auth_key, enc_key FROM gorilla_session_keys ORDER BY key_order DESC")
	if err != nil {
		return nil, fmt.Errorf("unable to query for session key: %w", err)
	}

	sessionKeys, err := pgx.CollectRows(rows, pgx.RowToStructByName[sessionKey])
	if err != nil {
		return nil, fmt.Errorf("unable to get rows for session secrets: %w", err)
	}

	if len(sessionKeys) == 0 {
		return nil, errors.New("no session keys available")
	}

	return sessionKeys, nil
}

func getCSRFKey(dbPool *pgxpool.Pool) ([]byte, error) {
	var csrfKey []byte
	err := dbPool.QueryRow(context.Background(), "SELECT auth_key FROM gorilla_csrf_keys WHERE active = TRUE").Scan(&csrfKey)
	if err != nil {
		return nil, fmt.Errorf("unable to query for CSRF key: %w", err)
	}

	return csrfKey, nil
}

func getSessionStore(logger zerolog.Logger, dbPool *pgxpool.Pool) (*sessions.CookieStore, error) {
	sessionKeys, err := getSessionKeys(dbPool)
	if err != nil {
		return nil, fmt.Errorf("unable to find session keys in database, make sure the database is initialized via the 'init' command: %w", err)
	}

	if sessionKeys[0].EncKey == nil {
		logger.Info().Msg("gorilla session encryption key is nil, using unencrypted cookies")
	}

	sessionKeyPairs := [][]byte{}
	for _, sk := range sessionKeys {
		sessionKeyPairs = append(sessionKeyPairs, sk.AuthKey)
		sessionKeyPairs = append(sessionKeyPairs, sk.EncKey)
	}

	return sessions.NewCookieStore(sessionKeyPairs...), nil
}

func getCSRFMiddleware(dbPool *pgxpool.Pool, secure bool) (func(http.Handler) http.Handler, error) {
	csrfKey, err := getCSRFKey(dbPool)
	if err != nil {
		return nil, fmt.Errorf("unable to find CSRF key in database, make sure the database is initialized via the 'init' command: %w", err)
	}

	csrfMiddleware := csrf.Protect(csrfKey, csrf.Secure(secure))

	return csrfMiddleware, nil
}

func Run(logger zerolog.Logger, devMode bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Exit gracefully on SIGINT or SIGTERM
	go func(logger zerolog.Logger, cancel context.CancelFunc) {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		s := <-sigCh
		logger.Info().Str("signal", s.String()).Msg("received signal")
		cancel()
	}(logger, cancel)

	conf, err := config.GetConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to get config")
	}

	pgConfig, err := conf.PGConfig()
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to parse PostgreSQL config string")
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create database pool")
	}
	defer dbPool.Close()

	err = dbPool.Ping(context.Background())
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to ping database connection")
	}

	// Verify that the database appears initialized by 'init' command
	var rolesExists bool
	err = dbPool.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM roles)").Scan(&rolesExists)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to check for roles in the database, is it initialized? (see init command)")
	}
	if !rolesExists {
		logger.Fatal().Msg("we exepect there to exist at least one role in the database, make sure the database is initialized via the 'init' command")
	}

	cookieStore, err := getSessionStore(logger, dbPool)
	if err != nil {
		logger.Fatal().Err(err).Msg("getSessionStore failed")
	}

	secureCSRF := true
	if devMode {
		secureCSRF = false
	}

	csrfMiddleware, err := getCSRFMiddleware(dbPool, secureCSRF)
	if err != nil {
		logger.Fatal().Err(err).Msg("getCSRFMiddleware failed")
	}

	router := newChiRouter(devMode, logger, dbPool, cookieStore, csrfMiddleware)

	err = setupHumaAPI(router, dbPool)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to setup Huma API")
	}

	srv := &http.Server{
		Addr:         conf.Server.Addr,
		Handler:      router,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
		ErrorLog:     log.New(&zerologErrorWriter{&logger}, "", 0),
	}

	// Handle graceful shutdown of HTTP server when receiving signal
	idleConnsClosed := make(chan struct{})

	go func(ctx context.Context, logger zerolog.Logger) {
		<-ctx.Done()

		shutdownDelay := time.Second * 5
		logger.Info().Msgf("sleeping for %s then calling Shutdown()", shutdownDelay)
		time.Sleep(shutdownDelay)
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Err(err).Msg("HTTP server Shutdown failure")
		}
		close(idleConnsClosed)
	}(ctx, logger)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("HTTP server ListenAndServe failed")
	}

	<-idleConnsClosed

	return nil
}
