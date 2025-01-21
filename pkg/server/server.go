package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/components"
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/coreos/go-oidc/v3/oidc"
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
	"golang.org/x/oauth2"
)

func init() {
	gob.Register(authData{})
	gob.Register(oidcCallbackData{})

	// Withouth this the decoder will fail on "error":"schema: invalid path \"gorilla.csrf.Token\""" when using gorilla/csrf
	schemaDecoder.IgnoreUnknownKeys(true)
}

const (
	// https://www.postgresql.org/docs/current/errcodes-appendix.html
	// unique_violation: 23505
	pgUniqueViolation = "23505"
	// check_violation: 23514
	pgCheckViolation = "23514"
	// exclusion_violation: 23P01
	pgExclusionViolation = "23P01"
)

var (
	errForbidden               = errors.New("access to resource is not allowed")
	errNotFound                = errors.New("resource not found")
	errUnprocessable           = errors.New("resource not processable")
	errAlreadyExists           = errors.New("resource already exists")
	errCheckViolation          = errors.New("invalid input data")
	errExclutionViolation      = errors.New("conflicting data in database")
	errBadPassword             = errors.New("bad password")
	errKeyCloakEmailUnverified = errors.New("keycloak user email is not verified")
	errBadOldPassword          = errors.New("old password is invalid")

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
	validatedRedirect("/console", w, r)
}

func consoleHomeHandler(cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		err := renderConsolePage(w, r, ad, "home", "SUNET CDN manager", []components.Service{})
		if err != nil {
			logger.Err(err).Msg("unable to render console page")
			return
		}
	}
}

func consoleServicesHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		services, err := selectServices(dbPool, ad)
		if err != nil {
			if errors.Is(err, errForbidden) {
				logger.Err(err).Msg("services console: not authorized to view page")
				http.Error(w, "not allowed to view this page, you need to be a member of an organization", http.StatusForbidden)
				return
			}
			logger.Err(err).Msg("services console: database lookup failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		cServices := []components.Service{}
		for _, service := range services {
			cServices = append(cServices, components.Service{Name: service.Name})
		}

		err = renderConsolePage(w, r, ad, "services", "SUNET CDN manager: Services", cServices)
		if err != nil {
			logger.Err(err).Msg("unable to render console page")
			return
		}
	}
}

// Login page/form for browser based (not API) requests
func renderConsolePage(w http.ResponseWriter, r *http.Request, ad authData, pageType string, heading string, services []components.Service) error {
	orgs := []string{}
	if ad.OrgName != nil {
		orgs = append(orgs, *ad.OrgName)
	}
	component := components.ConsolePage(pageType, heading, ad.Username, orgs, ad.Superuser, services)
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
func loginHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
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

			session := getSession(r, cookieStore)
			session.Values["ad"] = ad

			logger.Info().Msg("saving login session")
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
func logoutHandler(cookieStore *sessions.CookieStore) http.HandlerFunc {
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

		session := logoutSession(r, cookieStore)

		logger.Info().Msg("logout: saving expired login session")
		err := session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// User should be logged out at this point, send them to where they were originally headed (which will in turn probably redirect them to /auth/login).
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

type oidcCallbackData struct {
	State        string `validate:"required"`
	Nonce        string `validate:"required"`
	PKCEVerifier string `validate:"required"`
	ReturnTo     string
}

// Based on example code at https://github.com/coreos/go-oidc/blob/v3/example/idtoken/app.go
func oidcRandString() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func logoutSession(r *http.Request, cookieStore *sessions.CookieStore) *sessions.Session {
	logger := hlog.FromRequest(r)
	session, err := cookieStore.Get(r, cookieName)
	if err != nil {
		logger.Err(err).Msg("logoutSession: unable to decode existing cookie, using new one")
	}

	// Individual sessions can be deleted by setting Options.MaxAge = -1 for that session.
	session.Options.MaxAge = -1

	return session
}

func getSession(r *http.Request, cookieStore *sessions.CookieStore) *sessions.Session {
	logger := hlog.FromRequest(r)
	session, err := cookieStore.Get(r, cookieName)
	if err != nil {
		logger.Err(err).Msg("getSession: unable to decode existing cookie, using new one")
	}

	return session
}

// Endpoint used for initiating OIDC auth against keycloak
func keycloakOIDCHandler(cookieStore *sessions.CookieStore, oauth2Config oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		var err error

		q := r.URL.Query()
		returnTo := q.Get(returnToKey)

		ocd := oidcCallbackData{
			ReturnTo: returnTo,
		}

		ocd.State, err = oidcRandString()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ocd.Nonce, err = oidcRandString()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ocd.PKCEVerifier = oauth2.GenerateVerifier()

		// Add items to session that we access to check in the callback handler
		session := getSession(r, cookieStore)
		session.Values["ocd"] = ocd
		err = session.Save(r, w)
		if err != nil {
			logger.Err(err).Msg("unable to save keycloak OIDC session")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, oauth2Config.AuthCodeURL(ocd.State, oidc.Nonce(ocd.Nonce), oauth2.S256ChallengeOption(ocd.PKCEVerifier)), http.StatusFound)
	}
}

// Endpoint used for receiving callback from keycloak server
func oauth2CallbackHandler(cookieStore *sessions.CookieStore, oauth2Config oauth2.Config, idTokenVerifier *oidc.IDTokenVerifier, dbPool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		session := getSession(r, cookieStore)
		if session.IsNew {
			http.Error(w, "session data not available", http.StatusBadRequest)
			return
		}

		ocdInt, ok := session.Values["ocd"]
		if !ok {
			http.Error(w, "OIDC callback data not present in session", http.StatusInternalServerError)
			return
		}

		ocd := ocdInt.(oidcCallbackData)

		err := validate.Struct(ocd)
		if err != nil {
			logger.Err(err).Msg("OIDC callback struct did not validate")
		}

		if r.URL.Query().Get("state") != ocd.State {
			logger.Error().Msg("state did not match")
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"), oauth2.VerifierOption(ocd.PKCEVerifier))
		if err != nil {
			logger.Err(err).Msg("unable to exchange code for token")
			http.Error(w, "bad oauth2 exchange", http.StatusInternalServerError)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.Error().Msg("unable to extact id_token")
			http.Error(w, "unable to extract id_token", http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := idTokenVerifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			logger.Err(err).Msg("unable to verify id_token")
			http.Error(w, "unable to extract id_token", http.StatusInternalServerError)
			return
		}

		if idToken.Nonce != ocd.Nonce {
			logger.Error().Msg("nonce did not match")
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		// Example token content:
		//
		// "OAuth2Token": {
		//     "access_token": "*REDACTED*",
		//     "token_type": "Bearer",
		//     "refresh_token": "*REDACTED*",
		//     "expiry": "2025-01-06T08:27:36.664975+01:00"
		// },
		// "IDTokenClaims": {
		//     "exp": 1736148456,
		//     "iat": 1736148156,
		//     "auth_time": 1736148156,
		//     "jti": "c379d3fc-2fe0-4037-b861-30a701ba0064",
		//     "iss": "http://localhost:8080/realms/sunet-cdn-manager",
		//     "aud": "sunet-cdn-manager-server",
		//     "sub": "ab809abb-5bac-4db1-8088-3d340ea23de8",
		//     "typ": "ID",
		//     "azp": "sunet-cdn-manager-server",
		//     "nonce": "wgxCiPN-j2d5m10dI195aA",
		//     "sid": "568d1ff7-d26e-4707-ba22-9645340eb97a",
		//     "at_hash": "yFCg6LpJlK4qRZT49h6FcQ",
		//     "acr": "1",
		//     "email_verified": false,
		//     "name": "Test User",
		//     "preferred_username": "testuser",
		//     "given_name": "Test",
		//     "family_name": "User",
		//     "email": "testuser@example.com"
		// }

		// Extract custom claims
		kcc := keycloakClaims{}
		if err := idToken.Claims(&kcc); err != nil {
			logger.Err(err).Msg("unable to parse claims")
			http.Error(w, "unable to parse claims", http.StatusInternalServerError)
			return
		}

		err = validate.Struct(kcc)
		if err != nil {
			logger.Err(err).Msg("keycloak preferred_username failed validation")
			http.Error(w, "keycloak preferred_username failed validation", http.StatusBadRequest)
			return
		}

		// Get authData for keycloak user
		ad, err := keycloakUser(dbPool, logger, idToken.Subject, kcc)
		if err != nil {
			logger.Err(err).Msg("unable to get keycloak user")
			if errors.Is(err, errKeyCloakEmailUnverified) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		session.Values["ad"] = ad

		err = session.Save(r, w)
		if err != nil {
			logger.Err(err).Msg("unable to save session")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ocd.ReturnTo != "" {
			validatedRedirect(ocd.ReturnTo, w, r)
			return
		}

		validatedRedirect("/console", w, r)
	}
}

type keycloakClaims struct {
	// The length checks needs to be kept in sync with the CHECK constraint
	// for the users.name column in the database.
	PreferredUsername string `json:"preferred_username" validate:"min=1,max=63"`
}

func addKeycloakUser(dbPool *pgxpool.Pool, subject, name string) (pgtype.UUID, pgtype.UUID, error) {
	var userID, keycloakProviderID pgtype.UUID

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), "INSERT INTO users (name, role_id, auth_provider_id) VALUES ($1, (SELECT id from roles WHERE name=$2), (SELECT id FROM auth_providers WHERE name=$3)) RETURNING id", name, "user", "keycloak").Scan(&userID)
		if err != nil {
			return fmt.Errorf("unable to INSERT user from keyclaok data: %w", err)
		}

		err = tx.QueryRow(context.Background(), "INSERT INTO auth_provider_keycloak (user_id, subject) VALUES ($1, $2) RETURNING id", userID, subject).Scan(&keycloakProviderID)
		if err != nil {
			return fmt.Errorf("unable to INSERT auth_provider_keycloak dataf for new user: %w", err)
		}

		return nil
	})
	if err != nil {
		return pgtype.UUID{}, pgtype.UUID{}, fmt.Errorf("transaction failed: %w", err)
	}

	return userID, keycloakProviderID, nil
}

func keycloakUser(dbPool *pgxpool.Pool, logger *zerolog.Logger, subject string, kcc keycloakClaims) (authData, error) {
	// We keep track of keycloak users via the sub value returned in the ID
	// token. For keycloak this is a UUID, e.g.
	// "ab809abb-5bac-4db1-8088-3d340ea23de8" which is the actual user ID in keycloak which
	// should remain the same even if the username or email is changed at a
	// later time.
	//
	// This means we need to backup the keycloak database since
	// if the database is lost users are recreated with another UUID and
	// treated as a new user by us.

	var username string
	var userID, keycloakProviderID pgtype.UUID
	err := dbPool.QueryRow(
		context.Background(),
		"SELECT users.id, users.name FROM users JOIN auth_provider_keycloak ON users.id = auth_provider_keycloak.user_id WHERE auth_provider_keycloak.subject = $1",
		subject,
	).Scan(&userID, &username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User does not exist, add to database
			userID, keycloakProviderID, err = addKeycloakUser(dbPool, subject, kcc.PreferredUsername)
			if err != nil {
				return authData{}, fmt.Errorf("unable to add keycloak user to database: %w", err)
			}
			username = kcc.PreferredUsername
			logger.Info().Str("user_id", userID.String()).Str("keycloak_provider_id", keycloakProviderID.String()).Msg("created user based on keycloak credentials")
		} else {
			return authData{}, fmt.Errorf("keycloak user lookup failed: %w", err)
		}
	}

	if username != kcc.PreferredUsername {
		logger.Info().Str("from", username).Str("to", kcc.PreferredUsername).Msg("keycloak username out of sync, updating local username")
		_, err := dbPool.Exec(context.Background(), "UPDATE users SET name=$1 WHERE id=$2", kcc.PreferredUsername, userID)
		if err != nil {
			return authData{}, fmt.Errorf("renaming user based on keycloak data failed: %w", err)
		}

		username = kcc.PreferredUsername
	}

	var roleID pgtype.UUID
	var orgID *pgtype.UUID // can be nil if not belonging to a organization
	var orgName *string    // same as above
	var superuser bool
	var roleName string
	err = dbPool.QueryRow(
		context.Background(),
		`SELECT
				users.id,
				users.org_id,
				orgs.name,
				users.role_id,
				roles.name,
				roles.superuser
			FROM users
			JOIN roles ON users.role_id = roles.id
			LEFT JOIN orgs ON users.org_id = orgs.id
			WHERE users.name=$1`,
		username,
	).Scan(
		&userID,
		&orgID,
		&orgName,
		&roleID,
		&roleName,
		&superuser,
	)
	if err != nil {
		return authData{}, err
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
	redirectURL.Path = "/auth/login"

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
				orgs.name,
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
			LEFT JOIN orgs ON users.org_id = orgs.id
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

const (
	cookieName = "sunet-cdn-manager"
)

func authFromSession(logger *zerolog.Logger, cookieStore *sessions.CookieStore, r *http.Request) *authData {
	session := getSession(r, cookieStore)

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

			if r.Method != "GET" {
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
				return
			}

			adRef := authFromSession(logger, cookieStore, r)
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
		rows, err = dbPool.Query(context.Background(), "SELECT id, name, org_id, role_id FROM users ORDER BY name")
		if err != nil {
			logger.Err(err).Msg("unable to query for users")
			return nil, fmt.Errorf("unable to query for users")
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name, org_id, role_id FROM users WHERE users.id=$1 ORDER BY name", ad.UserID)
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

	var roleID pgtype.UUID
	var orgID *pgtype.UUID
	if userIdent.isID() {
		if !ad.Superuser && (ad.UserID != *userIdent.id) {
			return user{}, errNotFound
		}

		var userName string
		err := dbPool.QueryRow(context.Background(), "SELECT name, org_id, role_id FROM users WHERE users.id=$1", *userIdent.id).Scan(&userName, &orgID, &roleID)
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
		err := dbPool.QueryRow(context.Background(), "SELECT id, org_id, role_id FROM users WHERE name=$1", inputID).Scan(&userID, &orgID, &roleID)
		if err != nil {
			logger.Err(err).Str("id", inputID).Msg("unable to SELECT user by name")
			return user{}, fmt.Errorf("unable to SELECT user by name")
		}
		u.ID = userID
		u.Name = *userIdent.name
	}

	u.RoleID = roleID
	u.OrgID = orgID

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

func upsertArgon2Tx(tx pgx.Tx, userID pgtype.UUID, a2Data argon2Data) (pgtype.UUID, error) {
	var keyID pgtype.UUID
	err := tx.QueryRow(
		context.Background(),
		"INSERT INTO user_argon2keys (key, salt, time, memory, threads, tag_size, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (user_id) DO UPDATE SET key = $1, salt = $2, time = $3, memory = $4, threads = $5, tag_size = $6 RETURNING id",
		a2Data.key,
		a2Data.salt,
		a2Data.argonTime,
		a2Data.argonMemory,
		a2Data.argonThreads,
		a2Data.argonTagSize,
		userID,
	).Scan(&keyID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to UPDATE user argon2 data: %w", err)
	}

	return keyID, nil
}

func setLocalPassword(logger *zerolog.Logger, ad authData, dbPool *pgxpool.Pool, user string, oldPassword string, newPassword string) (pgtype.UUID, error) {
	userIdent, err := parseNameOrID(user)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to parse user for local-password: %w", err)
	}

	// While we could potentially do the argon2 operation inside the
	// transaction below after we know the user is actually allowed to
	// change the password it feels wrong to keep a transaction open
	// longer than necessary. So do the initial hashing here. We still do
	// another round of hashing when testing the oldPassword below but in
	// that case it probably makes sense to know the database is in a
	// consistent state (via FOR SHARE selects) during the operation.
	a2Data, err := passwordToArgon2(newPassword)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to generate argon2 data from newPassword: %w", err)
	}

	var keyID pgtype.UUID
	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		var userID pgtype.UUID
		var userName string
		if userIdent.isID() {
			userID = *userIdent.id
			userName, err = userIDToNameTx(tx, *userIdent.id)
			if err != nil {
				return fmt.Errorf("unable to resolve ID to username: %w", err)
			}
		} else {
			userName = *userIdent.name
			userID, err = userNameToIDTx(tx, *userIdent.name)
			if err != nil {
				return fmt.Errorf("unable to resolve username to ID: %w", err)
			}
		}

		// We only allow the setting of passwords for users using the "local" auth provider
		var authProviderName string
		err = tx.QueryRow(context.Background(), "SELECT auth_providers.name FROM auth_providers JOIN users ON auth_providers.id = users.auth_provider_id WHERE users.id=$1 FOR SHARE", userID).Scan(&authProviderName)
		if err != nil {
			return fmt.Errorf("unable to look up name of auth provider for user with id '%s': %w", userID, err)
		}

		if authProviderName != "local" {
			return fmt.Errorf("ignoring local-password request for non-local user")
		}

		// A superuser can change any password and a normal user can only change their own password
		if !ad.Superuser && ad.UserID != userID {
			return errForbidden
		}

		// A normal user most supply the old password
		if !ad.Superuser && oldPassword == "" {
			return errors.New("old password required for non-superusers")
		}

		// ... and finally, verify that the password supplied by a normal user actually is correct
		if !ad.Superuser {
			_, err := dbUserLogin(dbPool, userName, oldPassword)
			if err != nil {
				logger.Err(err).Msg("old password check failed")
				return errBadOldPassword
			}
		}

		keyID, err = upsertArgon2Tx(tx, userID, a2Data)
		if err != nil {
			return fmt.Errorf("unable to UPDATE user argon2 data: %w", err)
		}

		return nil
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("setLocalPassword: transaction failed: %w", err)
	}

	return keyID, nil
}

func createUser(dbPool *pgxpool.Pool, name string, role string, org *string, ad authData) (pgtype.UUID, error) {
	if !ad.Superuser {
		return pgtype.UUID{}, errForbidden
	}

	var err error
	var orgIdent identifier
	if org != nil {
		orgIdent, err = parseNameOrID(*org)
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("unable to parse organization for user INSERT: %w", err)
		}
	}

	roleIdent, err := parseNameOrID(role)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to parse role for user INSERT: %w", err)
	}

	var userID, roleID pgtype.UUID
	var orgID *pgtype.UUID

	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		if org != nil {
			if !orgIdent.isID() {
				orgID, err = orgNameToIDTx(tx, *orgIdent.name)
				if err != nil {
					return fmt.Errorf("unable to map org name to id: %w", err)
				}
			} else {
				orgID = orgIdent.id
			}
		}

		if !roleIdent.isID() {
			roleID, err = roleNameToIDTx(tx, *roleIdent.name)
			if err != nil {
				return fmt.Errorf("unable to map role name to id: %w", err)
			}
		} else {
			roleID = *roleIdent.id
		}

		authProviderID, err := authProviderNameToIDTx(tx, "local")
		if err != nil {
			return fmt.Errorf("unble to resolve authProvider name to ID: %w", err)
		}

		userID, err = insertUserTx(tx, name, orgID, roleID, authProviderID)
		if err != nil {
			return fmt.Errorf("createUser: INSERT failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("createUser: transaction failed: %w", err)
	}

	return userID, nil
}

func insertUserTx(tx pgx.Tx, name string, orgID *pgtype.UUID, roleID pgtype.UUID, authProviderID pgtype.UUID) (pgtype.UUID, error) {
	var userID pgtype.UUID
	err := tx.QueryRow(context.Background(), "INSERT INTO users (name, org_id, role_id, auth_provider_id) VALUES ($1, $2, $3, $4) RETURNING id", name, orgID, roleID, authProviderID).Scan(&userID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("INSERT user failed: %w", err)
	}

	return userID, nil
}

// Helpers for converting names to IDs and back.
// The use of FOR SHARE in selects is to make sure later operations in the
// already created transaction can know that nothing learned from these selects
// has changed under their feet at the time of a write. FOR SHARE should be
// fairly safe since multiple readers can hold them at once, but we need to be
// careful to not introduce deadlocks if contending with FOR UPDATE calls etc.
func orgNameToIDTx(tx pgx.Tx, name string) (*pgtype.UUID, error) {
	var orgID *pgtype.UUID
	err := tx.QueryRow(context.Background(), "SELECT id FROM orgs WHERE name=$1 FOR SHARE", name).Scan(&orgID)
	if err != nil {
		return nil, err
	}
	return orgID, nil
}

func roleNameToIDTx(tx pgx.Tx, name string) (pgtype.UUID, error) {
	var roleID pgtype.UUID
	err := tx.QueryRow(context.Background(), "SELECT id FROM roles WHERE name=$1 FOR SHARE", name).Scan(&roleID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return roleID, nil
}

func authProviderNameToIDTx(tx pgx.Tx, name string) (pgtype.UUID, error) {
	var authProviderID pgtype.UUID
	err := tx.QueryRow(context.Background(), "SELECT id FROM auth_providers WHERE name=$1 FOR SHARE", name).Scan(&authProviderID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return authProviderID, nil
}

func userNameToIDTx(tx pgx.Tx, name string) (pgtype.UUID, error) {
	var userID pgtype.UUID
	err := tx.QueryRow(context.Background(), "SELECT id from users WHERE name=$1 FOR SHARE", name).Scan(&userID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return userID, nil
}

func userIDToNameTx(tx pgx.Tx, userID pgtype.UUID) (string, error) {
	var name string
	err := tx.QueryRow(context.Background(), "SELECT name from users WHERE id=$1 FOR SHARE", userID).Scan(&name)
	if err != nil {
		return "", err
	}
	return name, nil
}

func patchUser(dbPool *pgxpool.Pool, ad authData, nameOrID string, org *string) error {
	if !ad.Superuser {
		return errForbidden
	}

	userIdent, err := parseNameOrID(nameOrID)
	if err != nil {
		return fmt.Errorf("unable to parse user name or ID for PATCH: %w", err)
	}

	var orgIdent identifier
	// org can be nil when the user should have its org value unset
	if org != nil {
		orgIdent, err = parseNameOrID(*org)
		if err != nil {
			return fmt.Errorf("unable to parse org ID for PATCH: %w", err)
		}
	}

	var userID pgtype.UUID
	var orgID *pgtype.UUID
	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		if org != nil {
			if orgIdent.isID() {
				orgID = orgIdent.id
			} else {
				orgID, err = orgNameToIDTx(tx, *orgIdent.name)
				if err != nil {
					return fmt.Errorf("unable to resolve org name to id: %w", err)
				}
			}
		}

		if userIdent.isID() {
			userID = *userIdent.id
		} else {
			userID, err = userNameToIDTx(tx, *userIdent.name)
			if err != nil {
				return fmt.Errorf("unable to resolve user name to id: %w", err)
			}
		}

		_, err := tx.Exec(context.Background(), "UPDATE users SET org_id = $1 WHERE id = $2", orgID, userID)
		if err != nil {
			return fmt.Errorf("unable to update org for user id '%s' %w", userID, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("user PATCH transaction failed: %w", err)
	}

	return nil
}

func selectOrgs(dbPool *pgxpool.Pool, ad authData) ([]org, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM orgs ORDER BY time_created")
		if err != nil {
			return nil, fmt.Errorf("unable to query for orgs: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM orgs WHERE id=$1 ORDER BY time_created", *ad.OrgID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for orgs: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	orgs, err := pgx.CollectRows(rows, pgx.RowToStructByName[org])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for orgs: %w", err)
	}

	return orgs, nil
}

func isSuperuserOrOrgMember(ad authData, orgIdent identifier) bool {
	if ad.Superuser {
		return true
	}

	if orgIdent.isID() {
		if ad.OrgID != nil && *ad.OrgID == *orgIdent.id {
			return true
		}
	} else {
		if ad.OrgName != nil && *ad.OrgName == *orgIdent.name {
			return true
		}
	}

	return false
}

func selectOrgIPs(dbPool *pgxpool.Pool, inputID string, ad authData) (orgAddresses, error) {
	orgIdent, err := parseNameOrID(inputID)
	if err != nil {
		return orgAddresses{}, fmt.Errorf("unable to parse org name or id")
	}

	if !isSuperuserOrOrgMember(ad, orgIdent) {
		return orgAddresses{}, errNotFound
	}

	var orgID pgtype.UUID
	if !orgIdent.isID() {
		err := dbPool.QueryRow(context.Background(), "SELECT id FROM orgs WHERE name=$1", inputID).Scan(&orgID)
		if err != nil {
			return orgAddresses{}, fmt.Errorf("unable to SELECT organization by name: %w", err)
		}
	} else {
		orgID = *orgIdent.id
	}

	oAddrs := orgAddresses{
		OrgID:              orgID,
		AllocatedAddresses: []orgAddress{},
	}

	rows, err := dbPool.Query(context.Background(), "SELECT address FROM org_ipv4_addresses WHERE org_id=$1", orgID)
	if err != nil {
		return orgAddresses{}, fmt.Errorf("unable to SELECT IPv4 addresses for organization by id: %w", err)
	}

	ipv4Addrs, err := pgx.CollectRows(rows, pgx.RowToStructByName[orgAddress])
	if err != nil {
		return orgAddresses{}, fmt.Errorf("unable to collect IPv4 addresses from rows: %w", err)
	}

	oAddrs.AllocatedAddresses = append(oAddrs.AllocatedAddresses, ipv4Addrs...)

	rows, err = dbPool.Query(context.Background(), "SELECT address FROM org_ipv6_addresses WHERE org_id=$1", orgID)
	if err != nil {
		return orgAddresses{}, fmt.Errorf("unable to SELECT IPv6 addresses for organization by id: %w", err)
	}

	ipv6Addrs, err := pgx.CollectRows(rows, pgx.RowToStructByName[orgAddress])
	if err != nil {
		return orgAddresses{}, fmt.Errorf("unable to collect IPv4 addresses from rows: %w", err)
	}

	oAddrs.AllocatedAddresses = append(oAddrs.AllocatedAddresses, ipv6Addrs...)

	return oAddrs, nil
}

func selectOrgByID(dbPool *pgxpool.Pool, inputID string, ad authData) (org, error) {
	o := org{}
	orgIdent, err := parseNameOrID(inputID)
	if err != nil {
		return org{}, fmt.Errorf("unable to parse name or id")
	}

	if !isSuperuserOrOrgMember(ad, orgIdent) {
		return org{}, errNotFound
	}

	if orgIdent.isID() {
		var name string
		err := dbPool.QueryRow(context.Background(), "SELECT name FROM orgs WHERE id=$1", *orgIdent.id).Scan(&name)
		if err != nil {
			return org{}, fmt.Errorf("unable to SELECT organization by id")
		}
		o.Name = name
		o.ID = *orgIdent.id
	} else {
		var id pgtype.UUID
		err := dbPool.QueryRow(context.Background(), "SELECT id FROM orgs WHERE name=$1", inputID).Scan(&id)
		if err != nil {
			return org{}, fmt.Errorf("unable to SELECT organization by name: %w", err)
		}
		o.Name = inputID
		o.ID = id
	}

	return o, nil
}

func insertOrg(dbPool *pgxpool.Pool, name string, ad authData) (pgtype.UUID, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return pgtype.UUID{}, errForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO orgs (name) VALUES ($1) RETURNING id", name).Scan(&id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT organization: %w", err)
	}

	return id, nil
}

func selectServices(dbPool *pgxpool.Pool, ad authData) ([]service, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services ORDER BY time_created")
		if err != nil {
			return nil, fmt.Errorf("unable to Query for getServices as superuser: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT id, name FROM services WHERE org_id=$1 ORDER BY time_created", *ad.OrgID)
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
			err := dbPool.QueryRow(context.Background(), "SELECT services.name FROM services JOIN orgs ON services.org_id = orgs.id WHERE services.id=$1 AND orgs.id=$2", *serviceIdent.id, ad.OrgID).Scan(&serviceName)
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
			err := dbPool.QueryRow(context.Background(), "SELECT services.id FROM services JOIN orgs ON services.org_id = orgs.id WHERE services.name=$1 AND orgs.id=$2", inputID, ad.OrgID).Scan(&serviceID)
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
			err := dbPool.QueryRow(context.Background(), "INSERT INTO services (name, org_id) SELECT $1, orgs.id FROM orgs WHERE orgs.name=$2 returning id", name, *orgIdent.name).Scan(&serviceID)
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
				if pgErr.Code == pgUniqueViolation {
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
				err := tx.QueryRow(context.Background(), "SELECT id FROM orgs WHERE name=$1 FOR UPDATE", *orgIdent.name).Scan(&orgID)
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
				orgs.id AS org_id,
				services.id AS service_id,
				service_versions.version,
				service_versions.active,
				service_vcl_recv.content AS vcl_recv_content,
				agg_domains.domains,
				agg_origins.origins
			FROM
				orgs
				JOIN services ON orgs.id = services.org_id
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
			ORDER BY orgs.name`,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to query for vcls as superuser: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(
			context.Background(),
			`SELECT
				orgs.id AS org_id,
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
				orgs
				JOIN services ON orgs.id = services.org_id
				JOIN service_versions ON services.id = service_versions.service_id
				JOIN service_vcl_recv ON service_versions.id = service_vcl_recv.service_version_id
			WHERE orgs.id=$1
			ORDER BY orgs.name`,
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

func selectIPv4Networks(dbPool *pgxpool.Pool, ad authData) ([]ipv4Network, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, network FROM ipv4_networks ORDER BY time_created")
		if err != nil {
			return nil, fmt.Errorf("unable to query for ipv4_networks: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	ipv4Networks, err := pgx.CollectRows(rows, pgx.RowToStructByName[ipv4Network])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for ipv4 networks: %w", err)
	}

	return ipv4Networks, nil
}

func insertIPv4Network(dbPool *pgxpool.Pool, network netip.Prefix, ad authData) (ipv4Network, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return ipv4Network{}, errForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO ipv4_networks (network) VALUES ($1) RETURNING id", network).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				return ipv4Network{}, errAlreadyExists
			case pgCheckViolation:
				return ipv4Network{}, errCheckViolation
			case pgExclusionViolation:
				return ipv4Network{}, errExclutionViolation
			}
		}
		return ipv4Network{}, fmt.Errorf("unable to INSERT ipv4 network '%s': %w", network, err)
	}

	return ipv4Network{
		ID:      id,
		Network: network,
	}, nil
}

func selectIPv6Networks(dbPool *pgxpool.Pool, ad authData) ([]ipv6Network, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT id, network FROM ipv6_networks ORDER BY time_created")
		if err != nil {
			return nil, fmt.Errorf("unable to query for ipv6_networks: %w", err)
		}
	} else {
		return nil, errForbidden
	}

	ipv6Networks, err := pgx.CollectRows(rows, pgx.RowToStructByName[ipv6Network])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for ipv6 networks: %w", err)
	}

	return ipv6Networks, nil
}

func insertIPv6Network(dbPool *pgxpool.Pool, network netip.Prefix, ad authData) (ipv6Network, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return ipv6Network{}, errForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO ipv6_networks (network) VALUES ($1) RETURNING id", network).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				return ipv6Network{}, errAlreadyExists
			case pgCheckViolation:
				return ipv6Network{}, errCheckViolation
			case pgExclusionViolation:
				return ipv6Network{}, errExclutionViolation
			}
		}
		return ipv6Network{}, fmt.Errorf("unable to INSERT ipv6 network '%s': %w", network, err)
	}

	return ipv6Network{
		ID:      id,
		Network: network,
	}, nil
}

func newChiRouter(conf config.Config, logger zerolog.Logger, dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore, csrfMiddleware func(http.Handler) http.Handler, provider *oidc.Provider) *chi.Mux {
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
		r.Get("/console", consoleHomeHandler(cookieStore))
		r.Get("/console/services", consoleServicesHandler(dbPool, cookieStore))
	})

	// Console login related routes
	router.Route("/auth", func(r chi.Router) {
		r.Use(csrfMiddleware)
		r.Get("/login", loginHandler(dbPool, cookieStore))
		r.Post("/login", loginHandler(dbPool, cookieStore))
		r.Get("/logout", logoutHandler(cookieStore))
		if provider != nil {
			idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: conf.OIDC.ClientID})

			// Configure an OpenID Connect aware OAuth2 client.
			oauth2Config := oauth2.Config{
				ClientID:     conf.OIDC.ClientID,
				ClientSecret: conf.OIDC.ClientSecret,
				RedirectURL:  conf.OIDC.RedirectURL,

				// Discovery returns the OAuth2 endpoints.
				Endpoint: provider.Endpoint(),

				// "openid" is a required scope for OpenID Connect flows.
				Scopes: []string{oidc.ScopeOpenID},
			}

			r.Get("/oidc/keycloak", keycloakOIDCHandler(cookieStore, oauth2Config))
			r.Get("/oidc/keycloak/callback", oauth2CallbackHandler(cookieStore, oauth2Config, idTokenVerifier, dbPool))
		}
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

			user, err := selectUserByID(dbPool, logger, input.User, ad)
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
			resp.Body.ID = user.ID
			resp.Body.Name = user.Name
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
					Name string  `json:"name" example:"you@example.com" doc:"The username" minLength:"1" maxLength:"63"`
					Role string  `json:"role" example:"customer" doc:"Role ID or name" minLength:"1" maxLength:"63"`
					Org  *string `json:"org,omitempty" example:"Some name" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
				}
			},
			) (*userOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from users POST handler")
				}

				id, err := createUser(dbPool, input.Body.Name, input.Body.Role, input.Body.Org, ad)
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

		huma.Put(api, "/v1/users/{user}/local-password", func(ctx context.Context, input *struct {
			User string `path:"user" example:"1" doc:"User ID or name" minLength:"1" maxLength:"63"`
			Body struct {
				OldPassword string `json:"old,omitempty" example:"verysecretpassword" doc:"The previous local password, not needed if superuser" minLength:"1" maxLength:"64"`
				NewPassword string `json:"new" example:"verysecretpassword" doc:"The new user password" minLength:"15" maxLength:"64"`
			}
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)
			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from local-password PUT handler")
			}

			_, err := setLocalPassword(logger, ad, dbPool, input.User, input.Body.OldPassword, input.Body.NewPassword)
			if err != nil {
				if errors.Is(err, errBadOldPassword) {
					return nil, huma.Error400BadRequest("old password is not correct")
				}
				return nil, fmt.Errorf("unable to set password: %w", err)
			}
			return nil, nil
		})

		huma.Patch(api, "/v1/users/{user}", func(ctx context.Context, input *struct {
			User string `path:"user" example:"1" doc:"User ID or name" minLength:"1" maxLength:"63"`
			Body struct {
				Org *string `json:"org" example:"Some name" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
			}
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from user PATCH handler")
			}

			err := patchUser(dbPool, ad, input.User, input.Body.Org)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				} else if errors.Is(err, errNotFound) {
					return nil, huma.Error404NotFound("user not found")
				}
				logger.Err(err).Msg("unable to patch user")
				return nil, err
			}
			return nil, nil
		})

		huma.Get(api, "/v1/orgs", func(ctx context.Context, _ *struct{},
		) (*orgsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from orgs GET handler")
			}

			orgs, err := selectOrgs(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query orgs")
				return nil, err
			}

			resp := &orgsOutput{
				Body: orgs,
			}
			return resp, nil
		})

		huma.Get(api, "/v1/orgs/{org}", func(ctx context.Context, input *struct {
			Org string `path:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*orgOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization GET handler")
			}

			org, err := selectOrgByID(dbPool, input.Org, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				} else if errors.Is(err, errNotFound) {
					return nil, huma.Error404NotFound("organization not found")
				}
				logger.Err(err).Msg("unable to query organization")
				return nil, err
			}
			resp := &orgOutput{}
			resp.Body.ID = org.ID
			resp.Body.Name = org.Name
			return resp, nil
		})

		huma.Get(api, "/v1/orgs/{org}/ips", func(ctx context.Context, input *struct {
			Org string `path:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*orgIPsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization GET handler")
			}

			oAddrs, err := selectOrgIPs(dbPool, input.Org, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				} else if errors.Is(err, errNotFound) {
					return nil, huma.Error404NotFound("organization not found")
				}
				logger.Err(err).Msg("unable to query organization ips")
				return nil, err
			}
			resp := &orgIPsOutput{}
			resp.Body = oAddrs
			return resp, nil
		})

		// We want to set a custom DefaultStatus, that is why we are not just using huma.Post().
		postOrgsPath := "/v1/orgs"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postOrgsPath, &orgOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postOrgsPath, &orgOutput{}),
				Method:        http.MethodPost,
				Path:          postOrgsPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Name string `json:"name" example:"Some name" doc:"Organization name" minLength:"1" maxLength:"63"`
				}
			},
			) (*orgOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from organization POST handler: %w")
				}

				id, err := insertOrg(dbPool, input.Body.Name, ad)
				if err != nil {
					if errors.Is(err, errForbidden) {
						return nil, huma.Error403Forbidden("not allowed to add resource")
					}
					logger.Err(err).Msg("unable to add organization")
					return nil, err
				}
				resp := &orgOutput{}
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
					Name string  `json:"name" example:"Some name" doc:"Service name" minLength:"1" maxLength:"63"`
					Org  *string `json:"org,omitempty" example:"Name or ID of organization" doc:"org1" minLength:"1" maxLength:"63"`
				}
			},
			) (*orgOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from service GET handler")
				}

				id, err := insertService(dbPool, input.Body.Name, input.Body.Org, ad)
				if err != nil {
					if errors.Is(err, errUnprocessable) {
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add service")
					} else if errors.Is(err, errAlreadyExists) {
						return nil, huma.Error409Conflict("service already exists")
					} else if errors.Is(err, errForbidden) {
						return nil, huma.Error403Forbidden("not allowed to create this service")
					}
					logger.Err(err).Msg("unable to add service")
					return nil, err
				}
				resp := &orgOutput{}
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
					ServiceID uuid.UUID      `json:"service_id" doc:"Service ID"`
					Org       *string        `json:"org,omitempty" example:"Name or ID of organization" doc:"Name or ID of the organization" minLength:"1" maxLength:"63"`
					Domains   []domainString `json:"domains" doc:"List of domains handled by the service" minItems:"1" maxItems:"10"`
					Origins   []origin       `json:"origins" doc:"List of origin hosts for this service" minItems:"1" maxItems:"10"`
					Active    *bool          `json:"active,omitempty" doc:"If the submitted config should be activated or not"`
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

				serviceVersionInsertRes, err := insertServiceVersion(dbPool, pgServiceID, input.Body.Org, input.Body.Domains, input.Body.Origins, input.Body.Active, ad)
				if err != nil {
					if errors.Is(err, errUnprocessable) {
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add service version")
					} else if errors.Is(err, errAlreadyExists) {
						return nil, huma.Error409Conflict("service version already exists")
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

		huma.Get(api, "/v1/ipv4_networks", func(ctx context.Context, _ *struct{},
		) (*ipv4NetworksOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from ipv4 networks GET handler")
			}

			networks, err := selectIPv4Networks(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query ipv4 networks")
				return nil, err
			}

			resp := &ipv4NetworksOutput{
				Body: networks,
			}
			return resp, nil
		})

		postIPv4NetworksPath := "/v1/ipv4_networks"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postIPv4NetworksPath, &ipv4NetworkOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postIPv4NetworksPath, &ipv4NetworkOutput{}),
				Method:        http.MethodPost,
				Path:          postIPv4NetworksPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Network netip.Prefix `json:"network" doc:"A IPv4 network prefix"`
				}
			},
			) (*ipv4NetworkOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from IPv4 POST handler")
				}

				ipv4Net, err := insertIPv4Network(dbPool, input.Body.Network, ad)
				if err != nil {
					switch {
					case errors.Is(err, errAlreadyExists):
						return nil, huma.Error409Conflict("IPv4 network already exists")
					case errors.Is(err, errForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this IPv4 network")
					case errors.Is(err, errCheckViolation):
						return nil, huma.Error400BadRequest("content of request is not valid for IPv4 network")
					case errors.Is(err, errExclutionViolation):
						return nil, huma.Error409Conflict("IPv4 network is already covered by existing networks")
					}
					logger.Err(err).Msg("unable to add IPv4 network")
					return nil, err
				}
				resp := &ipv4NetworkOutput{Body: ipv4Net}
				return resp, nil
			},
		)

		huma.Get(api, "/v1/ipv6_networks", func(ctx context.Context, _ *struct{},
		) (*ipv6NetworksOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from ipv6 networks GET handler")
			}

			networks, err := selectIPv6Networks(dbPool, ad)
			if err != nil {
				if errors.Is(err, errForbidden) {
					return nil, huma.Error403Forbidden("not allowed to access resource")
				}
				logger.Err(err).Msg("unable to query ipv6 networks")
				return nil, err
			}

			resp := &ipv6NetworksOutput{
				Body: networks,
			}
			return resp, nil
		})

		postIPv6NetworksPath := "/v1/ipv6_networks"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postIPv6NetworksPath, &ipv6NetworkOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postIPv6NetworksPath, &ipv6NetworkOutput{}),
				Method:        http.MethodPost,
				Path:          postIPv6NetworksPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Network netip.Prefix `json:"network" doc:"A IPv6 network prefix"`
				}
			},
			) (*ipv6NetworkOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from IPv6 POST handler")
				}

				ipv6Net, err := insertIPv6Network(dbPool, input.Body.Network, ad)
				if err != nil {
					switch {
					case errors.Is(err, errAlreadyExists):
						return nil, huma.Error409Conflict("IPv6 network already exists")
					case errors.Is(err, errForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this IPv6 network")
					case errors.Is(err, errCheckViolation):
						return nil, huma.Error400BadRequest("invalid data for IPv6 network")
					case errors.Is(err, errExclutionViolation):
						return nil, huma.Error409Conflict("IPv6 network is already covered by existing networks")
					}
					logger.Err(err).Str("network", input.Body.Network.String()).Msg("unable to add IPv6 network")
					return nil, err
				}
				resp := &ipv6NetworkOutput{Body: ipv6Net}
				return resp, nil
			},
		)
	})

	return nil
}

type user struct {
	ID     pgtype.UUID  `json:"id" doc:"ID of user"`
	Name   string       `json:"name" example:"user1" doc:"name of user"`
	RoleID pgtype.UUID  `json:"role_id" doc:"ID of organization, UUIDv4"`
	OrgID  *pgtype.UUID `json:"org_id" doc:"ID of organization, UUIDv4"`
}

type userOutput struct {
	Body user
}

type usersOutput struct {
	Body []user
}

type org struct {
	ID   pgtype.UUID `json:"id" doc:"ID of organization, UUIDv4"`
	Name string      `json:"name" example:"organization 1" doc:"name of organization"`
}

type orgAddresses struct {
	OrgID              pgtype.UUID  `json:"org_id" doc:"ID of organization, UUIDv4"`
	AllocatedAddresses []orgAddress `json:"allocated_addresses" doc:"list of addresses allocated to the org"`
}

type orgAddress struct {
	Address netip.Addr `json:"address" doc:"IP address (IPv4 or IPv6)"`
}

type orgOutput struct {
	Body org
}

type orgsOutput struct {
	Body []org
}

type orgIPsOutput struct {
	Body orgAddresses
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

type ipv4Network struct {
	ID      pgtype.UUID  `json:"id" doc:"ID of IPv4 network, UUIDv4"`
	Network netip.Prefix `json:"network" example:"198.51.100.0/24" doc:"a IPv4 network"`
}

type ipv4NetworksOutput struct {
	Body []ipv4Network
}

type ipv4NetworkOutput struct {
	Body ipv4Network
}

type ipv6Network struct {
	ID      pgtype.UUID  `json:"id" doc:"ID of IPv6 network, UUIDv4"`
	Network netip.Prefix `json:"network" example:"2001:db8::/32" doc:"a IPv6 network"`
}

type ipv6NetworksOutput struct {
	Body []ipv6Network
}

type ipv6NetworkOutput struct {
	Body ipv6Network
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
	ID           pgtype.UUID
	Name         string
	Role         string
	Password     string
	AuthProvider string
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

	authProviderNames := []string{"local", "keycloak"}

	u := InitUser{
		Name:         "admin",
		Role:         "admin",
		Password:     password,
		AuthProvider: authProviderNames[0],
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
		var adminRoleID pgtype.UUID
		err = tx.QueryRow(context.Background(), "INSERT INTO roles (name, superuser) VALUES ($1, TRUE) RETURNING id", u.Role).Scan(&adminRoleID)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial superuser role '%s': %w", u.Role, err)
		}

		// Also add role used by ordinary users
		_, err = tx.Exec(context.Background(), "INSERT INTO roles (name) VALUES ($1)", "user")
		if err != nil {
			return fmt.Errorf("unable to INSERT initial superuser role '%s': %w", u.Role, err)
		}

		var localAuthProviderID pgtype.UUID
		for _, authProviderName := range authProviderNames {
			var authProviderID pgtype.UUID
			err = tx.QueryRow(context.Background(), "INSERT INTO auth_providers (name) VALUES ($1) RETURNING id", authProviderName).Scan(&authProviderID)
			if err != nil {
				return fmt.Errorf("unable to INSERT auth provider '%s': %w", authProviderName, err)
			}
			if authProviderName == "local" {
				localAuthProviderID = authProviderID
			}
		}

		userID, err := insertUserTx(tx, u.Name, nil, adminRoleID, localAuthProviderID)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user: %w", err)
		}

		_, err = upsertArgon2Tx(tx, userID, a2Data)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user password: %w", err)
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
	TimeCreated time.Time `db:"time_created"`
	AuthKey     []byte    `db:"auth_key"`
	EncKey      []byte    `db:"enc_key"`
}

func getSessionKeys(dbPool *pgxpool.Pool) ([]sessionKey, error) {
	rows, err := dbPool.Query(context.Background(), "SELECT time_created, auth_key, enc_key FROM gorilla_session_keys ORDER BY key_order DESC")
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

func getSessionStore(logger zerolog.Logger, dbPool *pgxpool.Pool, devMode bool) (*sessions.CookieStore, error) {
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

	sessionStore := sessions.NewCookieStore(sessionKeyPairs...)

	sessionStore.Options = &sessions.Options{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	}

	// Allow development without HTTPS
	if devMode {
		sessionStore.Options.Secure = false
	}

	return sessionStore, nil
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

	cookieStore, err := getSessionStore(logger, dbPool, devMode)
	if err != nil {
		logger.Fatal().Err(err).Msg("getSessionStore failed")
	}

	secureCSRF := !devMode

	csrfMiddleware, err := getCSRFMiddleware(dbPool, secureCSRF)
	if err != nil {
		logger.Fatal().Err(err).Msg("getCSRFMiddleware failed")
	}

	provider, err := oidc.NewProvider(context.Background(), conf.OIDC.Issuer)
	if err != nil {
		logger.Fatal().Err(err).Msg("setting up OIDC provider failed")
	}

	router := newChiRouter(conf, logger, dbPool, cookieStore, csrfMiddleware, provider)

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
