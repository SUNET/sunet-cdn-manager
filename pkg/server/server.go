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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/components"
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/SUNET/sunet-cdn-manager/pkg/types"
	"github.com/a-h/templ"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
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
	"go4.org/netipx"
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

	consolePath  = "/console"
	api403String = "not allowed to access resource"
)

var (
	// Set a Decoder instance as a package global, because it caches
	// meta-data about structs, and an instance can be shared safely.
	schemaDecoder = schema.NewDecoder()

	// use a single instance of Validate, it caches struct info
	validate = validator.New(validator.WithRequiredStructEnabled())

	returnToKey = "return_to"

	validNetworkFamilies = map[int]struct{}{
		4: {},
		6: {},
	}
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
	validatedRedirect(consolePath, w, r)
}

func consoleDashboardHandler(cookieStore *sessions.CookieStore) http.HandlerFunc {
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

		err := renderConsolePage(w, r, ad, "SUNET CDN manager", components.Dashboard(ad.Username))
		if err != nil {
			logger.Err(err).Msg("unable to render console home page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
			if errors.Is(err, cdnerrors.ErrForbidden) {
				logger.Err(err).Msg("services console: not authorized to view page")
				http.Error(w, "not allowed to view this page, you need to be a member of an organization", http.StatusForbidden)
				return
			}
			logger.Err(err).Msg("services console: database lookup failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = renderConsolePage(w, r, ad, "Services", components.ServicesContent(services))
		if err != nil {
			logger.Err(err).Msg("unable to render services page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleCreateServiceHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		title := "Create service"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		switch r.Method {
		case "GET":
			err := renderConsolePage(w, r, ad, title, components.CreateServiceContent(nil))
			if err != nil {
				logger.Err(err).Msg("unable to render services page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case "POST":
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse create-service POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := createServiceForm{}

			err = schemaDecoder.Decode(&formData, r.PostForm)
			if err != nil {
				logger.Err(err).Msg("unable to decode POST create-service form data")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			err = validate.Struct(formData)
			if err != nil {
				logger.Err(err).Msg("unable to validate POST create-service form data")
				err := renderConsolePage(w, r, ad, title, components.CreateServiceContent(cdnerrors.ErrInvalidFormData))
				if err != nil {
					logger.Err(err).Msg("unable to render service creation page")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			_, err = insertService(logger, dbPool, formData.Name, ad.OrgName, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrAlreadyExists) {
					err := renderConsolePage(w, r, ad, title, components.CreateServiceContent(err))
					if err != nil {
						logger.Err(err).Msg("unable to render service creation page")
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
				logger.Err(err).Msg("unable to insert service")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			validatedRedirect("/console/services", w, r)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for create-service handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func consoleServiceHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg("console: missing service path in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgName := r.URL.Query().Get("org")
		if orgName == "" {
			logger.Error().Msg("console: missing org parameter in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		title := "Service"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		serviceVersions, err := selectServiceVersions(dbPool, ad, serviceName, orgName)
		if err != nil {
			logger.Error().Msg("console: unable to select service versions")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = renderConsolePage(w, r, ad, title, components.ServiceContent(orgName, serviceName, serviceVersions))
		if err != nil {
			logger.Err(err).Msg("unable to render services page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleServiceVersionHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg("console: missing service path in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceVersionStr := chi.URLParam(r, "version")
		if serviceVersionStr == "" {
			logger.Error().Msg("console: missing version path in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceVersion, err := strconv.ParseInt(serviceVersionStr, 10, 64)
		if err != nil {
			logger.Error().Msg("console: unable to convert version parameter to int")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgName := r.URL.Query().Get("org")
		if orgName == "" {
			logger.Error().Msg("console: missing org parameter in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		title := "Service version"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		svc, err := getServiceVersionConfig(dbPool, ad, orgName, serviceName, serviceVersion)
		if err != nil {
			logger.Err(err).Msg("console: unable to select service version config")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = renderConsolePage(w, r, ad, title, components.ServiceVersionContent(serviceName, svc))
		if err != nil {
			logger.Err(err).Msg("unable to render services page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

// Used to turn e.g. "VclRecv" into "vcl_recv"
func camelCaseToSnakeCase(s string) string {
	var b strings.Builder
	for i, c := range s {
		if unicode.IsUpper(c) {
			if i > 0 {
				b.WriteString("_")
			}
			b.WriteRune(unicode.ToLower(c))
		} else {
			b.WriteRune(c)
		}
	}

	return b.String()
}

func consoleCreateServiceVersionHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		orgName := r.URL.Query().Get("org")
		if orgName == "" {
			logger.Error().Msg("console: missing org parameter in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg("console: missing service path in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		title := "Create service version"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		// Dynamically look up the names of VCL steps we know about
		// based on struct fields.
		vclStepNames := []string{}
		vclStepNamesMap := map[string]struct{}{}
		for _, field := range reflect.VisibleFields(reflect.TypeOf(types.VclSteps{})) {
			vclStepNames = append(vclStepNames, camelCaseToSnakeCase(field.Name))
			vclStepNamesMap[field.Name] = struct{}{}
		}

		switch r.Method {
		case "GET":
			err := renderConsolePage(w, r, ad, title, components.CreateServiceVersionContent(serviceName, orgName, vclStepNames, nil))
			if err != nil {
				logger.Err(err).Msg("unable to render services page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case "POST":
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse create-service-version POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := createServiceVersionForm{}

			err = schemaDecoder.Decode(&formData, r.PostForm)
			if err != nil {
				logger.Err(err).Msg("unable to decode POST create-service-version form data")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			// Deal with the fact that submitting an empty
			// text field from an HTML form will cause
			// schemaDecoder to set a *string field to a pointer to
			// an empty string instead of leaving the pointer nil.
			// We do not allow empty strings for VCL columns in the
			// database (they should be NULL) so reset any Vcl
			// string pointer fields back to nil if they are
			// pointing to empty strings.
			// https://github.com/gorilla/schema/issues/161
			val := reflect.ValueOf(&formData)
			structVal := val.Elem()
			for _, field := range reflect.VisibleFields(structVal.Type()) {
				if _, ok := vclStepNamesMap[field.Name]; ok {
					fieldVal := structVal.FieldByIndex(field.Index)
					if fieldVal.Kind() == reflect.Ptr && field.Type.Elem().Kind() == reflect.String {
						if !fieldVal.IsNil() && fieldVal.Elem().String() == "" {
							fieldVal.Set(reflect.Zero(field.Type))
						}
					}
				}
			}

			err = validate.Struct(formData)
			if err != nil {
				logger.Err(err).Msg("unable to validate POST create-service form data")
				err := renderConsolePage(w, r, ad, title, components.CreateServiceVersionContent(serviceName, orgName, vclStepNames, cdnerrors.ErrInvalidFormData))
				if err != nil {
					logger.Err(err).Msg("unable to render service creation page")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			origins := []origin{}
			for i, formOrigin := range formData.Origins {
				host, port, err := net.SplitHostPort(formOrigin)
				if err != nil {
					logger.Err(err).Msg("unable to parse formOrigin")
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					return
				}

				portInt, err := strconv.Atoi(port)
				if err != nil {
					logger.Err(err).Msg("unable to parse formOrigin port as int")
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					return
				}
				origins = append(origins, origin{
					Host: host,
					Port: portInt,
					TLS:  formData.OriginTLS[i],
				})
			}

			_, err = insertServiceVersion(logger, ad, dbPool, orgName, serviceName, formData.Domains, origins, false, formData.VclSteps)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrAlreadyExists) {
					err := renderConsolePage(w, r, ad, title, components.CreateServiceContent(err))
					if err != nil {
						logger.Err(err).Msg("unable to render service creation page")
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
				logger.Err(err).Msg("unable to insert service")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			validatedRedirect(fmt.Sprintf("/console/services/%s?org=%s", serviceName, orgName), w, r)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for create-service-version handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func consoleActivateServiceVersionHandler(dbPool *pgxpool.Pool, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg("console: missing service path in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		versionStr := chi.URLParam(r, "version")
		if versionStr == "" {
			logger.Error().Msg("console: missing version path in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		version, err := strconv.ParseInt(versionStr, 10, 64)
		if err != nil {
			logger.Err(err).Msg("unable to parse service version")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Query parameters
		orgName := r.URL.Query().Get("org")
		if orgName == "" {
			logger.Error().Msg("console: missing org parameter in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		title := "Activate service version"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg("console: session missing authData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(authData)

		switch r.Method {
		case "GET":
			err := renderConsolePage(w, r, ad, title, components.ActivateServiceVersionContent(orgName, serviceName, version, nil))
			if err != nil {
				logger.Err(err).Msg("unable to render activate-service-version page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case "POST":
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse activate-service-version POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := activateServiceVersionForm{}

			err = schemaDecoder.Decode(&formData, r.PostForm)
			if err != nil {
				logger.Err(err).Msg("unable to decode POST activate-service-version form data")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			err = validate.Struct(formData)
			if err != nil {
				logger.Err(err).Msg("unable to validate POST activate-service form data")
				err := renderConsolePage(w, r, ad, title, components.ActivateServiceVersionContent(orgName, serviceName, version, cdnerrors.ErrInvalidFormData))
				if err != nil {
					logger.Err(err).Msg("unable to render service version activation page in POST")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			if !formData.Confirmation {
				validatedRedirect(fmt.Sprintf("/console/services/%s?org=%s", serviceName, orgName), w, r)
			}

			if formData.Confirmation {
				err := activateServiceVersion(logger, ad, dbPool, orgName, serviceName, version)
				if err != nil {
					logger.Err(err).Msg("service version activation failed")
					err = renderConsolePage(w, r, ad, title, components.ActivateServiceVersionContent(orgName, serviceName, version, err))
					if err != nil {
						logger.Err(err).Msg("unable to render activate-service-version page on activation failure")
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
			}

			validatedRedirect(fmt.Sprintf("/console/services/%s?org=%s", serviceName, orgName), w, r)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for activate-service-version handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func renderConsolePage(w http.ResponseWriter, r *http.Request, ad authData, title string, contents templ.Component) error {
	orgs := []string{}
	if ad.OrgName != nil {
		orgs = append(orgs, *ad.OrgName)
	}
	component := components.ConsolePage(title, orgs, contents)
	return component.Render(r.Context(), w)
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

type createServiceForm struct {
	// Username length validation needs to be kept in sync with the CHECK
	// constraints in the service table, see the migrations module.
	Name string `schema:"name" validate:"min=1,max=63"`
}

type createServiceVersionForm struct {
	types.VclSteps
	Domains   []domainString `schema:"domains" validate:"dive,min=1,max=63"`
	Origins   []string       `schema:"origins" validate:"gte=1,dive,min=1,max=63"`
	OriginTLS []bool         `schema:"origins-tls" validate:"eqfield=Origins"`
}

type activateServiceVersionForm struct {
	Confirmation bool `schema:"confirmation"`
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
					// http.Redirect(w, r, consolePath, http.StatusFound)
					validatedRedirect(consolePath, w, r)
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
				return
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
					return
				}
				return
			}

			var ad authData
			err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
				ad, err = dbUserLogin(tx, formData.Username, formData.Password)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				switch err {
				case pgx.ErrNoRows:
					// The user does not exist etc, try again
					err := renderLoginPage(w, r, formData.ReturnTo, true)
					if err != nil {
						logger.Err(err).Msg("unable to render bad password page for non-existant user")
					}
					return
				case cdnerrors.ErrBadPassword:
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

			// Login is successful at this point, send the now authenticated user to their original location (or consolePath if no such hint is available)
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
				logger.Info().Msg("no return_to in POST data, redirecting logged in user to consolePath")
				validatedRedirect(consolePath, w, r)
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
				// http.Redirect(w, r, consolePath, http.StatusFound)
				validatedRedirect(consolePath, w, r)
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
				return
			}
			validatedRedirect(u.String(), w, r)
			return
		}

		// No return_to hint, just send them to the console
		validatedRedirect(consolePath, w, r)
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
			if errors.Is(err, cdnerrors.ErrKeyCloakEmailUnverified) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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

		validatedRedirect(consolePath, w, r)
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

func sendHumaBasicAuth(logger *zerolog.Logger, api huma.API, ctx huma.Context) {
	ctx.SetHeader("WWW-Authenticate", `Basic realm="SUNET CDN Manager`)
	err := huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
	if err != nil {
		logger.Err(err).Msg("failed writing Basic Auth response")
	}
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

func dbUserLogin(tx pgx.Tx, username string, password string) (authData, error) {
	var userID, roleID pgtype.UUID
	var orgID *pgtype.UUID // can be nil if not belonging to a organization
	var orgName *string    // same as above
	var argon2Key, argon2Salt []byte
	var argon2Time, argon2Memory, argon2TagSize uint32
	var argon2Threads uint8
	var superuser bool
	var roleName string

	err := tx.QueryRow(
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
		return authData{}, cdnerrors.ErrBadPassword
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

func consoleAuthMiddleware(cookieStore *sessions.CookieStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			adRef := authFromSession(logger, cookieStore, r)
			if adRef == nil {
				logger.Info().Msg("consoleAuthMiddleware: redirecting to login page")
				err := redirectToLoginPage(w, r)
				if err != nil {
					logger.Err(err).Msg("unable to redirect to login page")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
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
		return nil, cdnerrors.ErrForbidden
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[user])
	if err != nil {
		logger.Err(err).Msg("unable to CollectRows for users")
		return nil, errors.New("unable to get rows for users")
	}

	return users, nil
}

func selectUser(dbPool *pgxpool.Pool, userNameOrID string, ad authData) (user, error) {
	u := user{}

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		userIdent, err := newUserIdentifier(tx, userNameOrID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		if !ad.Superuser && ad.UserID != userIdent.id {
			return cdnerrors.ErrNotFound
		}

		u.ID = userIdent.id
		u.Name = userIdent.name
		u.RoleID = userIdent.roleID
		u.OrgID = userIdent.orgID

		return nil
	})
	if err != nil {
		return user{}, fmt.Errorf("selectUser transaction failed: %w", err)
	}

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

func setLocalPassword(logger *zerolog.Logger, ad authData, dbPool *pgxpool.Pool, userNameOrID string, oldPassword string, newPassword string) (pgtype.UUID, error) {
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
		userIdent, err := newUserIdentifier(tx, userNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse user for local-password: %w", err)
		}

		// We only allow the setting of passwords for users using the "local" auth provider
		var authProviderName string
		err = tx.QueryRow(context.Background(), "SELECT auth_providers.name FROM auth_providers JOIN users ON auth_providers.id = users.auth_provider_id WHERE users.id=$1 FOR SHARE", userIdent.id).Scan(&authProviderName)
		if err != nil {
			return fmt.Errorf("unable to look up name of auth provider for user with id '%s': %w", userIdent.id, err)
		}

		// A superuser can change any password and a normal user can only change their own password
		if !ad.Superuser && ad.UserID != userIdent.id {
			return cdnerrors.ErrForbidden
		}

		if authProviderName != "local" {
			return fmt.Errorf("ignoring local-password request for non-local user")
		}

		// A normal user most supply the old password
		if !ad.Superuser && oldPassword == "" {
			return errors.New("old password required for non-superusers")
		}

		// ... and finally, verify that the password supplied by a normal user actually is correct.
		// This does result in running a relatively time consuming
		// operation (argon2 hashing) inside a transaction which is not
		// optimal but not sure about a better way since we want to do
		// the following upsert operation in the transaction.
		if !ad.Superuser {
			_, err := dbUserLogin(tx, userIdent.name, oldPassword)
			if err != nil {
				logger.Err(err).Msg("old password check failed")
				return cdnerrors.ErrBadOldPassword
			}
		}

		keyID, err = upsertArgon2Tx(tx, userIdent.id, a2Data)
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

func createUser(dbPool *pgxpool.Pool, name string, role string, org *string, ad authData) (user, error) {
	if !ad.Superuser {
		return user{}, cdnerrors.ErrForbidden
	}

	var err error

	var userID pgtype.UUID

	var orgIdent orgIdentifier
	var roleIdent roleIdentifier
	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		if org != nil {
			orgIdent, err = newOrgIdentifier(tx, *org)
			if err != nil {
				return fmt.Errorf("unable to parse organization for user INSERT: %w", err)
			}
		}

		roleIdent, err = newRoleIdentifier(tx, role)
		if err != nil {
			return fmt.Errorf("unable to parse role for user INSERT: %w", err)
		}

		authProviderID, err := authProviderNameToIDTx(tx, "local")
		if err != nil {
			return fmt.Errorf("unble to resolve authProvider name to ID: %w", err)
		}

		userID, err = insertUserTx(tx, name, &orgIdent.id, roleIdent.id, authProviderID)
		if err != nil {
			return fmt.Errorf("createUser: INSERT failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return user{}, fmt.Errorf("createUser: transaction failed: %w", err)
	}

	return user{
		ID:     userID,
		Name:   name,
		RoleID: roleIdent.id,
		OrgID:  &orgIdent.id,
	}, nil
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
func authProviderNameToIDTx(tx pgx.Tx, name string) (pgtype.UUID, error) {
	var authProviderID pgtype.UUID
	err := tx.QueryRow(context.Background(), "SELECT id FROM auth_providers WHERE name=$1 FOR SHARE", name).Scan(&authProviderID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return authProviderID, nil
}

func updateUserTx(tx pgx.Tx, userID pgtype.UUID, name string, orgID *pgtype.UUID, roleID pgtype.UUID) error {
	_, err := tx.Exec(context.Background(), "UPDATE users SET name = $1, org_id = $2, role_id = $3 WHERE id = $4", name, orgID, roleID, userID)
	if err != nil {
		return fmt.Errorf("unable to update user with id '%s': %w", userID, err)
	}

	return nil
}

func updateUser(dbPool *pgxpool.Pool, ad authData, nameOrID string, org *string, role string) (user, error) {
	if !ad.Superuser {
		return user{}, cdnerrors.ErrForbidden
	}

	var u user
	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		userIdent, err := newUserIdentifier(tx, nameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse user name or ID for PUT: %w", err)
		}

		roleIdent, err := newRoleIdentifier(tx, role)
		if err != nil {
			return fmt.Errorf("unable to parse role name or ID for PUT: %w", err)
		}

		// org can be nil when the user should have its org value unset
		var orgID *pgtype.UUID
		if org != nil {
			orgIdent, err := newOrgIdentifier(tx, *org)
			if err != nil {
				return fmt.Errorf("unable to parse org ID for PATCH: %w", err)
			}
			orgID = &orgIdent.id
		}

		err = updateUserTx(tx, userIdent.id, userIdent.name, orgID, roleIdent.id)
		if err != nil {
			return fmt.Errorf("update failed: %w", err)
		}

		u.ID = userIdent.id
		u.Name = userIdent.name
		u.RoleID = roleIdent.id
		u.OrgID = orgID

		return nil
	})
	if err != nil {
		return user{}, fmt.Errorf("user PUT transaction failed: %w", err)
	}

	return u, nil
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
		return nil, cdnerrors.ErrForbidden
	}

	orgs, err := pgx.CollectRows(rows, pgx.RowToStructByName[org])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for orgs: %w", err)
	}

	return orgs, nil
}

func selectServiceIPs(dbPool *pgxpool.Pool, serviceNameOrID string, orgNameOrID string, ad authData) (serviceAddresses, error) {
	sAddrs := serviceAddresses{}
	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		serviceIdent, err := newServiceIdentifier(tx, serviceNameOrID, orgID)
		if err != nil {
			return err
		}

		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != serviceIdent.orgID) {
			return cdnerrors.ErrNotFound
		}

		sAddrs = serviceAddresses{
			ServiceID:          serviceIdent.id,
			AllocatedAddresses: []serviceAddress{},
		}

		rows, err := tx.Query(context.Background(), "SELECT address FROM service_ip_addresses WHERE service_id=$1", serviceIdent.id)
		if err != nil {
			return fmt.Errorf("unable to SELECT IP addresses for organization by id: %w", err)
		}

		addrs, err := pgx.CollectRows(rows, pgx.RowToStructByName[serviceAddress])
		if err != nil {
			return fmt.Errorf("unable to collect IPv4 addresses from rows: %w", err)
		}

		sAddrs.AllocatedAddresses = append(sAddrs.AllocatedAddresses, addrs...)

		return nil
	})
	if err != nil {
		return serviceAddresses{}, fmt.Errorf("selectServiceIPs: transaction failed: %w", err)
	}

	return sAddrs, nil
}

func selectOrg(dbPool *pgxpool.Pool, orgNameOrID string, ad authData) (org, error) {
	o := org{}

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != orgIdent.id) {
			return cdnerrors.ErrNotFound
		}

		o.Name = orgIdent.name
		o.ID = orgIdent.id

		return nil
	})
	if err != nil {
		return org{}, fmt.Errorf("selectOrg: transaction failed: %w", err)
	}

	return o, nil
}

func insertOrg(dbPool *pgxpool.Pool, name string, ad authData) (pgtype.UUID, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return pgtype.UUID{}, cdnerrors.ErrForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO orgs (name) VALUES ($1) RETURNING id", name).Scan(&id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT organization: %w", err)
	}

	return id, nil
}

func selectServices(dbPool *pgxpool.Pool, ad authData) ([]types.Service, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(context.Background(), "SELECT services.id, services.org_id, services.name, orgs.name AS org_name FROM services JOIN orgs ON services.org_id = orgs.id ORDER BY services.time_created")
		if err != nil {
			return nil, fmt.Errorf("unable to query for getServices as superuser: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbPool.Query(context.Background(), "SELECT services.id, services.org_id, services.name, orgs.name AS org_name FROM services JOIN orgs ON services.org_id = orgs.id WHERE services.org_id=$1 ORDER BY services.time_created", *ad.OrgID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for getServices as org member: %w", err)
		}
	} else {
		return nil, cdnerrors.ErrForbidden
	}

	services, err := pgx.CollectRows(rows, pgx.RowToStructByName[types.Service])
	if err != nil {
		return nil, fmt.Errorf("unable to collect rows for services in API GET: %w", err)
	}

	return services, nil
}

func selectService(dbPool *pgxpool.Pool, orgNameOrID string, serviceNameOrID string, ad authData) (types.Service, error) {
	s := types.Service{}

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		var serviceIdent serviceIdentifier
		var err error

		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		// Looking up a service by ID works without supplying an org,
		// for looking up service by name an org must be included
		serviceIdent, err = newServiceIdentifier(tx, serviceNameOrID, orgID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		// Normal users are only allowed to see services belonging to the same org as they are
		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != serviceIdent.orgID) {
			return cdnerrors.ErrNotFound
		}

		s.Name = serviceIdent.name
		s.ID = serviceIdent.id

		return nil
	})
	if err != nil {
		return types.Service{}, fmt.Errorf("selectService: transaction failed: %w", err)
	}

	return s, nil
}

type resourceIdentifier struct {
	name string
	id   pgtype.UUID
}

type orgIdentifier struct {
	resourceIdentifier
}

type serviceIdentifier struct {
	resourceIdentifier
	orgID pgtype.UUID
}

type roleIdentifier struct {
	resourceIdentifier
}

type userIdentifier struct {
	resourceIdentifier
	orgID  *pgtype.UUID
	roleID pgtype.UUID
}

func newOrgIdentifier(tx pgx.Tx, input string) (orgIdentifier, error) {
	if input == "" {
		return orgIdentifier{}, errors.New("input identifier is empty")
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(context.Background(), "SELECT id, name FROM orgs WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return orgIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (org names are globally unique)
		err := tx.QueryRow(context.Background(), "SELECT id, name FROM orgs WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
		if err != nil {
			return orgIdentifier{}, err
		}
	}

	return orgIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
	}, nil
}

func newServiceIdentifier(tx pgx.Tx, input string, inputOrgID pgtype.UUID) (serviceIdentifier, error) {
	if input == "" {
		return serviceIdentifier{}, errors.New("input identfier is empty")
	}

	var id, orgID pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(context.Background(), "SELECT id, name, org_id FROM services WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &orgID)
		if err != nil {
			return serviceIdentifier{}, err
		}
	} else {
		if !inputOrgID.Valid {
			return serviceIdentifier{}, cdnerrors.ErrServiceByNameNeedsOrg
		}
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (service names are only unique per org)
		err := tx.QueryRow(context.Background(), "SELECT id, name, org_id FROM services WHERE name = $1 and org_id = $2 FOR SHARE", input, inputOrgID).Scan(&id, &name, &orgID)
		if err != nil {
			return serviceIdentifier{}, err
		}
	}

	return serviceIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
		orgID: orgID,
	}, nil
}

func newRoleIdentifier(tx pgx.Tx, input string) (roleIdentifier, error) {
	if input == "" {
		return roleIdentifier{}, errors.New("input identifier is empty")
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(context.Background(), "SELECT id, name FROM roles WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return roleIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (role names are globally unique)
		err := tx.QueryRow(context.Background(), "SELECT id, name FROM roles WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
		if err != nil {
			return roleIdentifier{}, err
		}
	}

	return roleIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
	}, nil
}

func newUserIdentifier(tx pgx.Tx, input string) (userIdentifier, error) {
	if input == "" {
		return userIdentifier{}, errors.New("input identifier is empty")
	}

	var id pgtype.UUID
	var orgID *pgtype.UUID
	var roleID pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(context.Background(), "SELECT id, name, org_id, role_id FROM users WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &orgID, &roleID)
		if err != nil {
			return userIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (org names are globally unique)
		err := tx.QueryRow(context.Background(), "SELECT id, name, org_id, role_id FROM users WHERE name = $1 FOR SHARE", input).Scan(&id, &name, &orgID, &roleID)
		if err != nil {
			return userIdentifier{}, err
		}
	}

	return userIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
		orgID:  orgID,
		roleID: roleID,
	}, nil
}

type serviceIPAddr struct {
	networkID pgtype.UUID
	Address   netip.Addr
}

func allocateServiceIPs(tx pgx.Tx, serviceID pgtype.UUID, requestedV4 int, requestedV6 int) ([]serviceIPAddr, error) {
	if requestedV4 == 0 && requestedV6 == 0 {
		return nil, errors.New("must allocate at least one address")
	}

	// Get available networks, order by network, FOR UPDATE to lock out
	// any concurrently runnnig allocateServiceIPs() from allocating addresses at
	// the same time.
	rows, err := tx.Query(context.Background(), "SELECT id, network FROM ip_networks ORDER BY network FOR UPDATE")
	if err != nil {
		return nil, fmt.Errorf("unable to query for networks: %w", err)
	}

	ipNetworks, err := pgx.CollectRows(rows, pgx.RowToStructByName[ipNetwork])
	if err != nil {
		return nil, fmt.Errorf("unable to collect rows for networks: %w", err)
	}

	// Collect all currently used addresses, FOR SHARE since we probably
	// dont want anyone changing these during allocation as well.
	rows, err = tx.Query(context.Background(), "SELECT address FROM service_ip_addresses ORDER BY address FOR SHARE")
	if err != nil {
		return nil, fmt.Errorf("unable to query for service addresses: %w", err)
	}

	usedAddrs, err := pgx.CollectRows(rows, pgx.RowToStructByName[serviceIPAddr])
	if err != nil {
		return nil, fmt.Errorf("unable to collect rows for addresses: %w", err)
	}

	var usedAddrBuilder netipx.IPSetBuilder

	for _, used := range usedAddrs {
		usedAddrBuilder.Add(used.Address)
	}

	usedAddrSet, err := usedAddrBuilder.IPSet()
	if err != nil {
		log.Fatalf("failed creating IPset of used addresses")
	}

	allocatedV4 := []serviceIPAddr{}
	allocatedV6 := []serviceIPAddr{}

	for _, ipNet := range ipNetworks {
		r := netipx.RangeOfPrefix(ipNet.Network)
		if !r.IsValid() {
			return nil, errors.New("range is not valid")
		}

		// Iterate over all addresses of the network, skipping network
		// and broadcast address.
		if ipNet.Network.Addr().Is4() && len(allocatedV4) < requestedV4 {
			for a := r.From().Next(); a.Less(r.To()); a = a.Next() {
				if !usedAddrSet.Contains(a) {
					allocatedV4 = append(allocatedV4, serviceIPAddr{networkID: ipNet.ID, Address: a})
				}

				if len(allocatedV4) == requestedV4 {
					break
				}
			}
		}

		if ipNet.Network.Addr().Is6() && len(allocatedV6) < requestedV6 {
			for a := r.From().Next(); a.Less(r.To()); a = a.Next() {
				if !usedAddrSet.Contains(a) {
					allocatedV6 = append(allocatedV6, serviceIPAddr{networkID: ipNet.ID, Address: a})
				}

				if len(allocatedV6) == requestedV6 {
					break
				}
			}
		}

		if len(allocatedV4) == requestedV4 && len(allocatedV6) == requestedV6 {
			break
		}
	}

	if len(allocatedV4) != requestedV4 {
		return nil, fmt.Errorf("unable to allocate requested number of IPv4 addresses (%d)", requestedV4)
	}

	if len(allocatedV6) != requestedV6 {
		return nil, fmt.Errorf("unable to allocate requested number of IPv6 addresses (%d)", requestedV6)
	}

	allocatedIPs := []serviceIPAddr{}

	allocatedIPs = append(allocatedIPs, allocatedV4...)
	allocatedIPs = append(allocatedIPs, allocatedV6...)

	for _, allocIP := range allocatedIPs {
		var serviceIPID pgtype.UUID
		err = tx.QueryRow(context.Background(), "INSERT INTO service_ip_addresses (service_id, network_id, address) VALUES ($1, $2, $3) returning id", serviceID, allocIP.networkID, allocIP.Address).Scan(&serviceIPID)
		if err != nil {
			return nil, fmt.Errorf("unable to insert ip %s into service_ip_addresses: %w", allocIP.Address, err)
		}
	}

	return allocatedIPs, nil
}

func insertService(logger *zerolog.Logger, dbPool *pgxpool.Pool, name string, orgNameOrID *string, ad authData) (pgtype.UUID, error) {
	var serviceID pgtype.UUID

	var orgIdent orgIdentifier
	var err error

	if !ad.Superuser && ad.OrgID == nil {
		return pgtype.UUID{}, cdnerrors.ErrForbidden
	}

	if orgNameOrID == nil {
		return pgtype.UUID{}, cdnerrors.ErrUnprocessable
	}

	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		orgIdent, err = newOrgIdentifier(tx, *orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnprocessable
		}

		// A normal user must supply an org id for an org they are
		// a member of
		if !ad.Superuser && *ad.OrgID != orgIdent.id {
			return cdnerrors.ErrForbidden
		}

		var serviceQuota int64
		// Verify we are not hitting the limit of how many services the
		// org allows, do "FOR UPDATE" to lock out any concurrently
		// running function until we are done with counting rows.
		err = tx.QueryRow(context.Background(), "SELECT service_quota FROM orgs WHERE id=$1 FOR UPDATE", orgIdent.id).Scan(&serviceQuota)
		if err != nil {
			return err
		}

		var numServices int64
		err = tx.QueryRow(context.Background(), "SELECT COUNT(*) FROM services WHERE org_id=$1", orgIdent.id).Scan(&numServices)
		if err != nil {
			return err
		}

		if numServices >= serviceQuota {
			logger.Error().Int64("num_services", numServices).Int64("service_quota", serviceQuota).Msg("unable to create additional service as quota has been reached")
			return cdnerrors.ErrServiceQuotaHit
		}

		err = tx.QueryRow(context.Background(), "INSERT INTO services (name, org_id) VALUES ($1, $2) RETURNING id", name, orgIdent.id).Scan(&serviceID)
		if err != nil {
			return fmt.Errorf("unable to INSERT service: %w", err)
		}

		// Allocate 1 IPv4 and 1 IPv6 address for the service
		_, err := allocateServiceIPs(tx, serviceID, 1, 1)
		if err != nil {
			return fmt.Errorf("unable to allocate service IPs: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("insertServices transaction failed")
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return pgtype.UUID{}, cdnerrors.ErrAlreadyExists
			}
		}
		return pgtype.UUID{}, fmt.Errorf("insertService transaction failed: %w", err)
	}

	return serviceID, nil
}

func deleteService(logger *zerolog.Logger, dbPool *pgxpool.Pool, orgNameOrID string, serviceNameOrID string, ad authData) (pgtype.UUID, error) {
	if !ad.Superuser && ad.OrgID == nil {
		return pgtype.UUID{}, cdnerrors.ErrNotFound
	}

	var serviceID pgtype.UUID
	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
			if err != nil {
				logger.Err(err).Msg("unable to look up org identifier")
				return cdnerrors.ErrUnprocessable
			}
			orgID = orgIdent.id
		}

		serviceIdent, err := newServiceIdentifier(tx, serviceNameOrID, orgID)
		if err != nil {
			logger.Err(err).Msg("unable to look up service identifier")
			return cdnerrors.ErrUnprocessable
		}

		// A normal user can only delete a service belonging to the
		// same org they are a member of
		if !ad.Superuser && *ad.OrgID != serviceIdent.orgID {
			return cdnerrors.ErrNotFound
		}

		err = tx.QueryRow(context.Background(), "DELETE FROM services WHERE id = $1 RETURNING id", serviceIdent.id).Scan(&serviceID)
		if err != nil {
			return fmt.Errorf("unable to DELETE service: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("deleteService transaction failed")
		return pgtype.UUID{}, fmt.Errorf("deleteService transaction failed: %w", err)
	}

	return serviceID, nil
}

func selectServiceVersions(dbPool *pgxpool.Pool, ad authData, serviceNameOrID string, orgNameOrID string) ([]types.ServiceVersion, error) {
	var rows pgx.Rows

	var err error
	serviceVersions := []types.ServiceVersion{}
	err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		var serviceIdent serviceIdentifier

		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		// Looking up a service by ID works without supplying an org,
		// for looking up service by name an org must be included
		serviceIdent, err = newServiceIdentifier(tx, serviceNameOrID, orgID)
		if err != nil {
			return fmt.Errorf("looking up service identifier failed: %w", err)
		}

		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != serviceIdent.orgID) {
			return cdnerrors.ErrForbidden
		}

		rows, err = tx.Query(
			context.Background(),
			"SELECT service_versions.id, service_versions.version, service_versions.active, orgs.name FROM service_versions JOIN services ON service_versions.service_id = services.id JOIN orgs ON services.org_id = orgs.id WHERE service_id = $1 ORDER BY service_versions.version",
			serviceIdent.id,
		)
		var id pgtype.UUID
		var orgName string
		var version int64
		var active bool
		_, err = pgx.ForEachRow(rows, []any{&id, &version, &active, &orgName}, func() error {
			serviceVersions = append(
				serviceVersions,
				types.ServiceVersion{
					ID:          id,
					ServiceID:   serviceIdent.id,
					ServiceName: serviceIdent.name,
					Version:     version,
					Active:      active,
					OrgID:       serviceIdent.orgID,
					OrgName:     orgName,
				},
			)

			return nil
		})
		if err != nil {
			return fmt.Errorf("unable to ForEachRow over service versions: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("selectServiceVersions: transaction failed: %w", err)
	}

	return serviceVersions, nil
}

func getServiceVersionConfig(dbPool *pgxpool.Pool, ad authData, orgNameOrID string, serviceNameOrID string, version int64) (types.ServiceVersionConfig, error) {
	// If neither a superuser or a normal user belonging to an org there
	// is nothing further that is allowed
	if !ad.Superuser {
		if ad.OrgID == nil {
			return types.ServiceVersionConfig{}, cdnerrors.ErrForbidden
		}
	}

	var svc types.ServiceVersionConfig
	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(tx, serviceNameOrID, orgIdent.id)
		if err != nil {
			return cdnerrors.ErrUnprocessable
		}

		if !ad.Superuser {
			if *ad.OrgID != serviceIdent.orgID {
				return cdnerrors.ErrForbidden
			}
		}

		// Usage of JOIN with subqueries based on
		// https://stackoverflow.com/questions/27622398/multiple-array-agg-calls-in-a-single-query
		rows, err := tx.Query(
			context.Background(),
			`SELECT
				orgs.id AS org_id,
				orgs.name AS org_name,
				services.id AS service_id,
				services.name AS service_name,
				service_versions.id,
				service_versions.version,
				service_versions.active,
				service_vcls.vcl_recv,
				service_vcls.vcl_pipe,
				service_vcls.vcl_pass,
				service_vcls.vcl_hash,
				service_vcls.vcl_purge,
				service_vcls.vcl_miss,
				service_vcls.vcl_hit,
				service_vcls.vcl_deliver,
				service_vcls.vcl_synth,
				service_vcls.vcl_backend_fetch,
				service_vcls.vcl_backend_response,
				service_vcls.vcl_backend_error,
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
				JOIN service_vcls ON service_versions.id = service_vcls.service_version_id
			WHERE services.id=$1 AND service_versions.version=$2`,
			serviceIdent.id,
			version,
		)
		if err != nil {
			return fmt.Errorf("unable to query for service version config: %w", err)
		}

		svc, err = pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[types.ServiceVersionConfig])
		if err != nil {
			return fmt.Errorf("unable to collect service version config into struct: %w", err)
		}

		return nil
	})
	if err != nil {
		return types.ServiceVersionConfig{}, fmt.Errorf("getServiceVersionConfig transaction failed: %w", err)
	}

	return svc, nil
}

type serviceVersionInsertResult struct {
	versionID     pgtype.UUID
	version       int64
	active        bool
	domainIDs     []pgtype.UUID
	originIDs     []pgtype.UUID
	deactivatedID *pgtype.UUID
	vclID         pgtype.UUID
}

func deactivatePreviousServiceVersionTx(tx pgx.Tx, serviceIdent serviceIdentifier) (*pgtype.UUID, error) {
	var deactivatedServiceVersionID *pgtype.UUID

	// Start with finding out if there even is any active version at all,
	// if not there is nothing more to do.
	var found bool
	err := tx.QueryRow(
		context.Background(),
		"SELECT TRUE FROM service_versions WHERE service_id=$1 AND active=true",
		serviceIdent.id,
	).Scan(&found)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	err = tx.QueryRow(
		context.Background(),
		"UPDATE service_versions SET active=false WHERE service_id=$1 AND active=true returning id",
		serviceIdent.id,
	).Scan(&deactivatedServiceVersionID)
	if err != nil {
		return nil, fmt.Errorf("unable to UPDATE active status for previous service version: %w", err)
	}

	return deactivatedServiceVersionID, nil
}

func insertServiceVersionTx(tx pgx.Tx, serviceIdent serviceIdentifier, domains []domainString, origins []origin, active bool, vcls types.VclSteps) (serviceVersionInsertResult, error) {
	var serviceVersionID pgtype.UUID
	var versionCounter int64
	var deactivatedServiceVersionID *pgtype.UUID

	err := tx.QueryRow(
		context.Background(),
		"UPDATE services SET version_counter=version_counter+1 WHERE id=$1 RETURNING version_counter",
		serviceIdent.id,
	).Scan(&versionCounter)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to UPDATE version_counter for service version: %w", err)
	}

	// If the new version is expected to be active we need to deactivate the currently active version
	if active {
		deactivatedServiceVersionID, err = deactivatePreviousServiceVersionTx(tx, serviceIdent)
		if err != nil {
			return serviceVersionInsertResult{}, err
		}
	}

	err = tx.QueryRow(
		context.Background(),
		"INSERT INTO service_versions (service_id, version, active) VALUES ($1, $2, $3) RETURNING id",
		serviceIdent.id,
		versionCounter,
		active,
	).Scan(&serviceVersionID)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service version: %w", err)
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
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service domain: %w", err)
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
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service origin: %w", err)
		}
		serviceOriginIDs = append(serviceOriginIDs, serviceOriginID)
	}

	var serviceVclID pgtype.UUID
	err = tx.QueryRow(
		context.Background(),
		`INSERT INTO service_vcls (
			service_version_id,
			vcl_recv,
			vcl_pipe,
			vcl_pass,
			vcl_hash,
			vcl_purge,
			vcl_miss,
			vcl_hit,
			vcl_deliver,
			vcl_synth,
			vcl_backend_fetch,
			vcl_backend_response,
			vcl_backend_error
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			$10,
			$11,
			$12,
			$13
		) RETURNING id`,
		serviceVersionID,
		vcls.VclRecv,
		vcls.VclPipe,
		vcls.VclPass,
		vcls.VclHash,
		vcls.VclPurge,
		vcls.VclMiss,
		vcls.VclHit,
		vcls.VclDeliver,
		vcls.VclSynth,
		vcls.VclBackendFetch,
		vcls.VclBackendResponse,
		vcls.VclBackendError,
	).Scan(&serviceVclID)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service vcl: %w", err)
	}

	res := serviceVersionInsertResult{
		versionID:     serviceVersionID,
		version:       versionCounter,
		domainIDs:     serviceDomainIDs,
		originIDs:     serviceOriginIDs,
		deactivatedID: deactivatedServiceVersionID,
		vclID:         serviceVclID,
		active:        active,
	}

	return res, nil
}

func insertServiceVersion(logger *zerolog.Logger, ad authData, dbPool *pgxpool.Pool, orgNameOrID string, serviceNameOrID string, domains []domainString, origins []origin, active bool, vcls types.VclSteps) (serviceVersionInsertResult, error) {
	// If neither a superuser or a normal user belonging to an org there
	// is nothing further that is allowed
	if !ad.Superuser {
		if ad.OrgID == nil {
			return serviceVersionInsertResult{}, cdnerrors.ErrForbidden
		}
	}

	var serviceVersionResult serviceVersionInsertResult

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
		if err != nil {
			logger.Err(err).Msg("looking up org failed")
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(tx, serviceNameOrID, orgIdent.id)
		if err != nil {
			logger.Err(err).Msg("looking up service failed")
			return cdnerrors.ErrUnprocessable
		}

		// If the user is not a superuser they must belong to the same
		// org as the service they are trying to add a version to
		if !ad.Superuser {
			if *ad.OrgID != orgIdent.id {
				return cdnerrors.ErrForbidden
			}
		}

		serviceVersionResult, err = insertServiceVersionTx(tx, serviceIdent, domains, origins, active, vcls)
		if err != nil {
			return fmt.Errorf("unable to INSERT service version with org ID: %w", err)
		}

		return nil
	})
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("service version INSERT transaction failed: %w", err)
	}

	return serviceVersionResult, nil
}

func activateServiceVersion(logger *zerolog.Logger, ad authData, dbPool *pgxpool.Pool, orgNameOrID string, serviceNameOrID string, version int64) error {
	// If neither a superuser or a normal user belonging to an org there
	// is nothing further that is allowed
	if !ad.Superuser {
		if ad.OrgID == nil {
			return cdnerrors.ErrForbidden
		}
	}

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(tx, orgNameOrID)
		if err != nil {
			logger.Err(err).Msg("unable to validate org id")
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(tx, serviceNameOrID, orgIdent.id)
		if err != nil {
			logger.Err(err).Msg("unable to validate org id")
			return cdnerrors.ErrUnprocessable
		}

		// If the user is not a superuser they must belong to the same
		// org as the service they are trying activate a version for
		if !ad.Superuser {
			if *ad.OrgID != orgIdent.id {
				return cdnerrors.ErrForbidden
			}
		}

		_, err = activateServiceVersionTx(tx, serviceIdent, version)
		if err != nil {
			return fmt.Errorf("unable to activate service version with version: %w", err)
		}

		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cdnerrors.ErrNotFound
		}
		return fmt.Errorf("service version activation transaction failed: %w", err)
	}

	return nil
}

func activateServiceVersionTx(tx pgx.Tx, serviceIdent serviceIdentifier, version int64) (pgtype.UUID, error) {
	_, err := deactivatePreviousServiceVersionTx(tx, serviceIdent)
	if err != nil {
		return pgtype.UUID{}, err
	}

	var activatedServiceVersionID pgtype.UUID
	err = tx.QueryRow(context.Background(), "UPDATE service_versions SET active=true WHERE service_id=$1 AND version=$2 RETURNING id", serviceIdent.id, version).Scan(&activatedServiceVersionID)
	if err != nil {
		return pgtype.UUID{}, err
	}

	return activatedServiceVersionID, nil
}

func writeVclRecv(b *strings.Builder, domains []string, vclRecv *string) error {
	b.WriteString("sub vcl_recv {\n")
	if len(domains) > 0 {
		b.WriteString("  if ")
		for i, domain := range domains {
			if i > 0 {
				b.WriteString(" && ")
			}
			b.WriteString(fmt.Sprintf("req.http.host != \"%s\"", domain))
		}
		b.WriteString(" {\n")
		b.WriteString("    return(synth(400,\"Unknown Host header.\"));\n")
		b.WriteString("  }\n")
	}

	if vclRecv != nil {
		b.WriteString("  # vcl_recv content from database\n")
		scanner := bufio.NewScanner(strings.NewReader(*vclRecv))
		for scanner.Scan() {
			if scanner.Text() != "" {
				b.WriteString("  " + scanner.Text() + "\n")
			} else {
				b.WriteString("\n")
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scanning vcl_recv failed: %w", err)
		}
	}
	b.WriteString("}\n")
	return nil
}

func writeGenericVclSub(b *strings.Builder, subName string, vclContent *string) error {
	if vclContent != nil {
		b.WriteString(fmt.Sprintf("sub %s {\n", subName))
		b.WriteString(fmt.Sprintf("  # %s content from database\n", subName))
		scanner := bufio.NewScanner(strings.NewReader(*vclContent))
		for scanner.Scan() {
			if scanner.Text() != "" {
				b.WriteString("  " + scanner.Text() + "\n")
			} else {
				b.WriteString("\n")
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scanning %s failed: %w", subName, err)
		}
		b.WriteString("}\n")
	}
	return nil
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

	err := writeVclRecv(&b, sv.Domains, sv.VclRecv)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_pipe", sv.VclPipe)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_pass", sv.VclPass)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_hash", sv.VclHash)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_purge", sv.VclPurge)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_miss", sv.VclMiss)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_hit", sv.VclHit)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_deliver", sv.VclDeliver)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_synth", sv.VclSynth)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_backend_fetch", sv.VclBackendFetch)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_backend_response", sv.VclBackendResponse)
	if err != nil {
		return "", err
	}
	err = writeGenericVclSub(&b, "vcl_backend_error", sv.VclBackendError)
	if err != nil {
		return "", err
	}

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
				service_vcls.vcl_recv,
				service_vcls.vcl_pipe,
				service_vcls.vcl_pass,
				service_vcls.vcl_hash,
				service_vcls.vcl_purge,
				service_vcls.vcl_miss,
				service_vcls.vcl_hit,
				service_vcls.vcl_deliver,
				service_vcls.vcl_synth,
				service_vcls.vcl_backend_fetch,
				service_vcls.vcl_backend_response,
				service_vcls.vcl_backend_error,
				agg_domains.domains,
				agg_origins.origins
			FROM
				orgs
				JOIN services ON orgs.id = services.org_id
				JOIN service_versions ON services.id = service_versions.service_id
				JOIN service_vcls ON service_versions.id = service_vcls.service_version_id
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
				service_vcls.vcl_recv,
				service_vcls.vcl_pipe,
				service_vcls.vcl_pass,
				service_vcls.vcl_hash,
				service_vcls.vcl_purge,
				service_vcls.vcl_miss,
				service_vcls.vcl_hit,
				service_vcls.vcl_deliver,
				service_vcls.vcl_synth,
				service_vcls.vcl_backend_fetch,
				service_vcls.vcl_backend_response,
				service_vcls.vcl_backend_error,
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
				JOIN service_vcls ON service_versions.id = service_vcls.service_version_id
			WHERE orgs.id=$1
			ORDER BY orgs.name`,
			*ad.OrgID,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to query for vcls as normal user: %w", err)
		}
	} else {
		return nil, cdnerrors.ErrForbidden
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

func selectNetworks(dbPool *pgxpool.Pool, ad authData, family int) ([]ipNetwork, error) {
	if !ad.Superuser {
		return nil, cdnerrors.ErrForbidden
	}

	var rows pgx.Rows
	var err error

	if family == 0 {
		rows, err = dbPool.Query(context.Background(), "SELECT id, network FROM ip_networks ORDER BY network")
		if err != nil {
			return nil, fmt.Errorf("unable to query for all networks: %w", err)
		}
	} else {
		if _, ok := validNetworkFamilies[family]; !ok {
			return nil, errors.New("invalid network family")
		}
		rows, err = dbPool.Query(context.Background(), "SELECT id, network FROM ip_networks WHERE family(network) = $1 ORDER BY network", family)
		if err != nil {
			return nil, fmt.Errorf("unable to query for networks: %w", err)
		}
	}

	ipNetworks, err := pgx.CollectRows(rows, pgx.RowToStructByName[ipNetwork])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for networks: %w", err)
	}

	return ipNetworks, nil
}

func insertNetwork(dbPool *pgxpool.Pool, network netip.Prefix, ad authData) (ipNetwork, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return ipNetwork{}, cdnerrors.ErrForbidden
	}
	err := dbPool.QueryRow(context.Background(), "INSERT INTO ip_networks (network) VALUES ($1) RETURNING id", network).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				return ipNetwork{}, cdnerrors.ErrAlreadyExists
			case pgCheckViolation:
				return ipNetwork{}, cdnerrors.ErrCheckViolation
			case pgExclusionViolation:
				return ipNetwork{}, cdnerrors.ErrExclutionViolation
			}
		}
		return ipNetwork{}, fmt.Errorf("unable to INSERT network '%s': %w", network, err)
	}

	return ipNetwork{
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
		r.Get(consolePath, consoleDashboardHandler(cookieStore))
		r.Get(consolePath+"/services", consoleServicesHandler(dbPool, cookieStore))
		r.Get(consolePath+"/services/{service}", consoleServiceHandler(dbPool, cookieStore))
		r.Get(consolePath+"/create/service", consoleCreateServiceHandler(dbPool, cookieStore))
		r.Post(consolePath+"/create/service", consoleCreateServiceHandler(dbPool, cookieStore))
		r.Get(consolePath+"/services/{service}/{version}", consoleServiceVersionHandler(dbPool, cookieStore))
		r.Get(consolePath+"/create/service-version/{service}", consoleCreateServiceVersionHandler(dbPool, cookieStore))
		r.Post(consolePath+"/create/service-version/{service}", consoleCreateServiceVersionHandler(dbPool, cookieStore))
		r.Get(consolePath+"/services/{service}/{version}/activate", consoleActivateServiceVersionHandler(dbPool, cookieStore))
		r.Post(consolePath+"/services/{service}/{version}/activate", consoleActivateServiceVersionHandler(dbPool, cookieStore))
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

// Unfortunately we dont have access to net/http request.BasicAuth() in the
// huma handler so include basic decode ourselves.
func decodeBasicAuth(token string) (username, password string, ok bool) {
	c, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

// https://huma.rocks/how-to/oauth2-jwt/#huma-auth-middleware
func newAPIAuthMiddleware(api huma.API, dbPool *pgxpool.Pool) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		logger := zlog.Ctx(ctx.Context())

		token := strings.TrimPrefix(ctx.Header("Authorization"), "Basic ")
		if len(token) == 0 {
			sendHumaBasicAuth(logger, api, ctx)
			return
		}

		username, password, ok := decodeBasicAuth(token)
		if !ok {
			sendHumaBasicAuth(logger, api, ctx)
			return
		}

		var ad authData
		var err error
		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			ad, err = dbUserLogin(tx, username, password)
			return err
		})
		if err != nil {
			switch err {
			case pgx.ErrNoRows, cdnerrors.ErrBadPassword:
				// The user does not exist etc or the password was bad, try again
				sendHumaBasicAuth(logger, api, ctx)
				return
			}
			logger.Err(err).Msg("handleBasicAuth transaction failed")
			err = huma.WriteErr(api, ctx, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			if err != nil {
				logger.Err(err).Msg("faled writing error about trasnaction")
			}
			return
		}

		ctx = huma.WithValue(ctx, authDataKey{}, ad)

		next(ctx)
	}
}

func setupHumaAPI(router chi.Router, dbPool *pgxpool.Pool) error {
	router.Route("/api", func(r chi.Router) {
		config := huma.DefaultConfig("SUNET CDN API", "0.0.1")
		config.Servers = []*huma.Server{
			{URL: "https://manager.cdn.example.se/api"},
		}

		config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
			"basicAuth": {
				Type:   "http",
				Scheme: "Basic",
			},
		}

		config.Security = []map[string][]string{
			{"basicAuth": {""}},
		}

		api := humachi.New(r, config)

		api.UseMiddleware(newAPIAuthMiddleware(api, dbPool))

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
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
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

			user, err := selectUser(dbPool, input.User, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
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
			func(ctx context.Context, input *userPostInput) (*userOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from users POST handler")
				}

				user, err := createUser(dbPool, input.Body.Name, input.Body.Role, input.Body.Org, ad)
				if err != nil {
					if errors.Is(err, cdnerrors.ErrForbidden) {
						return nil, huma.Error403Forbidden("not allowed to add resource")
					}
					logger.Err(err).Msg("unable to add user")
					return nil, err
				}
				return &userOutput{
					Body: user,
				}, nil
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
				if errors.Is(err, cdnerrors.ErrBadOldPassword) {
					return nil, huma.Error400BadRequest("old password is not correct")
				}
				return nil, fmt.Errorf("unable to set password: %w", err)
			}
			return nil, nil
		})

		huma.Put(api, "/v1/users/{user}", func(ctx context.Context, input *userPutInput) (*userOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from user PATCH handler")
			}

			user, err := updateUser(dbPool, ad, input.User, input.Body.Org, input.Body.Role)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("user not found")
				}
				logger.Err(err).Msg("unable to update user")
				return nil, err
			}
			return &userOutput{Body: user}, nil
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
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
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

			org, err := selectOrg(dbPool, input.Org, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
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

		huma.Get(api, "/v1/services/{service}/ips", func(ctx context.Context, input *struct {
			Service string `path:"service" example:"1" doc:"Service ID or name" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*orgIPsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization GET handler")
			}

			oAddrs, err := selectServiceIPs(dbPool, input.Service, input.Org, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
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
					if errors.Is(err, cdnerrors.ErrForbidden) {
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
				if errors.Is(err, cdnerrors.ErrForbidden) {
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
			Org     string `query:"org" example:"my-org" doc:"Organization ID or name, required if service is supplied by name" minLength:"1" maxLength:"63"`
		},
		) (*serviceOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service GET handler")
			}

			services, err := selectService(dbPool, input.Org, input.Service, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("service not found")
				} else if errors.Is(err, cdnerrors.ErrForbidden) {
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

		huma.Delete(api, "/v1/services/{service}", func(ctx context.Context, input *struct {
			Service string `path:"service" example:"1" doc:"Service ID or name" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"my-org" doc:"Organization ID or name, required if service is supplied by name" minLength:"1" maxLength:"63"`
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service GET handler")
			}

			_, err := deleteService(logger, dbPool, input.Org, input.Service, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("service not found")
				} else if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden("access to this service is not allowed")
				}
				logger.Err(err).Msg("unable to delete service")
				return nil, err
			}

			return nil, nil
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
					Name string `json:"name" example:"Some name" doc:"Service name" minLength:"1" maxLength:"63"`
					Org  string `json:"org" example:"Name or ID of organization" doc:"org1" minLength:"1" maxLength:"63"`
				}
			},
			) (*orgOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from service POST handler")
				}

				id, err := insertService(logger, dbPool, input.Body.Name, &input.Body.Org, ad)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrUnprocessable):
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add service")
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("service already exists")
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this service")
					case errors.Is(err, cdnerrors.ErrServiceQuotaHit):
						return nil, huma.Error409Conflict("service quota hit, not allowed to create more services")
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

		huma.Get(api, "/v1/services/{service}/service-versions", func(ctx context.Context, input *struct {
			Service string `path:"service" doc:"Service name or ID" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"Name or ID of organization, required if service is supplied by name" doc:"org1" minLength:"1" maxLength:"63"`
		},
		) (*serviceVersionsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service-versions GET handler")
			}

			serviceVersions, err := selectServiceVersions(dbPool, ad, input.Service, input.Org)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden(api403String)
				case errors.Is(err, cdnerrors.ErrServiceByNameNeedsOrg):
					return nil, huma.Error422UnprocessableEntity(cdnerrors.ErrServiceByNameNeedsOrg.Error())
				}
				logger.Err(err).Msg("unable to query service-versions")
				return nil, err
			}

			resp := &serviceVersionsOutput{
				Body: serviceVersions,
			}
			return resp, nil
		})

		postServiceVersionsPath := "/v1/services/{service}/service-versions"
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
				Service string `path:"service" doc:"Service name or ID" minLength:"1" maxLength:"63"`
				Body    struct {
					types.VclSteps
					Org     string         `json:"org" example:"Name or ID of organization" doc:"org1" minLength:"1" maxLength:"63"`
					Domains []domainString `json:"domains" doc:"List of domains handled by the service" minItems:"1" maxItems:"10"`
					Origins []origin       `json:"origins" doc:"List of origin hosts for this service" minItems:"1" maxItems:"10"`
					Active  bool           `json:"active,omitempty" doc:"If the submitted config should be activated or not"`
				}
			},
			) (*serviceVersionOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from service version POST handler")
				}

				serviceVersionInsertRes, err := insertServiceVersion(logger, ad, dbPool, input.Body.Org, input.Service, input.Body.Domains, input.Body.Origins, input.Body.Active, input.Body.VclSteps)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrUnprocessable):
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add service version")
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("service version already exists")
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this service version")
					case errors.Is(err, cdnerrors.ErrNotFound):
						return nil, huma.Error422UnprocessableEntity("service name not found")
					}
					logger.Err(err).Msg("unable to add service version")
					return nil, err
				}
				resp := &serviceVersionOutput{}
				resp.Body.ID = serviceVersionInsertRes.versionID
				resp.Body.Version = serviceVersionInsertRes.version
				resp.Body.Active = serviceVersionInsertRes.active
				return resp, nil
			},
		)

		huma.Put(api, "/v1/services/{service}/service-versions/{version}/active", func(ctx context.Context, input *struct {
			Service string `path:"service" example:"my-service" doc:"Service ID or name" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"my-org" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
			Version int64  `path:"version" example:"1" doc:"The service version to activate"`
			Body    struct {
				Active bool `json:"active" example:"true" doc:"If the version should be active (must be true)" minLength:"15" maxLength:"64"`
			}
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)
			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from service version active PUT handler")
			}

			if !input.Body.Active {
				return nil, huma.Error422UnprocessableEntity("active must be true")
			}

			err := activateServiceVersion(logger, ad, dbPool, input.Org, input.Service, input.Version)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrNotFound):
					return nil, huma.Error404NotFound("service or version does not exist")
				case errors.Is(err, cdnerrors.ErrUnprocessable):
					return nil, huma.Error422UnprocessableEntity("invalid data in request")
				}
				return nil, fmt.Errorf("unable to update active version: %w", err)
			}
			return nil, nil
		})

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
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				}
				logger.Err(err).Msg("unable to query vcls")
				return nil, err
			}

			resp := &completeVclsOutput{
				Body: vcls,
			}
			return resp, nil
		})

		huma.Get(api, "/v1/ip-networks", func(ctx context.Context, input *struct {
			Family string `query:"family" example:"4" doc:"Network IP family to limit query to" enum:"4,6"` // is string instead of int to make enum work
		},
		) (*ipNetworksOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(authData)
			if !ok {
				return nil, errors.New("unable to read auth data from networks GET handler")
			}

			family := 0

			if input.Family != "" {
				var err error
				family, err = strconv.Atoi(input.Family)
				if err != nil {
					return nil, huma.Error422UnprocessableEntity("unable to parse family string to int")
				}
			}

			networks, err := selectNetworks(dbPool, ad, family)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				}
				logger.Err(err).Msg("unable to query ipv4 networks")
				return nil, err
			}

			resp := &ipNetworksOutput{
				Body: networks,
			}
			return resp, nil
		})

		postNetworksPath := "/v1/ip-networks"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postNetworksPath, &ipNetworkOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postNetworksPath, &ipNetworkOutput{}),
				Method:        http.MethodPost,
				Path:          postNetworksPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Network netip.Prefix `json:"network" doc:"A IPv4 or IPv6 network prefix"`
				}
			},
			) (*ipNetworkOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(authData)
				if !ok {
					return nil, errors.New("unable to read auth data from networks POST handler")
				}

				ipNet, err := insertNetwork(dbPool, input.Body.Network, ad)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("IPv4 network already exists")
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this IPv4 network")
					case errors.Is(err, cdnerrors.ErrCheckViolation):
						return nil, huma.Error400BadRequest("content of request is not valid for IPv4 network")
					case errors.Is(err, cdnerrors.ErrExclutionViolation):
						return nil, huma.Error409Conflict("IPv4 network is already covered by existing networks")
					}
					logger.Err(err).Msg("unable to add IPv4 network")
					return nil, err
				}
				resp := &ipNetworkOutput{Body: ipNet}
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

type userBodyInput struct {
	Name string  `json:"name" example:"you@example.com" doc:"The username" minLength:"1" maxLength:"63"`
	Role string  `json:"role" example:"customer" doc:"Role ID or name" minLength:"1" maxLength:"63"`
	Org  *string `json:"org,omitempty" example:"Some name" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
}

type userPostInput struct {
	Body userBodyInput
}

type userPutInput struct {
	User string `path:"user" example:"1" doc:"User ID or name" minLength:"1" maxLength:"63"`
	Body userBodyInput
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

type serviceAddresses struct {
	ServiceID          pgtype.UUID      `json:"service_id" doc:"ID of service, UUIDv4"`
	AllocatedAddresses []serviceAddress `json:"allocated_addresses" doc:"list of addresses allocated to the org"`
}

type serviceAddress struct {
	Address netip.Addr `json:"address" doc:"IP address (IPv4 or IPv6)"`
}

type orgOutput struct {
	Body org
}

type orgsOutput struct {
	Body []org
}

type orgIPsOutput struct {
	Body serviceAddresses
}

type serviceOutput struct {
	Body types.Service
}

type servicesOutput struct {
	Body []types.Service
}

type serviceVersionOutput struct {
	Body types.ServiceVersion
}

type serviceVersionsOutput struct {
	Body []types.ServiceVersion
}

type origin struct {
	Host string `json:"host" minLength:"1" maxLength:"253"`
	Port int    `json:"port" minimum:"1" maximum:"65535"`
	TLS  bool   `json:"tls"`
}

type selectVcl struct {
	types.VclSteps
	OrgID     pgtype.UUID `json:"org_id" doc:"ID of organization"`
	ServiceID pgtype.UUID `json:"service_id" doc:"ID of service"`
	Active    bool        `json:"active" example:"true" doc:"If the VCL is active"`
	Version   int64       `json:"version" example:"1" doc:"Version of the service"`
	Domains   []string    `json:"domains" doc:"The domains used by the VCL"`
	Origins   []origin    `json:"origins" doc:"The origins used by the VCL"`
}

type ipNetwork struct {
	ID      pgtype.UUID  `json:"id" doc:"ID of IPv4 or IPv6 network, UUIDv4"`
	Network netip.Prefix `json:"network" example:"198.51.100.0/24" doc:"a IPv4 or IPv6 network"`
}

type ipNetworksOutput struct {
	Body []ipNetwork
}

type ipNetworkOutput struct {
	Body ipNetwork
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
		err := tx.QueryRow(context.Background(), "UPDATE gorilla_csrf_keys SET active = false WHERE active = TRUE RETURNING id").Scan(&prevCSRFKeyID)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return pgtype.UUID{}, pgtype.UUID{}, fmt.Errorf("unable to deactivate previous gorilla CSRF key: %w", err)
			}
		}
	}

	err := tx.QueryRow(
		context.Background(),
		"INSERT INTO gorilla_csrf_keys (active, auth_key) VALUES ($1, $2) RETURNING id",
		active,
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

func Run(logger zerolog.Logger, devMode bool, shutdownDelay time.Duration) error {
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

	go func(ctx context.Context, logger zerolog.Logger, shutdownDelay time.Duration) {
		<-ctx.Done()

		logger.Info().Msgf("sleeping for %s then calling Shutdown()", shutdownDelay)
		time.Sleep(shutdownDelay)
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Err(err).Msg("HTTP server Shutdown failure")
		}
		close(idleConnsClosed)
	}(ctx, logger, shutdownDelay)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("HTTP server ListenAndServe failed")
	}

	<-idleConnsClosed

	return nil
}
