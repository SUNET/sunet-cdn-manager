package server

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
	"unicode"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/SUNET/sunet-cdn-manager/pkg/components"
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/a-h/templ"
	"github.com/caddyserver/certmagic"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/errsink"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/libdns/acmedns"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	zlog "github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go4.org/netipx"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func init() {
	gob.Register(cdntypes.AuthData{})
	gob.Register(oidcCallbackData{})
}

//go:embed templates
var templateFS embed.FS

// Keys used for flash message storing
var flashMessageKeys = struct {
	apiTokens string
	domains   string
	services  string
}{
	apiTokens: "_flash_api_tokens",
	domains:   "_flash_domains",
	services:  "_flash_services",
}

const (
	// https://www.postgresql.org/docs/current/errcodes-appendix.html
	// unique_violation: 23505
	pgUniqueViolation = "23505"
	// check_violation: 23514
	pgCheckViolation = "23514"
	// exclusion_violation: 23P01
	pgExclusionViolation = "23P01"

	consolePath                 = "/console"
	api403String                = "not allowed to access resource"
	consoleNeedOrgMembershipMsg = "not allowed to view this page, you need to be a member of an organization"

	// Used for TXT domain verification
	sunetTxtTag       = "sunet-cdn-verification"
	sunetTxtSeparator = "="
	sunetTxtPrefix    = sunetTxtTag + sunetTxtSeparator

	// The expected "aud" set in JWts sent as access tokens to the API
	jwtAudience = "sunet-cdn-manager"
	// The client-scope used for adding the above "aud" via a mapper
	clientScopeName = "sunet-cdn-manager-aud"
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

type vclValidatorClient struct {
	url    *url.URL
	client *http.Client
}

func newVclValidator(u *url.URL) *vclValidatorClient {
	c := &http.Client{
		Timeout: 15 * time.Second,
	}

	return &vclValidatorClient{
		url:    u,
		client: c,
	}
}

func validateInputOrigins(ctx context.Context, tx pgx.Tx, inputOrigins []cdntypes.InputOrigin, serviceID pgtype.UUID) ([]cdntypes.Origin, error) {
	origins := []cdntypes.Origin{}
	for _, inputOrigin := range inputOrigins {
		originGroupIdent, err := newOriginGroupIdentifier(ctx, tx, inputOrigin.OriginGroup, serviceID)
		if err != nil {
			return nil, fmt.Errorf("looking up origin group name failed: %w", err)
		}

		if originGroupIdent.serviceID != serviceID {
			return nil, fmt.Errorf("users can only reference origin groups belonging to the same service ID")
		}

		origins = append(origins, cdntypes.Origin{
			OriginGroupID: originGroupIdent.id,
			Host:          inputOrigin.Host,
			Port:          inputOrigin.Port,
			TLS:           inputOrigin.TLS,
			VerifyTLS:     inputOrigin.VerifyTLS,
		})
	}

	return origins, nil
}

func (vclValidator *vclValidatorClient) validateServiceVersionConfig(confTemplates configTemplates, iSvc cdntypes.InputServiceVersion, serviceIPAddrs []netip.Addr, originGroups []cdntypes.OriginGroup, origins []cdntypes.Origin) error {
	err := validate.Struct(iSvc)
	if err != nil {
		return fmt.Errorf("unable to validate input svc struct: %w", err)
	}

	vcl, err := generateCompleteVcl(confTemplates.vcl, serviceIPAddrs, originGroups, origins, iSvc.Domains, iSvc.VclSteps)
	if err != nil {
		return fmt.Errorf("unable to generate vcl from svc: %w", err)
	}

	r := strings.NewReader(vcl)

	resp, err := vclValidator.client.Post(vclValidator.url.String(), "text/plain; charset=utf-8", r)
	if err != nil {
		return fmt.Errorf("svc validation request failed: %w", err)
	}
	defer resp.Body.Close()

	// sunet-vcl-validator returns 422 if varnishd did not like the VCL content
	if resp.StatusCode == http.StatusUnprocessableEntity {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.New("unable to ready response body for invalid VCL")
		}

		return cdnerrors.NewValidationError(string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unknown validation error: %d", resp.StatusCode)
	}

	return nil
}

func setupACME(logger zerolog.Logger, conf config.Config) *tls.Config {
	acmednsProvider := &acmedns.Provider{Configs: map[string]acmedns.DomainConfig{}}

	for domain, domainSettings := range conf.AcmeDNS {
		logger.Info().Msgf("configuring acme-dns settings for domain '%s'", domain)
		acmednsProvider.Configs[domain] = acmedns.DomainConfig{
			Username:   domainSettings.Username,
			Password:   domainSettings.Password,
			Subdomain:  domainSettings.Subdomain,
			FullDomain: domainSettings.FullDomain,
			ServerURL:  domainSettings.ServerURL,
		}
	}

	// Enable DNS challenge
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: acmednsProvider,
		},
	}

	if !conf.CertMagic.LetsEncryptProd {
		logger.Info().Msg("using LetsEncrypt Staging CA, TLS certificates will not be trusted")
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	// read and agree to your CA's legal documents
	certmagic.DefaultACME.Agreed = true

	// provide an email address
	certmagic.DefaultACME.Email = conf.CertMagic.Email

	// Use custom data directory for cert storage if supplied
	if conf.CertMagic.DataDir != "" {
		logger.Info().Str("data-dir", conf.CertMagic.DataDir).Msg("using certmagic data dir from config")
		certmagic.Default.Storage = &certmagic.FileStorage{
			Path: conf.CertMagic.DataDir,
		}
	}

	tlsConfig, err := certmagic.TLS(conf.CertMagic.Domains)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msgf("cannot create tlsconfig")
	}

	return tlsConfig
}

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
	validatedRedirect(consolePath, w, r, http.StatusFound)
}

const (
	consoleMissingAuthData    = "console: session missing AuthData"
	consoleMissingServicePath = "console: missing service path in URL"
	consoleMissingOrgPath     = "console: missing org path in URL"
	consoleMissingOrgParam    = "console: missing org parameter in URL"
	unableToSetFlashMessage   = "unable to set flash message"
	consoleServiceOrgRedirect = "/console/org/%s/services/%s"
)

func consoleDashboardHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		if ad.Username == nil {
			logger.Error().Msg("consoleDashboardHandler: ad.Username is not set")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ad.Superuser {
			err := renderConsolePage(ctx, dbc, w, r, ad, "Dashboard", "", components.Dashboard(cdntypes.DashboardData{ResourceAccess: true}))
			if err != nil {
				logger.Err(err).Msg("unable to render console home page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else if ad.OrgName != nil {
			orgConsole, err := url.JoinPath(consolePath, "org", *ad.OrgName)
			if err != nil {
				logger.Err(err).Msg("unable to create org console path")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			validatedRedirect(orgConsole, w, r, http.StatusSeeOther)
		} else {
			logger.Error().Str("username", *ad.Username).Msg("user is not superuser or belonging to an organization")
			err := renderConsolePage(ctx, dbc, w, r, ad, "Dashboard", "", components.Dashboard(cdntypes.DashboardData{ResourceAccess: false}))
			if err != nil {
				logger.Err(err).Msg("unable to render console home page for user without access")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}
	}
}

// Functions that interact with the database will do their own validation of
// input data prior to doing anything, so if such a function is called and did
// not fail it should be safe to use the orgName without further validation.
// However sometimes we want to use the orgName without having talked to the
// database e.g. to build redirect URLs. In that case you can use this prior to
// building the URL with unknown data.
func validateOrgName(ctx context.Context, logger *zerolog.Logger, dbPool *pgxpool.Pool, orgName string) (orgIdentifier, error) {
	if orgName == "" {
		return orgIdentifier{}, errEmptyInputIdentifier
	}

	var orgIdent orgIdentifier
	var err error
	err = pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
		orgIdent, err = newOrgIdentifier(ctx, tx, orgName)
		if err != nil {
			logger.Err(err).Msg("validateOrgName: unable to find organization for name")
			return err
		}
		return nil
	})
	if err != nil {
		logger.Err(err).Msg("validateOrgName: db request for looking up orgName failed")
		return orgIdentifier{}, err
	}

	return orgIdent, nil
}

func validateServiceName(ctx context.Context, logger *zerolog.Logger, dbPool *pgxpool.Pool, orgIdent orgIdentifier, serviceName string) (serviceIdentifier, error) {
	if serviceName == "" {
		return serviceIdentifier{}, errEmptyInputIdentifier
	}

	var serviceIdent serviceIdentifier
	var err error
	err = pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
		serviceIdent, err = newServiceIdentifier(ctx, tx, serviceName, orgIdent.id)
		if err != nil {
			logger.Err(err).Msg("validateServiceName: unable to find service for name")
			return err
		}
		return nil
	})
	if err != nil {
		logger.Err(err).Msg("validateServiceName: db request for looking up serviceName failed")
		return serviceIdentifier{}, err
	}

	return serviceIdent, nil
}

// We protect against CSRF by using http.CrossOriginProtection middleware. That
// middleware tries to verify "fetch metadata" present in headers for all browsers
// since 2023 and potentially falling back to Origin header checks. Since this
// is an app that does not expect to cater to existing users lets go one step
// further and outright reject requests that are missing the expected fetch
// metadata header so an old browser would not work at all rather than possibly
// allowing a CSRF attack against this app.
type strictFetchMetadataMiddleware struct{}

func (*strictFetchMetadataMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Safe methods are always allowed the same way
			// http.CrossOriginProtection does it.
			next.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("Sec-Fetch-Site") == "" {
			http.Error(w, "request is missing the Sec-Fetch-Site header, do you need to update your browser?", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getOrgDashboardData(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, org orgIdentifier) (cdntypes.DashboardData, error) {
	var serviceQuota, servicesUsed, domainQuota, domainsUsed, clientTokenQuota, clientTokensUsed int64

	// Must be either superuser or a member of an org
	if !ad.Superuser && ad.OrgID == nil {
		return cdntypes.DashboardData{}, cdnerrors.ErrForbidden
	}

	// If not a superuser make sure the org membership matches the queried org
	if !ad.Superuser && *ad.OrgID != org.id {
		return cdntypes.DashboardData{}, cdnerrors.ErrForbidden
	}

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		err := tx.QueryRow(
			ctx,
			`SELECT
			   orgs.service_quota,
			   (SELECT COUNT(*) FROM services WHERE services.org_id = orgs.id),
			   orgs.domain_quota,
			   (SELECT COUNT(*) FROM domains WHERE domains.org_id = orgs.id),
			   orgs.client_token_quota,
			   (SELECT COUNT(*) FROM org_keycloak_client_credentials WHERE org_keycloak_client_credentials.org_id = orgs.id)
			 FROM orgs WHERE id=$1`,
			org.id,
		).Scan(
			&serviceQuota,
			&servicesUsed,
			&domainQuota,
			&domainsUsed,
			&clientTokenQuota,
			&clientTokensUsed,
		)
		if err != nil {
			return fmt.Errorf("unable to get quota usage: %w", err)
		}

		return nil
	})
	if err != nil {
		return cdntypes.DashboardData{}, fmt.Errorf("getOrgDashboardData transaction failed: %w", err)
	}

	return cdntypes.DashboardData{
		ResourceAccess:   true,
		OrgDashboard:     true,
		ServiceUsed:      servicesUsed,
		ServiceQuota:     serviceQuota,
		DomainUsed:       domainsUsed,
		DomainQuota:      domainQuota,
		ClientCredsUsed:  clientTokensUsed,
		ClientCredsQuota: clientTokenQuota,
	}, nil
}

func consoleOrgDashboardHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("consoleOrgDashboardHandler: db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		if ad.Username == nil {
			logger.Error().Msg("consoleOrgDashboardHandler: ad.Username is not set")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		dashData, err := getOrgDashboardData(ctx, dbc, ad, orgIdent)
		if err != nil {
			switch {
			case errors.Is(err, cdnerrors.ErrForbidden):
				logger.Err(err).Msg("consoleOrgDashboardHandler: forbidden from looking up dashboard data")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			default:
				logger.Err(err).Msg("consoleOrgDashboardHandler: db request for looking up dashboard data failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		if ad.Superuser {
			err := renderConsolePage(ctx, dbc, w, r, ad, "Dashboard", orgIdent.name, components.Dashboard(dashData))
			if err != nil {
				logger.Err(err).Msg("unable to render console home page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else if ad.OrgName != nil {
			if *ad.OrgName != orgIdent.name {
				logger.Error().Msgf("user is not superuser or belongs to the '%s' org", orgIdent.name)
				http.Error(w, "invalid organization name", http.StatusForbidden)
				return
			}
			err := renderConsolePage(ctx, dbc, w, r, ad, "Dashboard", orgIdent.name, components.Dashboard(dashData))
			if err != nil {
				logger.Err(err).Msg("unable to render console home page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			logger.Error().Str("username", *ad.Username).Msg("user is not superuser or belongs to an org")
			err := renderConsolePage(ctx, dbc, w, r, ad, "Dashboard", orgIdent.name, components.Dashboard(dashData))
			if err != nil {
				logger.Err(err).Msg("unable to render console org dashboard for user with no access")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}
	}
}

func getFlashMessageStrings(flashMessages []any) []string {
	flashMessageStrings := []string{}
	for _, message := range flashMessages {
		if stringMessage, ok := message.(string); ok {
			flashMessageStrings = append(flashMessageStrings, stringMessage)
		}
	}

	return flashMessageStrings
}

func consoleDomainsHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		domains, err := selectDomains(ctx, dbc, ad, orgName)
		if err != nil {
			if errors.Is(err, cdnerrors.ErrForbidden) {
				logger.Err(err).Msg("domains console: not authorized to view page")
				http.Error(w, consoleNeedOrgMembershipMsg, http.StatusForbidden)
				return
			}
			logger.Err(err).Msg("domains console: database lookup failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// If someone has been redirected from domain creation we will
		// have a flash message to tell the user so.
		flashMessages := session.Flashes(flashMessageKeys.domains)
		if flashMessages != nil {
			err = session.Save(r, w)
			if err != nil {
				logger.Err(err).Msg("domains console: updating session with flash message failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		flashMessageStrings := getFlashMessageStrings(flashMessages)

		err = renderConsolePage(ctx, dbc, w, r, ad, "Domains", orgName, components.DomainsContent(orgName, domains, sunetTxtTag, sunetTxtSeparator, flashMessageStrings))
		if err != nil {
			logger.Err(err).Msg("unable to render domains page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleDomainDeleteHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg("console: missing org name in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("consoleDomainDeleteHandler: db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !ad.Superuser {
			if ad.OrgName == nil {
				logger.Error().Msg("consoleDomainDelete: user is not superuser and not member of any org")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			} else if *ad.OrgName != orgIdent.name {
				logger.Error().Msg("consoleDomainDelete: user is not superuser and not member of the matching org")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		domainName := chi.URLParam(r, "domain")
		if domainName == "" {
			logger.Error().Msg("console: missing domain name in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		_, err = deleteDomain(ctx, logger, dbc, ad, domainName)
		if err != nil {
			if errors.Is(err, cdnerrors.ErrForbidden) {
				logger.Err(err).Msg("domains console: not authorized to delete domain")
				http.Error(w, "not allowed to delete domain", http.StatusForbidden)
				return
			}
			logger.Err(err).Msg("domains console: domain deletion failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		session.AddFlash(fmt.Sprintf("Domain '%s' deleted!", domainName), flashMessageKeys.domains)
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, unableToSetFlashMessage, http.StatusInternalServerError)
			return
		}

		// Use StatusSeeOther (303) here to make htmx hx-delete AJAX
		// request replace original DELETE method with GET when
		// following the redirect.
		redirectURL, err := url.JoinPath(consolePath, "org", orgIdent.name, "domains")
		if err != nil {
			logger.Err(err).Msg("domains console: unable to create redirect URL")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		validatedRedirect(redirectURL, w, r, http.StatusSeeOther)
	}
}

func consoleAPITokensHandler(dbc *dbConn, cookieStore *sessions.CookieStore, tokenURL *url.URL, serverURL *url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgClientCreds, err := selectSafeOrgClientCredentials(ctx, dbc, orgName, ad)
		if err != nil {
			switch {
			case errors.Is(err, cdnerrors.ErrForbidden), errors.Is(err, cdnerrors.ErrNotFound):
				logger.Err(err).Msg("api tokens console: not authorized to view page")
				http.Error(w, consoleNeedOrgMembershipMsg, http.StatusForbidden)
			default:
				logger.Err(err).Msg("api tokens console: database lookup failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		// If someone has been redirected from api token creation we will
		// have a flash message to tell the user so.
		flashMessages := session.Flashes(flashMessageKeys.apiTokens)
		if flashMessages != nil {
			err = session.Save(r, w)
			if err != nil {
				logger.Err(err).Msg("consoleAPITokensHandler: updating session with flash message failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		flashMessageStrings := getFlashMessageStrings(flashMessages)

		err = renderConsolePage(ctx, dbc, w, r, ad, "API Tokens", orgName, components.APITokensContent(orgName, orgClientCreds, flashMessageStrings, tokenURL, serverURL))
		if err != nil {
			logger.Err(err).Msg("unable to render api-tokens page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleAPITokenDeleteHandler(dbc *dbConn, cookieStore *sessions.CookieStore, clientCredAEADs []cipher.AEAD, kccm *keycloakClientManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg("console: missing org name in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("consoleAPITokenDeleteHandler: db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !ad.Superuser {
			if ad.OrgName == nil {
				logger.Error().Msg("consoleAPITokenDeleteHandler: user is not superuser and not member of any org")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			} else if *ad.OrgName != orgIdent.name {
				logger.Error().Msg("consoleAPITokenDeleteHandler: user is not superuser and not member of the matching org")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		apiTokenName := chi.URLParam(r, "api-token")
		if apiTokenName == "" {
			logger.Error().Msg("console: missing api-token name in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		_, err = deleteOrgClientCredential(ctx, logger, dbc, clientCredAEADs, ad, kccm, orgName, apiTokenName)
		if err != nil {
			switch {
			case errors.Is(err, cdnerrors.ErrForbidden):
				logger.Err(err).Msg("api-tokens console: not authorized to delete API token")
				http.Error(w, "not allowed to delete api-token", http.StatusForbidden)
			case errors.Is(err, cdnerrors.ErrNotFound):
				logger.Err(err).Msg("api-tokens console: API token not found")
				http.Error(w, "api-token not found", http.StatusNotFound)
			default:
				logger.Err(err).Msg("API token console: API token deletion failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		session.AddFlash(fmt.Sprintf("API token '%s' deleted!", apiTokenName), flashMessageKeys.apiTokens)
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, unableToSetFlashMessage, http.StatusInternalServerError)
			return
		}

		// Use StatusSeeOther (303) here to make htmx hx-delete AJAX
		// request replace original DELETE method with GET when
		// following the redirect.
		redirectURL, err := url.JoinPath(consolePath, "org", orgIdent.name, "api-tokens")
		if err != nil {
			logger.Err(err).Msg("api-tokens console: unable to create redirect URL")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		validatedRedirect(redirectURL, w, r, http.StatusSeeOther)
	}
}

func consoleCreateAPITokenHandler(dbc *dbConn, cookieStore *sessions.CookieStore, clientCredAEAD cipher.AEAD, kccm *keycloakClientManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		title := "Add API token"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !ad.Superuser {
			if ad.OrgName == nil {
				logger.Error().Msg("consoleCreateAPITokenHandler: not member of org")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			if *ad.OrgName != orgIdent.name {
				logger.Error().Msg("consoleCreateAPITokenHandler: not member of correct org")
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		switch r.Method {
		case http.MethodGet:
			err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateAPITokenContent(orgIdent.name, components.APITokenData{}))
			if err != nil {
				logger.Err(err).Msg("unable to render api-token creation page in GET")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse create-api-token POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := createAPITokenForm{}

			err = schemaDecoder.Decode(&formData, r.PostForm)
			if err != nil {
				logger.Err(err).Msg("unable to decode POST create-api-token form data")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			apiTokenData := components.APITokenData{
				APITokenFormFields: components.APITokenFormFields{
					Name:        formData.Name,
					Description: formData.Description,
				},
			}

			err = validate.Struct(formData)
			if err != nil {
				validationErrors := err.(validator.ValidationErrors)
				for _, fieldError := range validationErrors {
					switch fieldError.StructField() {
					case "Name":
						if fieldError.Tag() == "dns_rfc1035_label" {
							apiTokenData.Errors.Name = "not a valid DNS label"
						} else {
							apiTokenData.Errors.Name = fieldError.Error()
						}
					case "Description":
						apiTokenData.Errors.Description = fieldError.Error()
					}
				}
				logger.Err(err).Msg("unable to validate POST create-api-token form data")
				err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateAPITokenContent(orgIdent.name, apiTokenData))
				if err != nil {
					logger.Err(err).Msg("unable to render api-token creation page in POST")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			newClientCred, err := insertOrgClientCredential(ctx, logger, dbc, formData.Name, formData.Description, orgIdent.name, ad, kccm, clientCredAEAD)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrAlreadyExists) {
					apiTokenData.Errors.Name = cdnerrors.ErrAlreadyExists.Error()
				} else {
					logger.Err(err).Msg("unable to insert API token")
					apiTokenData.Errors.ServerError = "unable to insert API token"
				}
				err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateAPITokenContent(orgIdent.name, apiTokenData))
				if err != nil {
					logger.Err(err).Msg("unable to render API token creation page after insert error")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			session.AddFlash(fmt.Sprintf("API token '%s' added!", formData.Name), flashMessageKeys.apiTokens)
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, unableToSetFlashMessage, http.StatusInternalServerError)
				return
			}

			redirectURL, err := url.JoinPath(consolePath, "org", orgIdent.name, "api-tokens")
			if err != nil {
				logger.Err(err).Msg("consoleCreateAPITokenHandler: unable to create redirect URL")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			err = renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.NewAPITokenContent(orgIdent.name, newClientCred, redirectURL))
			if err != nil {
				logger.Err(err).Msg("consoleCreateAPITokenHandler: unable to render new API token page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for create-api-token handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func consoleServiceDeleteHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg("console: missing service name in URL")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		_, err := deleteService(ctx, logger, dbc, orgName, serviceName, ad)
		if err != nil {
			if errors.Is(err, cdnerrors.ErrForbidden) {
				logger.Err(err).Msg("services console: not authorized to delete service")
				http.Error(w, "not allowed to delete service", http.StatusForbidden)
				return
			}
			logger.Err(err).Msg("services console: service deletion failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		session.AddFlash(fmt.Sprintf("Service '%s' deleted!", serviceName), flashMessageKeys.services)
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, unableToSetFlashMessage, http.StatusInternalServerError)
			return
		}

		redirectURL, err := url.JoinPath(consolePath, "org", orgName, "services")
		if err != nil {
			logger.Err(err).Msg("consoleServiceDeleteHandler: unable to create redirect URL")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Use StatusSeeOther (303) here to make htmx hx-delete AJAX
		// request replace original DELETE method with GET when
		// following the redirect.
		validatedRedirect(redirectURL, w, r, http.StatusSeeOther)
	}
}

func consoleServicesHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		services, err := selectServices(ctx, dbc, ad, orgName)
		if err != nil {
			if errors.Is(err, cdnerrors.ErrForbidden) {
				logger.Err(err).Msg("services console: not authorized to view page")
				http.Error(w, consoleNeedOrgMembershipMsg, http.StatusForbidden)
				return
			}
			logger.Err(err).Msg("services console: database lookup failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// If someone has been redirected from service creation we will
		// have a flash message to tell the user so.
		flashMessages := session.Flashes(flashMessageKeys.services)
		if flashMessages != nil {
			err := session.Save(r, w)
			if err != nil {
				logger.Err(err).Msg("services console: updating session with flash message failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		flashMessageStrings := getFlashMessageStrings(flashMessages)

		err = renderConsolePage(ctx, dbc, w, r, ad, "Services", orgName, components.ServicesContent(orgName, services, flashMessageStrings))
		if err != nil {
			logger.Err(err).Msg("unable to render services page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleCreateDomainHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		title := "Add domain"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !ad.Superuser {
			if ad.OrgName == nil {
				logger.Error().Msg("consoleCreateDomainHandler: not member of org")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if *ad.OrgName != orgIdent.name {
				logger.Error().Msg("consoleCreateDomainHandler: not member of correct org")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		switch r.Method {
		case http.MethodGet:
			err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateDomainContent(orgIdent.name, components.DomainData{}))
			if err != nil {
				logger.Err(err).Msg("unable to render domain creation page in GET")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse create-domain POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := createDomainForm{}

			err = schemaDecoder.Decode(&formData, r.PostForm)
			if err != nil {
				logger.Err(err).Msg("unable to decode POST create-domain form data")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			domainData := components.DomainData{
				DomainFormFields: components.DomainFormFields{
					Name: formData.Name,
				},
			}

			err = validate.Struct(formData)
			if err != nil {
				validationErrors := err.(validator.ValidationErrors)
				for _, fieldError := range validationErrors {
					if fieldError.StructField() == "Name" {
						if fieldError.Tag() == "fqdn" {
							domainData.Errors.Name = "not a valid FQDN"
						} else {
							domainData.Errors.Name = fieldError.Error()
						}
					}
				}
				logger.Err(err).Msg("unable to validate POST create-domain form data")
				err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateDomainContent(orgIdent.name, domainData))
				if err != nil {
					logger.Err(err).Msg("unable to render domain creation page in POST")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			_, err = insertDomain(ctx, logger, dbc, formData.Name, &orgIdent.name, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrAlreadyExists) {
					domainData.Errors.Name = cdnerrors.ErrAlreadyExists.Error()
				} else {
					logger.Err(err).Msg("unable to insert domain")
					domainData.Errors.ServerError = "unable to insert domain"
				}
				err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateDomainContent(orgIdent.name, domainData))
				if err != nil {
					logger.Err(err).Msg("unable to render domain creation page after insert error")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			session.AddFlash(fmt.Sprintf("Domain '%s' added!", formData.Name), flashMessageKeys.domains)
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, unableToSetFlashMessage, http.StatusInternalServerError)
				return
			}

			redirectURL, err := url.JoinPath(consolePath, "org", orgIdent.name, "domains")
			if err != nil {
				logger.Err(err).Msg("consoleCreateDomainHandler: unable to create redirect URL")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			validatedRedirect(redirectURL, w, r, http.StatusFound)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for create-domain handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func consoleCreateServiceHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		title := "Create service"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgPath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("consoleCreateServiceHandler: db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		switch r.Method {
		case http.MethodGet:
			err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateServiceContent(orgIdent.name, nil))
			if err != nil {
				logger.Err(err).Msg("GET: unable to render service creation page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
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
				err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateServiceContent(orgIdent.name, cdnerrors.ErrInvalidFormData))
				if err != nil {
					logger.Err(err).Msg("POST: unable to render service creation page")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			_, err = insertService(ctx, logger, dbc, formData.Name, &orgIdent.name, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrAlreadyExists) {
					err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateServiceContent(orgIdent.name, err))
					if err != nil {
						logger.Err(err).Msg("service already exists: unable to render service creation page")
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
				logger.Err(err).Msg("unable to insert service")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			session.AddFlash(fmt.Sprintf("Service '%s' added!", formData.Name), flashMessageKeys.services)
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, unableToSetFlashMessage, http.StatusInternalServerError)
				return
			}

			redirectURL, err := url.JoinPath(consolePath, "org", orgIdent.name, "services")
			if err != nil {
				logger.Err(err).Msg("unable to create redirect url")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			validatedRedirect(redirectURL, w, r, http.StatusFound)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for create-service handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func consoleNewOriginFieldsetHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgStr := r.URL.Query().Get("org")
		if orgStr == "" {
			logger.Error().Msg("missing 'org' query parameter")
			http.Error(w, "missing 'org' query paramter", http.StatusBadRequest)
			return
		}

		serviceStr := r.URL.Query().Get("service")
		if serviceStr == "" {
			logger.Error().Msg("missing 'service' query parameter")
			http.Error(w, "missing 'service' query paramter", http.StatusBadRequest)
			return
		}

		// Use the same error for validateOrgName() as the user
		// permission check so we don't give away if an org exists or
		// not if the user is not allowed to use it. Protects against
		// enumeration of what orgs exists.
		validationError := "org name validation failed"
		validationErrorCode := http.StatusBadRequest

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgStr)
		if err != nil {
			logger.Err(err).Msg("org name validation failed")
			http.Error(w, validationError, validationErrorCode)
			return
		}

		serviceIdent, err := validateServiceName(ctx, logger, dbc.dbPool, orgIdent, serviceStr)
		if err != nil {
			logger.Err(err).Msg("service name validation failed")
			http.Error(w, validationError, validationErrorCode)
			return
		}

		if !ad.Superuser {
			if ad.OrgName == nil {
				logger.Err(err).Msg("user not allowed to get originfieldset")
				http.Error(w, validationError, validationErrorCode)
				return
			}
			if *ad.OrgName != orgIdent.name {
				logger.Err(err).Msg("user not member of the requested org")
				http.Error(w, validationError, validationErrorCode)
				return
			}
			if orgIdent.id != serviceIdent.orgID {
				logger.Err(err).Msg("requested service is not member of the requested org")
				http.Error(w, validationError, validationErrorCode)
				return
			}
		}

		originGroups, err := selectOriginGroups(ctx, dbc, ad, serviceIdent.name, orgStr)
		if err != nil {
			logger.Err(err).Msg("consoleActivateServiceVersionHandler GET: unable to select service groups")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		index := 0
		indexStr := r.URL.Query().Get("next-origin-index")
		if indexStr != "" {
			var err error
			index, err = strconv.Atoi(indexStr)
			if err != nil {
				logger.Error().Msg("console: invalid console fieldset index")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		}
		component := components.OriginFieldSet(orgIdent.name, serviceIdent.name, index, index+1, nil, cdntypes.Origin{}, originGroups, true)
		err = component.Render(r.Context(), w)
		if err != nil {
			logger.Error().Msg("console: unable to render origin fieldset")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleOrgSwitcherHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		orgStr := r.URL.Query().Get("org")
		if orgStr == "" {
			logger.Error().Msg("missing 'org' query parameter")
			http.Error(w, "missing 'org' query paramter", http.StatusBadRequest)
			return
		}

		var orgURL string

		if orgStr == cdntypes.OrgNotSelected {
			// The special "not selected" option leads to the root console path.
			orgURL = consolePath
		} else {
			// Use the same error for validateOrgName() as the user
			// permission check so we don't give away if an org exists or
			// not if the user is not allowed to use it. Protects against
			// enumeration of what orgs exists.
			validationError := "org name validation failed"
			validationErrorCode := http.StatusBadRequest

			orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgStr)
			if err != nil {
				logger.Err(err).Msg("org name validation failed")
				http.Error(w, validationError, validationErrorCode)
				return
			}

			if !ad.Superuser {
				if ad.OrgName == nil {
					logger.Err(err).Msg("user not allowed to check if org exists")
					http.Error(w, validationError, validationErrorCode)
					return
				}
				if *ad.OrgName != orgIdent.name {
					logger.Err(err).Msg("user not member of the correct org for switching to it")
					http.Error(w, validationError, validationErrorCode)
					return
				}
			}
			orgURL, err = url.JoinPath(consolePath, "org", orgIdent.name)
			if err != nil {
				logger.Err(err).Msg("unable to create URL for switching org")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		validatedRedirect(orgURL, w, r, http.StatusFound)
	}
}

func consoleServiceHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg(consoleMissingServicePath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		title := "Service"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		serviceVersions, err := selectServiceVersions(ctx, dbc, ad, serviceName, orgName)
		if err != nil {
			logger.Error().Msg("console: unable to select service versions")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = renderConsolePage(ctx, dbc, w, r, ad, title, orgName, components.ServiceContent(orgName, serviceName, serviceVersions))
		if err != nil {
			logger.Err(err).Msg("unable to render service page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func consoleServiceVersionHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg(consoleMissingServicePath)
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

		title := "Service version"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		svc, err := getServiceVersionConfig(ctx, dbc, ad, orgName, serviceName, serviceVersion)
		if err != nil {
			logger.Err(err).Msg("console: unable to select service version config")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		vclKeyToConf, keyOrder := cdntypes.VclStepsToMap(svc.VclSteps)

		err = renderConsolePage(ctx, dbc, w, r, ad, title, orgName, components.ServiceVersionContent(serviceName, svc, vclKeyToConf, keyOrder))
		if err != nil {
			logger.Err(err).Msg("unable to render service version page")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

// Used to turn e.g. "VclRecv" or "VCLRecv" into "vcl_recv"
func camelCaseToSnakeCase(s string) string {
	// Handle capitalized VCL
	s = strings.ReplaceAll(s, "VCL", "Vcl")
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

func getServiceVersionCloneData(ctx context.Context, tx pgx.Tx, ad cdntypes.AuthData, orgName string, serviceName string, cloneVersion int64) (cdntypes.ServiceVersionCloneData, error) {
	orgIdent, err := newOrgIdentifier(ctx, tx, orgName)
	if err != nil {
		return cdntypes.ServiceVersionCloneData{}, err
	}

	if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != orgIdent.id) {
		return cdntypes.ServiceVersionCloneData{}, cdnerrors.ErrForbidden
	}

	serviceIdent, err := newServiceIdentifier(ctx, tx, serviceName, orgIdent.id)
	if err != nil {
		return cdntypes.ServiceVersionCloneData{}, err
	}

	if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != serviceIdent.orgID) {
		return cdntypes.ServiceVersionCloneData{}, cdnerrors.ErrForbidden
	}

	rows, err := tx.Query(
		ctx,
		`SELECT
			(SELECT
				array_agg(domains.name ORDER BY domains.name)
				FROM domains
				JOIN service_domains ON service_domains.domain_id = domains.id
				WHERE domains.verified = true AND service_version_id = service_versions.id
			) AS domains,
			(SELECT
				array_agg((origin_group_id, host, port, tls, verify_tls) ORDER BY host, port)
				FROM service_origins
				WHERE service_version_id = service_versions.id
			) AS origins,
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
			service_vcls.vcl_backend_error
		FROM
			services
			JOIN service_versions ON services.id = service_versions.service_id
			JOIN service_vcls ON service_versions.id = service_vcls.service_version_id
		WHERE services.id=$1 AND service_versions.version=$2`,
		serviceIdent.id,
		cloneVersion,
	)
	if err != nil {
		return cdntypes.ServiceVersionCloneData{}, fmt.Errorf("unable to query for version config data for cloning: %w", err)
	}

	cloneData, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[cdntypes.ServiceVersionCloneData])
	if err != nil {
		return cdntypes.ServiceVersionCloneData{}, fmt.Errorf("unable to collect service version clone data into struct: %w", err)
	}

	return cloneData, nil
}

func consoleCreateServiceVersionHandler(dbc *dbConn, cookieStore *sessions.CookieStore, vclValidator *vclValidatorClient, confTemplates configTemplates) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg(consoleMissingServicePath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		title := "Create service version"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		vclSK := cdntypes.NewVclStepKeys()

		domains, err := selectDomains(ctx, dbc, ad, orgName)
		if err != nil {
			logger.Error().Msg("console: unable to lookup domains for service version creation")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("consoleActivateServiceVersionHandler GET: looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		serviceIdent, err := validateServiceName(ctx, logger, dbc.dbPool, orgIdent, serviceName)
		if err != nil {
			logger.Err(err).Msg("consoleActivateServiceVersionHandler GET: looking up serviceName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		originGroups, err := selectOriginGroups(ctx, dbc, ad, serviceIdent.name, orgIdent.name)
		if err != nil {
			logger.Err(err).Msg("consoleActivateServiceVersionHandler GET: unable to select service groups")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		switch r.Method {
		case http.MethodGet:
			var cloneData cdntypes.ServiceVersionCloneData
			cloneVersionStr := r.URL.Query().Get("clone-version")
			if cloneVersionStr != "" {
				cloneVersion, err := strconv.ParseInt(cloneVersionStr, 10, 64)
				if err != nil {
					logger.Err(err).Msg("console: unable to parse clone version as int")
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					return
				}

				err = pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
					cloneData, err = getServiceVersionCloneData(ctx, tx, ad, orgName, serviceName, cloneVersion)
					if err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					logger.Err(err).Msg("db request to fill in service version clone data failed")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}

			err = renderConsolePage(ctx, dbc, w, r, ad, title, orgName, components.CreateServiceVersionContent(serviceName, orgName, vclSK, domains, originGroups, nil, cloneData, nil, ""))
			if err != nil {
				logger.Err(err).Msg("unable to render create service version page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
			err := r.ParseForm()
			if err != nil {
				logger.Err(err).Msg("unable to parse create-service-version POST form")
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			formData := cdntypes.CreateServiceVersionForm{}

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
			// database (they should be NULL) so reset any VCL
			// string pointer fields back to nil if they are
			// pointing to empty strings.
			// https://github.com/gorilla/schema/issues/161
			val := reflect.ValueOf(&formData)
			structVal := val.Elem()
			for _, field := range reflect.VisibleFields(structVal.Type()) {
				if _, ok := vclSK.FieldToKey[field.Name]; ok {
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
				logger.Err(err).Msg("unable to validate POST create-service-version form data")

				err = renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.CreateServiceVersionContent(serviceIdent.name, orgIdent.name, vclSK, domains, originGroups, &formData, cdntypes.ServiceVersionCloneData{}, cdnerrors.ErrInvalidFormData, ""))
				if err != nil {
					logger.Err(err).Msg("unable to render service creation page after validation failure")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			inputOrigins := []cdntypes.InputOrigin{}
			for _, formOrigin := range formData.Origins {
				inputOrigins = append(inputOrigins, cdntypes.InputOrigin{
					OriginGroup: formOrigin.OriginGroup,
					Host:        formOrigin.OriginHost,
					Port:        formOrigin.OriginPort,
					TLS:         formOrigin.OriginTLS,
					VerifyTLS:   formOrigin.OriginVerifyTLS,
				})
			}
			_, err = insertServiceVersion(ctx, logger, confTemplates, ad, dbc, vclValidator, orgName, serviceName, formData.Domains, inputOrigins, false, formData.VclSteps)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrAlreadyExists), errors.Is(err, cdnerrors.ErrInvalidVCL):
					errDetails := ""
					var ve *cdnerrors.VCLValidationError
					if errors.As(err, &ve) {
						errDetails = ve.Details
					}
					err := renderConsolePage(ctx, dbc, w, r, ad, title, orgName, components.CreateServiceVersionContent(serviceName, orgName, vclSK, domains, originGroups, &formData, cdntypes.ServiceVersionCloneData{}, err, errDetails))
					if err != nil {
						logger.Err(err).Msg("unable to render service version creation page")
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
				logger.Err(err).Msg("unable to insert service version")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			validatedRedirect(fmt.Sprintf(consoleServiceOrgRedirect, orgName, serviceName), w, r, http.StatusFound)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for create-service-version handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func consoleActivateServiceVersionHandler(dbc *dbConn, cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

		orgName := chi.URLParam(r, "org")
		if orgName == "" {
			logger.Error().Msg(consoleMissingOrgParam)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		orgIdent, err := validateOrgName(ctx, logger, dbc.dbPool, orgName)
		if err != nil {
			logger.Err(err).Msg("consoleActivateServiceVersionHandler: db request for looking up orgName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		serviceName := chi.URLParam(r, "service")
		if serviceName == "" {
			logger.Error().Msg(consoleMissingServicePath)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		serviceIdent, err := validateServiceName(ctx, logger, dbc.dbPool, orgIdent, serviceName)
		if err != nil {
			logger.Err(err).Msg("consoleActivateServiceVersionHandler: db request for looking up serviceName failed")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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

		title := "Activate service version"

		session := getSession(r, cookieStore)

		adRef, ok := session.Values["ad"]
		if !ok {
			logger.Error().Msg(consoleMissingAuthData)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		ad := adRef.(cdntypes.AuthData)

		switch r.Method {
		case http.MethodGet:
			err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.ActivateServiceVersionContent(orgIdent.name, serviceIdent.name, version, nil))
			if err != nil {
				logger.Err(err).Msg("unable to render activate-service-version page")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		case http.MethodPost:
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
				err := renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.ActivateServiceVersionContent(orgIdent.name, serviceIdent.name, version, cdnerrors.ErrInvalidFormData))
				if err != nil {
					logger.Err(err).Msg("unable to render service version activation page in POST")
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}

			if !formData.Confirmation {
				validatedRedirect(fmt.Sprintf(consoleServiceOrgRedirect, orgIdent.name, serviceIdent.name), w, r, http.StatusFound)
				return
			}

			if formData.Confirmation {
				err := activateServiceVersion(ctx, logger, ad, dbc, orgIdent.name, serviceIdent.name, version)
				if err != nil {
					logger.Err(err).Msg("service version activation failed")
					err = renderConsolePage(ctx, dbc, w, r, ad, title, orgIdent.name, components.ActivateServiceVersionContent(orgIdent.name, serviceIdent.name, version, err))
					if err != nil {
						logger.Err(err).Msg("unable to render activate-service-version page on activation failure")
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
			}

			validatedRedirect(fmt.Sprintf(consoleServiceOrgRedirect, orgIdent.name, serviceIdent.name), w, r, http.StatusFound)
		default:
			logger.Error().Str("method", r.Method).Msg("method not supported for activate-service-version handler")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
	}
}

func renderConsolePage(ctx context.Context, dbc *dbConn, w http.ResponseWriter, r *http.Request, ad cdntypes.AuthData, title string, orgName string, contents templ.Component) error {
	availableOrgNames := []string{}
	if !ad.Superuser {
		// The orgName can be empty for users that are not belonging to
		// an org.
		if orgName != "" {
			availableOrgNames = append(availableOrgNames, orgName)
		}
	} else {
		orgs, err := selectOrgs(ctx, dbc, ad)
		if err != nil {
			return fmt.Errorf("unable to select orgs: %w", err)
		}

		for _, org := range orgs {
			availableOrgNames = append(availableOrgNames, org.Name)
		}
	}

	component := components.ConsolePage(title, ad, orgName, availableOrgNames, contents)
	return component.Render(r.Context(), w)
}

// Return user to content of return_to query parameter but only if it points to a place we control
// https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
func validatedRedirect(returnTo string, w http.ResponseWriter, r *http.Request, code int) {
	logger := hlog.FromRequest(r)
	returnToURL, err := url.Parse(returnTo)
	if err != nil {
		logger.Err(err).Msg("unable to parse return_to content as URL")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Make sure the URL does not point to anything outside this server
	if r.URL.Host != returnToURL.Host {
		logger.Err(err).Msg("redirect target does not point to this service, not redirecting")
		http.Error(w, "redirect target does not point to this service", http.StatusBadRequest)
		return
	}

	logger.Info().Str("return_to", returnToURL.String()).Msg("redirecting user")
	http.Redirect(w, r, returnToURL.String(), code)
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
	// Service name length validation needs to be kept in sync with the CHECK
	// constraints in the service table, see the migrations module.
	Name string `schema:"name" validate:"min=1,max=63,dns_rfc1035_label"`
}

type createDomainForm struct {
	// Domain name length validation needs to be kept in sync with the CHECK
	// constraints in the domains table, see the migrations module.
	Name string `schema:"name" validate:"min=1,max=253,fqdn"`
}

type createAPITokenForm struct {
	// API token name length validation needs to be kept in sync with the CHECK
	// constraints in the org_keycloak_client_credentials table, see the
	// migrations module.
	Name        string `schema:"name" validate:"min=1,max=63,dns_rfc1035_label"`
	Description string `schema:"description" validate:"min=1,max=255"`
}

type activateServiceVersionForm struct {
	Confirmation bool `schema:"confirmation"`
}

// Endpoint used for console login
func loginHandler(dbc *dbConn, argon2Mutex *sync.Mutex, loginCache *lru.Cache[string, struct{}], cookieStore *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			q := r.URL.Query()
			returnTo := q.Get(returnToKey)
			_, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if ok {
				switch returnTo {
				case "":
					logger.Info().Msg("login: session already has ad data but no return_to, redirecting to console")
					validatedRedirect(consolePath, w, r, http.StatusFound)
					return
				default:
					logger.Info().Msg("login: session already has ad data and return_to, redirecting to return_to")
					validatedRedirect(returnTo, w, r, http.StatusFound)
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
		case http.MethodPost:
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

			var ad cdntypes.AuthData

			err = pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
				ad, err = dbUserLogin(ctx, tx, logger, argon2Mutex, loginCache, formData.Username, formData.Password)
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

				logger.Info().Msg("redirecting logged in user to return_to found in POSTed form if valid")
				validatedRedirect(u.String(), w, r, http.StatusFound)
				return
			}
			logger.Info().Msg("no return_to in POST data, redirecting logged in user to consolePath")
			validatedRedirect(consolePath, w, r, http.StatusFound)
			return
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

		_, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
		if ok {
			switch returnTo {
			case "":
				logger.Info().Msg("login: session already has ad data but no return_to, redirecting to console")
				validatedRedirect(consolePath, w, r, http.StatusFound)
				return
			default:
				logger.Info().Msg("login: session already has ad data and return_to, redirecting to return_to")
				validatedRedirect(returnTo, w, r, http.StatusFound)
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
			validatedRedirect(u.String(), w, r, http.StatusFound)
			return
		}

		// No return_to hint, just send them to the console
		validatedRedirect(consolePath, w, r, http.StatusFound)
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
func oauth2CallbackHandler(oauth2HTTPClient *http.Client, cookieStore *sessions.CookieStore, oauth2Config oauth2.Config, idTokenVerifier *oidc.IDTokenVerifier, dbc *dbConn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		ctx := r.Context()

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

		oauth2Ctx := context.WithValue(ctx, oauth2.HTTPClient, oauth2HTTPClient)

		oauth2Token, err := oauth2Config.Exchange(oauth2Ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(ocd.PKCEVerifier))
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
		idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
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

		// Get AuthData for keycloak user
		ad, err := keycloakUser(ctx, dbc, logger, idToken.Subject, kcc)
		if err != nil {
			logger.Err(err).Msg("unable to get keycloak user")
			switch {
			case errors.Is(err, cdnerrors.ErrKeyCloakEmailUnverified), errors.Is(err, cdnerrors.ErrKeyCloakUserExists):
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			default:
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		session.Values["ad"] = ad

		err = session.Save(r, w)
		if err != nil {
			logger.Err(err).Msg("unable to save session")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ocd.ReturnTo != "" {
			validatedRedirect(ocd.ReturnTo, w, r, http.StatusFound)
			return
		}

		validatedRedirect(consolePath, w, r, http.StatusFound)
	}
}

type keycloakClaims struct {
	// The length checks needs to be kept in sync with the CHECK constraint
	// for the users.name column in the database.
	PreferredUsername string `json:"preferred_username" validate:"min=1,max=63"`
}

func addKeycloakUser(ctx context.Context, dbc *dbConn, subject, name string) (pgtype.UUID, pgtype.UUID, error) {
	var userID, keycloakProviderID pgtype.UUID

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "INSERT INTO users (name, role_id, auth_provider_id) VALUES ($1, (SELECT id from roles WHERE name=$2), (SELECT id FROM auth_providers WHERE name=$3)) RETURNING id", name, "user", "keycloak").Scan(&userID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				if pgErr.Code == pgUniqueViolation {
					return cdnerrors.ErrKeyCloakUserExists
				}
			}
			return fmt.Errorf("unable to INSERT user from keycloak data: %w", err)
		}

		err = tx.QueryRow(ctx, "INSERT INTO auth_provider_keycloak (user_id, subject) VALUES ($1, $2) RETURNING id", userID, subject).Scan(&keycloakProviderID)
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

func keycloakUser(ctx context.Context, dbc *dbConn, logger *zerolog.Logger, subject string, kcc keycloakClaims) (cdntypes.AuthData, error) {
	// We keep track of keycloak users via the sub value returned in the ID
	// token. For keycloak this is a UUID, e.g.
	// "ab809abb-5bac-4db1-8088-3d340ea23de8" which is the actual user ID in keycloak which
	// should remain the same even if the username or email is changed at a
	// later time.
	//
	// This means we need to backup the keycloak database since
	// if the database is lost users are recreated with another UUID and
	// treated as a new user by us.

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var username string
	var userID, keycloakProviderID pgtype.UUID
	err := dbc.dbPool.QueryRow(
		dbCtx,
		"SELECT users.id, users.name FROM users JOIN auth_provider_keycloak ON users.id = auth_provider_keycloak.user_id WHERE auth_provider_keycloak.subject = $1",
		subject,
	).Scan(&userID, &username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User does not exist, add to database
			userID, keycloakProviderID, err = addKeycloakUser(dbCtx, dbc, subject, kcc.PreferredUsername)
			if err != nil {
				return cdntypes.AuthData{}, fmt.Errorf("unable to add keycloak user '%s' to database: %w", kcc.PreferredUsername, err)
			}
			username = kcc.PreferredUsername
			logger.Info().Str("user_id", userID.String()).Str("keycloak_provider_id", keycloakProviderID.String()).Msg("created user based on keycloak credentials")
		} else {
			return cdntypes.AuthData{}, fmt.Errorf("keycloak user lookup failed: %w", err)
		}
	}

	if username != kcc.PreferredUsername {
		logger.Info().Str("from", username).Str("to", kcc.PreferredUsername).Msg("keycloak username out of sync, updating local username")
		_, err := dbc.dbPool.Exec(dbCtx, "UPDATE users SET name=$1 WHERE id=$2", kcc.PreferredUsername, userID)
		if err != nil {
			return cdntypes.AuthData{}, fmt.Errorf("renaming user based on keycloak data failed: %w", err)
		}

		username = kcc.PreferredUsername
	}

	var roleID pgtype.UUID
	var orgID *pgtype.UUID // can be nil if not belonging to a organization
	var orgName *string    // same as above
	var superuser bool
	var roleName string
	err = dbc.dbPool.QueryRow(
		dbCtx,
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
		return cdntypes.AuthData{}, err
	}

	return cdntypes.AuthData{
		Username:  &username,
		UserID:    &userID,
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

// Keep in mind that if you change these values existing encryption keys
// derived from these settings will not match anymore.
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

const (
	wwwAuthenticateHeader = "WWW-Authenticate"
	apiAuthRealm          = "SUNET CDN Manager"
)

func authChallenge(scheme string, realm string) string {
	return fmt.Sprintf(`%s realm="%s"`, scheme, realm)
}

func sendHumaUnauthorized(logger *zerolog.Logger, api huma.API, humaCtx huma.Context) {
	humaCtx.AppendHeader(wwwAuthenticateHeader, authChallenge("Basic", apiAuthRealm))
	humaCtx.AppendHeader(wwwAuthenticateHeader, authChallenge("Bearer", apiAuthRealm))
	err := huma.WriteErr(api, humaCtx, http.StatusUnauthorized, "Unauthorized")
	if err != nil {
		logger.Err(err).Msg("sendHumaUnauthorized: writing auth challenge response")
	}
}

// Login page/form for browser based (not API) requests
func renderLoginPage(w http.ResponseWriter, r *http.Request, returnTo string, loginFailed bool) error {
	component := components.LoginPage(returnTo, loginFailed)
	err := component.Render(r.Context(), w)
	return err
}

func redirectToLoginPage(w http.ResponseWriter, r *http.Request) error {
	// Even if a url.URL contains a pointer it is expected to be immutable
	// so it should be safe to make a shallow copy:
	// https://github.com/golang/go/issues/38351
	redirectURL := *r.URL

	// Remember where we wanted to go, but only overwrite it if it is not already set
	q := r.URL.Query()
	if !q.Has(returnToKey) {
		q.Set(returnToKey, r.URL.String())
		redirectURL.RawQuery = q.Encode()
	}

	// Redirect to the login handler
	redirectURL.Path = "/auth/login"

	validatedRedirect(redirectURL.String(), w, r, http.StatusFound)

	return nil
}

func createLoginCacheKey(userID pgtype.UUID, expectedPasswordHash []byte, expectedSalt []byte, password string) string {
	var loginCacheKey []byte
	loginCacheKey = append(loginCacheKey, userID.String()...)
	loginCacheKey = append(loginCacheKey, expectedPasswordHash...)
	loginCacheKey = append(loginCacheKey, expectedSalt...)
	loginCacheKey = append(loginCacheKey, password...)
	hashedCacheKeyBytes := sha256.Sum256(loginCacheKey)
	hashedCacheKey := hex.EncodeToString(hashedCacheKeyBytes[:])

	return hashedCacheKey
}

func dbUserLogin(ctx context.Context, tx pgx.Tx, logger *zerolog.Logger, argon2Mutex *sync.Mutex, loginCache *lru.Cache[string, struct{}], username string, password string) (cdntypes.AuthData, error) {
	var userID, roleID pgtype.UUID
	var orgID *pgtype.UUID // can be nil if not belonging to a organization
	var orgName *string    // same as above
	var argon2Key, argon2Salt []byte
	var argon2Time, argon2Memory, argon2TagSize uint32
	var argon2Threads uint8
	var superuser bool
	var roleName string

	err := tx.QueryRow(
		ctx,
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
		return cdntypes.AuthData{}, err
	}

	hashedCacheKey := createLoginCacheKey(userID, argon2Key, argon2Salt, password)

	validLogin := false

	if _, ok := loginCache.Get(hashedCacheKey); ok {
		logger.Info().Msgf("login cache hit for userID '%s'", userID.String())
		validLogin = true
	} else {
		logger.Info().Msgf("login cache miss for userID '%s'", userID.String())
	}

	if !validLogin {
		// Protect concurrent access to memory intensive argon2
		// operation. We do not want to overwhelm the server
		// with many simultaneous logins which could cause OOM
		// problems.
		argon2Mutex.Lock()
		logger.Info().Msgf("calculating hash for userID '%s'", userID.String())
		loginKey := argon2.IDKey([]byte(password), argon2Salt, argon2Time, argon2Memory, argon2Threads, argon2TagSize)
		argon2Mutex.Unlock()
		// Use subtle.ConstantTimeCompare() in an attempt to
		// not leak password contents via timing attack
		passwordMatch := (subtle.ConstantTimeCompare(loginKey, argon2Key) == 1)

		if passwordMatch {
			validLogin = true
			evicted := loginCache.Add(hashedCacheKey, struct{}{})
			if evicted {
				logger.Info().Msg("adding key to loginCache resulted in eviction")
			}
		}
	}

	if !validLogin {
		return cdntypes.AuthData{}, cdnerrors.ErrBadPassword
	}

	logger.Info().Msgf("successful login for userID '%s', username '%s'", userID.String(), username)

	return cdntypes.AuthData{
		Username:  &username,
		UserID:    &userID,
		OrgID:     orgID,
		OrgName:   orgName,
		RoleID:    roleID,
		RoleName:  roleName,
		Superuser: superuser,
	}, nil
}

func jwtToAuthData(ctx context.Context, tx pgx.Tx, jwtToken jwt.Token) (cdntypes.AuthData, error) {
	var clientCredID, orgID, roleID pgtype.UUID
	var clientCredName, orgName, roleName string
	var superuser bool

	// Example content of jwt token:
	//{
	//  "exp": 1769522430,
	//  "iat": 1769522130,
	//  "jti": "e91b3156-0fc5-4e6f-ba0b-0d22829dce39",
	//  "iss": "http://localhost:55005/realms/sunet-cdn-manager",
	//  "aud": "sunet-cdn-manager",
	//  "sub": "9c6d4e96-0c03-4813-b3e7-8db4f61feb9f",
	//  "typ": "Bearer",
	//  "azp": "sunet-cdn-org-client-0f00ba36-ab0e-48ec-a3af-d271484884ca",
	//  "scope": "",
	//  "clientHost": "192.168.65.1",
	//  "clientAddress": "192.168.65.1",
	//  "client_id": "sunet-cdn-org-client-0f00ba36-ab0e-48ec-a3af-d271484884ca"
	//}
	//
	// The "sub" in a keycloak access token is the UUID of the related
	// service account. We only store the client_id we selected in our
	// database so use that instead. It is interesting that the same string
	// is present in the "azp" field above, but as the azp field is only
	// really specified for OIDC ID tokens prefer the Oauth2 client_id
	// instead as this seems more correct for an access token.
	var clientID string
	err := jwtToken.Get("client_id", &clientID)
	if err != nil {
		return cdntypes.AuthData{}, fmt.Errorf("jwtToAuthData(): looking up client_id failed: %w", err)
	}

	// The Get() will be happy as long as the claim exists at all, even
	// with an empty value, so verify it is was not empty.
	if clientID == "" {
		return cdntypes.AuthData{}, errors.New("jwtToAuthData(): client_id is empty")
	}

	err = tx.QueryRow(
		ctx,
		`SELECT
			org_keycloak_client_credentials.id,
			org_keycloak_client_credentials.name,
			org_keycloak_client_credentials.org_id,
			orgs.name,
			org_keycloak_client_credentials.role_id,
			roles.name,
			roles.superuser
		FROM org_keycloak_client_credentials
		JOIN roles ON org_keycloak_client_credentials.role_id = roles.id
		LEFT JOIN orgs ON org_keycloak_client_credentials.org_id = orgs.id
		WHERE org_keycloak_client_credentials.client_id=$1`,
		clientID,
	).Scan(
		&clientCredID,
		&clientCredName,
		&orgID,
		&orgName,
		&roleID,
		&roleName,
		&superuser,
	)
	if err != nil {
		return cdntypes.AuthData{}, err
	}

	return cdntypes.AuthData{
		Username:  nil,
		UserID:    nil,
		OrgID:     &orgID,
		OrgName:   &orgName,
		RoleID:    roleID,
		RoleName:  roleName,
		Superuser: superuser,
	}, nil
}

const (
	cookieName = "sunet-cdn-manager"
)

func authFromSession(logger *zerolog.Logger, cookieStore *sessions.CookieStore, r *http.Request) *cdntypes.AuthData {
	session := getSession(r, cookieStore)

	adInt, ok := session.Values["ad"]
	if !ok {
		return nil
	}

	logger.Info().Msg("using authentication data from session")
	ad := adInt.(cdntypes.AuthData)
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

func selectUsers(ctx context.Context, dbPool *pgxpool.Pool, logger *zerolog.Logger, ad cdntypes.AuthData) ([]user, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbPool.Query(ctx, "SELECT id, name, org_id, role_id FROM users ORDER BY name")
		if err != nil {
			logger.Err(err).Msg("unable to query for users")
			return nil, fmt.Errorf("unable to query for users")
		}
	} else if ad.OrgID != nil && ad.UserID != nil {
		rows, err = dbPool.Query(ctx, "SELECT id, name, org_id, role_id FROM users WHERE users.id=$1 ORDER BY name", *ad.UserID)
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

func selectUser(ctx context.Context, dbPool *pgxpool.Pool, userNameOrID string, ad cdntypes.AuthData) (user, error) {
	u := user{}

	err := pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
		userIdent, err := newUserIdentifier(ctx, tx, userNameOrID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		if !ad.Superuser && ad.UserID == nil {
			return cdnerrors.ErrNotFound
		}

		if !ad.Superuser && *ad.UserID != userIdent.id {
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

func passwordToArgon2(argon2Mutex *sync.Mutex, password string) (argon2Data, error) {
	argon2Settings := newArgon2DefaultSettings()

	// Generate 16 byte (128 bit) salt as
	// recommended for argon2 in RFC 9106
	saltLen := 16

	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return argon2Data{}, fmt.Errorf("unable to create argon2 salt: %w", err)
	}

	// Protect access to memory intensive hash calculation to not overwhelm server if handling many concurrect connections.
	argon2Mutex.Lock()
	key := argon2.IDKey([]byte(password), salt, argon2Settings.argonTime, argon2Settings.argonMemory, argon2Settings.argonThreads, argon2Settings.argonTagSize)
	argon2Mutex.Unlock()

	return argon2Data{
		key:            key,
		salt:           salt,
		argon2Settings: argon2Settings,
	}, nil
}

func upsertArgon2Tx(ctx context.Context, tx pgx.Tx, userID pgtype.UUID, a2Data argon2Data) (pgtype.UUID, error) {
	var keyID pgtype.UUID
	err := tx.QueryRow(
		ctx,
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

func getClientCredEncryptionKeys(conf config.Config) ([][]byte, error) {
	if len(conf.KeycloakClientAdmin.EncryptionSalt) != 32 {
		return nil, errors.New("getClientCredEncryptionKeys: client admin salt must be a 32-character hex string")
	}

	salt, err := saltFromHex(conf.KeycloakClientAdmin.EncryptionSalt)
	if err != nil {
		return nil, fmt.Errorf("getClientCredEncryptionKeys: cannot decode salt hex: %w", err)
	}

	argon2Settings := newArgon2DefaultSettings()

	encKeys := [][]byte{}
	for _, password := range conf.KeycloakClientAdmin.EncryptionPasswords {
		encKeys = append(
			encKeys,
			argon2.IDKey(
				[]byte(password),
				salt,
				argon2Settings.argonTime,
				argon2Settings.argonMemory,
				argon2Settings.argonThreads,
				chacha20poly1305.KeySize,
			),
		)
	}

	return encKeys, nil
}

func saltFromHex(hexString string) ([]byte, error) {
	if len(hexString) != 32 {
		return nil, fmt.Errorf("saltFromHex: hex string must be 32 hex characters long")
	}
	salt, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("saltFromHex: cannot decode salt hex: %w", err)
	}
	return salt, nil
}

func setLocalPassword(ctx context.Context, logger *zerolog.Logger, ad cdntypes.AuthData, dbc *dbConn, argon2Mutex *sync.Mutex, loginCache *lru.Cache[string, struct{}], userNameOrID string, oldPassword string, newPassword string) (pgtype.UUID, error) {
	// While we could potentially do the argon2 operation inside the
	// transaction below after we know the user is actually allowed to
	// change the password it feels wrong to keep a transaction open
	// longer than necessary. So do the initial hashing here. We still do
	// another round of hashing when testing the oldPassword below but in
	// that case it probably makes sense to know the database is in a
	// consistent state (via FOR SHARE selects) during the operation.
	a2Data, err := passwordToArgon2(argon2Mutex, newPassword)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to generate argon2 data from newPassword: %w", err)
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var keyID pgtype.UUID
	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		userIdent, err := newUserIdentifier(dbCtx, tx, userNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse user for local-password: %w", err)
		}

		// We only allow the setting of passwords for users using the "local" auth provider
		var authProviderName string
		err = tx.QueryRow(dbCtx, "SELECT auth_providers.name FROM auth_providers JOIN users ON auth_providers.id = users.auth_provider_id WHERE users.id=$1 FOR SHARE", userIdent.id).Scan(&authProviderName)
		if err != nil {
			return fmt.Errorf("unable to look up name of auth provider for user with id '%s': %w", userIdent.id, err)
		}

		// A superuser can change any password and a normal user can only change their own password
		if !ad.Superuser && ad.UserID == nil {
			return cdnerrors.ErrForbidden
		}
		if !ad.Superuser && *ad.UserID != userIdent.id {
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
			_, err := dbUserLogin(dbCtx, tx, logger, argon2Mutex, loginCache, userIdent.name, oldPassword)
			if err != nil {
				logger.Err(err).Msg("old password check failed")
				return cdnerrors.ErrBadOldPassword
			}
		}

		keyID, err = upsertArgon2Tx(dbCtx, tx, userIdent.id, a2Data)
		if err != nil {
			return fmt.Errorf("unable to UPDATE user argon2 data: %w", err)
		}

		// Clear the login cache if the password is updated correctly. This should not be strictly
		// needed because the random salt added to the account should make sure even reuse of
		// the same password results in a different cache hash, but be careful just in case.
		lenBefore := loginCache.Len()
		loginCache.Purge()
		lenAfter := loginCache.Len()
		logger.Info().Msgf("purged login cache after successful password change, items before: %d, items after: %d", lenBefore, lenAfter)

		return nil
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("setLocalPassword: transaction failed: %w", err)
	}

	return keyID, nil
}

func setCacheNodeMaintenance(ctx context.Context, ad cdntypes.AuthData, dbc *dbConn, cacheNodeNameOrID string, maintenance bool) error {
	if !ad.Superuser {
		return cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		cacheNodeIdent, err := newCacheNodeIdentifier(dbCtx, tx, cacheNodeNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse cache node ID for maintenance: %w", err)
		}

		_, err = tx.Exec(dbCtx, "UPDATE cache_nodes SET maintenance = $1 WHERE id = $2", maintenance, cacheNodeIdent.id)
		if err != nil {
			return fmt.Errorf("unable to update maintenance mode for cache node: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("setCacheNodeMaintenance: transaction failed: %w", err)
	}

	return nil
}

func setCacheNodeGroup(ctx context.Context, ad cdntypes.AuthData, dbc *dbConn, cacheNodeNameOrID string, nodeGroupNameOrID string) error {
	if !ad.Superuser {
		return cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		cacheNodeIdent, err := newCacheNodeIdentifier(dbCtx, tx, cacheNodeNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse cacheNodeIdent node ID for node-group: %w", err)
		}

		nodeGroupIdent, err := newNodeGroupIdentifier(dbCtx, tx, nodeGroupNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse nodeGroupIdent group ID for cache node-group: %w", err)
		}

		_, err = tx.Exec(dbCtx, "UPDATE cache_nodes SET node_group_id = $1 WHERE id = $2", nodeGroupIdent.id, cacheNodeIdent.id)
		if err != nil {
			return fmt.Errorf("unable to set node group for cache node: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("setCacheNodeGroup: transaction failed: %w", err)
	}

	return nil
}

func selectCacheNodes(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData) ([]cdntypes.CacheNode, error) {
	if !ad.Superuser {
		return nil, cdnerrors.ErrForbidden
	}

	var rows pgx.Rows
	var err error

	rows, err = dbc.dbPool.Query(
		ctx,
		`SELECT
			cache_nodes.id,
			cache_nodes.name,
			cache_nodes.description,
			cache_nodes.maintenance,
			agg_addresses.addresses
		FROM cache_nodes
		JOIN (
			SELECT node_id, array_agg(address ORDER BY address) as addresses
			FROM cache_node_addresses
			GROUP BY node_id
		) AS agg_addresses ON agg_addresses.node_id = cache_nodes.id
		ORDER BY cache_nodes.name
		`)
	if err != nil {
		return nil, fmt.Errorf("unable to query for all cache nodes: %w", err)
	}

	cacheNodes, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.CacheNode])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for cache nodes: %w", err)
	}

	return cacheNodes, nil
}

func createCacheNode(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, name string, description string, addresses []netip.Addr, maintenance bool) (cdntypes.CacheNode, error) {
	if !ad.Superuser {
		return cdntypes.CacheNode{}, cdnerrors.ErrForbidden
	}

	var err error

	var cacheNodeID pgtype.UUID

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		cacheNodeID, err = insertCacheNodeTx(dbCtx, tx, name, description, addresses, maintenance)
		if err != nil {
			return fmt.Errorf("createCacheNode: INSERT failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return cdntypes.CacheNode{}, fmt.Errorf("createCacheNode: transaction failed: %w", err)
	}

	return cdntypes.CacheNode{
		Node: cdntypes.Node{
			Name:        name,
			ID:          cacheNodeID,
			Description: description,
			Addresses:   addresses,
			Maintenance: maintenance,
		},
	}, nil
}

func insertCacheNodeTx(ctx context.Context, tx pgx.Tx, name string, description string, addresses []netip.Addr, maintenance bool) (pgtype.UUID, error) {
	var cacheNodeID pgtype.UUID
	err := tx.QueryRow(ctx, "INSERT INTO cache_nodes (name, description, maintenance) VALUES ($1, $2, $3) RETURNING id", name, description, maintenance).Scan(&cacheNodeID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("INSERT cache node failed: %w", err)
	}

	for _, address := range addresses {
		var cacheNodeAddressID pgtype.UUID
		err = tx.QueryRow(ctx, "INSERT INTO cache_node_addresses (node_id, address) VALUES ($1, $2) RETURNING id", cacheNodeID, address).Scan(&cacheNodeAddressID)
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("INSERT cache node address failed: %w", err)
		}
	}

	return cacheNodeID, nil
}

func setL4LBNodeMaintenance(ctx context.Context, ad cdntypes.AuthData, dbc *dbConn, l4lbNodeNameOrID string, maintenance bool) error {
	if !ad.Superuser {
		return cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		l4lbNodeIdent, err := newL4LBNodeIdentifier(dbCtx, tx, l4lbNodeNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse l4lbNodeIdent node ID for maintenance: %w", err)
		}

		_, err = tx.Exec(dbCtx, "UPDATE l4lb_nodes SET maintenance = $1 WHERE id = $2", maintenance, l4lbNodeIdent.id)
		if err != nil {
			return fmt.Errorf("unable to update maintenance mode for l4lb node: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("setL4LBNodeMaintenance: transaction failed: %w", err)
	}

	return nil
}

func setL4LBNodeGroup(ctx context.Context, ad cdntypes.AuthData, dbc *dbConn, l4lbNodeNameOrID string, nodeGroupNameOrID string) error {
	if !ad.Superuser {
		return cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		l4lbNodeIdent, err := newL4LBNodeIdentifier(dbCtx, tx, l4lbNodeNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse l4lbNodeIdent node ID for node-group: %w", err)
		}

		nodeGroupIdent, err := newNodeGroupIdentifier(dbCtx, tx, nodeGroupNameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse nodeGroupIdent group ID for l4lb node-group: %w", err)
		}

		_, err = tx.Exec(dbCtx, "UPDATE l4lb_nodes SET node_group_id = $1 WHERE id = $2", nodeGroupIdent.id, l4lbNodeIdent.id)
		if err != nil {
			return fmt.Errorf("unable to set node group for l4lb node: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("setL4LBNodeGroup: transaction failed: %w", err)
	}

	return nil
}

func selectL4LBNodes(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData) ([]cdntypes.L4LBNode, error) {
	if !ad.Superuser {
		return nil, cdnerrors.ErrForbidden
	}

	var rows pgx.Rows
	var err error

	rows, err = dbc.dbPool.Query(
		ctx,
		`SELECT
			l4lb_nodes.id,
			l4lb_nodes.name,
			l4lb_nodes.description,
			l4lb_nodes.maintenance,
			agg_addresses.addresses
		FROM l4lb_nodes
		JOIN (
			SELECT node_id, array_agg(address ORDER BY address) as addresses
			FROM l4lb_node_addresses
			GROUP BY node_id
		) AS agg_addresses ON agg_addresses.node_id = l4lb_nodes.id
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("unable to query for all l4lb nodes: %w", err)
	}

	l4lbNodes, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.L4LBNode])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for l4lb nodes: %w", err)
	}

	return l4lbNodes, nil
}

func createL4LBNode(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, name string, description string, addresses []netip.Addr, maintenance bool) (cdntypes.L4LBNode, error) {
	if !ad.Superuser {
		return cdntypes.L4LBNode{}, cdnerrors.ErrForbidden
	}

	var err error

	var l4lbNodeID pgtype.UUID

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		l4lbNodeID, err = insertL4LBNodeTx(dbCtx, tx, name, description, addresses, maintenance)
		if err != nil {
			return fmt.Errorf("createL4LBNode: INSERT failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return cdntypes.L4LBNode{}, fmt.Errorf("createL4LBNode: transaction failed: %w", err)
	}

	return cdntypes.L4LBNode{
		Node: cdntypes.Node{
			Name:        name,
			ID:          l4lbNodeID,
			Description: description,
			Addresses:   addresses,
			Maintenance: maintenance,
		},
	}, nil
}

func insertL4LBNodeTx(ctx context.Context, tx pgx.Tx, name string, description string, addresses []netip.Addr, maintenance bool) (pgtype.UUID, error) {
	var l4lbNodeID pgtype.UUID
	err := tx.QueryRow(ctx, "INSERT INTO l4lb_nodes (name, description, maintenance) VALUES ($1, $2, $3) RETURNING id", name, description, maintenance).Scan(&l4lbNodeID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("INSERT l4lb node failed: %w", err)
	}

	for _, address := range addresses {
		var l4lbAddressID pgtype.UUID
		err = tx.QueryRow(ctx, "INSERT INTO l4lb_node_addresses (node_id, address) VALUES ($1, $2) RETURNING id", l4lbNodeID, address).Scan(&l4lbAddressID)
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("INSERT l4lb node IP address failed: %w", err)
		}
	}

	return l4lbNodeID, nil
}

func createUser(ctx context.Context, dbc *dbConn, name string, role string, org *string, ad cdntypes.AuthData) (user, error) {
	if !ad.Superuser {
		return user{}, cdnerrors.ErrForbidden
	}

	var err error

	var userID pgtype.UUID

	var orgIdent orgIdentifier
	var roleIdent roleIdentifier

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		if org != nil {
			orgIdent, err = newOrgIdentifier(dbCtx, tx, *org)
			if err != nil {
				return fmt.Errorf("unable to parse organization for user INSERT: %w", err)
			}
		}

		roleIdent, err = newRoleIdentifier(dbCtx, tx, role)
		if err != nil {
			return fmt.Errorf("unable to parse role for user INSERT: %w", err)
		}

		authProviderID, err := authProviderNameToIDTx(dbCtx, tx, "local")
		if err != nil {
			return fmt.Errorf("unble to resolve authProvider name to ID: %w", err)
		}

		userID, err = insertUserTx(dbCtx, tx, name, &orgIdent.id, roleIdent.id, authProviderID)
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

func deleteUser(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, ad cdntypes.AuthData, userNameOrID string) (pgtype.UUID, error) {
	if !ad.Superuser {
		return pgtype.UUID{}, cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var userID pgtype.UUID
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		userIdent, err := newUserIdentifier(dbCtx, tx, userNameOrID)
		if err != nil {
			logger.Err(err).Msg("unable to look up user identifier")
			return cdnerrors.ErrUnprocessable
		}

		// A user can not delete itself to protect against locking
		// yourself out of the system. For now this also locks out
		// requests from org client credentials (API tokens) since
		// ad.UserID is nil on those.
		if ad.UserID == nil || *ad.UserID == userIdent.id {
			return cdnerrors.ErrForbidden
		}

		err = tx.QueryRow(dbCtx, "DELETE FROM users WHERE id = $1 RETURNING id", userIdent.id).Scan(&userID)
		if err != nil {
			return fmt.Errorf("unable to DELETE user: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("deleteUser transaction failed")
		return pgtype.UUID{}, fmt.Errorf("deleteUser transaction failed: %w", err)
	}

	return userID, nil
}

func insertUserTx(ctx context.Context, tx pgx.Tx, name string, orgID *pgtype.UUID, roleID pgtype.UUID, authProviderID pgtype.UUID) (pgtype.UUID, error) {
	var userID pgtype.UUID
	err := tx.QueryRow(ctx, "INSERT INTO users (name, org_id, role_id, auth_provider_id) VALUES ($1, $2, $3, $4) RETURNING id", name, orgID, roleID, authProviderID).Scan(&userID)
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
func authProviderNameToIDTx(ctx context.Context, tx pgx.Tx, name string) (pgtype.UUID, error) {
	var authProviderID pgtype.UUID
	err := tx.QueryRow(ctx, "SELECT id FROM auth_providers WHERE name=$1 FOR SHARE", name).Scan(&authProviderID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return authProviderID, nil
}

func updateUserTx(ctx context.Context, tx pgx.Tx, userID pgtype.UUID, name string, orgID *pgtype.UUID, roleID pgtype.UUID) error {
	_, err := tx.Exec(ctx, "UPDATE users SET name = $1, org_id = $2, role_id = $3 WHERE id = $4", name, orgID, roleID, userID)
	if err != nil {
		return fmt.Errorf("unable to update user with id '%s': %w", userID, err)
	}

	return nil
}

func updateUser(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, nameOrID string, org *string, role string) (user, error) {
	if !ad.Superuser {
		return user{}, cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var u user
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		userIdent, err := newUserIdentifier(dbCtx, tx, nameOrID)
		if err != nil {
			return fmt.Errorf("unable to parse user name or ID for PUT: %w", err)
		}

		roleIdent, err := newRoleIdentifier(dbCtx, tx, role)
		if err != nil {
			return fmt.Errorf("unable to parse role name or ID for PUT: %w", err)
		}

		// org can be nil when the user should have its org value unset
		var orgID *pgtype.UUID
		if org != nil {
			orgIdent, err := newOrgIdentifier(dbCtx, tx, *org)
			if err != nil {
				return fmt.Errorf("unable to parse org ID for PATCH: %w", err)
			}
			orgID = &orgIdent.id
		}

		err = updateUserTx(dbCtx, tx, userIdent.id, userIdent.name, orgID, roleIdent.id)
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

func selectOrgs(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData) ([]cdntypes.Org, error) {
	var rows pgx.Rows
	var err error
	if ad.Superuser {
		rows, err = dbc.dbPool.Query(ctx, "SELECT id, name FROM orgs ORDER BY time_created")
		if err != nil {
			return nil, fmt.Errorf("unable to query for orgs: %w", err)
		}
	} else if ad.OrgID != nil {
		rows, err = dbc.dbPool.Query(ctx, "SELECT id, name FROM orgs WHERE id=$1 ORDER BY time_created", *ad.OrgID)
		if err != nil {
			return nil, fmt.Errorf("unable to query for orgs: %w", err)
		}
	} else {
		return nil, cdnerrors.ErrForbidden
	}

	orgs, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.Org])
	if err != nil {
		return nil, fmt.Errorf("unable to CollectRows for orgs: %w", err)
	}

	return orgs, nil
}

func selectDomains(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, orgNameOrID string) ([]cdntypes.Domain, error) {
	domains := []cdntypes.Domain{}

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var err error
		var orgIdent orgIdentifier
		var lookupOrg pgtype.UUID

		// Must be either superuser or member of an org
		if !ad.Superuser && ad.OrgID == nil {
			return cdnerrors.ErrForbidden
		}

		if orgNameOrID != "" {
			orgIdent, err = newOrgIdentifier(ctx, tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}

			lookupOrg = orgIdent.id
		}

		// If not superuser and a specific org is requested the user is
		// only allowed to request it if they are member of the same org
		if !ad.Superuser && lookupOrg.Valid {
			if lookupOrg != *ad.OrgID {
				return cdnerrors.ErrForbidden
			}
		}

		// If not superuser and a specific org was not requested, set
		// it to the org of the user.
		if !ad.Superuser && !lookupOrg.Valid {
			lookupOrg = *ad.OrgID
		}

		var rows pgx.Rows
		if lookupOrg.Valid {
			rows, err = tx.Query(ctx, "SELECT id, name, verified, verification_token FROM domains WHERE org_id=$1 ORDER BY name", lookupOrg)
			if err != nil {
				return fmt.Errorf("unable to query for domains for specific org: %w", err)
			}
		} else {
			rows, err = tx.Query(ctx, "SELECT id, name, verified, verification_token FROM domains ORDER BY name")
			if err != nil {
				return fmt.Errorf("unable to query for all domains: %w", err)
			}
		}

		domains, err = pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.Domain])
		if err != nil {
			return fmt.Errorf("unable to CollectRows for org domains: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("selectDomains: transaction failed: %w", err)
	}

	return domains, nil
}

func deleteDomain(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, ad cdntypes.AuthData, domainNameOrID string) (pgtype.UUID, error) {
	if !ad.Superuser && ad.OrgID == nil {
		return pgtype.UUID{}, cdnerrors.ErrNotFound
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var domainID pgtype.UUID
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		domainIdent, err := newDomainIdentifier(dbCtx, tx, domainNameOrID)
		if err != nil {
			logger.Err(err).Msg("unable to look up domain identifier")
			return cdnerrors.ErrUnprocessable
		}

		// A normal user can only delete a domain belonging to the
		// same org they are a member of
		if !ad.Superuser && *ad.OrgID != domainIdent.orgID {
			return cdnerrors.ErrNotFound
		}

		err = tx.QueryRow(dbCtx, "DELETE FROM domains WHERE id = $1 RETURNING id", domainIdent.id).Scan(&domainID)
		if err != nil {
			return fmt.Errorf("unable to DELETE domain: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("deleteDomain transaction failed")
		return pgtype.UUID{}, fmt.Errorf("deleteDomain transaction failed: %w", err)
	}

	return domainID, nil
}

func selectServiceIPs(ctx context.Context, dbc *dbConn, serviceNameOrID string, orgNameOrID string, ad cdntypes.AuthData) (serviceAddresses, error) {
	sAddrs := serviceAddresses{}
	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		serviceIdent, err := newServiceIdentifier(ctx, tx, serviceNameOrID, orgID)
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

		rows, err := tx.Query(ctx, "SELECT address FROM service_ip_addresses WHERE service_id=$1", serviceIdent.id)
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

func selectOrg(ctx context.Context, dbc *dbConn, orgNameOrID string, ad cdntypes.AuthData) (cdntypes.Org, error) {
	o := cdntypes.Org{}

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
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
		return cdntypes.Org{}, fmt.Errorf("selectOrg: transaction failed: %w", err)
	}

	return o, nil
}

func selectSafeOrgClientCredentials(ctx context.Context, dbc *dbConn, orgNameOrID string, ad cdntypes.AuthData) ([]cdntypes.OrgClientCredentialSafe, error) {
	safeOrgClientCredentials := []cdntypes.OrgClientCredentialSafe{}

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != orgIdent.id) {
			return cdnerrors.ErrNotFound
		}

		rows, err := tx.Query(
			ctx,
			"SELECT id, name, org_id, client_id, description FROM org_keycloak_client_credentials WHERE org_id = $1",
			orgIdent.id,
		)
		if err != nil {
			return fmt.Errorf("unable to query org_keycloak_client_credentials: %w", err)
		}

		safeOrgClientCredentials, err = pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.OrgClientCredentialSafe])
		if err != nil {
			return fmt.Errorf("collecting rows for org_keycloak_client_credentials failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("selectSafeOrgClientCredentials: transaction failed: %w", err)
	}

	return safeOrgClientCredentials, nil
}

type keycloakClientData struct {
	Protocol                  string   `json:"protocol"`
	ClientID                  string   `json:"clientId"`
	PublicClient              bool     `json:"publicClient"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool     `json:"serviceAccountsEnabled"`
	DefaultClientScopes       []string `json:"defaultClientScopes,omitempty"`
}

func newKeycloakClientReq(clientID string, defaultClientScopes []string) keycloakClientData {
	kcd := keycloakClientData{
		Protocol:                  "openid-connect",
		ClientID:                  clientID,
		PublicClient:              false,
		StandardFlowEnabled:       false,
		DirectAccessGrantsEnabled: false,
		ServiceAccountsEnabled:    true,
	}

	kcd.DefaultClientScopes = append(kcd.DefaultClientScopes, defaultClientScopes...)

	return kcd
}

type keycloakClientRegistrationData struct {
	keycloakClientData
	ID                      string `json:"id"`
	Secret                  string `json:"secret"`
	RegistrationAccessToken string `json:"registrationAccessToken"`
}

func sendHTTPReq(client *http.Client, method string, url string, headers map[string]string, reqBody []byte, queryParams url.Values, expectedStatusCode int) (respBody []byte, err error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	if queryParams != nil {
		req.URL.RawQuery = queryParams.Encode()
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resp != nil {
			err = errors.Join(err, resp.Body.Close())
		}
	}()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != expectedStatusCode {
		return nil, fmt.Errorf("sendHTTPReq: unexpected status code for URL '%s', method '%s', want: %d, have: %d", url, method, expectedStatusCode, resp.StatusCode)
	}

	return respBody, nil
}

// [
//
//	{
//	 "id": "fc687680-0e84-4a67-b26d-985c75a9ff16",
//	 "name": "sunet-cdn-manager-aud",
//	 "description": "Assigned to client credentials used for authenticating to the SUNET CDN Manager API",
//	 "protocol": "openid-connect",
//	 "attributes": {
//	   "include.in.token.scope": "false",
//	   "display.on.consent.screen": "true",
//	   "gui.order": "",
//	   "consent.screen.text": ""
//	 },
//	 "protocolMappers": [
//	   {
//	     "id": "04c78222-4055-496d-828a-233097a28244",
//	     "name": "sunet-cdn-manager-aud",
//	     "protocol": "openid-connect",
//	     "protocolMapper": "oidc-audience-mapper",
//	     "consentRequired": false,
//	     "config": {
//	       "id.token.claim": "false",
//	       "lightweight.claim": "false",
//	       "access.token.claim": "true",
//	       "introspection.token.claim": "true",
//	       "included.custom.audience": "sunet-cdn-manager"
//	     }
//	   }
//	 ]
//	}
//
// ]
type keycloakClientScope struct {
	ID              string                        `json:"id,omitempty"` // omitempty is needed when using this struct to create new scopes in tests
	Protocol        string                        `json:"protocol"`
	Name            string                        `json:"name"`
	Description     string                        `json:"description"`
	Type            string                        `json:"type"`
	Attributes      keycloakClientScopeAttributes `json:"attributes"`
	ProtocolMappers []keycloakClientScopeMapper   `json:"protocolMappers"`
}

type keycloakClientScopeMapper struct {
	Name           string                       `json:"name"`
	Protocol       string                       `json:"protocol"`
	ProtocolMapper string                       `json:"protocolMapper"`
	Config         keycloakProtocolMapperConfig `json:"config"`
}

type keycloakProtocolMapperConfig struct {
	IncludedClientAudience  string `json:"included.client.audience"`
	IncludedCustomAudience  string `json:"included.custom.audience"`
	IDTokenClaim            string `json:"id.token.claim"`
	AccessTokenClaim        string `json:"access.token.claim"`
	LightweightClaim        string `json:"lightweight.claim"`
	IntrospectionTokenClaim string `json:"introspection.token.claim"`
}

type keycloakClientScopeAttributes struct {
	DisplayOnConsentScreen string `json:"display.on.consent.screen"`
	ConsentScreenText      string `json:"consent.screen.text"`
	IncludeInTokenScope    string `json:"include.in.token.scope"`
	GuiOrder               string `json:"gui.order"`
}

func (kccm *keycloakClientManager) createClientCred(clientID string) (string, string, string, error) {
	ckBody := newKeycloakClientReq(clientID, []string{clientScopeName})

	regURL, err := url.JoinPath(kccm.baseURL.String(), "realms", kccm.realm, "clients-registrations/default")
	if err != nil {
		return "", "", "", fmt.Errorf("createClientCred: unable to create client-registrations URL: %w", err)
	}

	ckBytes, err := json.Marshal(ckBody)
	if err != nil {
		return "", "", "", fmt.Errorf("createClientCred: unable to marshal json: %w", err)
	}

	regBody, err := sendHTTPReq(
		kccm.createClient,
		http.MethodPost,
		regURL,
		map[string]string{"Content-Type": "application/json"},
		ckBytes,
		nil,
		http.StatusCreated,
	)
	if err != nil {
		return "", "", "", fmt.Errorf("createClientCred: unable to POST registration request: %w", err)
	}

	var regData keycloakClientRegistrationData

	err = json.Unmarshal(regBody, &regData)
	if err != nil {
		return "", "", "", fmt.Errorf("createClientCred: unable to unmarshal client registration JSON: %w", err)
	}

	return regData.ID, regData.Secret, regData.RegistrationAccessToken, nil
}

func (kccm *keycloakClientManager) deleteClientCred(clientID string, registrationAccessToken string) error {
	deleteURL, err := url.JoinPath(kccm.baseURL.String(), "realms", kccm.realm, "clients-registrations/default", clientID)
	if err != nil {
		return fmt.Errorf("deleteClientCred: unable to create DELETE URL: %w", err)
	}

	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		return fmt.Errorf("deleteClientCred: unable to create DELETE request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+registrationAccessToken)

	resp, err := kccm.deleteClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleteClientCred: unable to do DELETE request: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			kccm.logger.Err(err).Msg("deleteClientCred: unable to close DELETE body")
		}
	}()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("deleteClientCred: unexpected status code for client deletion: %d", resp.StatusCode)
	}

	return nil
}

func insertOrgClientCredential(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, name string, description string, orgNameOrID string, ad cdntypes.AuthData, kcClientManager *keycloakClientManager, clientCredAEAD cipher.AEAD) (cdntypes.NewOrgClientCredential, error) {
	var orgID, orgClientTokenID pgtype.UUID
	var clientID, clientSecret, registrationAccessToken string
	var clientRegistered bool

	if !ad.Superuser && ad.OrgID == nil {
		return cdntypes.NewOrgClientCredential{}, cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(dbCtx, tx, orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnprocessable
		}

		// A normal user must supply an org id for an org they are
		// a member of
		if !ad.Superuser && *ad.OrgID != orgIdent.id {
			return cdnerrors.ErrForbidden
		}

		orgID = orgIdent.id

		var clientTokenQuota int64
		// Verify we are not hitting the limit of how many client tokens the
		// org allows, do "FOR UPDATE" to lock out any concurrently
		// running function until we are done with counting rows.
		err = tx.QueryRow(dbCtx, "SELECT client_token_quota FROM orgs WHERE id=$1 FOR UPDATE", orgIdent.id).Scan(&clientTokenQuota)
		if err != nil {
			return err
		}

		var numClientTokens int64
		err = tx.QueryRow(dbCtx, "SELECT COUNT(*) FROM org_keycloak_client_credentials WHERE org_id=$1", orgIdent.id).Scan(&numClientTokens)
		if err != nil {
			return err
		}

		if numClientTokens >= clientTokenQuota {
			logger.Error().Int64("num_client_tokens", numClientTokens).Int64("client_token_quota", clientTokenQuota).Msg("unable to create additional credential as quota has been reached")
			return cdnerrors.ErrOrgClientTokenQuotaHit
		}

		// Mostly the "id" in our database is an UUIDv4 generated for us
		// by the database via "DEFAULT gen_random_uuid()", but in this
		// case since we want to reuse our "id" value in the
		// "client_id" used in keycloak (e.g. sunet-cdn-org-client-<uuid>) instead
		// generate it ourselves here.
		tokenUUID, err := uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("unable to generate UUID: %w", err)
		}

		clientID = fmt.Sprintf("sunet-cdn-org-client-%s", tokenUUID)

		// Doing network operations inside transactions is not optimal
		// but this way the database contents are rolled back if the
		// keycloak operation fails.
		_, clientSecret, registrationAccessToken, err = kcClientManager.createClientCred(clientID)
		if err != nil {
			return fmt.Errorf("unable to register keycloak client: %w", err)
		}

		clientRegistered = true

		// Encrypt client registration token prior to placing it in the database
		// Select a random nonce, and leave capacity for the ciphertext.
		nonce := make([]byte, clientCredAEAD.NonceSize(), clientCredAEAD.NonceSize()+len(registrationAccessToken)+clientCredAEAD.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("unable to create random nonce for client registration token: %w", err)
		}

		// Encrypt the registration access token and append the ciphertext to the nonce.
		// Include UUID of the table row as additional data so we fail
		// to decrypt it if the ciphertext has somehow been moved to
		// another row.
		cryptRegistrationAccessToken := clientCredAEAD.Seal(nonce, nonce, []byte(registrationAccessToken), tokenUUID[:])

		err = tx.QueryRow(dbCtx, "INSERT INTO org_keycloak_client_credentials (id, org_id, role_id, name, client_id, description, crypt_registration_access_token) VALUES ($1, $2, (SELECT id from roles WHERE name=$3), $4, $5, $6, $7) RETURNING id", tokenUUID, orgIdent.id, "user", name, clientID, description, cryptRegistrationAccessToken).Scan(&orgClientTokenID)
		if err != nil {
			return fmt.Errorf("unable to INSERT org keycloak client token: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("insertOrgClientCredential transaction failed")
		if clientRegistered {
			logger.Info().Msgf("operation failed after client was successfully registered, cleanup orphaned client: %s", clientID)
			err = kcClientManager.deleteClientCred(clientID, registrationAccessToken)
			if err != nil {
				logger.Err(err).Msgf("unable to cleanup orphaned client credential from keycloak service, client ID: %s", clientID)
			}
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return cdntypes.NewOrgClientCredential{}, cdnerrors.ErrAlreadyExists
			}
		}
		return cdntypes.NewOrgClientCredential{}, fmt.Errorf("insertOrgClientCredential transaction failed: %w", err)
	}

	nocd := cdntypes.NewOrgClientCredential{
		OrgClientCredentialSafe: cdntypes.OrgClientCredentialSafe{
			ID:          orgClientTokenID,
			Name:        name,
			OrgID:       orgID,
			Description: description,
			ClientID:    clientID,
		},
		ClientSecret: clientSecret,
	}

	return nocd, nil
}

func deleteOrgClientCredential(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, clientCredAEADs []cipher.AEAD, ad cdntypes.AuthData, kccm *keycloakClientManager, orgNameOrID string, orgClientCredentialNameOrID string) (pgtype.UUID, error) {
	if !ad.Superuser && ad.OrgID == nil {
		return pgtype.UUID{}, cdnerrors.ErrNotFound
	}

	if len(clientCredAEADs) == 0 {
		logger.Error().Msg("deleteOrgClientCredential: no client credential AEADs configured")
		return pgtype.UUID{}, fmt.Errorf("no client credential AEADs configured")
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var orgClientCredentialID pgtype.UUID
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(dbCtx, tx, orgNameOrID)
			if err != nil {
				logger.Err(err).Msg("unable to look up org identifier")
				return cdnerrors.ErrUnprocessable
			}
			orgID = orgIdent.id
		}

		orgClientCredentialIdent, err := newOrgClientCredentialIdentifier(dbCtx, tx, orgClientCredentialNameOrID, orgID)
		if err != nil {
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				logger.Err(err).Msg("no such client credential identifier")
				return cdnerrors.ErrNotFound
			default:
				logger.Err(err).Msg("unable to look up org client credential identifier")
				return cdnerrors.ErrUnprocessable
			}
		}

		// A normal user can only delete a org client credential belonging to the
		// same org they are a member of
		if !ad.Superuser && *ad.OrgID != orgClientCredentialIdent.orgID {
			return cdnerrors.ErrNotFound
		}

		var clientID string
		var cryptRegistrationAccessToken []byte
		err = tx.QueryRow(dbCtx, "DELETE FROM org_keycloak_client_credentials WHERE id = $1 RETURNING id, client_id, crypt_registration_access_token", orgClientCredentialIdent.id).Scan(&orgClientCredentialID, &clientID, &cryptRegistrationAccessToken)
		if err != nil {
			return fmt.Errorf("unable to DELETE org client credential: %w", err)
		}

		// Since we expect all AEADs to be of the same type, just compare nonce
		// size of the first one even if it is not the one used for
		// encrypting this specific ciphertext.
		if len(cryptRegistrationAccessToken) < clientCredAEADs[0].NonceSize() {
			return errors.New("deleteOrgClientCredential: ciphertext too short")
		}

		// Split nonce and ciphertext. Same here: all AEADs are the
		// same type, so just use the first entry for fetching the
		// nonce size
		nonce, ciphertext := cryptRegistrationAccessToken[:clientCredAEADs[0].NonceSize()], cryptRegistrationAccessToken[clientCredAEADs[0].NonceSize():]

		// Decrypt the message and check it wasn't tampered with potentially trying all configured encryption passwords.
		var registrationAccessToken []byte
		decryptionSuccessful := false

		// We expect the last password in the encryption password list
		// to be used for encrypting new values, so check the list
		// backwards when doing decryption.
		for i := len(clientCredAEADs) - 1; i >= 0; i-- {
			registrationAccessToken, err = clientCredAEADs[i].Open(nil, nonce, ciphertext, orgClientCredentialID.Bytes[:])
			if err != nil {
				logger.Debug().Err(err).Int("key_offset", i).Msg("deleteOrgClientCredential: unable to decrypt registration access token with offset")
				continue
			}
			decryptionSuccessful = true
			break
		}
		if !decryptionSuccessful {
			// We expect err to be set to the last err seen in decryption here
			return fmt.Errorf("deleteOrgClientCredential: unable to decrypt registration access token: %w", err)
		}

		// It is not great to perform network calls inside database
		// transaction but if the request fails we probably want to
		// roll back the DELETE so we do not get orphaned clients in
		// keycloak
		err = kccm.deleteClientCred(clientID, string(registrationAccessToken))
		if err != nil {
			return fmt.Errorf("unable to delete org client credential from keycloak service: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("deleteOrgClientCredential transaction failed")
		return pgtype.UUID{}, fmt.Errorf("deleteOrgClientCredential transaction failed: %w", err)
	}

	return orgClientCredentialID, nil
}

func reEncryptOrgClientCredentials(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, ad cdntypes.AuthData, clientCredAEADs []cipher.AEAD) (cdntypes.OrgClientRegistrationTokenReEncryptResult, error) {
	if !ad.Superuser {
		return cdntypes.OrgClientRegistrationTokenReEncryptResult{}, cdnerrors.ErrForbidden
	}

	// We can only attempt reencryption if there is at least two encryption passwords in the config file
	if len(clientCredAEADs) < 2 {
		return cdntypes.OrgClientRegistrationTokenReEncryptResult{}, cdnerrors.ErrReEncryptionMissingPassword
	}

	// Use custom timeout here rather than calling dbc.detachedContext()
	// since it might take longer
	dbCtx, cancel := dbc.detachedContextWithDuration(ctx, time.Minute*2)
	defer cancel()

	// We use the last encryption password in the configuration file for
	// encryption
	encryptionClientCredAEAD := clientCredAEADs[len(clientCredAEADs)-1]

	reEncryptRes := cdntypes.OrgClientRegistrationTokenReEncryptResult{}

	type cryptToken struct {
		id    pgtype.UUID
		crypt []byte
	}

	startTime := time.Now()
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		// Fetch all registration access tokens and related id so we
		// can attempt reencryption (the id is needed as well since we
		// use that for additional data). Do FOR UPDATE to lock out
		// concurrent modifications to the data until this transaction
		// is complete.

		var cryptoTokens []cryptToken
		rows, err := tx.Query(dbCtx, "SELECT id, crypt_registration_access_token FROM org_keycloak_client_credentials ORDER BY id FOR UPDATE")
		if err != nil {
			return fmt.Errorf("failed selecting encrypted registration tokens: %w", err)
		}

		{
			// Scope temporary id/cryptRegistrationAccessToken
			// so we dont accidentally use them further down when
			// we iterate over cryptoTokens.
			var id pgtype.UUID
			var cryptRegistrationAccessToken []byte
			_, err = pgx.ForEachRow(rows, []any{&id, &cryptRegistrationAccessToken}, func() error {
				cryptoTokens = append(cryptoTokens, cryptToken{id: id, crypt: cryptRegistrationAccessToken})
				return nil
			})
			if err != nil {
				return fmt.Errorf("failed iterating over registration tokens: %w", err)
			}
		}

		reEncryptRes.TotalTokens = int64(len(cryptoTokens))
		for _, ct := range cryptoTokens {
			// Since we expect all AEADs to be of the same type, just compare nonce
			// size of the first one even if it is not the one used for
			// encrypting this specific ciphertext.
			if len(ct.crypt) < clientCredAEADs[0].NonceSize() {
				logger.Error().
					Str("id", ct.id.String()).
					Int("token_length", len(ct.crypt)).
					Int("required_nonce_size", clientCredAEADs[0].NonceSize()).
					Msg("reEncryptOrgClientCredentials: cryptRegistrationAccessToken too short to contain nonce")
				reEncryptRes.FailedTokens++
				continue
			}

			// Split nonce and ciphertext. Same here: all AEADs are the
			// same type, so just use the first entry for fetching the
			// nonce size
			oldNonce, oldCiphertext := ct.crypt[:clientCredAEADs[0].NonceSize()], ct.crypt[clientCredAEADs[0].NonceSize():]

			// As the goal is to reencrypt with the last password
			// in the list, keep track of what offset that is so we
			// can tell if a value is already encrypted with that
			// one, in that case we do not need to encrypt again.
			latestPasswordOffset := len(clientCredAEADs) - 1

			// We expect the last password in the encryption password list
			// to be used for encrypting new values, so check the list
			// backwards when doing decryption to hopefully skip
			// unnecessary decryption work.
			decryptionSuccessful := false
			var registrationAccessTokenBytes []byte
			successfulOffset := 0
			var lastErr error
			for i := latestPasswordOffset; i >= 0; i-- {
				registrationAccessTokenBytes, err = clientCredAEADs[i].Open(nil, oldNonce, oldCiphertext, ct.id.Bytes[:])
				if err != nil {
					logger.Debug().Err(err).Str("id", ct.id.String()).Int("password_offset", i).Msg("reEncryptOrgClientCredentials: unable to decrypt registration access token")
					lastErr = err
					continue
				}
				decryptionSuccessful = true
				successfulOffset = i
				break
			}
			if !decryptionSuccessful {
				logger.Err(lastErr).Str("id", ct.id.String()).Msg("reEncryptOrgClientCredentials: unable to decrypt registration access token with any available encryption passwords")
				reEncryptRes.FailedTokens++
				continue
			}

			if successfulOffset == latestPasswordOffset {
				logger.Info().Str("id", ct.id.String()).Msg("token already encrypted with latest password")
				reEncryptRes.SkippedTokens++
				continue
			}

			// Select a new random nonce so we don't accidentally reuse nonce+key more than once
			newNonce := make([]byte, encryptionClientCredAEAD.NonceSize(), encryptionClientCredAEAD.NonceSize()+len(registrationAccessTokenBytes)+encryptionClientCredAEAD.Overhead())
			if _, err := rand.Read(newNonce); err != nil {
				return fmt.Errorf("unable to create new random nonce for client registration token re-encryption: %w", err)
			}

			newCryptRegistrationAccessToken := encryptionClientCredAEAD.Seal(newNonce, newNonce, registrationAccessTokenBytes, ct.id.Bytes[:])

			_, err = tx.Exec(dbCtx, "UPDATE org_keycloak_client_credentials SET crypt_registration_access_token = $1 WHERE id = $2", newCryptRegistrationAccessToken, ct.id)
			if err != nil {
				return fmt.Errorf("unable to UPDATE org keycloak client token: %w", err)
			}

			reEncryptRes.UpdatedTokens++
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("reEncryptOrgClientCredentials transaction failed")
		return cdntypes.OrgClientRegistrationTokenReEncryptResult{}, fmt.Errorf("reEncryptOrgClientCredentials transaction failed: %w", err)
	}
	reEncryptRes.Duration = time.Since(startTime)

	if reEncryptRes.FailedTokens != 0 {
		return reEncryptRes, cdnerrors.ErrReEncryptionFailed
	}

	return reEncryptRes, nil
}

func insertOrg(ctx context.Context, dbc *dbConn, name string, ad cdntypes.AuthData) (pgtype.UUID, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return pgtype.UUID{}, cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := dbc.dbPool.QueryRow(dbCtx, "INSERT INTO orgs (name) VALUES ($1) RETURNING id", name).Scan(&id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT organization: %w", err)
	}

	return id, nil
}

func selectServices(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, orgNameOrID string) ([]cdntypes.Service, error) {
	var services []cdntypes.Service
	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var err error
		var orgIdent orgIdentifier
		var lookupOrg pgtype.UUID

		// Must be either superuser or member of an org
		if !ad.Superuser && ad.OrgID == nil {
			return cdnerrors.ErrForbidden
		}

		if orgNameOrID != "" {
			orgIdent, err = newOrgIdentifier(ctx, tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}

			lookupOrg = orgIdent.id
		}

		// If not superuser and a specific org is requested the user is
		// only allowed to request it if they are member of the same org
		if !ad.Superuser && lookupOrg.Valid {
			if lookupOrg != *ad.OrgID {
				return cdnerrors.ErrForbidden
			}
		}

		// If not superuser and a specific org was not requested, set
		// it to the org of the user.
		if !ad.Superuser && !lookupOrg.Valid {
			lookupOrg = *ad.OrgID
		}

		var rows pgx.Rows
		if lookupOrg.Valid {
			rows, err = tx.Query(ctx, "SELECT services.id, services.org_id, services.name, lower(services.uid_range) AS uid_range_first, upper(services.uid_range)-1 AS uid_range_last, orgs.name AS org_name FROM services JOIN orgs ON services.org_id = orgs.id WHERE services.org_id=$1 ORDER BY services.time_created", lookupOrg)
			if err != nil {
				return fmt.Errorf("unable to query for services for specific org: %w", err)
			}
		} else {
			rows, err = tx.Query(ctx, "SELECT services.id, services.org_id, services.name, lower(services.uid_range) AS uid_range_first, upper(services.uid_range)-1 AS uid_range_last, orgs.name AS org_name FROM services JOIN orgs ON services.org_id = orgs.id ORDER BY services.time_created")
			if err != nil {
				return fmt.Errorf("unable to query for all services: %w", err)
			}
		}

		services, err = pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.Service])
		if err != nil {
			return fmt.Errorf("unable to CollectRows for services: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("selectServices: transaction failed: %w", err)
	}

	return services, nil
}

func selectService(ctx context.Context, dbc *dbConn, orgNameOrID string, serviceNameOrID string, ad cdntypes.AuthData) (cdntypes.Service, error) {
	s := cdntypes.Service{}

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var serviceIdent serviceIdentifier
		var err error

		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		// Looking up a service by ID works without supplying an org,
		// for looking up service by name an org must be included
		serviceIdent, err = newServiceIdentifier(ctx, tx, serviceNameOrID, orgID)
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
		return cdntypes.Service{}, fmt.Errorf("selectService: transaction failed: %w", err)
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

type cacheNodeIdentifier struct {
	resourceIdentifier
}

type l4lbNodeIdentifier struct {
	resourceIdentifier
}

type nodeGroupIdentifier struct {
	resourceIdentifier
}

type domainIdentifier struct {
	resourceIdentifier
	orgID pgtype.UUID
}

type originGroupIdentifier struct {
	resourceIdentifier
	serviceID pgtype.UUID
}

type orgClientCredentialIdentifier struct {
	resourceIdentifier
	orgID pgtype.UUID
}

var errEmptyInputIdentifier = errors.New("input identifier is empty")

func newOrgIdentifier(ctx context.Context, tx pgx.Tx, input string) (orgIdentifier, error) {
	if input == "" {
		return orgIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name FROM orgs WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return orgIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (org names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name FROM orgs WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
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

func newServiceIdentifier(ctx context.Context, tx pgx.Tx, input string, inputOrgID pgtype.UUID) (serviceIdentifier, error) {
	if input == "" {
		return serviceIdentifier{}, errEmptyInputIdentifier
	}

	var id, orgID pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id FROM services WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &orgID)
		if err != nil {
			return serviceIdentifier{}, err
		}
	} else {
		if !inputOrgID.Valid {
			return serviceIdentifier{}, cdnerrors.ErrServiceByNameNeedsOrg
		}
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (service names are only unique per org)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id FROM services WHERE name = $1 and org_id = $2 FOR SHARE", input, inputOrgID).Scan(&id, &name, &orgID)
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

func newRoleIdentifier(ctx context.Context, tx pgx.Tx, input string) (roleIdentifier, error) {
	if input == "" {
		return roleIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name FROM roles WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return roleIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (role names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name FROM roles WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
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

func isUUID(input string) bool {
	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	return err == nil
}

func newUserIdentifier(ctx context.Context, tx pgx.Tx, input string) (userIdentifier, error) {
	if input == "" {
		return userIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var orgID *pgtype.UUID
	var roleID pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id, role_id FROM users WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &orgID, &roleID)
		if err != nil {
			return userIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (org names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id, role_id FROM users WHERE name = $1 FOR SHARE", input).Scan(&id, &name, &orgID, &roleID)
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

func newCacheNodeIdentifier(ctx context.Context, tx pgx.Tx, input string) (cacheNodeIdentifier, error) {
	if input == "" {
		return cacheNodeIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name FROM cache_nodes WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return cacheNodeIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (cache node names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name FROM cache_nodes WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
		if err != nil {
			return cacheNodeIdentifier{}, err
		}
	}

	return cacheNodeIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
	}, nil
}

func newL4LBNodeIdentifier(ctx context.Context, tx pgx.Tx, input string) (l4lbNodeIdentifier, error) {
	if input == "" {
		return l4lbNodeIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name FROM l4lb_nodes WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return l4lbNodeIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (l4lb node names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name FROM l4lb_nodes WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
		if err != nil {
			return l4lbNodeIdentifier{}, err
		}
	}

	return l4lbNodeIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
	}, nil
}

func newNodeGroupIdentifier(ctx context.Context, tx pgx.Tx, input string) (nodeGroupIdentifier, error) {
	if input == "" {
		return nodeGroupIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name FROM node_groups WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name)
		if err != nil {
			return nodeGroupIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (node group names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name FROM node_groups WHERE name = $1 FOR SHARE", input).Scan(&id, &name)
		if err != nil {
			return nodeGroupIdentifier{}, err
		}
	}

	return nodeGroupIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
	}, nil
}

func newDomainIdentifier(ctx context.Context, tx pgx.Tx, input string) (domainIdentifier, error) {
	if input == "" {
		return domainIdentifier{}, errEmptyInputIdentifier
	}

	var id pgtype.UUID
	var name string
	var orgID pgtype.UUID

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id FROM domains WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &orgID)
		if err != nil {
			return domainIdentifier{}, err
		}
	} else {
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (domain names are globally unique)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id FROM domains WHERE name = $1 FOR SHARE", input).Scan(&id, &name, &orgID)
		if err != nil {
			return domainIdentifier{}, err
		}
	}

	return domainIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
		orgID: orgID,
	}, nil
}

func newOriginGroupIdentifier(ctx context.Context, tx pgx.Tx, input string, inputServiceID pgtype.UUID) (originGroupIdentifier, error) {
	if input == "" {
		return originGroupIdentifier{}, errEmptyInputIdentifier
	}

	var id, serviceID pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name, service_id FROM service_origin_groups WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &serviceID)
		if err != nil {
			return originGroupIdentifier{}, err
		}
	} else {
		if !inputServiceID.Valid {
			return originGroupIdentifier{}, cdnerrors.ErrOriginGroupByNameNeedsService
		}
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (origin group names are only unique per service)
		err := tx.QueryRow(ctx, "SELECT id, name, service_id FROM service_origin_groups WHERE name = $1 and service_id = $2 FOR SHARE", input, inputServiceID).Scan(&id, &name, &serviceID)
		if err != nil {
			return originGroupIdentifier{}, err
		}
	}

	return originGroupIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
		serviceID: serviceID,
	}, nil
}

func newOrgClientCredentialIdentifier(ctx context.Context, tx pgx.Tx, input string, inputOrgID pgtype.UUID) (orgClientCredentialIdentifier, error) {
	if input == "" {
		return orgClientCredentialIdentifier{}, errEmptyInputIdentifier
	}

	var id, orgID pgtype.UUID
	var name string

	inputID := new(pgtype.UUID)
	err := inputID.Scan(input)
	if err == nil {
		// This is a valid UUID, treat it as an ID and collect the name (also verifying the id exists in the process)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id FROM org_keycloak_client_credentials WHERE id = $1 FOR SHARE", *inputID).Scan(&id, &name, &orgID)
		if err != nil {
			return orgClientCredentialIdentifier{}, err
		}
	} else {
		if !inputOrgID.Valid {
			return orgClientCredentialIdentifier{}, cdnerrors.ErrUnprocessable
		}
		// This is not a valid UUID, treat it as a name and validate it by mapping it to an ID (org client credential names are only unique per org)
		err := tx.QueryRow(ctx, "SELECT id, name, org_id FROM org_keycloak_client_credentials WHERE name = $1 and org_id = $2 FOR SHARE", input, inputOrgID).Scan(&id, &name, &orgID)
		if err != nil {
			return orgClientCredentialIdentifier{}, err
		}
	}

	return orgClientCredentialIdentifier{
		resourceIdentifier: resourceIdentifier{
			name: name,
			id:   id,
		},
		orgID: orgID,
	}, nil
}

type serviceIPAddr struct {
	networkID pgtype.UUID
	Address   netip.Addr
}

func allocateServiceIPs(ctx context.Context, tx pgx.Tx, serviceID pgtype.UUID, requestedV4 int, requestedV6 int) ([]serviceIPAddr, error) {
	if requestedV4 == 0 && requestedV6 == 0 {
		return nil, errors.New("must allocate at least one address")
	}

	// Get available networks, order by network, FOR UPDATE to lock out
	// any concurrently runnnig allocateServiceIPs() from allocating addresses at
	// the same time.
	rows, err := tx.Query(ctx, "SELECT id, network FROM ip_networks ORDER BY network FOR UPDATE")
	if err != nil {
		return nil, fmt.Errorf("unable to query for networks: %w", err)
	}

	ipNetworks, err := pgx.CollectRows(rows, pgx.RowToStructByName[ipNetwork])
	if err != nil {
		return nil, fmt.Errorf("unable to collect rows for networks: %w", err)
	}

	// Collect all currently used addresses, FOR SHARE since we probably
	// dont want anyone changing these during allocation as well.
	rows, err = tx.Query(ctx, "SELECT address FROM service_ip_addresses ORDER BY address FOR SHARE")
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

		// Iterate over all addresses of the network, including network
		// and broadcast address since that does not matter when using
		// these as /32 or /128 routing announcements.
		if ipNet.Network.Addr().Is4() && len(allocatedV4) < requestedV4 {
			for a := r.From(); a != r.To().Next(); a = a.Next() {
				if !usedAddrSet.Contains(a) {
					allocatedV4 = append(allocatedV4, serviceIPAddr{networkID: ipNet.ID, Address: a})
				}

				if len(allocatedV4) == requestedV4 {
					break
				}
			}
		}

		if ipNet.Network.Addr().Is6() && len(allocatedV6) < requestedV6 {
			for a := r.From(); a != r.To().Next(); a = a.Next() {
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
		err = tx.QueryRow(ctx, "INSERT INTO service_ip_addresses (service_id, network_id, address) VALUES ($1, $2, $3) returning id", serviceID, allocIP.networkID, allocIP.Address).Scan(&serviceIPID)
		if err != nil {
			return nil, fmt.Errorf("unable to insert ip %s into service_ip_addresses: %w", allocIP.Address, err)
		}
	}

	return allocatedIPs, nil
}

func insertOriginGroup(ctx context.Context, logger *zerolog.Logger, ad cdntypes.AuthData, dbc *dbConn, serviceNameOrID string, orgNameOrID string, name string) (cdntypes.OriginGroup, error) {
	if !ad.Superuser {
		if ad.OrgID == nil {
			logger.Error().Msg("insertOriginGroup: not superuser or member of an org")
			return cdntypes.OriginGroup{}, cdnerrors.ErrForbidden
		}
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var originGroup cdntypes.OriginGroup
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(dbCtx, tx, orgNameOrID)
		if err != nil {
			logger.Err(err).Msg("looking up org failed")
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(dbCtx, tx, serviceNameOrID, orgIdent.id)
		if err != nil {
			logger.Err(err).Msg("unable to validate org id")
			return cdnerrors.ErrUnprocessable
		}

		// If the user is not a superuser they must belong to the same
		// org as the service they are trying to add a version to
		if !ad.Superuser {
			if *ad.OrgID != serviceIdent.orgID {
				return cdnerrors.ErrForbidden
			}
		}

		// We explicitly do not support changing the default origin
		// group as this could affect the configuration of already
		// existing service versions.
		defaultGroup := false
		originGroupID, err := insertOriginGroupTx(dbCtx, tx, serviceIdent.id, defaultGroup, name)
		if err != nil {
			return fmt.Errorf("insertOriginGroup: unable to create default origin group: %w", err)
		}

		originGroup.ID = originGroupID
		originGroup.Name = name
		originGroup.DefaultGroup = defaultGroup

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("insertOriginGroup transaction failed")
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return cdntypes.OriginGroup{}, cdnerrors.ErrAlreadyExists
			}
		}
		return cdntypes.OriginGroup{}, fmt.Errorf("insertOriginGroup transaction failed: %w", err)
	}

	return originGroup, nil
}

func insertOriginGroupTx(ctx context.Context, tx pgx.Tx, serviceID pgtype.UUID, defaultGroup bool, name string) (pgtype.UUID, error) {
	// As default origin groups affects the content of configuration for
	// already saved service versions we do not support changing the
	// default origin group.
	var originGroupID pgtype.UUID
	err := tx.QueryRow(ctx, "INSERT INTO service_origin_groups (service_id, default_group, name) VALUES ($1, $2, $3) returning id", serviceID, defaultGroup, name).Scan(&originGroupID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return pgtype.UUID{}, cdnerrors.ErrAlreadyExists
			}
		}
		return pgtype.UUID{}, fmt.Errorf("unable to insert origin group %s into service_origin_groups: %w", name, err)
	}
	return originGroupID, nil
}

func selectOriginGroups(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, serviceNameOrID string, orgNameOrID string) ([]cdntypes.OriginGroup, error) {
	originGroups := []cdntypes.OriginGroup{}
	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		// Looking up a service by ID works without supplying an org,
		// for looking up service by name an org must be included
		serviceIdent, err := newServiceIdentifier(ctx, tx, serviceNameOrID, orgID)
		if err != nil {
			return fmt.Errorf("looking up service identifier failed: %w", err)
		}

		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != serviceIdent.orgID) {
			return cdnerrors.ErrForbidden
		}

		originGroups, err = selectOriginGroupsTx(ctx, tx, serviceIdent.id)
		if err != nil {
			return fmt.Errorf("unable to collect origin group rows: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("selectOriginGroups: transaction failed: %w", err)
	}

	return originGroups, nil
}

func selectOriginGroupsTx(ctx context.Context, tx pgx.Tx, serviceID pgtype.UUID) ([]cdntypes.OriginGroup, error) {
	rows, err := tx.Query(
		ctx,
		"SELECT id, default_group, name FROM service_origin_groups WHERE service_id = $1 ORDER BY name",
		serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to select origin group rows: %w", err)
	}

	originGroups, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.OriginGroup])
	if err != nil {
		return nil, fmt.Errorf("unable to collect origin group rows: %w", err)
	}

	return originGroups, nil
}

func selectNodeGroups(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData) ([]cdntypes.NodeGroup, error) {
	if !ad.Superuser {
		return nil, cdnerrors.ErrForbidden
	}

	nodeGroups := []cdntypes.NodeGroup{}
	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var err error
		nodeGroups, err = selectNodeGroupsTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("selectNodeGroups: unable to collect node group rows: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("selectNodeGroups: transaction failed: %w", err)
	}

	return nodeGroups, nil
}

func selectNodeGroupsTx(ctx context.Context, tx pgx.Tx) ([]cdntypes.NodeGroup, error) {
	rows, err := tx.Query(
		ctx,
		"SELECT id, name, description FROM node_groups ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("selectNodeGroupsTx: unable to select node group rows: %w", err)
	}

	nodeGroups, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.NodeGroup])
	if err != nil {
		return nil, fmt.Errorf("selectNodeGroupsTx: unable to collect node group rows: %w", err)
	}

	return nodeGroups, nil
}

func insertNodeGroup(ctx context.Context, logger *zerolog.Logger, ad cdntypes.AuthData, dbc *dbConn, name string, description string) (cdntypes.NodeGroup, error) {
	if !ad.Superuser {
		logger.Error().Msg("insertNodeGroup: not superuser")
		return cdntypes.NodeGroup{}, cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var nodeGroup cdntypes.NodeGroup
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		nodeGroupID, err := insertNodeGroupTx(dbCtx, tx, name, description)
		if err != nil {
			return fmt.Errorf("insertNodeGroup: unable to create node group: %w", err)
		}

		nodeGroup.ID = nodeGroupID
		nodeGroup.Name = name
		nodeGroup.Description = description

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("insertNodeGroup transaction failed")
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return cdntypes.NodeGroup{}, cdnerrors.ErrAlreadyExists
			}
		}
		return cdntypes.NodeGroup{}, fmt.Errorf("insertNodeGroup transaction failed: %w", err)
	}

	return nodeGroup, nil
}

func insertNodeGroupTx(ctx context.Context, tx pgx.Tx, name string, description string) (pgtype.UUID, error) {
	var nodeGroupID pgtype.UUID
	err := tx.QueryRow(ctx, "INSERT INTO node_groups (name, description) VALUES ($1, $2) returning id", name, description).Scan(&nodeGroupID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return pgtype.UUID{}, cdnerrors.ErrAlreadyExists
			}
		}
		return pgtype.UUID{}, fmt.Errorf("unable to insert node group %s into node_groups: %w", name, err)
	}
	return nodeGroupID, nil
}

func insertDomain(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, name string, orgNameOrID *string, ad cdntypes.AuthData) (cdntypes.Domain, error) {
	var domainID pgtype.UUID
	var verificationToken string

	// Cleanup any trailing "." in domain name
	name = strings.TrimRight(name, ".")

	var orgIdent orgIdentifier
	var err error

	if !ad.Superuser && ad.OrgID == nil {
		return cdntypes.Domain{}, cdnerrors.ErrForbidden
	}

	if orgNameOrID == nil {
		return cdntypes.Domain{}, cdnerrors.ErrUnprocessable
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err = newOrgIdentifier(dbCtx, tx, *orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnprocessable
		}

		// A normal user must supply an org id for an org they are
		// a member of
		if !ad.Superuser && *ad.OrgID != orgIdent.id {
			return cdnerrors.ErrForbidden
		}

		var domainQuota int64
		// Verify we are not hitting the limit of how many domains the
		// org allows, do "FOR UPDATE" to lock out any concurrently
		// running function until we are done with counting rows.
		err = tx.QueryRow(dbCtx, "SELECT domain_quota FROM orgs WHERE id=$1 FOR UPDATE", orgIdent.id).Scan(&domainQuota)
		if err != nil {
			return err
		}

		var numDomains int64
		err = tx.QueryRow(dbCtx, "SELECT COUNT(*) FROM domains WHERE org_id=$1", orgIdent.id).Scan(&numDomains)
		if err != nil {
			return err
		}

		if numDomains >= domainQuota {
			logger.Error().Int64("num_domains", numDomains).Int64("domain_quota", domainQuota).Msg("unable to create additional domain as quota has been reached")
			return cdnerrors.ErrDomainQuotaHit
		}

		// Generate verification token, just reuse our password generation function for now
		verificationToken, err = generatePassword(40)
		if err != nil {
			return fmt.Errorf("failed generating verification token: %w", err)
		}

		err = tx.QueryRow(dbCtx, "INSERT INTO domains (name, verification_token, org_id) VALUES ($1, $2, $3) RETURNING id", name, verificationToken, orgIdent.id).Scan(&domainID)
		if err != nil {
			return fmt.Errorf("unable to INSERT domain: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("insertDomain transaction failed")
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgUniqueViolation {
				return cdntypes.Domain{}, cdnerrors.ErrAlreadyExists
			}
		}
		return cdntypes.Domain{}, fmt.Errorf("insertDomain transaction failed: %w", err)
	}

	d := cdntypes.Domain{
		ID:                domainID,
		Name:              name,
		Verified:          false,
		VerificationToken: verificationToken,
	}

	return d, nil
}

func insertService(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, name string, orgNameOrID *string, ad cdntypes.AuthData) (pgtype.UUID, error) {
	var serviceID pgtype.UUID

	var orgIdent orgIdentifier
	var err error

	if !ad.Superuser && ad.OrgID == nil {
		logger.Error().Msg("insertService: not superuser or member of an org")
		return pgtype.UUID{}, cdnerrors.ErrForbidden
	}

	if orgNameOrID == nil {
		logger.Error().Msg("insertService: missing orgNameOrID")
		return pgtype.UUID{}, cdnerrors.ErrUnprocessable
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err = newOrgIdentifier(dbCtx, tx, *orgNameOrID)
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
		err = tx.QueryRow(dbCtx, "SELECT service_quota FROM orgs WHERE id=$1 FOR UPDATE", orgIdent.id).Scan(&serviceQuota)
		if err != nil {
			return err
		}

		var numServices int64
		err = tx.QueryRow(dbCtx, "SELECT COUNT(*) FROM services WHERE org_id=$1", orgIdent.id).Scan(&numServices)
		if err != nil {
			return err
		}

		if numServices >= serviceQuota {
			logger.Error().Int64("num_services", numServices).Int64("service_quota", serviceQuota).Msg("unable to create additional service as quota has been reached")
			return cdnerrors.ErrServiceQuotaHit
		}

		// Figure out the next available uid range (or default to
		// 1000010000-1000019999 for the first created service). This
		// SELECT is protected by the FOR UPDATE select above, so is
		// safe from concurrent service creation.
		var uidRange pgtype.Range[pgtype.Int8]
		err = tx.QueryRow(dbCtx, "SELECT COALESCE((SELECT int8range(upper(uid_range), upper(uid_range)+10000) FROM services ORDER BY uid_range DESC LIMIT 1), int8range(1000010000, 1000020000))").Scan(&uidRange)
		if err != nil {
			return err
		}

		err = tx.QueryRow(dbCtx, "INSERT INTO services (name, org_id, uid_range) VALUES ($1, $2, $3) RETURNING id", name, orgIdent.id, uidRange).Scan(&serviceID)
		if err != nil {
			return fmt.Errorf("unable to INSERT service: %w", err)
		}

		// Allocate 1 IPv4 and 1 IPv6 address for the service
		_, err := allocateServiceIPs(dbCtx, tx, serviceID, 1, 1)
		if err != nil {
			return fmt.Errorf("unable to allocate service IPs: %w", err)
		}

		// Create a default origin group, this is the only time it is valid to make it the default group
		_, err = insertOriginGroupTx(dbCtx, tx, serviceID, true, "default")
		if err != nil {
			return fmt.Errorf("insertService: unable to create default origin group: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Err(err).Msg("insertService transaction failed")
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

func deleteService(ctx context.Context, logger *zerolog.Logger, dbc *dbConn, orgNameOrID string, serviceNameOrID string, ad cdntypes.AuthData) (pgtype.UUID, error) {
	if !ad.Superuser && ad.OrgID == nil {
		return pgtype.UUID{}, cdnerrors.ErrNotFound
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	var serviceID pgtype.UUID
	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(dbCtx, tx, orgNameOrID)
			if err != nil {
				logger.Err(err).Msg("unable to look up org identifier")
				return cdnerrors.ErrUnprocessable
			}
			orgID = orgIdent.id
		}

		serviceIdent, err := newServiceIdentifier(dbCtx, tx, serviceNameOrID, orgID)
		if err != nil {
			logger.Err(err).Msg("unable to look up service identifier")
			return cdnerrors.ErrUnprocessable
		}

		// A normal user can only delete a service belonging to the
		// same org they are a member of
		if !ad.Superuser && *ad.OrgID != serviceIdent.orgID {
			return cdnerrors.ErrNotFound
		}

		err = tx.QueryRow(dbCtx, "DELETE FROM services WHERE id = $1 RETURNING id", serviceIdent.id).Scan(&serviceID)
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

func getFirstV4Addr(addrs []netip.Addr) (netip.Addr, error) {
	for _, addr := range addrs {
		if addr.Is4() {
			return addr, nil
		}
	}

	return netip.Addr{}, errors.New("getFirstV4Addr: no IPv4 present")
}

func selectCacheNodeTx(ctx context.Context, tx pgx.Tx, cacheNodeID pgtype.UUID) (cdntypes.CacheNode, error) {
	rows, err := tx.Query(
		ctx,
		`SELECT
			cache_nodes.id,
			cache_nodes.name,
			cache_nodes.description,
			cache_nodes.maintenance,
			agg_addresses.addresses
		FROM cache_nodes
		JOIN (
			SELECT node_id, array_agg(address ORDER BY address) as addresses
			FROM cache_node_addresses
			GROUP BY node_id
		) AS agg_addresses ON agg_addresses.node_id = cache_nodes.id
		WHERE id = $1`,
		cacheNodeID,
	)
	if err != nil {
		return cdntypes.CacheNode{}, fmt.Errorf("selectCacheNode: unable to select cache node for id '%s': %w", cacheNodeID, err)
	}

	cacheNode, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[cdntypes.CacheNode])
	if err != nil {
		return cdntypes.CacheNode{}, fmt.Errorf("selectCacheNode: unable to collect l4lb node for id '%s': %w", cacheNodeID, err)
	}

	return cacheNode, nil
}

func selectCacheNodeConfig(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, confTemplates configTemplates, cacheNodeNameOrID string) (cdntypes.CacheNodeConfig, error) {
	if !ad.Superuser && ad.RoleName != "node" {
		return cdntypes.CacheNodeConfig{}, cdnerrors.ErrForbidden
	}

	if cacheNodeNameOrID == "" {
		return cdntypes.CacheNodeConfig{}, cdnerrors.ErrUnprocessable
	}

	// Usage of JOIN with subqueries based on
	// https://stackoverflow.com/questions/27622398/multiple-array-agg-calls-in-a-single-query
	rows, err := dbc.dbPool.Query(
		ctx,
		`SELECT
		       orgs.id AS org_id,
		       services.id AS service_id,
		       services.uid_range,
		       service_versions.id AS service_version_id,
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
		       agg_service_ip_addresses.service_ip_addresses,
		       agg_domains.domains,
		       agg_origins.origins,
		       agg_service_origin_groups.origin_groups
	       FROM
		       orgs
		       JOIN services ON orgs.id = services.org_id
		       JOIN service_versions ON services.id = service_versions.service_id
		       JOIN service_vcls ON service_versions.id = service_vcls.service_version_id
		       JOIN (
				SELECT service_id, array_agg(address ORDER BY address) as service_ip_addresses
				FROM service_ip_addresses
				GROUP BY service_id
			) AS agg_service_ip_addresses ON agg_service_ip_addresses.service_id = services.id
		       JOIN (
			       SELECT service_version_id, array_agg(domains.name ORDER BY domains.name) AS domains
			       FROM service_domains
			       JOIN domains ON service_domains.domain_id = domains.id
			       WHERE domains.verified = true
			       GROUP BY service_version_id
		       ) AS agg_domains ON agg_domains.service_version_id = service_versions.id
		       JOIN (
			       SELECT service_version_id, array_agg((origin_group_id, host, port, tls, verify_tls) ORDER BY host, port) AS origins
			       FROM service_origins
			       GROUP BY service_version_id
		       ) AS agg_origins ON agg_origins.service_version_id = service_versions.id
		       JOIN (
				SELECT service_id, array_agg((id, default_group, name) ORDER BY name) as origin_groups
				FROM service_origin_groups
				GROUP BY service_id
			) AS agg_service_origin_groups ON agg_service_origin_groups.service_id = services.id
	       ORDER BY orgs.name`,
	)
	if err != nil {
		return cdntypes.CacheNodeConfig{}, fmt.Errorf("unable to query for cache node config: %w", err)
	}

	cnc := cdntypes.CacheNodeConfig{
		Orgs: map[string]cdntypes.OrgWithServices{},
	}

	var orgID, serviceID, serviceVersionID pgtype.UUID
	var serviceIPAddresses []netip.Addr
	var serviceUIDRange pgtype.Range[pgtype.Int8]
	var serviceVersion int64
	var serviceVersionActive bool
	var vclRecv, vclPipe, vclPass, vclHash, vclPurge, vclMiss, vclHit, vclDeliver, vclSynth, vclBackendFetch, vclBackendResponse, vclBackendError *string
	var domains []cdntypes.DomainString
	var originGroups []cdntypes.OriginGroup
	var origins []cdntypes.Origin
	_, err = pgx.ForEachRow(
		rows,
		[]any{
			&orgID,
			&serviceID,
			&serviceUIDRange,
			&serviceVersionID,
			&serviceVersion,
			&serviceVersionActive,
			&vclRecv,
			&vclPipe,
			&vclPass,
			&vclHash,
			&vclPurge,
			&vclMiss,
			&vclHit,
			&vclDeliver,
			&vclSynth,
			&vclBackendFetch,
			&vclBackendResponse,
			&vclBackendError,
			&serviceIPAddresses,
			&domains,
			&origins,
			&originGroups,
		},
		func() error {
			if _, orgExists := cnc.Orgs[orgID.String()]; !orgExists {
				cnc.Orgs[orgID.String()] = cdntypes.OrgWithServices{
					ID:       orgID,
					Services: map[string]cdntypes.ServiceWithVersions{},
				}
			}

			if _, serviceExists := cnc.Orgs[orgID.String()].Services[serviceID.String()]; !serviceExists {
				cnc.Orgs[orgID.String()].Services[serviceID.String()] = cdntypes.ServiceWithVersions{
					ID:              serviceID,
					IPAddresses:     serviceIPAddresses,
					UIDRangeFirst:   serviceUIDRange.Lower.Int64,
					UIDRangeLast:    serviceUIDRange.Upper.Int64,
					ServiceVersions: map[int64]cdntypes.ServiceVersionWithConfig{},
				}
			}

			// We only expect to see a given service version once for a given service
			if _, serviceVersionExists := cnc.Orgs[orgID.String()].Services[serviceID.String()].ServiceVersions[serviceVersion]; serviceVersionExists {
				return fmt.Errorf("%s, %s: saw service version %d a second time, this is unpexpected", orgID, serviceID, serviceVersion)
			}

			vcl, err := generateCompleteVcl(
				confTemplates.vcl,
				serviceIPAddresses,
				originGroups,
				origins,
				domains,
				cdntypes.VclSteps{
					VclRecv:            vclRecv,
					VclPipe:            vclPipe,
					VclPass:            vclPass,
					VclHash:            vclHash,
					VclPurge:           vclPurge,
					VclMiss:            vclMiss,
					VclHit:             vclHit,
					VclDeliver:         vclDeliver,
					VclSynth:           vclSynth,
					VclBackendFetch:    vclBackendFetch,
					VclBackendResponse: vclBackendResponse,
					VclBackendError:    vclBackendError,
				})
			if err != nil {
				return fmt.Errorf("unable to generate VCL for cache node config: %w", err)
			}

			haProxyConf, err := generateCompleteHaProxyConf(confTemplates.haproxy, serviceIPAddresses, originGroups, origins)
			if err != nil {
				return fmt.Errorf("unable to generate haproxy conf for cache node config: %w", err)
			}

			tlsActive := false
			for _, origin := range origins {
				if origin.TLS {
					tlsActive = true
					break
				}
			}

			cnc.Orgs[orgID.String()].Services[serviceID.String()].ServiceVersions[serviceVersion] = cdntypes.ServiceVersionWithConfig{
				ID:            serviceVersionID,
				Version:       serviceVersion,
				Active:        serviceVersionActive,
				TLS:           tlsActive,
				Domains:       domains,
				VCL:           vcl,
				HAProxyConfig: haProxyConf,
			}

			return nil
		},
	)
	if err != nil {
		return cdntypes.CacheNodeConfig{}, fmt.Errorf("ForEachRow of cache node config failed: %w", err)
	}

	// Include what service networks have been added to the system so we
	// can create firewall rules on the cache nodes.
	rows, err = dbc.dbPool.Query(
		ctx,
		`SELECT network FROM ip_networks ORDER BY network`,
	)
	if err != nil {
		return cdntypes.CacheNodeConfig{}, fmt.Errorf("unable to query for networks for cache node config: %w", err)
	}

	cnc.IPNetworks, err = pgx.CollectRows(rows, pgx.RowTo[netip.Prefix])
	if err != nil {
		return cdntypes.CacheNodeConfig{}, fmt.Errorf("pgx.CollectRows of IP networks for cache node config failed: %w", err)
	}

	err = pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		cacheNodeIdent, err := newCacheNodeIdentifier(ctx, tx, cacheNodeNameOrID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		cnc.L4LBNodes, err = selectL4LBMembersForCacheNode(ctx, tx, cacheNodeIdent.id)
		if err != nil {
			return fmt.Errorf("selectCacheNodeConfig: unable to get L4LB members of same node group: %w", err)
		}

		cnc.CacheNode, err = selectCacheNodeTx(ctx, tx, cacheNodeIdent.id)
		if err != nil {
			return fmt.Errorf("selectCacheNodeConfig: unable to get cache node: %w", err)
		}

		return nil
	})
	if err != nil {
		return cdntypes.CacheNodeConfig{}, fmt.Errorf("selectCacheNodeConfig: transaction failed %w", err)
	}

	return cnc, nil
}

func selectL4LBMembersForCacheNode(ctx context.Context, tx pgx.Tx, cacheNodeID pgtype.UUID) ([]cdntypes.L4LBNode, error) {
	rows, err := tx.Query(
		ctx,
		`SELECT
			l4lb_nodes.id,
			l4lb_nodes.name,
			l4lb_nodes.description,
			l4lb_nodes.maintenance,
			agg_addresses.addresses
		FROM l4lb_nodes
		JOIN node_groups ON node_groups.id = l4lb_nodes.node_group_id
		JOIN (
			SELECT node_id, array_agg(address ORDER BY address) as addresses
			FROM l4lb_node_addresses
			GROUP BY node_id
		) AS agg_addresses ON agg_addresses.node_id = l4lb_nodes.id
		WHERE node_groups.id = (SELECT node_group_id FROM cache_nodes WHERE id = $1)
		ORDER BY l4lb_nodes.name
		`,
		cacheNodeID,
	)
	if err != nil {
		return nil, fmt.Errorf("selectL4LBMembersForCacheNode: unable to select l4lb nodes for cache node '%s': %w", cacheNodeID, err)
	}

	l4lbNodes, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.L4LBNode])
	if err != nil {
		return nil, fmt.Errorf("selectL4LBMembersForCacheNode unable to collect l4lb node groups: %w", err)
	}

	return l4lbNodes, nil
}

func selectCacheMembersForL4LBNode(ctx context.Context, tx pgx.Tx, l4lbNodeID pgtype.UUID) ([]cdntypes.CacheNode, error) {
	rows, err := tx.Query(
		ctx,
		`SELECT
				cache_nodes.id,
				cache_nodes.name,
				cache_nodes.description,
				cache_nodes.maintenance,
				agg_addresses.addresses
			FROM cache_nodes
			JOIN node_groups ON node_groups.id = cache_nodes.node_group_id
			JOIN (
				SELECT node_id, array_agg(address ORDER BY address) as addresses
				FROM cache_node_addresses
				GROUP BY node_id
			) AS agg_addresses ON agg_addresses.node_id = cache_nodes.id
			WHERE node_groups.id = (SELECT node_group_id FROM l4lb_nodes WHERE id = $1)
			ORDER BY cache_nodes.name
			`,
		l4lbNodeID,
	)
	if err != nil {
		return nil, fmt.Errorf("selectCacheMembersForL4LBNode: unable to select cache nodes for l4lb node '%s': %w", l4lbNodeID, err)
	}

	cacheNodes, err := pgx.CollectRows(rows, pgx.RowToStructByName[cdntypes.CacheNode])
	if err != nil {
		return nil, fmt.Errorf("selectCacheMembersForL4LBNode: unable to collect cache node groups: %w", err)
	}

	return cacheNodes, nil
}

func selectL4LBNodeTx(ctx context.Context, tx pgx.Tx, l4lbNodeID pgtype.UUID) (cdntypes.L4LBNode, error) {
	rows, err := tx.Query(
		ctx,
		`SELECT
			l4lb_nodes.id,
			l4lb_nodes.name,
			l4lb_nodes.description,
			l4lb_nodes.maintenance,
			agg_addresses.addresses
		FROM l4lb_nodes
		JOIN (
			SELECT node_id, array_agg(address ORDER BY address) as addresses
			FROM l4lb_node_addresses
			GROUP BY node_id
		) AS agg_addresses ON agg_addresses.node_id = l4lb_nodes.id
		WHERE id = $1`,
		l4lbNodeID,
	)
	if err != nil {
		return cdntypes.L4LBNode{}, fmt.Errorf("selectL4LBNode: unable to select l4lb node for id '%s': %w", l4lbNodeID, err)
	}

	l4lbNode, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[cdntypes.L4LBNode])
	if err != nil {
		return cdntypes.L4LBNode{}, fmt.Errorf("selectL4LBNode: unable to collect l4lb node for id '%s': %w", l4lbNodeID, err)
	}

	return l4lbNode, nil
}

type serviceIPInfo struct {
	ServiceID          pgtype.UUID
	ServiceIPAddresses []netip.Addr
	OriginTLSStatus    []bool
}

func selectL4LBNodeConfig(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, l4lbNodeNameOrID string) (cdntypes.L4LBNodeConfig, error) {
	if !ad.Superuser && ad.RoleName != "node" {
		return cdntypes.L4LBNodeConfig{}, cdnerrors.ErrForbidden
	}

	serviceIPInfos := []serviceIPInfo{}

	l4lbNode := cdntypes.L4LBNode{}
	cacheNodes := []cdntypes.CacheNode{}

	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		l4lbNodeIdent, err := newL4LBNodeIdentifier(ctx, tx, l4lbNodeNameOrID)
		if err != nil {
			return cdnerrors.ErrUnableToParseNameOrID
		}

		cacheNodes, err = selectCacheMembersForL4LBNode(ctx, tx, l4lbNodeIdent.id)
		if err != nil {
			return fmt.Errorf("unable to select cache node information: %w", err)
		}

		l4lbNode, err = selectL4LBNodeTx(ctx, tx, l4lbNodeIdent.id)
		if err != nil {
			return fmt.Errorf("unable to select l4lb node: %w", err)
		}

		// Collect IP addresses, TLS status and Service ID of every active service version
		rows, err := tx.Query(
			ctx,
			`SELECT
			service_versions.service_id,
			( SELECT
				array_agg(address)
				FROM service_ip_addresses
				WHERE service_ip_addresses.service_id = service_versions.service_id
			) AS service_ip_addresses,
			( SELECT
				array_agg(tls)
				FROM service_origins
				WHERE service_origins.service_version_id = service_versions.id
			) AS origin_tls_status
			FROM service_versions
			WHERE service_versions.active=true
			ORDER BY service_versions.service_id
	`,
		)
		if err != nil {
			return fmt.Errorf("selectL4LBNodeConfig: unable to select active service IP info: %w", err)
		}

		serviceIPInfos, err = pgx.CollectRows(rows, pgx.RowToStructByName[serviceIPInfo])
		if err != nil {
			return fmt.Errorf("unable to collect service IP info rows: %w", err)
		}

		return nil
	})
	if err != nil {
		return cdntypes.L4LBNodeConfig{}, fmt.Errorf("l4lb node config transaction failed: %w", err)
	}

	lnc := cdntypes.L4LBNodeConfig{
		L4LBNode:   l4lbNode,
		CacheNodes: cacheNodes,
	}

	for _, sii := range serviceIPInfos {
		if len(sii.OriginTLSStatus) < 1 {
			return cdntypes.L4LBNodeConfig{}, fmt.Errorf("we expect at least one origin in the set, this is odd, serviceID: %s", sii.ServiceID)
		}

		sConn := cdntypes.ServiceConnectivity{
			ServiceID:          sii.ServiceID,
			ServiceIPAddresses: sii.ServiceIPAddresses,
		}

		// Loop over the collected TLS status of each origin to figure
		// out if either HTTP, HTTPS or both is expected. This will
		// decide if we open up port 443/80 on the l4lb
		for _, originHasTLS := range sii.OriginTLSStatus {
			if originHasTLS {
				sConn.HTTPS = true
			} else {
				sConn.HTTP = true
			}

			if sConn.HTTPS && sConn.HTTP {
				// We have found both, no need to inspect
				// additional origins
				break
			}
		}

		lnc.Services = append(lnc.Services, sConn)
	}

	return lnc, nil
}

func selectServiceVersions(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, serviceNameOrID string, orgNameOrID string) ([]cdntypes.ServiceVersion, error) {
	var rows pgx.Rows

	var err error
	serviceVersions := []cdntypes.ServiceVersion{}
	err = pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		var serviceIdent serviceIdentifier

		var orgID pgtype.UUID
		if orgNameOrID != "" {
			orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
			if err != nil {
				return cdnerrors.ErrUnableToParseNameOrID
			}
			orgID = orgIdent.id
		}

		// Looking up a service by ID works without supplying an org,
		// for looking up service by name an org must be included
		serviceIdent, err = newServiceIdentifier(ctx, tx, serviceNameOrID, orgID)
		if err != nil {
			return fmt.Errorf("looking up service identifier failed: %w", err)
		}

		if !ad.Superuser && (ad.OrgID == nil || *ad.OrgID != serviceIdent.orgID) {
			return cdnerrors.ErrForbidden
		}

		rows, err = tx.Query(
			ctx,
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
				cdntypes.ServiceVersion{
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

func getServiceVersionConfig(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, orgNameOrID string, serviceNameOrID string, version int64) (cdntypes.ServiceVersionConfig, error) {
	// If neither a superuser or a normal user belonging to an org there
	// is nothing further that is allowed
	if !ad.Superuser {
		if ad.OrgID == nil {
			return cdntypes.ServiceVersionConfig{}, cdnerrors.ErrForbidden
		}
	}

	var svc cdntypes.ServiceVersionConfig
	err := pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(ctx, tx, orgNameOrID)
		if err != nil {
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(ctx, tx, serviceNameOrID, orgIdent.id)
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
			ctx,
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
				array_agg(address ORDER BY address)
				FROM service_ip_addresses
				WHERE service_id = services.id
			) AS service_ip_addresses,
			(SELECT
				array_agg(domains.name ORDER BY domains.name)
				FROM domains
				JOIN service_domains ON service_domains.domain_id = domains.id
				WHERE domains.verified = true AND service_version_id = service_versions.id
			) AS domains,
			(SELECT
				array_agg((origin_group_id, host, port, tls, verify_tls) ORDER BY host, port)
				FROM service_origins
				WHERE service_version_id = service_versions.id
			) AS origins,
			(SELECT
				array_agg((id, default_group, name) ORDER BY name)
				FROM service_origin_groups
				WHERE service_id = services.id
			) AS origin_groups
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

		svc, err = pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[cdntypes.ServiceVersionConfig])
		if err != nil {
			return fmt.Errorf("unable to collect service version config into struct: %w", err)
		}

		return nil
	})
	if err != nil {
		return cdntypes.ServiceVersionConfig{}, fmt.Errorf("getServiceVersionConfig transaction failed: %w", err)
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

func deactivatePreviousServiceVersionTx(ctx context.Context, tx pgx.Tx, serviceIdent serviceIdentifier) (*pgtype.UUID, error) {
	var deactivatedServiceVersionID *pgtype.UUID

	// Start with finding out if there even is any active version at all,
	// if not there is nothing more to do.
	var found bool
	err := tx.QueryRow(
		ctx,
		"SELECT TRUE FROM service_versions WHERE service_id=$1 AND active=true FOR UPDATE",
		serviceIdent.id,
	).Scan(&found)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	err = tx.QueryRow(
		ctx,
		"UPDATE service_versions SET active=false WHERE service_id=$1 AND active=true returning id",
		serviceIdent.id,
	).Scan(&deactivatedServiceVersionID)
	if err != nil {
		return nil, fmt.Errorf("unable to UPDATE active status for previous service version: %w", err)
	}

	return deactivatedServiceVersionID, nil
}

func insertServiceVersionTx(ctx context.Context, tx pgx.Tx, orgIdent orgIdentifier, serviceIdent serviceIdentifier, domains []cdntypes.DomainString, origins []cdntypes.Origin, active bool, vcls cdntypes.VclSteps) (serviceVersionInsertResult, error) {
	var serviceVersionID pgtype.UUID
	var versionCounter int64
	var deactivatedServiceVersionID *pgtype.UUID

	err := tx.QueryRow(
		ctx,
		"UPDATE services SET version_counter=version_counter+1 WHERE id=$1 RETURNING version_counter",
		serviceIdent.id,
	).Scan(&versionCounter)
	if err != nil {
		return serviceVersionInsertResult{}, fmt.Errorf("unable to UPDATE version_counter for service version: %w", err)
	}

	// If the new version is expected to be active we need to deactivate the currently active version
	if active {
		deactivatedServiceVersionID, err = deactivatePreviousServiceVersionTx(ctx, tx, serviceIdent)
		if err != nil {
			return serviceVersionInsertResult{}, err
		}
	}

	err = tx.QueryRow(
		ctx,
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
		// Map domain name to correct ID
		var domainID pgtype.UUID
		err = tx.QueryRow(
			ctx,
			"SELECT id FROM domains WHERE name=$1 AND org_id=$2 AND verified=$3",
			domain,
			orgIdent.id,
			true,
		).Scan(&domainID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return serviceVersionInsertResult{}, cdnerrors.ErrUnknownDomain
			}
			return serviceVersionInsertResult{}, fmt.Errorf("mapping domain name to existing domain failed: %w", err)
		}

		var serviceDomainID pgtype.UUID
		err = tx.QueryRow(
			ctx,
			"INSERT INTO service_domains (service_version_id, domain_id) VALUES ($1, $2) RETURNING id",
			serviceVersionID,
			domainID,
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
			ctx,
			"INSERT INTO service_origins (service_version_id, origin_group_id, host, port, tls, verify_tls) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
			serviceVersionID,
			origin.OriginGroupID,
			origin.Host,
			origin.Port,
			origin.TLS,
			origin.VerifyTLS,
		).Scan(&serviceOriginID)
		if err != nil {
			return serviceVersionInsertResult{}, fmt.Errorf("unable to INSERT service origin: %w", err)
		}
		serviceOriginIDs = append(serviceOriginIDs, serviceOriginID)
	}

	var serviceVclID pgtype.UUID
	err = tx.QueryRow(
		ctx,
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

func insertServiceVersion(ctx context.Context, logger *zerolog.Logger, confTemplates configTemplates, ad cdntypes.AuthData, dbc *dbConn, vclValidator *vclValidatorClient, orgNameOrID string, serviceNameOrID string, domains []cdntypes.DomainString, inputOrigins []cdntypes.InputOrigin, active bool, vcls cdntypes.VclSteps) (serviceVersionInsertResult, error) {
	// If neither a superuser or a normal user belonging to an org there
	// is nothing further that is allowed
	if !ad.Superuser {
		if ad.OrgID == nil {
			return serviceVersionInsertResult{}, cdnerrors.ErrForbidden
		}
	}

	var serviceVersionResult serviceVersionInsertResult

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(dbCtx, tx, orgNameOrID)
		if err != nil {
			logger.Err(err).Msg("looking up org failed")
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(dbCtx, tx, serviceNameOrID, orgIdent.id)
		if err != nil {
			logger.Err(err).Msg("looking up service failed")
			return cdnerrors.ErrUnprocessable
		}

		// If the user is not a superuser they must belong to the same
		// org as the service they are trying to add a version to
		if !ad.Superuser {
			if *ad.OrgID != serviceIdent.orgID {
				return cdnerrors.ErrForbidden
			}
		}

		// If someone is submitting data to create a new service version it
		// will not contain what addresses have been allocated to the
		// service, so we need to enrich the submitted data with this
		// information in order to be able to construct a complete VCL for
		// validation.
		var serviceIPAddrs []netip.Addr
		err = tx.QueryRow(
			dbCtx,
			"SELECT array_agg(address ORDER BY address) AS service_ip_addresses FROM service_ip_addresses WHERE service_id = $1",
			serviceIdent.id,
		).Scan(&serviceIPAddrs)
		if err != nil {
			logger.Err(err).Msg("looking up service IPs failed")
			return cdnerrors.ErrUnprocessable
		}

		// We also need to validate/convert input origin groups
		origins, err := validateInputOrigins(dbCtx, tx, inputOrigins, serviceIdent.id)
		if err != nil {
			logger.Err(err).Msg("validating input origins")
			return cdnerrors.ErrUnprocessable
		}

		originGroups, err := selectOriginGroupsTx(dbCtx, tx, serviceIdent.id)
		if err != nil {
			logger.Err(err).Msg("looking up origin groups failed")
			return cdnerrors.ErrUnprocessable
		}

		// It is not optimal to do network connections while holding a
		// database transaction open, but it is either this or duplicating
		// lookups to fill in stuff and the idea is that the validator
		// software is running on the same host as the manager.
		err = vclValidator.validateServiceVersionConfig(
			confTemplates,
			cdntypes.InputServiceVersion{
				VclSteps: vcls,
				Origins:  origins,
				Domains:  domains,
			},
			serviceIPAddrs,
			originGroups,
			origins,
		)
		if err != nil {
			return fmt.Errorf("VCL validation failed: %w", err)
		}

		serviceVersionResult, err = insertServiceVersionTx(dbCtx, tx, orgIdent, serviceIdent, domains, origins, active, vcls)
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

func activateServiceVersion(ctx context.Context, logger *zerolog.Logger, ad cdntypes.AuthData, dbc *dbConn, orgNameOrID string, serviceNameOrID string, version int64) error {
	// If neither a superuser or a normal user belonging to an org there
	// is nothing further that is allowed
	if !ad.Superuser {
		if ad.OrgID == nil {
			return cdnerrors.ErrForbidden
		}
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		orgIdent, err := newOrgIdentifier(dbCtx, tx, orgNameOrID)
		if err != nil {
			logger.Err(err).Msg("unable to validate org id")
			return cdnerrors.ErrUnprocessable
		}

		serviceIdent, err := newServiceIdentifier(dbCtx, tx, serviceNameOrID, orgIdent.id)
		if err != nil {
			logger.Err(err).Msg("unable to validate org id")
			return cdnerrors.ErrUnprocessable
		}

		// If the user is not a superuser they must belong to the same
		// org as the service they are trying activate a version for
		if !ad.Superuser {
			if *ad.OrgID != serviceIdent.orgID {
				return cdnerrors.ErrForbidden
			}
		}

		_, err = activateServiceVersionTx(dbCtx, tx, serviceIdent, version)
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

func activateServiceVersionTx(ctx context.Context, tx pgx.Tx, serviceIdent serviceIdentifier, version int64) (pgtype.UUID, error) {
	_, err := deactivatePreviousServiceVersionTx(ctx, tx, serviceIdent)
	if err != nil {
		return pgtype.UUID{}, err
	}

	var activatedServiceVersionID pgtype.UUID
	err = tx.QueryRow(ctx, "UPDATE service_versions SET active=true WHERE service_id=$1 AND version=$2 RETURNING id", serviceIdent.id, version).Scan(&activatedServiceVersionID)
	if err != nil {
		return pgtype.UUID{}, err
	}

	return activatedServiceVersionID, nil
}

type varnishVCLInput struct {
	VCLVersion             string
	Modules                []string
	DefaultOriginGroupName string
	OriginGroups           []enrichedOriginGroup
	Domains                []cdntypes.DomainString
	DefaultForHTTPS        bool
	DefaultForHTTP         bool
	HTTPSEnabled           bool
	HTTPEnabled            bool
	ServiceIPv4            netip.Addr
	VCLSteps               cdntypes.VclSteps
}

// Make it easier to generate varnish configuration
type enrichedOriginGroup struct {
	cdntypes.OriginGroup
	HTTP  bool
	HTTPS bool
}

func generateCompleteVcl(tmpl *template.Template, serviceIPAddresses []netip.Addr, originGroups []cdntypes.OriginGroup, origins []cdntypes.Origin, domains []cdntypes.DomainString, vclSteps cdntypes.VclSteps) (string, error) {
	serviceIPv4Address, err := getFirstV4Addr(serviceIPAddresses)
	if err != nil {
		return "", errors.New("no IPv4 address allocated to service")
	}

	// If we blindly add all existing origin groups to the varnish
	// configuration it will fail to load:
	// ===
	// Unused backend haproxy_http_origin-group-2, defined:
	// ('/tmp/vcl-content2391245548' Line 11 Pos 9)
	// backend haproxy_http_origin-group-2 {
	// --------###########################--
	//
	// Running VCC-compiler failed, exited with 2
	// VCL compilation failed
	// ===
	// ... so filter out any groups not referenced by origins
	originGroupIDs := map[pgtype.UUID][]cdntypes.Origin{}
	for _, origin := range origins {
		originGroupIDs[origin.OriginGroupID] = append(originGroupIDs[origin.OriginGroupID], origin)
	}

	// Detect what haproxy backends should be present
	haProxyHTTP := false
	haProxyHTTPS := false

	// Detect if there is a default origin group to send requests to
	// without user having to set explicit req.backend_hint config.
	defaultForHTTP := false
	defaultForHTTPS := false
	referencedOriginGroups := []enrichedOriginGroup{}
	for _, originGroup := range originGroups {
		if origins, ok := originGroupIDs[originGroup.ID]; ok {
			groupHasHTTPS := false
			groupHasHTTP := false
			for _, origin := range origins {
				if origin.TLS {
					haProxyHTTPS = true
					groupHasHTTPS = true
					// We need to know if we should include default VCL for
					// forwarding, this is only done if the at least one
					// origin belongs to the default origin group.
					if originGroup.DefaultGroup {
						defaultForHTTPS = true
					}
				} else {
					haProxyHTTP = true
					groupHasHTTP = true
					if originGroup.DefaultGroup {
						defaultForHTTP = true
					}
				}
			}
			referencedOriginGroups = append(
				referencedOriginGroups,
				enrichedOriginGroup{
					OriginGroup: originGroup,
					HTTP:        groupHasHTTP,
					HTTPS:       groupHasHTTPS,
				},
			)
		}
	}
	if !haProxyHTTP && !haProxyHTTPS {
		return "", fmt.Errorf("neither HTTPS or HTTP origin assigned, this is unexpected")
	}

	// Find the name of the default origin group
	defaultOriginGroup := ""
	for _, originGroup := range originGroups {
		if originGroup.DefaultGroup {
			defaultOriginGroup = originGroup.Name
		}
	}
	if defaultOriginGroup == "" {
		return "", fmt.Errorf("unable to find default origin group name, this is unexpected")
	}

	vvc := varnishVCLInput{
		VCLVersion: "4.1",
		Modules: []string{
			"std",
			"proxy",
		},
		OriginGroups:           referencedOriginGroups,
		DefaultOriginGroupName: defaultOriginGroup,
		Domains:                domains,
		ServiceIPv4:            serviceIPv4Address,
		DefaultForHTTPS:        defaultForHTTPS,
		DefaultForHTTP:         defaultForHTTP,
		HTTPSEnabled:           haProxyHTTPS,
		HTTPEnabled:            haProxyHTTP,
		VCLSteps:               vclSteps,
	}

	var b strings.Builder

	err = tmpl.Execute(&b, vvc)
	if err != nil {
		return "", fmt.Errorf("generateCompleteVcl: unable to execute template: %w", err)
	}

	return b.String(), nil
}

type haproxyConfInput struct {
	OriginGroups   []enrichedOriginGroup
	Origins        []cdntypes.Origin
	HTTPSEnabled   bool
	HTTPEnabled    bool
	AddressStrings []string
}

func generateCompleteHaProxyConf(tmpl *template.Template, serviceIPAddresses []netip.Addr, originGroups []cdntypes.OriginGroup, origins []cdntypes.Origin) (string, error) {
	//// Detect what haproxy backends should be present
	//haProxyHTTP := false
	//haProxyHTTPS := false
	//for _, origin := range origins {
	//	// If both have been found we do not need to look at more
	//	// backends
	//	if haProxyHTTP && haProxyHTTPS {
	//		break
	//	}

	//	if origin.TLS {
	//		haProxyHTTPS = true
	//	} else {
	//		haProxyHTTP = true
	//	}
	//}

	//if !haProxyHTTP && !haProxyHTTPS {
	//	return "", fmt.Errorf("neither HTTPS or HTTP origin assigned, this is unexpected")
	//}

	// Get a list of all origin groups that are actually referenced by
	// origins, we do the same for varnish where it is required but might
	// as well do it here so the config only contains exactly what is
	// needed.
	originGroupIDs := map[pgtype.UUID][]cdntypes.Origin{}
	for _, origin := range origins {
		originGroupIDs[origin.OriginGroupID] = append(originGroupIDs[origin.OriginGroupID], origin)
	}

	// Detect what haproxy backends should be present
	haProxyHTTP := false
	haProxyHTTPS := false
	referencedOriginGroups := []enrichedOriginGroup{}
	for _, originGroup := range originGroups {
		if origins, ok := originGroupIDs[originGroup.ID]; ok {
			groupHasHTTPS := false
			groupHasHTTP := false
			for _, origin := range origins {
				if origin.TLS {
					haProxyHTTPS = true
					groupHasHTTPS = true
				} else {
					haProxyHTTP = true
					groupHasHTTP = true
				}
			}
			referencedOriginGroups = append(
				referencedOriginGroups,
				enrichedOriginGroup{
					OriginGroup: originGroup,
					HTTP:        groupHasHTTP,
					HTTPS:       groupHasHTTPS,
				},
			)
		}
	}
	if !haProxyHTTP && !haProxyHTTPS {
		return "", fmt.Errorf("neither HTTPS or HTTP origin assigned, this is unexpected")
	}

	addressStrings := []string{}

	// HAProxy expects IPv6 addresses to be enclosed in []
	for _, addr := range serviceIPAddresses {
		if addr.Unmap().Is4() {
			addressStrings = append(addressStrings, addr.Unmap().String())
		} else if addr.Unmap().Is6() {
			addressStrings = append(addressStrings, fmt.Sprintf("[%s]", addr.Unmap()))
		} else {
			return "", fmt.Errorf("address is neither IPv4 or IPv6")
		}
	}

	hci := haproxyConfInput{
		OriginGroups:   referencedOriginGroups,
		Origins:        origins,
		AddressStrings: addressStrings,
		HTTPSEnabled:   haProxyHTTPS,
		HTTPEnabled:    haProxyHTTP,
	}

	var b strings.Builder

	err := tmpl.Execute(&b, hci)
	if err != nil {
		return "", fmt.Errorf("generateCompleteHaProxyConf: unable to execute template: %w", err)
	}

	return b.String(), nil
}

func selectNetworks(ctx context.Context, dbc *dbConn, ad cdntypes.AuthData, family int) ([]ipNetwork, error) {
	if !ad.Superuser {
		return nil, cdnerrors.ErrForbidden
	}

	var rows pgx.Rows
	var err error

	if family == 0 {
		rows, err = dbc.dbPool.Query(ctx, "SELECT id, network FROM ip_networks ORDER BY network")
		if err != nil {
			return nil, fmt.Errorf("unable to query for all networks: %w", err)
		}
	} else {
		if _, ok := validNetworkFamilies[family]; !ok {
			return nil, errors.New("invalid network family")
		}
		rows, err = dbc.dbPool.Query(ctx, "SELECT id, network FROM ip_networks WHERE family(network) = $1 ORDER BY network", family)
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

func insertNetwork(ctx context.Context, dbc *dbConn, network netip.Prefix, ad cdntypes.AuthData) (ipNetwork, error) {
	var id pgtype.UUID
	if !ad.Superuser {
		return ipNetwork{}, cdnerrors.ErrForbidden
	}

	dbCtx, cancel := dbc.detachedContext(ctx)
	defer cancel()

	err := dbc.dbPool.QueryRow(dbCtx, "INSERT INTO ip_networks (network) VALUES ($1) RETURNING id", network).Scan(&id)
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

func newChiRouter(conf config.Config, logger zerolog.Logger, dbc *dbConn, argon2Mutex *sync.Mutex, loginCache *lru.Cache[string, struct{}], cookieStore *sessions.CookieStore, provider *oidc.Provider, vclValidator *vclValidatorClient, confTemplates configTemplates, devMode bool, clientCredAEADs []cipher.AEAD, kccm *keycloakClientManager, tokenURL *url.URL, serverURL *url.URL) *chi.Mux {
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
	router.Handle("/css/*", http.FileServerFS(components.CSSFS))
	router.Handle("/js/*", http.FileServerFS(components.JsFS))

	strictFetch := &strictFetchMetadataMiddleware{}
	antiCSRF := http.NewCrossOriginProtection()

	// We use the last configured encryption password for encrypting new values
	encryptionClientCredAEAD := clientCredAEADs[len(clientCredAEADs)-1]

	// Authenticated console releated routes
	router.Route(consolePath, func(r chi.Router) {
		r.Use(strictFetch.Handler)
		r.Use(antiCSRF.Handler)
		r.Use(consoleAuthMiddleware(cookieStore))
		r.Get("/", consoleDashboardHandler(dbc, cookieStore))
		r.Get("/org/{org}", consoleOrgDashboardHandler(dbc, cookieStore))
		r.Get("/org/{org}/domains", consoleDomainsHandler(dbc, cookieStore))
		r.Delete("/org/{org}/domains/{domain}", consoleDomainDeleteHandler(dbc, cookieStore))
		r.Get("/org/{org}/create/domain", consoleCreateDomainHandler(dbc, cookieStore))
		r.Post("/org/{org}/create/domain", consoleCreateDomainHandler(dbc, cookieStore))
		r.Get("/org/{org}/services", consoleServicesHandler(dbc, cookieStore))
		r.Get("/org/{org}/services/{service}", consoleServiceHandler(dbc, cookieStore))
		r.Delete("/org/{org}/services/{service}", consoleServiceDeleteHandler(dbc, cookieStore))
		r.Get("/org/{org}/create/service", consoleCreateServiceHandler(dbc, cookieStore))
		r.Post("/org/{org}/create/service", consoleCreateServiceHandler(dbc, cookieStore))
		r.Get("/org/{org}/services/{service}/{version}", consoleServiceVersionHandler(dbc, cookieStore))
		r.Get("/org/{org}/create/service-version/{service}", consoleCreateServiceVersionHandler(dbc, cookieStore, vclValidator, confTemplates))
		r.Post("/org/{org}/create/service-version/{service}", consoleCreateServiceVersionHandler(dbc, cookieStore, vclValidator, confTemplates))
		r.Get("/org/{org}/services/{service}/{version}/activate", consoleActivateServiceVersionHandler(dbc, cookieStore))
		r.Post("/org/{org}/services/{service}/{version}/activate", consoleActivateServiceVersionHandler(dbc, cookieStore))
		r.Get("/org/{org}/api-tokens", consoleAPITokensHandler(dbc, cookieStore, tokenURL, serverURL))
		r.Delete("/org/{org}/api-tokens/{api-token}", consoleAPITokenDeleteHandler(dbc, cookieStore, clientCredAEADs, kccm))
		r.Get("/org/{org}/create/api-token", consoleCreateAPITokenHandler(dbc, cookieStore, encryptionClientCredAEAD, kccm))
		r.Post("/org/{org}/create/api-token", consoleCreateAPITokenHandler(dbc, cookieStore, encryptionClientCredAEAD, kccm))
		// htmx helpers
		r.Get("/new-origin-fieldset", consoleNewOriginFieldsetHandler(dbc, cookieStore))
		r.Get("/org-switcher", consoleOrgSwitcherHandler(dbc, cookieStore))
	})

	oauth2HTTPClient := &http.Client{
		Timeout: 15 * time.Second,
	}
	if devMode {
		logger.Info().Msg("disabling cert validation for oauth2 callback handler due to dev mode")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- only enabled in --dev mode
		}
		oauth2HTTPClient.Transport = tr
	}

	// Console login related routes
	router.Route("/auth", func(r chi.Router) {
		r.Use(strictFetch.Handler)
		r.Use(antiCSRF.Handler)
		r.Get("/login", loginHandler(dbc, argon2Mutex, loginCache, cookieStore))
		r.Post("/login", loginHandler(dbc, argon2Mutex, loginCache, cookieStore))
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
			r.Get("/oidc/keycloak/callback", oauth2CallbackHandler(oauth2HTTPClient, cookieStore, oauth2Config, idTokenVerifier, dbc))
		}
	})

	return router
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

// It is annoying that we need to create our own openidConfig struct when we
// already use oidc.NewProvider() and calling .Endpoint() on the returned
// provider for learning about keycloak oauth2 endpoints for the OIDC
// authorization code flow, but the oidc library does not expose JwksURI. Since
// we want to do validation of the Keycloak access token and this happens to be
// a JWT we just do our own lookup for the ".well-known/openid-configuration"
// even if this means we do a duplicate HTTP request this way.
type openidConfig struct {
	JwksURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

func validateKeycloakToken(ctx context.Context, c *jwk.Cache, issuer string, oiConf openidConfig, token string) (jwt.Token, error) {
	// https://www.keycloak.org/securing-apps/oidc-layers#_validating_access_tokens
	//
	// Even though access tokens in OAuth2 are generally treated as opaque values in
	// keycloak specifically they are defined as JWTs so lets inspect them as such.
	keySet, err := c.Lookup(ctx, oiConf.JwksURI)
	if err != nil {
		return jwt.New(), fmt.Errorf("validateKeycloakToken: failed to fetch JWKS: %w", err)
	}

	jwtToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(keySet), jwt.WithValidate(true), jwt.WithIssuer(issuer), jwt.WithAudience(jwtAudience))
	if err != nil {
		return jwt.New(), fmt.Errorf("validateKeycloakToken: failed to parse payload: %w", err)
	}

	return jwtToken, nil
}

// https://huma.rocks/how-to/oauth2-jwt/#huma-auth-middleware
func newAPIAuthMiddleware(api huma.API, dbc *dbConn, argon2Mutex *sync.Mutex, loginCache *lru.Cache[string, struct{}], jwkCache *jwk.Cache, jwtIssuer string, oiConf openidConfig) func(humaCtx huma.Context, next func(huma.Context)) {
	return func(humaCtx huma.Context, next func(huma.Context)) {
		ctx := humaCtx.Context()
		logger := zlog.Ctx(ctx)

		authorizationVal := humaCtx.Header("Authorization")
		if authorizationVal == "" {
			sendHumaUnauthorized(logger, api, humaCtx)
			return
		}

		// Split on first space only
		parts := strings.SplitN(authorizationVal, " ", 2)
		if len(parts) != 2 {
			sendHumaUnauthorized(logger, api, humaCtx)
			return
		}

		scheme := parts[0]
		token := parts[1]

		if token == "" {
			sendHumaUnauthorized(logger, api, humaCtx)
			return
		}

		var ad cdntypes.AuthData
		var err error

		switch {
		case strings.EqualFold(scheme, "Basic"):
			username, password, ok := decodeBasicAuth(token)
			if !ok {
				sendHumaUnauthorized(logger, api, humaCtx)
				return
			}

			err = pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
				ad, err = dbUserLogin(ctx, tx, logger, argon2Mutex, loginCache, username, password)
				return err
			})
			if err != nil {
				switch err {
				case pgx.ErrNoRows, cdnerrors.ErrBadPassword:
					// The user does not exist, has no password set etc or the password was bad, try again
					logger.Err(err).Msg("API basic auth failed")
					sendHumaUnauthorized(logger, api, humaCtx)
					return
				}
				logger.Err(err).Msg("handleBasicAuth transaction failed")
				err = huma.WriteErr(api, humaCtx, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
				if err != nil {
					logger.Err(err).Msg("failed writing error about user transaction")
				}
				return
			}
		case strings.EqualFold(scheme, "Bearer"):
			jwtToken, err := validateKeycloakToken(ctx, jwkCache, jwtIssuer, oiConf, token)
			if err != nil {
				logger.Err(err).Msg("unable to validate keycloak access token")
				sendHumaUnauthorized(logger, api, humaCtx)
				return
			}

			err = pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
				ad, err = jwtToAuthData(ctx, tx, jwtToken)
				return err
			})
			if err != nil {
				switch err {
				case pgx.ErrNoRows:
					// The client credential does not exist, try again
					logger.Err(err).Msg("API bearer auth failed")
					sendHumaUnauthorized(logger, api, humaCtx)
					return
				}
				logger.Err(err).Msg("handleBearerAuth transaction failed")
				err = huma.WriteErr(api, humaCtx, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
				if err != nil {
					logger.Err(err).Msg("failed writing error about bearer transaction")
				}
				return
			}
		default:
			logger.Error().Msg("no supported type in Authorization header")
			sendHumaUnauthorized(logger, api, humaCtx)
			return
		}

		humaCtx = huma.WithValue(humaCtx, authDataKey{}, ad)

		next(humaCtx)
	}
}

const (
	v1User                  = "/v1/users/{user}"
	userNotFound            = "user not found"
	notAllowedToAddResource = "not allowed to add resource"
)

type keycloakClientManager struct {
	realm        string
	createClient *http.Client // The createClient uses automatic token refreshing
	deleteClient *http.Client // ... where deleteClient uses a registration_access_token from the database
	baseURL      *url.URL
	logger       zerolog.Logger
}

func setupHumaAPI(router chi.Router, dbc *dbConn, argon2Mutex *sync.Mutex, loginCache *lru.Cache[string, struct{}], vclValidator *vclValidatorClient, confTemplates configTemplates, kcClientManager *keycloakClientManager, jwkCache *jwk.Cache, jwtIssuer string, oiConf openidConfig, clientCredAEADs []cipher.AEAD, serverURL *url.URL) error {
	apiURL := serverURL.JoinPath("api")

	// Use the last available encryption password for encrypting new values
	encryptionClientCredAEAD := clientCredAEADs[len(clientCredAEADs)-1]

	router.Route("/api", func(r chi.Router) {
		config := huma.DefaultConfig("SUNET CDN API", "0.0.1")
		config.Servers = []*huma.Server{
			{URL: apiURL.String()},
		}

		config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
			"basicAuth": {
				Type:   "http",
				Scheme: "basic",
			},
			"bearerAuth": {
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
			},
		}

		config.Security = []map[string][]string{
			{
				"basicAuth": {""},
			},
			{
				"bearerAuth": {""},
			},
		}

		api := humachi.New(r, config)

		api.UseMiddleware(newAPIAuthMiddleware(api, dbc, argon2Mutex, loginCache, jwkCache, jwtIssuer, oiConf))

		huma.Get(api, "/v1/users", func(ctx context.Context, _ *struct{},
		) (*usersOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				logger.Error().Msg("unable to read auth data from users handler")
				return nil, errors.New("unable to read auth data from users handler")
			}

			users, err := selectUsers(ctx, dbc.dbPool, logger, ad)
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

		huma.Get(api, v1User, func(ctx context.Context, input *struct {
			User string `path:"user" example:"1" doc:"User ID or name" minLength:"1" maxLength:"63"`
		},
		) (*userOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from user GET handler")
			}

			user, err := selectUser(ctx, dbc.dbPool, input.User, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound(userNotFound)
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

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from users POST handler")
				}

				user, err := createUser(ctx, dbc, input.Body.Name, input.Body.Role, input.Body.Org, ad)
				if err != nil {
					if errors.Is(err, cdnerrors.ErrForbidden) {
						return nil, huma.Error403Forbidden(notAllowedToAddResource)
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
			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from local-password PUT handler")
			}

			_, err := setLocalPassword(ctx, logger, ad, dbc, argon2Mutex, loginCache, input.User, input.Body.OldPassword, input.Body.NewPassword)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrBadOldPassword) {
					return nil, huma.Error400BadRequest("old password is not correct")
				}
				return nil, fmt.Errorf("unable to set password: %w", err)
			}
			return nil, nil
		})

		huma.Put(api, v1User, func(ctx context.Context, input *userPutInput) (*userOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from user PATCH handler")
			}

			user, err := updateUser(ctx, dbc, ad, input.User, input.Body.Org, input.Body.Role)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound(userNotFound)
				}
				logger.Err(err).Msg("unable to update user")
				return nil, err
			}
			return &userOutput{Body: user}, nil
		})

		huma.Delete(api, v1User, func(ctx context.Context, input *struct {
			User string `path:"user" example:"username" doc:"user ID or name" minLength:"1" maxLength:"63"`
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from user DELETE handler")
			}

			_, err := deleteUser(ctx, logger, dbc, ad, input.User)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound(userNotFound)
				} else if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden("access to this user is not allowed")
				}
				logger.Err(err).Msg("unable to delete user")
				return nil, err
			}

			return nil, nil
		})

		huma.Get(api, "/v1/orgs", func(ctx context.Context, _ *struct{},
		) (*orgsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from orgs GET handler")
			}

			orgs, err := selectOrgs(ctx, dbc, ad)
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

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization GET handler")
			}

			org, err := selectOrg(ctx, dbc, input.Org, ad)
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

		huma.Get(api, "/v1/orgs/{org}/client-credentials", func(ctx context.Context, input *struct {
			Org string `path:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*orgClientCredentialsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from organization client tokens GET handler")
			}

			safeOrgClientCredentials, err := selectSafeOrgClientCredentials(ctx, dbc, input.Org, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("organization client credentials not found")
				}
				logger.Err(err).Msg("unable to query organization client credentials")
				return nil, err
			}
			resp := &orgClientCredentialsOutput{}

			resp.Body = safeOrgClientCredentials
			return resp, nil
		})

		postOrgClientTokensPath := "/v1/orgs/{org}/client-credentials" // #nosec G101 -- Not a hardcoded credential
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postOrgClientTokensPath, &newOrgClientCredentialOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postOrgClientTokensPath, &newOrgClientCredentialOutput{}),
				Method:        http.MethodPost,
				Path:          postOrgClientTokensPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Org  string `path:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
				Body struct {
					Name        string `json:"name" example:"Some-name" doc:"Name for the token, must be a valid DNS label" minLength:"1" maxLength:"63"`
					Description string `json:"description" example:"Some description" doc:"Description for the token" minLength:"1" maxLength:"100"`
				}
			},
			) (*newOrgClientCredentialOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from organization POST handler")
				}

				newOrgClientCred, err := insertOrgClientCredential(ctx, logger, dbc, input.Body.Name, input.Body.Description, input.Org, ad, kcClientManager, encryptionClientCredAEAD)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden(notAllowedToAddResource)
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("client credential already exists")
					case errors.Is(err, cdnerrors.ErrUnprocessable):
						return nil, huma.Error422UnprocessableEntity("missing required params")
					}
					logger.Err(err).Msg("unable to add client credential")
					return nil, err
				}
				resp := &newOrgClientCredentialOutput{}
				resp.Body = newOrgClientCred
				return resp, nil
			},
		)

		postReEncryptOrgClientRegistrationTokens := "/v1/re-encrypt-org-client-registration-tokens" // #nosec G101 -- Not a hardcoded credential
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postReEncryptOrgClientRegistrationTokens, &reEncryptOrgClientCredentialsOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postReEncryptOrgClientRegistrationTokens, &reEncryptOrgClientCredentialsOutput{}),
				Method:        http.MethodPost,
				Path:          postReEncryptOrgClientRegistrationTokens,
				DefaultStatus: http.StatusOK,
			},
			func(ctx context.Context, _ *struct{},
			) (*reEncryptOrgClientCredentialsOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data for org client cred reg tokens re-encryption POST handler")
				}

				reEncryptRes, err := reEncryptOrgClientCredentials(ctx, logger, dbc, ad, clientCredAEADs)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden("only superusers can re-encrypt client registration tokens")
					case errors.Is(err, cdnerrors.ErrReEncryptionMissingPassword):
						return nil, huma.Error500InternalServerError("must have at least two encryption passwords in server config")
					case errors.Is(err, cdnerrors.ErrReEncryptionFailed):
						// In this specific error we
						// still get a filled in result
						// so we can display counters.
						logger.Error().Int64("total", reEncryptRes.TotalTokens).Int64("updated", reEncryptRes.UpdatedTokens).Int64("skipped", reEncryptRes.SkippedTokens).Int64("failed", reEncryptRes.FailedTokens).Msg("at least one re-encryption attempt failed")
						return nil, huma.Error500InternalServerError(
							fmt.Sprintf(
								"%s: total=%d, updated=%d, skipped=%d, failed=%d",
								cdnerrors.ErrReEncryptionFailed,
								reEncryptRes.TotalTokens,
								reEncryptRes.UpdatedTokens,
								reEncryptRes.SkippedTokens,
								reEncryptRes.FailedTokens,
							),
						)
					}
					logger.Err(err).Msg("unable to re-encrypt client credential registration tokens")
					return nil, err
				}

				resp := &reEncryptOrgClientCredentialsOutput{}
				resp.Body = reEncryptRes
				return resp, nil
			},
		)

		huma.Delete(api, "/v1/orgs/{org}/client-credentials/{client-credential}", func(ctx context.Context, input *struct {
			Org              string `path:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
			ClientCredential string `path:"client-credential" example:"1" doc:"Client credentials ID or name" minLength:"1" maxLength:"63"`
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from org client-credentials DELETE handler")
			}

			_, err := deleteOrgClientCredential(ctx, logger, dbc, clientCredAEADs, ad, kcClientManager, input.Org, input.ClientCredential)
			if err != nil {
				logger.Err(err).Msg("unable to delete client-credential")
				switch {
				case errors.Is(err, cdnerrors.ErrNotFound):
					return nil, huma.Error404NotFound("client-credential not found")
				default:
					return nil, err
				}
			}

			return nil, nil
		})

		huma.Get(api, "/v1/domains", func(ctx context.Context, input *struct {
			Org string `query:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*orgDomainsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from domains GET handler")
			}

			domains, err := selectDomains(ctx, dbc, ad, input.Org)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("domain not found")
				}
				logger.Err(err).Msg("unable to query organization")
				return nil, err
			}
			resp := &orgDomainsOutput{}
			resp.Body = domains
			return resp, nil
		})

		huma.Delete(api, "/v1/domains/{domain}", func(ctx context.Context, input *struct {
			Domain string `path:"domain" example:"1" doc:"Domain ID or name" minLength:"1" maxLength:"253"`
		},
		) (*struct{}, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from domain DELETE handler")
			}

			_, err := deleteDomain(ctx, logger, dbc, ad, input.Domain)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("domain not found")
				} else if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden("access to this domain is not allowed")
				}
				logger.Err(err).Msg("unable to delete domain")
				return nil, err
			}

			return nil, nil
		})

		postDomainsPath := "/v1/domains"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postDomainsPath, &orgDomainOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postDomainsPath, &orgDomainOutput{}),
				Method:        http.MethodPost,
				Path:          postDomainsPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Org  string `query:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
				Body struct {
					Name string `json:"name" example:"Some name" doc:"Organization name" minLength:"1" maxLength:"253" pattern:"^[a-z]([-.a-z0-9]*[a-z0-9])?$" patternDescription:"valid DNS name"`
				}
			},
			) (*orgDomainOutput, error) {
				logger := zlog.Ctx(ctx)

				// The regex used above is not really a good
				// filter for valid domain names, do some extra
				// validation
				_, ok := dns.IsDomainName(input.Body.Name)
				if !ok {
					return nil, huma.Error422UnprocessableEntity("the DNS name is not valid")
				}

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from organization POST handler: %w")
				}

				domain, err := insertDomain(ctx, logger, dbc, input.Body.Name, &input.Org, ad)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden(notAllowedToAddResource)
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("domain already exists")
					case errors.Is(err, cdnerrors.ErrUnprocessable):
						return nil, huma.Error422UnprocessableEntity("missing required params")
					}
					logger.Err(err).Msg("unable to add domain")
					return nil, err
				}
				resp := &orgDomainOutput{}
				resp.Body = domain
				return resp, nil
			},
		)

		huma.Get(api, "/v1/services/{service}/ips", func(ctx context.Context, input *struct {
			Service string `path:"service" example:"1" doc:"Service ID or name" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*orgIPsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from services GET handler")
			}

			oAddrs, err := selectServiceIPs(ctx, dbc, input.Service, input.Org, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				} else if errors.Is(err, cdnerrors.ErrNotFound) {
					return nil, huma.Error404NotFound("service IPs not found")
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
					Name string `json:"name" example:"Some name" doc:"Organization name" minLength:"1" maxLength:"63" pattern:"^[a-z]([-a-z0-9]*[a-z0-9])?$" patternDescription:"valid DNS label"`
				}
			},
			) (*orgOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from organization POST handler: %w")
				}

				id, err := insertOrg(ctx, dbc, input.Body.Name, ad)
				if err != nil {
					if errors.Is(err, cdnerrors.ErrForbidden) {
						return nil, huma.Error403Forbidden(notAllowedToAddResource)
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

		huma.Get(api, "/v1/services", func(ctx context.Context, input *struct {
			Org string `query:"org" example:"my-org" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
		},
		) (*servicesOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from services GET handler")
			}

			services, err := selectServices(ctx, dbc, ad, input.Org)
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

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from service GET handler")
			}

			services, err := selectService(ctx, dbc, input.Org, input.Service, ad)
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

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from service DELETE handler")
			}

			_, err := deleteService(ctx, logger, dbc, input.Org, input.Service, ad)
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
					Name string `json:"name" example:"Some name" doc:"Service name" minLength:"1" maxLength:"63" pattern:"^[a-z]([-a-z0-9]*[a-z0-9])?$" patternDescription:"valid DNS label"`
					Org  string `json:"org" example:"Name or ID of organization" doc:"org1" minLength:"1" maxLength:"63" pattern:"^[a-z]([-a-z0-9]*[a-z0-9])?$" patternDescription:"valid DNS label"`
				}
			},
			) (*orgOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from service POST handler")
				}

				id, err := insertService(ctx, logger, dbc, input.Body.Name, &input.Body.Org, ad)
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

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from service-versions GET handler")
			}

			serviceVersions, err := selectServiceVersions(ctx, dbc, ad, input.Service, input.Org)
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
					cdntypes.VclSteps
					Org     string                  `json:"org" example:"Name or ID of organization" doc:"org1" minLength:"1" maxLength:"63"`
					Domains []cdntypes.DomainString `json:"domains" doc:"List of domains handled by the service" minItems:"1" maxItems:"10"`
					Origins []cdntypes.InputOrigin  `json:"origins" doc:"List of origin hosts for this service" minItems:"1" maxItems:"10"`
					Active  bool                    `json:"active,omitempty" doc:"If the submitted config should be activated or not"`
				}
			},
			) (*serviceVersionOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from service version POST handler")
				}

				serviceVersionInsertRes, err := insertServiceVersion(ctx, logger, confTemplates, ad, dbc, vclValidator, input.Body.Org, input.Service, input.Body.Domains, input.Body.Origins, input.Body.Active, input.Body.VclSteps)
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
					case errors.Is(err, cdnerrors.ErrUnknownDomain):
						return nil, huma.Error422UnprocessableEntity("domain name(s) unknown or unverified")
					case errors.Is(err, cdnerrors.ErrInvalidVCL):
						var ve *cdnerrors.VCLValidationError
						if errors.As(err, &ve) {
							return nil, huma.Error422UnprocessableEntity(ve.Details)
						}
						return nil, huma.Error422UnprocessableEntity("VCL validation failed without details")
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
			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from service version active PUT handler")
			}

			if !input.Body.Active {
				return nil, huma.Error422UnprocessableEntity("active must be true")
			}

			err := activateServiceVersion(ctx, logger, ad, dbc, input.Org, input.Service, input.Version)
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

		huma.Get(api, "/v1/services/{service}/service-versions/{version}/vcl", func(ctx context.Context, input *struct {
			Service string `path:"service" doc:"Service name or ID" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"Name or ID of organization, required if service is supplied by name" doc:"org1" minLength:"1" maxLength:"63"`
			Version int64  `path:"version" example:"1" doc:"The service version to get VCL for"`
		},
		) (*serviceVersionVCLOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from service-versions GET handler")
			}

			svc, err := getServiceVersionConfig(ctx, dbc, ad, input.Org, input.Service, input.Version)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden(api403String)
				case errors.Is(err, cdnerrors.ErrUnprocessable):
					return nil, huma.Error422UnprocessableEntity("unprocessable request")
				case errors.Is(err, cdnerrors.ErrServiceByNameNeedsOrg):
					return nil, huma.Error422UnprocessableEntity(cdnerrors.ErrServiceByNameNeedsOrg.Error())
				case errors.Is(err, pgx.ErrNoRows):
					return nil, huma.Error404NotFound("service version not found")
				}
				logger.Err(err).Msg("unable to query service-versions/{version}/vcl")
				return nil, err
			}

			vcl, err := generateCompleteVcl(confTemplates.vcl, svc.ServiceIPAddresses, svc.OriginGroups, svc.Origins, svc.Domains, svc.VclSteps)
			if err != nil {
				logger.Err(err).Msg("unable to convert service version config to VCL")
				return nil, err
			}

			rBody := cdntypes.ServiceVersionVCL{
				ServiceVersion: svc.ServiceVersion,
				VCL:            vcl,
			}

			resp := &serviceVersionVCLOutput{
				Body: rBody,
			}
			return resp, nil
		})

		huma.Get(api, "/v1/services/{service}/origin-groups", func(ctx context.Context, input *struct {
			Service string `path:"service" doc:"Service name or ID" minLength:"1" maxLength:"63"`
			Org     string `query:"org" example:"Name or ID of organization, required if service is supplied by name" doc:"org1" minLength:"1" maxLength:"63"`
		},
		) (*originGroupsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from origin-groups GET handler")
			}

			originGroups, err := selectOriginGroups(ctx, dbc, ad, input.Service, input.Org)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden(api403String)
				case errors.Is(err, cdnerrors.ErrServiceByNameNeedsOrg):
					return nil, huma.Error422UnprocessableEntity(cdnerrors.ErrServiceByNameNeedsOrg.Error())
				}
				logger.Err(err).Msg("unable to query origin-groups")
				return nil, err
			}

			resp := &originGroupsOutput{
				Body: originGroups,
			}
			return resp, nil
		})

		postOriginGroupsPath := "/v1/services/{service}/origin-groups"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postOriginGroupsPath, &originGroupOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postOriginGroupsPath, &originGroupOutput{}),
				Method:        http.MethodPost,
				Path:          postOriginGroupsPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Service string `path:"service" doc:"Service name or ID" minLength:"1" maxLength:"63"`
				Org     string `query:"org" example:"1" doc:"Organization ID or name" minLength:"1" maxLength:"63"`
				Body    struct {
					Name string `json:"name" example:"myname" doc:"name of origin group" minLength:"1" maxLength:"63"`
				}
			},
			) (*originGroupOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from origin group POST handler")
				}

				originGroup, err := insertOriginGroup(ctx, logger, ad, dbc, input.Service, input.Org, input.Body.Name)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrUnprocessable):
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add origin group")
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("origin group already exists")
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this origin group")
					}
					logger.Err(err).Msg("unable to add origin group")
					return nil, err
				}
				resp := &originGroupOutput{}
				resp.Body = originGroup
				return resp, nil
			},
		)

		huma.Get(api, "/v1/cache-node-configs/{node}", func(ctx context.Context, input *struct {
			CacheNode string `path:"node" doc:"Node name or ID" minLength:"1" maxLength:"63"`
		},
		) (*cacheNodeConfigOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from cache-node-configs GET handler")
			}

			cnc, err := selectCacheNodeConfig(ctx, dbc, ad, confTemplates, input.CacheNode)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden(api403String)
				case errors.Is(err, cdnerrors.ErrUnableToParseNameOrID):
					return nil, huma.Error400BadRequest("invalid node name or id")
				}
				logger.Err(err).Msg("unable to query cache-node-configs")
				return nil, err
			}

			resp := &cacheNodeConfigOutput{
				Body: cnc,
			}

			return resp, nil
		})

		huma.Get(api, "/v1/l4lb-node-configs/{node}", func(ctx context.Context, input *struct {
			L4LBNode string `path:"node" doc:"Node name or ID" minLength:"1" maxLength:"63"`
		},
		) (*l4lbNodeConfigOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from l4lb-node-configs GET handler")
			}

			lnc, err := selectL4LBNodeConfig(ctx, dbc, ad, input.L4LBNode)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden(api403String)
				case errors.Is(err, cdnerrors.ErrUnableToParseNameOrID):
					return nil, huma.Error400BadRequest("invalid node name or id")
				}
				logger.Err(err).Msg("unable to query l4lb-version-configs")
				return nil, err
			}

			resp := &l4lbNodeConfigOutput{
				Body: lnc,
			}

			return resp, nil
		})

		huma.Get(api, "/v1/ip-networks", func(ctx context.Context, input *struct {
			Family string `query:"family" example:"4" doc:"Network IP family to limit query to" enum:"4,6"` // is string instead of int to make enum work
		},
		) (*ipNetworksOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
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

			networks, err := selectNetworks(ctx, dbc, ad, family)
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

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from networks POST handler")
				}

				ipNet, err := insertNetwork(ctx, dbc, input.Body.Network, ad)
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

		huma.Get(api, "/v1/cache-nodes", func(ctx context.Context, _ *struct{}) (*cacheNodesOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from cache-nodes GET handler")
			}

			cacheNodes, err := selectCacheNodes(ctx, dbc, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				}
				logger.Err(err).Msg("unable to query for cache nodes")
				return nil, err
			}

			resp := &cacheNodesOutput{
				Body: cacheNodes,
			}
			return resp, nil
		})

		postCacheNodesPath := "/v1/cache-nodes"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postCacheNodesPath, &cacheNodeOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postCacheNodesPath, &cacheNodeOutput{}),
				Method:        http.MethodPost,
				Path:          postCacheNodesPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *cacheNodePostInput) (*cacheNodeOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from cache-node POST handler")
				}

				var maintenance bool
				if input.Body.Maintenance == nil {
					maintenance = true
				} else {
					maintenance = *input.Body.Maintenance
				}

				// Convert our Huma workaround address type to real netip.Addr
				addresses := []netip.Addr{}
				for _, address := range input.Body.Addresses {
					addresses = append(addresses, netip.Addr(address))
				}

				cacheNode, err := createCacheNode(ctx, dbc, ad, input.Body.Name, input.Body.Description, addresses, maintenance)
				if err != nil {
					if errors.Is(err, cdnerrors.ErrForbidden) {
						return nil, huma.Error403Forbidden(notAllowedToAddResource)
					}
					logger.Err(err).Msg("unable to add cache node")
					return nil, err
				}
				return &cacheNodeOutput{
					Body: cacheNode,
				}, nil
			},
		)

		huma.Put(api, "/v1/cache-nodes/{cachenode}/maintenance", func(ctx context.Context, input *struct {
			CacheNode string `path:"cachenode" example:"cache-node1" doc:"Cache node ID or name" minLength:"1" maxLength:"63"`
			Body      struct {
				Maintenance bool `json:"maintenance" example:"true" doc:"Put the given cache node into maintenance mode"`
			}
		},
		) (*struct{}, error) {
			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from cache-nodes maintenance PUT handler")
			}

			err := setCacheNodeMaintenance(ctx, ad, dbc, input.CacheNode, input.Body.Maintenance)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden("not allowed to modify resource")
				}
				return nil, fmt.Errorf("unable to set cache maintenance: %w", err)
			}
			return nil, nil
		})

		huma.Put(api, "/v1/cache-nodes/{cachenode}/node-group", func(ctx context.Context, input *struct {
			L4LBNode string `path:"cachenode" example:"cache-node1" doc:"Cache node ID or name" minLength:"1" maxLength:"63"`
			Body     struct {
				NodeGroup string `json:"node-group" example:"some-node-group" doc:"Put the cache node in the given node group by name or ID"`
			}
		},
		) (*struct{}, error) {
			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from cache-nodes node group PUT handler")
			}

			err := setCacheNodeGroup(ctx, ad, dbc, input.L4LBNode, input.Body.NodeGroup)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden("not allowed to modify resource")
				case errors.Is(err, pgx.ErrNoRows):
					return nil, huma.Error422UnprocessableEntity("unable to find resources")
				}
				return nil, fmt.Errorf("unable to set cache node group: %w", err)
			}
			return nil, nil
		})

		huma.Get(api, "/v1/l4lb-nodes", func(ctx context.Context, _ *struct{}) (*l4lbNodesOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from l4lb-nodes GET handler")
			}

			l4lbNodes, err := selectL4LBNodes(ctx, dbc, ad)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden(api403String)
				}
				logger.Err(err).Msg("unable to query for l4lb nodes")
				return nil, err
			}

			resp := &l4lbNodesOutput{
				Body: l4lbNodes,
			}
			return resp, nil
		})

		postL4LBNodesPath := "/v1/l4lb-nodes"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postL4LBNodesPath, &l4lbNodeOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postL4LBNodesPath, &l4lbNodeOutput{}),
				Method:        http.MethodPost,
				Path:          postL4LBNodesPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *l4lbNodePostInput) (*l4lbNodeOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from l4lb-node POST handler")
				}

				var maintenance bool
				if input.Body.Maintenance == nil {
					maintenance = true
				} else {
					maintenance = *input.Body.Maintenance
				}

				// Convert our Huma workaround address type to real netip.Addr
				addresses := []netip.Addr{}
				for _, address := range input.Body.Addresses {
					addresses = append(addresses, netip.Addr(address))
				}

				l4lbNode, err := createL4LBNode(ctx, dbc, ad, input.Body.Name, input.Body.Description, addresses, maintenance)
				if err != nil {
					if errors.Is(err, cdnerrors.ErrForbidden) {
						return nil, huma.Error403Forbidden(notAllowedToAddResource)
					}
					logger.Err(err).Msg("unable to add l4lb node")
					return nil, err
				}
				return &l4lbNodeOutput{
					Body: l4lbNode,
				}, nil
			},
		)

		huma.Put(api, "/v1/l4lb-nodes/{l4lbnode}/maintenance", func(ctx context.Context, input *struct {
			L4LBNode string `path:"l4lbnode" example:"l4lb-node1" doc:"L4LB node ID or name" minLength:"1" maxLength:"63"`
			Body     struct {
				Maintenance bool `json:"maintenance" example:"true" doc:"Put the given l4lb node into maintenance mode"`
			}
		},
		) (*struct{}, error) {
			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from l4lb-nodes maintenance PUT handler")
			}

			err := setL4LBNodeMaintenance(ctx, ad, dbc, input.L4LBNode, input.Body.Maintenance)
			if err != nil {
				if errors.Is(err, cdnerrors.ErrForbidden) {
					return nil, huma.Error403Forbidden("not allowed to modify resource")
				}
				return nil, fmt.Errorf("unable to set l4lb maintenance: %w", err)
			}
			return nil, nil
		})

		huma.Put(api, "/v1/l4lb-nodes/{l4lbnode}/node-group", func(ctx context.Context, input *struct {
			L4LBNode string `path:"l4lbnode" example:"l4lb-node1" doc:"L4LB node ID or name" minLength:"1" maxLength:"63"`
			Body     struct {
				NodeGroup string `json:"node-group" example:"some-node-group" doc:"Put the given l4lb node in the given node group by name or ID"`
			}
		},
		) (*struct{}, error) {
			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from l4lb-nodes node group PUT handler")
			}

			err := setL4LBNodeGroup(ctx, ad, dbc, input.L4LBNode, input.Body.NodeGroup)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden("not allowed to modify resource")
				case errors.Is(err, pgx.ErrNoRows):
					return nil, huma.Error422UnprocessableEntity("unable to find resources")
				}
				return nil, fmt.Errorf("unable to set l4lb node group: %w", err)
			}
			return nil, nil
		})

		huma.Get(api, "/v1/node-groups", func(ctx context.Context, _ *struct{},
		) (*nodeGroupsOutput, error) {
			logger := zlog.Ctx(ctx)

			ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
			if !ok {
				return nil, errors.New("unable to read auth data from node-groups GET handler")
			}

			nodeGroups, err := selectNodeGroups(ctx, dbc, ad)
			if err != nil {
				switch {
				case errors.Is(err, cdnerrors.ErrForbidden):
					return nil, huma.Error403Forbidden(api403String)
				}
				logger.Err(err).Msg("unable to query node-groups")
				return nil, err
			}

			resp := &nodeGroupsOutput{
				Body: nodeGroups,
			}
			return resp, nil
		})

		postNodeGroupsPath := "/v1/node-groups"
		huma.Register(
			api,
			huma.Operation{
				OperationID:   huma.GenerateOperationID(http.MethodPost, postNodeGroupsPath, &nodeGroupOutput{}),
				Summary:       huma.GenerateSummary(http.MethodPost, postNodeGroupsPath, &nodeGroupOutput{}),
				Method:        http.MethodPost,
				Path:          postNodeGroupsPath,
				DefaultStatus: http.StatusCreated,
			},
			func(ctx context.Context, input *struct {
				Body struct {
					Name        string `json:"name" example:"myname" doc:"name of node group" minLength:"1" maxLength:"63"`
					Description string `json:"description" doc:"some identifying info for the node group" minLength:"1" maxLength:"100" `
				}
			},
			) (*nodeGroupOutput, error) {
				logger := zlog.Ctx(ctx)

				ad, ok := ctx.Value(authDataKey{}).(cdntypes.AuthData)
				if !ok {
					return nil, errors.New("unable to read auth data from node group POST handler")
				}

				nodeGroup, err := insertNodeGroup(ctx, logger, ad, dbc, input.Body.Name, input.Body.Description)
				if err != nil {
					switch {
					case errors.Is(err, cdnerrors.ErrUnprocessable):
						return nil, huma.Error422UnprocessableEntity("unable to parse request to add node group")
					case errors.Is(err, cdnerrors.ErrAlreadyExists):
						return nil, huma.Error409Conflict("node group already exists")
					case errors.Is(err, cdnerrors.ErrForbidden):
						return nil, huma.Error403Forbidden("not allowed to create this node group")
					}
					logger.Err(err).Msg("unable to add node group")
					return nil, err
				}
				resp := &nodeGroupOutput{}
				resp.Body = nodeGroup
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

// IPAddress is used to override huma IP address handling, it seems a
// []netip.Addr is automatically taken to mean it contains all IPv4 addresses,
// even if setting "format: "ipv6" (and even if the "ipv6" format worked we
// support mixing both ipv4 and ipv6 in the lists of addresses.
// Possibly related work: https://github.com/danielgtaylor/huma/pull/792
type IPAddress netip.Addr

func (IPAddress) Schema(_ huma.Registry) *huma.Schema {
	return &huma.Schema{
		Type:        huma.TypeString,
		Description: "IPv4 or IPv6 address",
		AnyOf: []*huma.Schema{
			{Type: huma.TypeString, Format: "ipv4"},
			{Type: huma.TypeString, Format: "ipv6"},
		},
		Examples: []any{
			"192.0.2.1",
			"2001:db8::1",
		},
	}
}

// parse strings into netip.Addr
func (ip *IPAddress) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return err
	}
	*ip = IPAddress(addr)
	return nil
}

type NodeInput struct {
	Name        string      `json:"name" example:"Some name" doc:"Node name" minLength:"1" maxLength:"63" pattern:"^[a-z]([-a-z0-9]*[a-z0-9])?$" patternDescription:"valid DNS label"`
	Description string      `json:"description" doc:"some identifying info for the node" minLength:"1" maxLength:"100" `
	Addresses   []IPAddress `json:"addresses,omitempty" doc:"The IPv4 and IPv6 addresses of the node"`
	Maintenance *bool       `json:"maintenance,omitempty" doc:"If the node should start in maintenance mode or not, defaults to maintenance mode"`
}

type cacheNodeInput struct {
	NodeInput
}

type cacheNodePostInput struct {
	Body cacheNodeInput
}

type l4lbNodeInput struct {
	NodeInput
}

type l4lbNodePostInput struct {
	Body l4lbNodeInput
}

type cacheNodeOutput struct {
	Body cdntypes.CacheNode
}

type cacheNodesOutput struct {
	Body []cdntypes.CacheNode
}

type l4lbNodeOutput struct {
	Body cdntypes.L4LBNode
}

type l4lbNodesOutput struct {
	Body []cdntypes.L4LBNode
}

type usersOutput struct {
	Body []user
}

type serviceAddresses struct {
	ServiceID          pgtype.UUID      `json:"service_id" doc:"ID of service, UUIDv4"`
	AllocatedAddresses []serviceAddress `json:"allocated_addresses" doc:"list of addresses allocated to the org"`
}

type serviceAddress struct {
	Address netip.Addr `json:"address" doc:"IP address (IPv4 or IPv6)"`
}

type orgOutput struct {
	Body cdntypes.Org
}

type orgsOutput struct {
	Body []cdntypes.Org
}

type newOrgClientCredentialOutput struct {
	Body cdntypes.NewOrgClientCredential
}

type reEncryptOrgClientCredentialsOutput struct {
	Body cdntypes.OrgClientRegistrationTokenReEncryptResult
}

type orgClientCredentialsOutput struct {
	Body []cdntypes.OrgClientCredentialSafe
}

type orgIPsOutput struct {
	Body serviceAddresses
}

type orgDomainOutput struct {
	Body cdntypes.Domain
}

type orgDomainsOutput struct {
	Body []cdntypes.Domain
}

type serviceOutput struct {
	Body cdntypes.Service
}

type servicesOutput struct {
	Body []cdntypes.Service
}

type serviceVersionOutput struct {
	Body cdntypes.ServiceVersion
}

type serviceVersionVCLOutput struct {
	Body cdntypes.ServiceVersionVCL
}

type l4lbNodeConfigOutput struct {
	Body cdntypes.L4LBNodeConfig
}

type cacheNodeConfigOutput struct {
	Body cdntypes.CacheNodeConfig
}

type serviceVersionsOutput struct {
	Body []cdntypes.ServiceVersion
}

type originGroupsOutput struct {
	Body []cdntypes.OriginGroup
}

type originGroupOutput struct {
	Body cdntypes.OriginGroup
}

type nodeGroupsOutput struct {
	Body []cdntypes.NodeGroup
}

type nodeGroupOutput struct {
	Body cdntypes.NodeGroup
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

func Init(logger zerolog.Logger, pgConfig *pgxpool.Config, encryptedSessionKey bool, password string) (InitUser, error) {
	// Make some basic requirements of the password
	minPasswordLen := 15
	if len(password) < minPasswordLen {
		return InitUser{}, fmt.Errorf("password too short, must be at least %d characters", minPasswordLen)
	}

	err := migrations.Up(logger, pgConfig)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to run migrations: %w", err)
	}

	initCtx, initCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer initCancel()

	dbPool, err := pgxpool.NewWithConfig(initCtx, pgConfig)
	if err != nil {
		return InitUser{}, fmt.Errorf("unable to create database pool: %w", err)
	}
	defer dbPool.Close()

	// We get away with a local version of the argon2 mutex here because
	// Init() is only called when first initializing the database, so there
	// is no possibility of concurrent calls to argon2 calculations.
	var initArgon2Mutex sync.Mutex

	a2Data, err := passwordToArgon2(&initArgon2Mutex, password)
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

	err = pgx.BeginFunc(initCtx, dbPool, func(tx pgx.Tx) error {
		// Verify there are no roles present
		var rolesExists bool
		err := tx.QueryRow(initCtx, "SELECT EXISTS(SELECT 1 FROM roles)").Scan(&rolesExists)
		if err != nil {
			return fmt.Errorf("checking if there are any roles failed: %w", err)
		}

		if rolesExists {
			return cdnerrors.ErrDatabaseInitialized
		}

		// Because of the NOT NULL role_id required for users, if there are no
		// roles there are no users either. So now we can create an initial
		// admin role and user.
		var adminRoleID pgtype.UUID
		err = tx.QueryRow(initCtx, "INSERT INTO roles (name, superuser) VALUES ($1, TRUE) RETURNING id", u.Role).Scan(&adminRoleID)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial superuser role '%s': %w", u.Role, err)
		}

		// Add role used by ordinary users
		_, err = tx.Exec(initCtx, "INSERT INTO roles (name) VALUES ($1)", "user")
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user role '%s': %w", u.Role, err)
		}

		// Add role used by cache and l4lb nodes to fetch config
		_, err = tx.Exec(initCtx, "INSERT INTO roles (name) VALUES ($1)", "node")
		if err != nil {
			return fmt.Errorf("unable to INSERT initial node role '%s': %w", u.Role, err)
		}

		var localAuthProviderID pgtype.UUID
		for _, authProviderName := range authProviderNames {
			var authProviderID pgtype.UUID
			err = tx.QueryRow(initCtx, "INSERT INTO auth_providers (name) VALUES ($1) RETURNING id", authProviderName).Scan(&authProviderID)
			if err != nil {
				return fmt.Errorf("unable to INSERT auth provider '%s': %w", authProviderName, err)
			}
			if authProviderName == "local" {
				localAuthProviderID = authProviderID
			}
		}

		userID, err := insertUserTx(initCtx, tx, u.Name, nil, adminRoleID, localAuthProviderID)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user: %w", err)
		}

		_, err = upsertArgon2Tx(initCtx, tx, userID, a2Data)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user password: %w", err)
		}

		u.ID = userID

		_, err = insertGorillaSessionKey(initCtx, tx, gorillaSessionAuthKey, gorillaSessionEncKey)
		if err != nil {
			return fmt.Errorf("unable to INSERT initial user session key: %w", err)
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

func insertGorillaSessionKey(ctx context.Context, tx pgx.Tx, authKey []byte, encKey []byte) (pgtype.UUID, error) {
	var sessionKeyID pgtype.UUID

	// key_order is either the current max key_order value + 1 or 0 if no rows exist
	err := tx.QueryRow(
		ctx,
		"INSERT INTO gorilla_session_keys (auth_key, enc_key, key_order) SELECT $1, $2, COALESCE(MAX(key_order)+1,0) FROM gorilla_session_keys RETURNING id",
		authKey,
		encKey,
	).Scan(&sessionKeyID)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("unable to INSERT gorilla session key: %w", err)
	}

	return sessionKeyID, nil
}

type sessionKey struct {
	TimeCreated time.Time `db:"time_created"`
	AuthKey     []byte    `db:"auth_key"`
	EncKey      []byte    `db:"enc_key"`
}

func getSessionKeys(ctx context.Context, dbPool *pgxpool.Pool) ([]sessionKey, error) {
	rows, err := dbPool.Query(ctx, "SELECT time_created, auth_key, enc_key FROM gorilla_session_keys ORDER BY key_order DESC")
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

func getSessionStore(ctx context.Context, logger zerolog.Logger, dbPool *pgxpool.Pool) (*sessions.CookieStore, error) {
	sessionKeys, err := getSessionKeys(ctx, dbPool)
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

	return sessionStore, nil
}

type domainVerifyData struct {
	ID                pgtype.UUID
	Name              string
	VerificationToken string
}

func verifyDomain(ctx context.Context, dbPool *pgxpool.Pool, logger zerolog.Logger, resolverAddress string, domainData domainVerifyData, udpClient *dns.Client, tcpClient *dns.Client) error {
	logger.Info().Str("name", domainData.Name).Msg("found unverified domain name")
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domainData.Name), dns.TypeTXT)
	m.SetEdns0(4096, false)
	in, rtt, err := udpClient.Exchange(m, resolverAddress)
	if err != nil {
		logger.Err(err).Dur("rtt", rtt).Str("name", domainData.Name).Msg("error looking up unverified domain via UDP")
		return err
	}

	if in.Truncated {
		logger.Error().Dur("rtt", rtt).Msg("udp query was truncated, retrying over TCP")
		in, rtt, err = tcpClient.Exchange(m, resolverAddress)
		if err != nil {
			logger.Err(err).Dur("rtt", rtt).Str("name", domainData.Name).Msg("error looking up unverified domain via TCP")
			return err
		}
	}

	if in.Rcode != dns.RcodeSuccess {
		logger.Error().Str("name", domainData.Name).Str("rcode", dns.RcodeToString[in.Rcode]).Msg("unsuccessful query rcode")
		return fmt.Errorf("unsuccessful query code")
	}

	for _, answer := range in.Answer {
		t, ok := answer.(*dns.TXT)
		if !ok {
			rrType := "unknown"
			if val, ok := dns.TypeToString[answer.Header().Rrtype]; ok {
				rrType = val
			}
			logger.Error().Str("name", domainData.Name).Str("rr_type", rrType).Msg("unable to parse entry in TXT answer section as TXT record")
			// Keep looking at any additional answers since our record might still be in there
			continue
		}

		// Handling of TXT record which contain multiple strings, e.g.:
		// record.example.com. 3600 IN TXT "a" "text" "record"
		//
		// Follow the SPF way of handling it as specified in
		// https://www.rfc-editor.org/rfc/rfc7208#section-3.3:
		// ===
		// If a published record contains multiple
		// character-strings, then the record MUST be treated
		// as if those strings are concatenated together
		// without adding spaces.
		// ===
		var b strings.Builder
		for _, s := range t.Txt {
			b.WriteString(s)
		}

		if strings.HasPrefix(b.String(), sunetTxtPrefix) {
			logger.Info().Str("txt_tag", sunetTxtTag).Msg("found tag")
			parts := strings.SplitN(b.String(), sunetTxtSeparator, 2)
			if len(parts) != 2 {
				logger.Error().Int("num_parts", len(parts)).Msg("unexpected number of parts after splitting TXT tag")
				continue
			}

			if parts[1] == domainData.VerificationToken {
				_, err := dbPool.Exec(ctx, "UPDATE domains SET verified=true WHERE id=$1", domainData.ID)
				if err != nil {
					logger.Err(err).Str("id", domainData.ID.String()).Str("name", domainData.Name).Msg("unable to update verified status for domain")
					return fmt.Errorf("unable to update database: %w", err)
				}
				logger.Info().Str("id", domainData.ID.String()).Str("name", domainData.Name).Msg("successfully verified domain")
				// We are done
				return nil
			}
		}
	}

	return errors.New("validation failed")
}

func domainVerifier(ctx context.Context, wg *sync.WaitGroup, logger zerolog.Logger, dbPool *pgxpool.Pool, resolverAddr string, verifyInterval time.Duration) {
	defer wg.Done()

	udpClient := &dns.Client{}
	tcpClient := &dns.Client{Net: "tcp"}

	for {
		select {
		case <-time.Tick(verifyInterval):
			rows, err := dbPool.Query(ctx, "SELECT id, name, verification_token FROM domains WHERE verified=false")
			if err != nil {
				logger.Err(err).Msg("lookup of unverified domains failed")
				continue
			}

			domainsToVerify, err := pgx.CollectRows(rows, pgx.RowToStructByName[domainVerifyData])
			if err != nil {
				logger.Err(err).Msg("CollectRows of unverified domains failed")
				continue
			}

			for _, domainToVerify := range domainsToVerify {
				err = verifyDomain(ctx, dbPool, logger, resolverAddr, domainToVerify, udpClient, tcpClient)
				if err != nil {
					// We already do logging etc in
					// verifyDomain(), no need to repeat
					// messages here.
					continue
				}
			}

		case <-ctx.Done():
			logger.Info().Msg("domainVerifier: shutting down")
			return
		}
	}
}

type configTemplates struct {
	vcl     *template.Template
	haproxy *template.Template
}

func setupJwkCache(ctx context.Context, logger zerolog.Logger, client *http.Client, oiConf openidConfig) (*jwk.Cache, error) {
	options := []httprc.NewClientOption{}
	options = append(
		options,
		httprc.WithErrorSink(
			errsink.NewFunc(
				func(_ context.Context, err error) {
					logger.Err(err).Msg("httprc errsink")
				},
			),
		),
	)
	options = append(options, httprc.WithHTTPClient(client))

	// First, set up the `jwk.Cache` object. You need to pass it a
	// `context.Context` object to control the lifecycle of the background fetching goroutine.
	jwkCache, err := jwk.NewCache(ctx, httprc.NewClient(options...))
	if err != nil {
		return nil, fmt.Errorf("unable to create JWK cache: %w", err)
	}

	if err := jwkCache.Register(ctx, oiConf.JwksURI); err != nil {
		return nil, fmt.Errorf("failed to register keycloak JWKS: %w", err)
	}

	return jwkCache, nil
}

func fetchKeyCloakOpenIDConfig(ctx context.Context, client *http.Client, issuer string) (oiConf openidConfig, err error) {
	openidConfigURL, err := url.JoinPath(issuer, ".well-known/openid-configuration")
	if err != nil {
		return openidConfig{}, fmt.Errorf("unable to parse keycloak openid-configuration URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openidConfigURL, nil)
	if err != nil {
		return openidConfig{}, fmt.Errorf("unable to create GET req for OpenID config: %w", err)
	}

	confResp, err := client.Do(req)
	if err != nil {
		return openidConfig{}, fmt.Errorf("unable to GET OpenID config: %w", err)
	}
	defer func() {
		err = errors.Join(err, confResp.Body.Close())
	}()

	if confResp.StatusCode != http.StatusOK {
		return openidConfig{}, fmt.Errorf("unexpected status code: %d", confResp.StatusCode)
	}

	confData, err := io.ReadAll(confResp.Body)
	if err != nil {
		return openidConfig{}, fmt.Errorf("unable to read response body: %w", err)
	}

	err = json.Unmarshal(confData, &oiConf)
	if err != nil {
		return openidConfig{}, fmt.Errorf("unable to unmarshal openid-configuration JSON: %w", err)
	}

	return oiConf, nil
}

func newKeycloakClientManager(logger zerolog.Logger, baseURL *url.URL, realm string, createClient *http.Client, deleteClient *http.Client) *keycloakClientManager {
	return &keycloakClientManager{
		realm:        realm,
		createClient: createClient,
		deleteClient: deleteClient,
		baseURL:      baseURL,
		logger:       logger,
	}
}

type dbConn struct {
	dbPool       *pgxpool.Pool
	queryTimeout time.Duration
}

func newDBConn(dbPool *pgxpool.Pool, queryTimeout time.Duration) (*dbConn, error) {
	if dbPool == nil {
		return nil, errors.New("dbPool must not be nil")
	}

	return &dbConn{
		dbPool:       dbPool,
		queryTimeout: queryTimeout,
	}, nil
}

// detachedContext is used in functions that want to modify the database. We
// give such functions a chance to complete the database requests instead of
// instantly getting cancelled in case the server is told to shut down.
func (dbc *dbConn) detachedContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), dbc.queryTimeout)
}

func (dbc *dbConn) detachedContextWithDuration(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), timeout)
}

func retryWithBackoff(ctx context.Context, logger zerolog.Logger, sleepBase time.Duration, sleepCap time.Duration, attempts int, description string, operation func(context.Context) error) error {
	var err error

	if sleepBase <= 0 {
		return fmt.Errorf("sleepBase must be larger than 0")
	}

	if sleepCap < sleepBase {
		return fmt.Errorf("sleepCap must be equal to or larger than sleepBase")
	}

	if attempts <= 0 {
		return fmt.Errorf("attempts must be larger than 0")
	}

	for attempt := range attempts {
		err = operation(ctx)
		if err == nil {
			if attempt > 0 {
				logger.Info().Int("attempt", attempt+1).Msgf("retryWithBackoff: operation '%s' succeeded after retries", description)
			}
			break
		}

		if attempt < attempts-1 {
			// Exponential backoff
			sleepDuration := min(sleepCap, sleepBase*(1<<attempt))
			// Add jitter
			sleepDuration = sleepDuration/2 + time.Duration(mrand.Int64N(int64(sleepDuration/2))) // #nosec G404 -- no need for cryptographically secure randomness for backoff timer
			logger.Err(err).Msgf("retryWithBackoff: operation '%s' failed, sleeping for %s", description, sleepDuration)
			select {
			case <-ctx.Done():
				return fmt.Errorf("retryWithBackoff: context cancelled while waiting for '%s': %w", description, ctx.Err())
			case <-time.After(sleepDuration):
			}
		} else {
			logger.Err(err).Msgf("retryWithBackoff: hit retry limit, giving up on '%s'", description)
		}
	}
	if err != nil {
		return fmt.Errorf("retryWithBackoff: '%s' failed after %d attempts: %w", description, attempts, err)
	}

	return nil
}

func Run(debug bool, localViper *viper.Viper, logger zerolog.Logger, devMode bool, shutdownDelay time.Duration, disableDomainVerification bool, disableAcme bool, tlsCertFile string, tlsKeyFile string) error {
	if debug {
		logger = logger.Level(zerolog.DebugLevel)
	}

	// runCtx is the main context relating to the running of the server
	// process. It will be cancelled when told to stop via signals.
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	// Exit gracefully on SIGINT or SIGTERM
	go func(logger zerolog.Logger, cancel context.CancelFunc) {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		s := <-sigCh
		logger.Info().Str("signal", s.String()).Msg("received signal")
		cancel()
	}(logger, runCancel)

	conf, err := config.GetConfig(localViper)
	if err != nil {
		return fmt.Errorf("unable to get config: %w", err)
	}

	pgConfig, err := conf.PGConfig()
	if err != nil {
		return fmt.Errorf("unable to parse PostgreSQL config string: %w", err)
	}

	dbPool, err := pgxpool.NewWithConfig(runCtx, pgConfig)
	if err != nil {
		return fmt.Errorf("unable to create database pool: %w", err)
	}
	defer dbPool.Close()

	logger.Info().Msg("checking DB connection")
	err = retryWithBackoff(
		runCtx,
		logger,
		time.Second*1,
		time.Second*30,
		10,
		"ping DB",
		dbPool.Ping,
	)
	if err != nil {
		return fmt.Errorf("pinging database connection failed: %w", err)
	}

	// Verify that the database appears initialized by 'init' command
	var rolesExists bool
	err = dbPool.QueryRow(runCtx, "SELECT EXISTS(SELECT 1 FROM roles)").Scan(&rolesExists)
	if err != nil {
		return fmt.Errorf("unable to check for roles in the database, is it initialized? (see init command): %w", err)
	}
	if !rolesExists {
		return errors.New("we exepect there to exist at least one role in the database, make sure the database is initialized via the 'init' command")
	}

	cookieStore, err := getSessionStore(runCtx, logger, dbPool)
	if err != nil {
		return fmt.Errorf("getSessionStore failed: %w", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	if devMode {
		logger.Info().Msg("disabling cert validation for OIDC discovery due to dev mode")
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- only enabled in --dev mode
		}
		client.Transport = tr
	}

	providerCtx := oidc.ClientContext(runCtx, client)
	logger.Info().Msg("setting up OIDC provider")
	var provider *oidc.Provider
	err = retryWithBackoff(
		providerCtx,
		logger,
		time.Second*1,
		time.Second*30,
		10,
		"reach OIDC provider",
		func(ctx context.Context) error {
			provider, err = oidc.NewProvider(ctx, conf.OIDC.Issuer)
			return err
		},
	)
	if err != nil {
		return fmt.Errorf("setting up OIDC provider failed: %w", err)
	}

	cc := clientcredentials.Config{
		ClientID:     conf.KeycloakClientAdmin.ClientID,
		ClientSecret: conf.KeycloakClientAdmin.ClientSecret,
		TokenURL:     provider.Endpoint().TokenURL,
	}

	kcClientBaseURL, err := url.Parse(conf.KeycloakClientAdmin.BaseURL)
	if err != nil {
		return fmt.Errorf("parsing Keycloak base URL failed: %w", err)
	}

	// Client used for creating client credentials in keycloak
	kcClientManager := newKeycloakClientManager(logger, kcClientBaseURL, conf.KeycloakClientAdmin.Realm, cc.Client(providerCtx), client)

	vclValidationURL, err := url.Parse(conf.Server.VCLValidationURL)
	if err != nil {
		return fmt.Errorf("parsing VCL validation URL failed: %w", err)
	}

	vclValidator := newVclValidator(vclValidationURL)

	confTemplates := configTemplates{}

	confTemplates.vcl, err = template.ParseFS(templateFS, "templates/sunet-cdn.vcl")
	if err != nil {
		return fmt.Errorf("unable to create varnish template: %w", err)
	}

	confTemplates.haproxy, err = template.ParseFS(templateFS, "templates/haproxy.cfg")
	if err != nil {
		return fmt.Errorf("unable to create haproxy template: %w", err)
	}

	var argon2Mutex sync.Mutex

	loginCache, err := lru.New[string, struct{}](128)
	if err != nil {
		return fmt.Errorf("unable to create LRU login cache: %w", err)
	}

	dbc, err := newDBConn(dbPool, conf.DB.QueryTimeout)
	if err != nil {
		return fmt.Errorf("unable to create db conn struct: %w", err)
	}

	// Fetch openid-configuration from keycloak manually (even if already
	// done by oidc.NewProvider() above) because the struct returned by
	// provider.Endpoint() does not give access to the JwksURI that we need
	// for fetching JWT keysets. This does result in a duplicate HTTP
	// request on startup but it is good enough for now.
	oiConf, err := fetchKeyCloakOpenIDConfig(runCtx, client, conf.OIDC.Issuer)
	if err != nil {
		return fmt.Errorf("unable to fetch openid-configuration: %w", err)
	}

	jwkCache, err := setupJwkCache(runCtx, logger, client, oiConf)
	if err != nil {
		return fmt.Errorf("unable to setup JWK cache: %w", err)
	}

	jwkCacheReadyCtx, jwkCacheReadyCancel := context.WithTimeout(runCtx, time.Second*60)
	defer jwkCacheReadyCancel()

	logger.Info().Msg("waiting for JWK cache to be ready")
	ready := jwkCache.Ready(jwkCacheReadyCtx, oiConf.JwksURI)
	if !ready {
		return fmt.Errorf("JWK cache is not ready")
	}

	clientCredKeys, err := getClientCredEncryptionKeys(conf)
	if err != nil {
		return fmt.Errorf("unable to get client cred encryption key: %w", err)
	}

	clientCredAEADs := []cipher.AEAD{}
	clientCredNonceSize := 0
	for i, clientCredKey := range clientCredKeys {
		clientCredAEAD, err := chacha20poly1305.NewX(clientCredKey)
		if err != nil {
			return fmt.Errorf("unable to create client cred AEAD for encryption password with offset %d: %w", i, err)
		}
		// As the code that manages client cred re-encryption expects
		// the nonce size to be the same for all AEADs in the slice,
		// verify this here in case that ever changes.
		if i == 0 {
			clientCredNonceSize = clientCredAEAD.NonceSize()
		} else {
			if clientCredAEAD.NonceSize() != clientCredNonceSize {
				return fmt.Errorf("the code expects all clientCred nonce sizes to be the same: prev: %d, cur: %d", clientCredNonceSize, clientCredAEAD.NonceSize())
			}
		}
		clientCredAEADs = append(clientCredAEADs, clientCredAEAD)
	}

	parsedTokenURL, err := url.Parse(provider.Endpoint().TokenURL)
	if err != nil {
		return fmt.Errorf("unable to parse token URL: %w", err)
	}

	serverURL, err := url.Parse(conf.Server.URL)
	if err != nil {
		return fmt.Errorf("unable to parse server URL '%s': %w", conf.Server.URL, err)
	}

	router := newChiRouter(conf, logger, dbc, &argon2Mutex, loginCache, cookieStore, provider, vclValidator, confTemplates, devMode, clientCredAEADs, kcClientManager, parsedTokenURL, serverURL)

	err = setupHumaAPI(router, dbc, &argon2Mutex, loginCache, vclValidator, confTemplates, kcClientManager, jwkCache, conf.OIDC.Issuer, oiConf, clientCredAEADs, serverURL)
	if err != nil {
		return fmt.Errorf("unable to setup Huma API: %w", err)
	}

	var wg sync.WaitGroup
	if disableDomainVerification {
		logger.Info().Msg("domain verification is disabled")
	} else {
		logger.Info().Msg("domain verification is enabled")
		wg.Add(1)
		go domainVerifier(runCtx, &wg, logger, dbPool, conf.Domains.ResolverAddr, conf.Domains.VerifyInterval)
	}

	var tlsConfig *tls.Config

	if disableAcme {
		logger.Info().Str("cert_file", tlsCertFile).Str("key_file", tlsCertFile).Msg("ACME is disabled, using files for TLS")
		cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load key pair: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		logger.Info().Msg("using ACME for TLS cert")
		tlsConfig = setupACME(logger, conf)
	}

	srv := &http.Server{
		TLSConfig:    tlsConfig,
		Addr:         conf.Server.Addr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: conf.DB.QueryTimeout + 5*time.Second,
		ErrorLog:     log.New(&zerologErrorWriter{&logger}, "", 0),
	}

	// Handle graceful shutdown of HTTP server when receiving signal
	idleConnsClosed := make(chan struct{})

	go func(ctx context.Context, logger zerolog.Logger, shutdownDelay time.Duration) {
		<-ctx.Done()

		logger.Info().Msgf("sleeping for %s then calling Shutdown()", shutdownDelay)
		time.Sleep(shutdownDelay)

		// Do not wait indefinitely for shutdown
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Err(err).Msg("HTTP server Shutdown() failure")
		}
		close(idleConnsClosed)
	}(runCtx, logger, shutdownDelay)

	logger.Info().Str("addr", conf.Server.Addr).Msg("starting HTTPS listener")

	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		return fmt.Errorf("HTTPS server ListenAndServe failed: %w", err)
	}

	<-idleConnsClosed

	// Wait for workers to complete
	wg.Wait()

	return nil
}
