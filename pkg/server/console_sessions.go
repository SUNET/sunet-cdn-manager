package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/SUNET/sunet-cdn-manager/pkg/consolesession"
	"github.com/gorilla/securecookie"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

// Console sessions.
//
// The session cookie only carries the token of a console_sessions row.
// Every request looks the session and the user's current rights up in the
// database. The pre-login cookie carries what an anonymous browser needs
// before it has a session: the page to return to after login and the OIDC
// state, nonce and PKCE verifier. It is never trusted for authentication.
const (
	sessionCookieName  = "__Host-sunet-cdn-manager-id"
	preLoginCookieName = "__Host-sunet-cdn-manager-pre"

	// How long a pre-login cookie is accepted after it was written
	preLoginMaxAge = 10 * time.Minute
)

// preLoginData is the content of the pre-login cookie.
type preLoginData struct {
	ReturnTo string            `json:"return_to,omitempty"`
	OIDC     *oidcCallbackData `json:"oidc,omitempty"`
}

// preLoginCookies encodes the pre-login cookie with the keys in the
// gorilla_session_keys table: signed, and encrypted when the key has an
// encryption part.
type preLoginCookies struct {
	codecs []securecookie.Codec
}

// newPreLoginCookies creates the codecs. keys[0], the newest key, is used for
// writing and all of them for reading. maxAge is how long a written cookie
// is accepted. It is required: securecookie defaults to 30 days and
// MaxAge(0) turns the timestamp check off.
func newPreLoginCookies(keys []sessionKey, maxAge time.Duration) (*preLoginCookies, error) {
	if len(keys) == 0 {
		return nil, errors.New("newPreLoginCookies: no session keys")
	}

	maxAgeSeconds := int(maxAge / time.Second)
	if maxAgeSeconds < 1 {
		return nil, fmt.Errorf("newPreLoginCookies: max age must be at least 1s, got %s", maxAge)
	}

	codecs := make([]securecookie.Codec, 0, len(keys))
	for _, key := range keys {
		sc := securecookie.New(key.AuthKey, key.EncKey)
		sc.MaxAge(maxAgeSeconds)
		// JSON instead of the default gob: the cookie holds one concrete
		// struct, so gob's support for interface values is not needed,
		// and gob adds its type descriptions to every cookie.
		sc.SetSerializer(securecookie.JSONEncoder{})
		codecs = append(codecs, sc)
	}

	return &preLoginCookies{codecs: codecs}, nil
}

// read returns the pre-login data of r. It returns the zero value and an
// error if the cookie is missing (http.ErrNoCookie), was tampered with or
// is older than the max age.
func (p *preLoginCookies) read(r *http.Request) (preLoginData, error) {
	cookie, err := r.Cookie(preLoginCookieName)
	if err != nil {
		return preLoginData{}, err
	}

	var d preLoginData
	err = securecookie.DecodeMulti(preLoginCookieName, cookie.Value, &d, p.codecs...)
	if err != nil {
		return preLoginData{}, err
	}

	return d, nil
}

// write sets the pre-login cookie to d.
func (p *preLoginCookies) write(w http.ResponseWriter, d preLoginData) error {
	value, err := securecookie.EncodeMulti(preLoginCookieName, d, p.codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, newHostCookie(preLoginCookieName, value))
	return nil
}

// newHostCookie returns a cookie that meets the requirements of the
// __Host- prefix (Secure, Path=/, no Domain). It has no Max-Age or
// Expires, so the browser keeps it for the browser session only. The
// server enforces every lifetime itself; closing the browser is not a
// logout.
func newHostCookie(name string, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// clearCookie tells the browser to drop the named __Host- cookie.
func clearCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- newHostCookie sets Secure, HttpOnly and SameSite, MaxAge only expires it
	c := newHostCookie(name, "")
	c.MaxAge = -1
	http.SetCookie(w, c)
}

const (
	// How often expired sessions and stale flash messages are deleted
	consoleSessionSweepInterval = 5 * time.Minute

	loginMethodLocal    = "local"
	loginMethodKeycloak = "keycloak"

	oidcLoginExpired = "login expired, please try again"
)

// newConsoleSessions creates the session store and the pre-login cookie
// codecs. idleTimeout and absoluteTimeout are console_session_max_age and
// console_session_cap_age.
func newConsoleSessions(ctx context.Context, logger zerolog.Logger, dbPool *pgxpool.Pool, idleTimeout time.Duration, absoluteTimeout time.Duration, preLoginCookieMaxAge time.Duration) (*consolesession.Store, *preLoginCookies, error) {
	keys, err := getSessionKeys(ctx, dbPool)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find session keys in database, make sure the database is initialized via the 'init' command: %w", err)
	}

	if keys[0].EncKey == nil {
		logger.Info().Msg("session key has no encryption key, using unencrypted pre-login cookies")
	} else {
		logger.Info().Msg("session key has an encryption key, using encrypted pre-login cookies")
	}

	preLogin, err := newPreLoginCookies(keys, preLoginCookieMaxAge)
	if err != nil {
		return nil, nil, err
	}

	store, err := consolesession.NewStore(dbPool, idleTimeout, absoluteTimeout)
	if err != nil {
		return nil, nil, err
	}

	return store, preLogin, nil
}

// sessionHandleKey is the request context key of the *sessionHandle.
type sessionHandleKey struct{}

// sessionHandle is the console session of an authenticated request.
type sessionHandle struct {
	store *consolesession.Store
	id    pgtype.UUID
	// orgSelected is false until the org switcher was used, or the
	// dashboard picked the user's own org, see consoleDashboardHandler.
	orgSelected bool
	// selectedOrgName is the org shown in the org switcher, "" for none.
	// It is a display preference only and never grants access. An org
	// the user may no longer use is not returned here.
	selectedOrgName string
	hasFlashes      bool
}

// addFlash stores a message to show on the next page of category. orgID is
// nil for global (superuser) pages. If the session ended during the request,
// e.g. because a superuser changed their own password, the message is
// dropped.
func (sh *sessionHandle) addFlash(ctx context.Context, category consolesession.FlashCategory, orgID *pgtype.UUID, msg string) error {
	err := sh.store.AddFlash(ctx, sh.id, category, orgID, msg)
	if errors.Is(err, consolesession.ErrFlashTargetGone) {
		// The request logger already carries session_id
		zerolog.Ctx(ctx).Info().Msg("session or org no longer exists, dropping flash message")
		return nil
	}
	return err
}

// popFlashes returns the messages for category and orgID. Without flashes
// in the session it returns right away, so a normal page view runs no
// query for them.
func (sh *sessionHandle) popFlashes(ctx context.Context, category consolesession.FlashCategory, orgID *pgtype.UUID) ([]string, error) {
	if !sh.hasFlashes {
		return []string{}, nil
	}

	messages, err := sh.store.PopFlashes(ctx, sh.id, category, orgID)
	if err != nil {
		return nil, err
	}
	if messages == nil {
		messages = []string{}
	}

	return messages, nil
}

// popOrgFlashes is popFlashes for an org page. orgID must come from the
// page's own scoped lookup of the org (resolveConsoleOrg).
func (sh *sessionHandle) popOrgFlashes(ctx context.Context, category consolesession.FlashCategory, orgID pgtype.UUID) ([]string, error) {
	if !sh.hasFlashes {
		return []string{}, nil
	}

	return sh.popFlashes(ctx, category, &orgID)
}

// setSelectedOrg stores the org picked in the org switcher, nil for an
// explicit "no org".
func (sh *sessionHandle) setSelectedOrg(ctx context.Context, orgID *pgtype.UUID) error {
	return sh.store.SetSelectedOrg(ctx, sh.id, orgID)
}

// scanConsoleAuth builds AuthData from a row selected by loadUserAuth or
// loadSessionAuth. It also returns the id and name of the selected org, nil
// and "" if there is none or it no longer exists.
func scanConsoleAuth(row pgx.Row) (cdntypes.AuthData, *pgtype.UUID, string, error) {
	var userID, roleID pgtype.UUID
	var displayName, roleName string
	var orgID, selectedOrgID *pgtype.UUID // nil if none
	var orgName, selectedOrgName *string  // same as above
	var superuser bool
	err := row.Scan(
		&userID,
		&displayName,
		&orgID,
		&orgName,
		&roleID,
		&roleName,
		&superuser,
		&selectedOrgID,
		&selectedOrgName,
	)
	if err != nil {
		return cdntypes.AuthData{}, nil, "", err
	}

	ad := cdntypes.AuthData{
		Username:  &displayName,
		UserID:    &userID,
		OrgID:     orgID,
		OrgName:   orgName,
		RoleID:    roleID,
		RoleName:  roleName,
		Superuser: superuser,
	}

	selected := ""
	if selectedOrgName != nil {
		selected = *selectedOrgName
	}

	return ad, selectedOrgID, selected, nil
}

// loadUserAuth builds the AuthData of a console user from the database. It
// returns pgx.ErrNoRows if the user does not exist.
//
// It is for a login, before the session exists. A request with a session
// must use loadSessionAuth instead, which reads the rights together with
// the session row (see there for why).
func loadUserAuth(ctx context.Context, dbc *dbConn, userID pgtype.UUID) (cdntypes.AuthData, error) {
	// Without a session there is no selected org
	ad, _, _, err := scanConsoleAuth(dbc.dbPool.QueryRow(
		ctx,
		`SELECT users.id, users.display_name, users.org_id, orgs.name,
		        users.role_id, roles.name, roles.superuser, NULL::uuid, NULL::text
		 FROM users
		 JOIN roles ON users.role_id = roles.id
		 LEFT JOIN orgs ON users.org_id = orgs.id
		 WHERE users.id = $1`,
		userID,
	))
	return ad, err
}

// loadSessionAuth builds the AuthData of the user of session sessionID and
// returns the id and current name of the org selected in the session, nil
// and "" if there is none or it no longer exists. The caller decides if the
// user may use it. It returns pgx.ErrNoRows if the session or its user no
// longer exists.
//
// The session row and the rights are read in one statement, so they come
// from the same snapshot. A role or org change ends the sessions of the
// user in the same transaction (see updateUser), so this either sees the
// old rights and the session, or no session. Reading the rights in a
// statement of their own after store.Lookup could combine a session that
// was just ended with the new rights.
func loadSessionAuth(ctx context.Context, dbc *dbConn, sessionID pgtype.UUID) (cdntypes.AuthData, *pgtype.UUID, string, error) {
	return scanConsoleAuth(dbc.dbPool.QueryRow(
		ctx,
		`SELECT users.id, users.display_name, users.org_id, orgs.name,
		        users.role_id, roles.name, roles.superuser, sel.id, sel.name
		 FROM console_sessions s
		 JOIN users ON users.id = s.user_id
		 JOIN roles ON users.role_id = roles.id
		 LEFT JOIN orgs ON users.org_id = orgs.id
		 LEFT JOIN orgs sel ON sel.id = s.selected_org_id
		 WHERE s.id = $1`,
		sessionID,
	))
}

// selectedOrgAllowed applies the membership rule of the org pages to the
// org switcher selection: superusers may use any org, other users only
// their own. selectedOrgID is nil if nothing is selected.
func selectedOrgAllowed(ad cdntypes.AuthData, selectedOrgID *pgtype.UUID) bool {
	if selectedOrgID == nil {
		return false
	}
	if ad.Superuser {
		return true
	}
	return ad.OrgID != nil && *ad.OrgID == *selectedOrgID
}

// authenticateConsoleRequest checks the session cookie of r against the
// database and loads the user's current rights. It returns a nil
// *sessionHandle for an anonymous request and clears a cookie it rejected.
// An error means the database could not be asked: nothing is written to w,
// the cookie is kept and the caller answers with an error.
func authenticateConsoleRequest(w http.ResponseWriter, r *http.Request, dbc *dbConn, store *consolesession.Store) (cdntypes.AuthData, *sessionHandle, error) {
	logger := hlog.FromRequest(r)

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		// No session cookie, the request is anonymous
		return cdntypes.AuthData{}, nil, nil
	}

	// Never log the cookie value, it contains the secret
	tok, err := consolesession.ParseToken(cookie.Value)
	if err != nil {
		logger.Warn().Str("reason", "malformed").Msg("session_invalid")
		clearCookie(w, sessionCookieName)
		return cdntypes.AuthData{}, nil, nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbc.queryTimeout)
	defer cancel()

	sess, err := store.Lookup(ctx, tok)
	if err != nil {
		switch {
		case errors.Is(err, consolesession.ErrNotFound):
			// Info, not warn: sessions that expired and were swept, and
			// revoked sessions, end up here in normal use. A blindly
			// guessed cookie also ends up here, its id does not exist.
			// bad_secret is the warning sign: a real id without its
			// secret.
			logger.Info().Str("reason", "unknown").Str("session_id", tok.ID.String()).Msg("session_invalid")
		case errors.Is(err, consolesession.ErrBadSecret):
			logger.Warn().Str("reason", "bad_secret").Str("session_id", tok.ID.String()).Msg("session_invalid")
		case errors.Is(err, consolesession.ErrIdleExpired), errors.Is(err, consolesession.ErrAbsoluteExpired):
			reason := "idle"
			if errors.Is(err, consolesession.ErrAbsoluteExpired) {
				reason = "absolute"
			}
			// err also carries a failure to delete the row, the
			// sweeper removes it later
			logger.Info().Err(err).Str("reason", reason).Str("session_id", tok.ID.String()).Str("target_user_id", sess.UserID.String()).Msg("session_expired")
		default:
			return cdntypes.AuthData{}, nil, fmt.Errorf("unable to look up console session: %w", err)
		}
		clearCookie(w, sessionCookieName)
		return cdntypes.AuthData{}, nil, nil
	}

	if sess.TouchDue {
		err := store.Touch(ctx, sess.ID)
		if err != nil {
			// The session stays valid, a later request updates last_seen
			logger.Err(err).Str("session_id", sess.ID.String()).Msg("unable to update session last_seen")
		}
	}

	ad, selectedOrgID, selectedOrgName, err := loadSessionAuth(ctx, dbc, sess.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The session was ended, or its user deleted, after the
			// lookup above
			logger.Info().Str("session_id", sess.ID.String()).Str("target_user_id", sess.UserID.String()).Msg("session or its user no longer exists")
			clearCookie(w, sessionCookieName)
			return cdntypes.AuthData{}, nil, nil
		}
		return cdntypes.AuthData{}, nil, fmt.Errorf("unable to load console user: %w", err)
	}

	// Drop a selection the user may no longer use, e.g. after a superuser
	// was demoted. selectedOrgID is also nil for a deleted org.
	if !selectedOrgAllowed(ad, selectedOrgID) {
		selectedOrgName = ""
	}

	addUserToRequestLog(logger, ad)
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("session_id", sess.ID.String())
	})

	return ad, &sessionHandle{
		store:           store,
		id:              sess.ID,
		orgSelected:     sess.OrgSelected,
		selectedOrgName: selectedOrgName,
		hasFlashes:      sess.HasFlashes,
	}, nil
}

// argon2KeyStillCurrent locks the argon2 row of userID and checks that it
// still holds verifiedKey, the key a login password was checked against
// outside of any transaction. A password change in between makes it return
// cdnerrors.ErrBadPassword. Unlike the FOR UPDATE in argon2KeyUnchanged,
// FOR SHARE lets logins of the same user run in parallel while still
// waiting for, or blocking, a password change.
func argon2KeyStillCurrent(ctx context.Context, tx pgx.Tx, userID pgtype.UUID, verifiedKey []byte) error {
	var storedKey []byte
	err := tx.QueryRow(ctx, "SELECT key FROM user_argon2keys WHERE user_id = $1 FOR SHARE", userID).Scan(&storedKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cdnerrors.ErrBadPassword
		}
		return fmt.Errorf("argon2KeyStillCurrent: unable to look up argon2 key: %w", err)
	}

	if subtle.ConstantTimeCompare(storedKey, verifiedKey) != 1 {
		return cdnerrors.ErrBadPassword
	}

	return nil
}

// destroyRequestSession ends the session of the cookie r carries, but only
// if its secret matches. A missing, malformed, unknown or wrong cookie is
// ignored.
func destroyRequestSession(ctx context.Context, r *http.Request, store *consolesession.Store, reason string) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}

	tok, err := consolesession.ParseToken(cookie.Value)
	if err != nil {
		return nil
	}

	userID, err := store.Destroy(ctx, tok)
	switch {
	case err == nil:
		hlog.FromRequest(r).Info().Str("reason", reason).Str("session_id", tok.ID.String()).Str("target_user_id", userID.String()).Msg("session_destroyed")
		return nil
	case errors.Is(err, consolesession.ErrNotFound), errors.Is(err, consolesession.ErrBadSecret):
		return nil
	default:
		return err
	}
}

// startConsoleSession logs in userID: it ends the session the browser had
// before, creates a new one and redirects to the stored return-to path.
// The old session is ended because the new cookie replaces its cookie, e.g.
// when someone logs in again without logging out first: the browser could
// no longer log it out, but a copy of the old cookie would stay valid until
// the session timed out.
//
// For a local login verifiedKey is the argon2 key the password was
// checked against; if the password changed since then the login fails with
// cdnerrors.ErrBadPassword, as it does if the user no longer exists. Nothing
// is written to w when an error is returned.
func startConsoleSession(w http.ResponseWriter, r *http.Request, dbc *dbConn, store *consolesession.Store, preLogin *preLoginCookies, userID pgtype.UUID, method string, verifiedKey []byte) error {
	logger := hlog.FromRequest(r)

	dbCtx, cancel := dbc.detachedContext(r.Context())
	defer cancel()

	err := destroyRequestSession(dbCtx, r, store, "login")
	if err != nil {
		return fmt.Errorf("unable to end the previous session: %w", err)
	}

	// A new id and secret every time, an id sent by the client is never
	// adopted and no rows exist before login, so session fixation is not
	// possible.
	var tok consolesession.Token
	err = pgx.BeginFunc(dbCtx, dbc.dbPool, func(tx pgx.Tx) error {
		// Lock the users row first, then the argon2 row: the same order
		// as setLocalPassword (users FOR SHARE, then argon2) and
		// deleteUser (DELETE of the users row, then the cascade into
		// user_argon2keys and console_sessions). updateUser takes the
		// users row first and then deletes the user's console_sessions
		// rows, which cannot deadlock with a login: the login only
		// inserts a fresh row. Taking the argon2 lock first and the
		// users lock later, which the console_sessions insert does
		// through its foreign key, would make a login and a deleteUser
		// wait for each other (SQLSTATE 40P01). FOR KEY SHARE is all the
		// foreign key needs and does not conflict with the FOR SHARE of
		// setLocalPassword. A user deleted in the meantime is answered
		// like an unknown user.
		var one int
		err := tx.QueryRow(dbCtx, "SELECT 1 FROM users WHERE id = $1 FOR KEY SHARE", userID).Scan(&one)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return cdnerrors.ErrBadPassword
			}
			return fmt.Errorf("unable to lock user: %w", err)
		}

		if verifiedKey != nil {
			// The password was checked against verifiedKey outside
			// this transaction. argon2KeyStillCurrent locks the
			// argon2 row, which orders this login and a password
			// change (see setLocalPassword) one of two ways:
			//   - the change locks the row first: this lock waits
			//     for it to commit, sees the new key and the login
			//     fails
			//   - this login locks the row first: the change waits
			//     until this transaction has committed the session
			//     row, then its DeleteForUserTx deletes it
			// Either way no session made with the old password
			// survives the change.
			err := argon2KeyStillCurrent(dbCtx, tx, userID, verifiedKey)
			if err != nil {
				return err
			}
		}

		tok, err = consolesession.CreateTx(dbCtx, tx, userID)
		return err
	})
	if err != nil {
		return err
	}

	returnTo := consolePath
	pre, err := preLogin.read(r)
	if err == nil && pre.ReturnTo != "" {
		returnTo = pre.ReturnTo
	}

	clearCookie(w, preLoginCookieName)
	http.SetCookie(w, newHostCookie(sessionCookieName, tok.String()))

	logger.Info().Str("session_id", tok.ID.String()).Str("target_user_id", userID.String()).Str("method", method).Msg("session_created")

	logger.Info().Str("return_to", returnTo).Msg("redirecting logged-in user")
	validatedRedirect(returnTo, w, r, http.StatusFound)

	return nil
}

// noStoreMiddleware stops browsers and proxies from storing console and
// login responses.
func noStoreMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// consoleSessionSweeper deletes expired console sessions and stale flash
// messages every interval. Correctness does not depend on it, every
// session check enforces the timeouts itself. It only keeps the tables
// small, and is safe to run on several instances.
func consoleSessionSweeper(ctx context.Context, logger zerolog.Logger, store *consolesession.Store, interval time.Duration) {
	for {
		select {
		case <-time.After(interval):
			sessions, flashes, err := store.Sweep(ctx)
			if err != nil {
				logger.Err(err).Msg("consoleSessionSweeper: unable to remove expired sessions")
				continue
			}
			if sessions > 0 || flashes > 0 {
				logger.Info().Int64("sessions", sessions).Int64("flashes", flashes).Msg("consoleSessionSweeper: removed expired console sessions and flash messages")
			}
		case <-ctx.Done():
			logger.Info().Msg("consoleSessionSweeper: shutting down")
			return
		}
	}
}

// consoleSessionMiddleware only lets requests with a valid console session
// through, with the user's current AuthData and the *sessionHandle in the
// request context. Other requests are sent to the login page.
func consoleSessionMiddleware(dbc *dbConn, store *consolesession.Store, preLogin *preLoginCookies) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			ad, sh, err := authenticateConsoleRequest(w, r, dbc, store)
			if err != nil {
				logger.Err(err).Msg("consoleSessionMiddleware: unable to check session")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if sh == nil {
				logger.Info().Msg("consoleSessionMiddleware: redirecting to login page")
				redirectToLoginPage(w, r, preLogin)
				return
			}

			ctx := context.WithValue(r.Context(), authDataKey{}, ad)
			ctx = context.WithValue(ctx, sessionHandleKey{}, sh)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
