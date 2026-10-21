package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/PuerkitoBio/goquery"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/SUNET/sunet-cdn-manager/pkg/consolesession"
	"github.com/gorilla/securecookie"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

func newTestSessionKey(encrypted bool) sessionKey {
	key := sessionKey{AuthKey: securecookie.GenerateRandomKey(32)}
	if encrypted {
		key.EncKey = securecookie.GenerateRandomKey(32)
	}
	return key
}

func newTestPreLoginCookies(t *testing.T, maxAge time.Duration, keys ...sessionKey) *preLoginCookies {
	t.Helper()
	p, err := newPreLoginCookies(keys, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// writePreLogin writes d with p and returns the cookie it set.
func writePreLogin(t *testing.T, p *preLoginCookies, d preLoginData) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := p.write(rec, d); err != nil {
		t.Fatal(err)
	}
	return findCookie(t, rec.Result().Cookies(), preLoginCookieName)
}

// findCookie returns the cookie called name, failing the test if there is
// none.
func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", name, cookies)
	return nil
}

// testRequest returns a request carrying cookies, with a test logger in its
// context the way hlog.NewHandler puts one there.
func testRequest(t *testing.T, method string, target string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	logger := zerolog.New(zerolog.NewTestWriter(t))
	return r.WithContext(logger.WithContext(r.Context()))
}

// assertHostCookie checks the attributes every console cookie needs. The
// Set-Cookie that clears a cookie needs them too: browsers ignore a
// __Host- cookie without them, so the cookie would not be deleted.
func assertHostCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %s: want Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain, got %+v", c.Name, c)
	}
}

// requireNonPersistentHostCookie checks a cookie that is being set: the
// host cookie attributes and no Max-Age or Expires.
func requireNonPersistentHostCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	assertHostCookie(t, c)
	if c.MaxAge != 0 || !c.Expires.IsZero() || c.RawExpires != "" {
		t.Fatalf("cookie %s must not have Max-Age or Expires: %+v", c.Name, c)
	}
}

// tamper changes one character in the middle of s.
func tamper(s string) string {
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestPreLoginCookieRoundTrip(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			p := newTestPreLoginCookies(t, preLoginMaxAge, newTestSessionKey(encrypted))
			want := preLoginData{
				ReturnTo: "/console/org/org1/domains",
				OIDC:     &oidcCallbackData{State: "state", Nonce: "nonce", PKCEVerifier: "verifier"},
			}

			c := writePreLogin(t, p, want)
			requireNonPersistentHostCookie(t, c)

			got, err := p.read(testRequest(t, http.MethodGet, "/", c))
			if err != nil {
				t.Fatal(err)
			}
			if got.ReturnTo != want.ReturnTo || got.OIDC == nil || *got.OIDC != *want.OIDC {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

// TestPreLoginCookieRejects checks that read only accepts a pre-login cookie
// it wrote itself, under its own name and with its own keys.
func TestPreLoginCookieRejects(t *testing.T) {
	p := newTestPreLoginCookies(t, preLoginMaxAge, newTestSessionKey(true))
	other := newTestPreLoginCookies(t, preLoginMaxAge, newTestSessionKey(true))
	d := preLoginData{ReturnTo: "/console"}

	if _, err := p.read(testRequest(t, http.MethodGet, "/")); err == nil {
		t.Fatal("a missing cookie was accepted")
	}

	// The cookie name is part of the MAC, a value made for another cookie
	// is rejected
	otherName, err := securecookie.EncodeMulti("some-other-cookie", d, p.codecs...)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		value string
	}{
		{name: "tampered", value: tamper(writePreLogin(t, p, d).Value)},
		{name: "other cookie name", value: otherName},
		{name: "other keys", value: writePreLogin(t, other, d).Value},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newHostCookie(preLoginCookieName, test.value)
			if _, err := p.read(testRequest(t, http.MethodGet, "/", c)); err == nil {
				t.Fatal("the cookie was accepted")
			}
		})
	}
}

func TestPreLoginCookieExpires(t *testing.T) {
	p := newTestPreLoginCookies(t, time.Second, newTestSessionKey(true))
	c := writePreLogin(t, p, preLoginData{ReturnTo: "/console"})

	// securecookie counts whole seconds, wait until the 1s limit has
	// surely passed
	time.Sleep(2100 * time.Millisecond)

	if _, err := p.read(testRequest(t, http.MethodGet, "/", c)); err == nil {
		t.Fatal("an expired pre-login cookie was accepted")
	}
}

func TestPreLoginCookieKeyRotation(t *testing.T) {
	oldKey := newTestSessionKey(true)
	newKey := newTestSessionKey(true)

	before := newTestPreLoginCookies(t, preLoginMaxAge, oldKey)
	// getSessionKeys returns the newest key first
	after := newTestPreLoginCookies(t, preLoginMaxAge, newKey, oldKey)

	written := writePreLogin(t, before, preLoginData{ReturnTo: "/console/org/org1"})
	got, err := after.read(testRequest(t, http.MethodGet, "/", written))
	if err != nil {
		t.Fatalf("a cookie written before the key rotation was rejected: %v", err)
	}
	if got.ReturnTo != "/console/org/org1" {
		t.Fatalf("got %+v", got)
	}

	// New cookies are written with the newest key
	rotated := writePreLogin(t, after, preLoginData{ReturnTo: "/console"})
	if _, err := before.read(testRequest(t, http.MethodGet, "/", rotated)); err == nil {
		t.Fatal("a cookie written after the rotation used the old key")
	}
}

func TestPreLoginCookieFitsLongestReturnTo(t *testing.T) {
	p := newTestPreLoginCookies(t, preLoginMaxAge, newTestSessionKey(true))

	// redirectToLoginPage allows request URIs up to 1024 characters.
	// oidcRandString gives 22 characters and a PKCE verifier has 43.
	d := preLoginData{
		ReturnTo: "/" + strings.Repeat("a", 1023),
		OIDC: &oidcCallbackData{
			State:        strings.Repeat("s", 22),
			Nonce:        strings.Repeat("n", 22),
			PKCEVerifier: strings.Repeat("v", 43),
		},
	}

	c := writePreLogin(t, p, d)
	if len(c.String()) >= 4096 {
		t.Fatalf("the cookie is %d bytes, browsers only keep cookies below 4096", len(c.String()))
	}
}

func TestNewPreLoginCookiesRejects(t *testing.T) {
	if _, err := newPreLoginCookies(nil, preLoginMaxAge); err == nil {
		t.Error("no keys: expected an error")
	}

	// securecookie.MaxAge(0) turns the timestamp check off, so a limit
	// below one second must be refused
	for _, maxAge := range []time.Duration{0, 999 * time.Millisecond} {
		if _, err := newPreLoginCookies([]sessionKey{newTestSessionKey(true)}, maxAge); err == nil {
			t.Errorf("max age %s: expected an error", maxAge)
		}
	}
}

func TestClearCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	clearCookie(rec, sessionCookieName)

	c := findCookie(t, rec.Result().Cookies(), sessionCookieName)
	assertHostCookie(t, c)
	if c.MaxAge != -1 || c.Value != "" {
		t.Fatalf("expected an expired empty cookie, got %+v", c)
	}
}

// Users, roles and orgs from populateTestData. username1ID (org1, role
// "user") is declared in server_test.go.
const (
	csAdminID        = "00000006-0000-0000-0000-000000000001" // "admin": superuser, no org
	csAdminWithOrgID = "00000006-0000-0000-0000-000000000009" // "admin-with-org": superuser, org1
	csUsername7ID    = "00000006-0000-0000-0000-000000000010" // "username7": user, org2
	csAdminRoleID    = "00000005-0000-0000-0000-000000000001"
	csUserRoleID     = "00000005-0000-0000-0000-000000000002"
	csOrg1ID         = "00000002-0000-0000-0000-000000000001"
	csOrg2ID         = "00000002-0000-0000-0000-000000000002"
)

func mustPgUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatal(err)
	}
	return u
}

func countUserSessions(t *testing.T, dbPool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	err := dbPool.QueryRow(context.Background(), "SELECT count(*) FROM console_sessions WHERE user_id = $1", userID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func execSQL(t *testing.T, dbPool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := dbPool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// testLoginDeps returns what verifyLocalUserPassword and setLocalPassword
// need, with a rate limit no test reaches.
func testLoginDeps(t *testing.T) (*argon2Slots, *loginRateLimiter, *lru.Cache[string, struct{}]) {
	t.Helper()
	// A limit the tests never reach: a burst of a million attempts
	loginLimiter, err := newLoginRateLimiter(time.Millisecond, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	loginCache, err := lru.New[string, struct{}](128)
	if err != nil {
		t.Fatal(err)
	}
	return newArgon2Slots(1, 30*time.Second), loginLimiter, loginCache
}

// sessionTestEnv is a database with the test data and the session plumbing
// of a server, for calling the session functions directly.
type sessionTestEnv struct {
	dbPool   *pgxpool.Pool
	dbc      *dbConn
	store    *consolesession.Store
	preLogin *preLoginCookies
	logger   zerolog.Logger
}

func newSessionTestEnv(t *testing.T) sessionTestEnv {
	t.Helper()
	ctx := context.Background()
	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	dbPool, err := initDatabase(ctx, t, logger, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbPool.Close)

	dbc, err := newDBConn(dbPool, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	store, preLogin, err := newConsoleSessions(ctx, logger, dbPool, time.Hour, 8*time.Hour, preLoginMaxAge)
	if err != nil {
		t.Fatal(err)
	}

	return sessionTestEnv{dbPool: dbPool, dbc: dbc, store: store, preLogin: preLogin, logger: logger}
}

// login creates a session for userID without checking a password and
// returns the session cookie.
func (env sessionTestEnv) login(t *testing.T, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	err := startConsoleSession(rec, testRequest(t, http.MethodPost, cdntypes.AuthLoginPath), env.dbc, env.store, env.preLogin, mustPgUUID(t, userID), loginMethodLocal, nil)
	if err != nil {
		t.Fatal(err)
	}
	return findCookie(t, rec.Result().Cookies(), sessionCookieName)
}

func TestLoadUserAuth(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()

	ad, err := loadUserAuth(ctx, env.dbc, mustPgUUID(t, username1ID))
	if err != nil {
		t.Fatal(err)
	}
	if ad.Username == nil || *ad.Username != "username1" || ad.UserID == nil || ad.UserID.String() != username1ID {
		t.Fatalf("unexpected user in AuthData: %+v", ad)
	}
	if ad.OrgName == nil || *ad.OrgName != "org1" || ad.RoleName != "user" || ad.Superuser {
		t.Fatalf("unexpected rights in AuthData: %+v", ad)
	}

	ad, err = loadUserAuth(ctx, env.dbc, mustPgUUID(t, csAdminID))
	if err != nil || !ad.Superuser || ad.OrgID != nil {
		t.Fatalf("admin: got %+v, %v", ad, err)
	}

	_, err = loadUserAuth(ctx, env.dbc, mustPgUUID(t, "00000006-0000-0000-0000-0000000000ff"))
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unknown user: want pgx.ErrNoRows, got %v", err)
	}
}

func TestLoadSessionAuth(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()
	org2 := mustPgUUID(t, csOrg2ID)

	tok, err := consolesession.ParseToken(env.login(t, username1ID).Value)
	if err != nil {
		t.Fatal(err)
	}

	ad, selectedID, selectedName, err := loadSessionAuth(ctx, env.dbc, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Username == nil || *ad.Username != "username1" || ad.UserID == nil || ad.UserID.String() != username1ID {
		t.Fatalf("unexpected user in AuthData: %+v", ad)
	}
	if ad.OrgName == nil || *ad.OrgName != "org1" || ad.RoleName != "user" || ad.Superuser {
		t.Fatalf("unexpected rights in AuthData: %+v", ad)
	}
	if selectedID != nil || selectedName != "" {
		t.Fatalf("no selected org: got %v, %q", selectedID, selectedName)
	}

	if err := env.store.SetSelectedOrg(ctx, tok.ID, &org2); err != nil {
		t.Fatal(err)
	}
	_, selectedID, selectedName, err = loadSessionAuth(ctx, env.dbc, tok.ID)
	if err != nil || selectedID == nil || *selectedID != org2 || selectedName != "org2" {
		t.Fatalf("selected org: got %v, %q, %v", selectedID, selectedName, err)
	}

	if _, err := env.store.Destroy(ctx, tok); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = loadSessionAuth(ctx, env.dbc, tok.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ended session: want pgx.ErrNoRows, got %v", err)
	}
}

// TestLoadSessionAuthAfterPromotion commits a promotion between the two
// reads of authenticateConsoleRequest: the session passes store.Lookup,
// then updateUser makes the user a superuser and ends the session. The
// ended session must not get the new rights.
func TestLoadSessionAuthAfterPromotion(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()
	logger := env.logger

	tok, err := consolesession.ParseToken(env.login(t, username1ID).Value)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := env.store.Lookup(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}

	org1 := "org1"
	_, err = updateUser(ctx, &logger, env.dbc, cdntypes.AuthData{Superuser: true}, sess.UserID, "", &org1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// A query of its own sees the promotion
	if ad, err := loadUserAuth(ctx, env.dbc, sess.UserID); err != nil || !ad.Superuser {
		t.Fatalf("the promotion is not visible: %+v, %v", ad, err)
	}

	ad, _, _, err := loadSessionAuth(ctx, env.dbc, sess.ID)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("want pgx.ErrNoRows for the ended session, got %+v, %v", ad, err)
	}
}

// TestAuthenticateConsoleRequestRacingPromotion commits a promotion inside
// authenticateConsoleRequest, after store.Lookup has accepted the session
// and before the rights are read. A transaction makes the user a superuser
// and ends their sessions like updateUser does, but stays open. The request
// passes Lookup, which only reads committed rows, then blocks in Touch on
// the session row the transaction deleted. Committing while it waits puts
// the promotion exactly between the two reads.
func TestAuthenticateConsoleRequestRacingPromotion(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()
	userID := mustPgUUID(t, username1ID)

	cookie := env.login(t, username1ID)
	// Old enough that the request calls Touch, young enough to be valid
	execSQL(t, env.dbPool, "UPDATE console_sessions SET last_seen = now() - interval '10 minutes' WHERE user_id = $1", userID)

	// The shared test pool is capped at one connection, which the request
	// uses. Hold the transaction and poll pg_stat_activity from a separate
	// pool against the same database.
	lockCfg := env.dbPool.Config().Copy()
	lockCfg.MaxConns = 2
	lockPool, err := pgxpool.NewWithConfig(ctx, lockCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lockPool.Close()

	tx, err := lockPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Normally already committed below, this covers an early
		// t.Fatal()
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			t.Logf("unable to roll back promotion transaction: %v", rbErr)
		}
	}()
	_, err = tx.Exec(ctx, "UPDATE users SET role_id = (SELECT id FROM roles WHERE name = 'admin') WHERE id = $1", userID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consolesession.DeleteForUserTx(ctx, tx, userID); err != nil {
		t.Fatal(err)
	}

	type result struct {
		ad  cdntypes.AuthData
		sh  *sessionHandle
		err error
		rec *httptest.ResponseRecorder
	}
	done := make(chan result, 1)
	r := testRequest(t, http.MethodGet, consolePath, cookie)
	go func() {
		rec := httptest.NewRecorder()
		ad, sh, err := authenticateConsoleRequest(rec, r, env.dbc, env.store)
		done <- result{ad: ad, sh: sh, err: err, rec: rec}
	}()

	// Wait until the request is blocked in Touch
	deadline := time.Now().Add(10 * time.Second)
	for {
		var blocked bool
		err := lockPool.QueryRow(
			ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			                WHERE datname = current_database()
			                  AND wait_event_type = 'Lock'
			                  AND query LIKE 'UPDATE console_sessions SET last_seen%')`,
		).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case res := <-done:
			t.Fatalf("the request finished without blocking in Touch: %+v", res)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the request did not block in Touch")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.sh != nil || res.ad.Superuser {
		t.Fatalf("the ended session was accepted with rights %+v", res.ad)
	}
	if c := findCookie(t, res.rec.Result().Cookies(), sessionCookieName); c.MaxAge != -1 {
		t.Fatalf("the cookie of the ended session must be cleared, got %+v", c)
	}
}

func TestSelectedOrgAllowed(t *testing.T) {
	org1 := mustPgUUID(t, csOrg1ID)
	org2 := mustPgUUID(t, csOrg2ID)
	tests := []struct {
		name string
		ad   cdntypes.AuthData
		org  *pgtype.UUID
		want bool
	}{
		{name: "nothing selected", ad: cdntypes.AuthData{Superuser: true}, org: nil, want: false},
		{name: "superuser, any org", ad: cdntypes.AuthData{Superuser: true}, org: &org2, want: true},
		{name: "own org", ad: cdntypes.AuthData{OrgID: &org1}, org: &org1, want: true},
		{name: "other org", ad: cdntypes.AuthData{OrgID: &org1}, org: &org2, want: false},
		{name: "no org", ad: cdntypes.AuthData{}, org: &org1, want: false},
	}
	for _, test := range tests {
		if got := selectedOrgAllowed(test.ad, test.org); got != test.want {
			t.Errorf("%s: got %t, want %t", test.name, got, test.want)
		}
	}
}

func TestAuthenticateConsoleRequest(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()

	authenticate := func(t *testing.T, cookies ...*http.Cookie) (cdntypes.AuthData, *sessionHandle, *httptest.ResponseRecorder) {
		t.Helper()
		rec := httptest.NewRecorder()
		ad, sh, err := authenticateConsoleRequest(rec, testRequest(t, http.MethodGet, consolePath, cookies...), env.dbc, env.store)
		if err != nil {
			t.Fatal(err)
		}
		return ad, sh, rec
	}

	// requireCleared checks that a rejected session cookie is cleared, so
	// the browser stops sending a token that can never work again.
	requireCleared := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		c := findCookie(t, rec.Result().Cookies(), sessionCookieName)
		assertHostCookie(t, c)
		if c.MaxAge != -1 {
			t.Fatalf("expected the session cookie to be cleared, got %+v", c)
		}
	}

	t.Run("no cookie", func(t *testing.T) {
		_, sh, rec := authenticate(t)
		if sh != nil {
			t.Fatal("a request without cookie got a session")
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("a request without cookie got a Set-Cookie")
		}
	})

	t.Run("valid session", func(t *testing.T) {
		cookie := env.login(t, username1ID)
		ad, sh, rec := authenticate(t, cookie)
		if sh == nil {
			t.Fatal("a valid session was rejected")
		}
		if ad.UserID == nil || ad.UserID.String() != username1ID {
			t.Fatalf("unexpected AuthData: %+v", ad)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("a valid session must not set cookies")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		_, sh, rec := authenticate(t, newHostCookie(sessionCookieName, "not-a-session"))
		if sh != nil {
			t.Fatal("a malformed cookie was accepted")
		}
		requireCleared(t, rec)
	})

	t.Run("unknown id", func(t *testing.T) {
		cookie := env.login(t, username1ID)
		_, secretPart, _ := strings.Cut(cookie.Value, ".")
		_, sh, rec := authenticate(t, newHostCookie(sessionCookieName, uuid.NewV4().String()+"."+secretPart))
		if sh != nil {
			t.Fatal("an unknown id was accepted")
		}
		requireCleared(t, rec)
	})

	t.Run("wrong secret keeps the row", func(t *testing.T) {
		cookie := env.login(t, username1ID)
		before := countUserSessions(t, env.dbPool, username1ID)
		idPart, _, _ := strings.Cut(cookie.Value, ".")
		_, sh, rec := authenticate(t, newHostCookie(sessionCookieName, idPart+"."+strings.Repeat("A", 43)))
		if sh != nil {
			t.Fatal("a wrong secret was accepted")
		}
		requireCleared(t, rec)
		if n := countUserSessions(t, env.dbPool, username1ID); n != before {
			t.Fatalf("a wrong secret changed the session count from %d to %d", before, n)
		}
	})

	t.Run("expired session is deleted", func(t *testing.T) {
		cookie := env.login(t, csUsername7ID)
		execSQL(t, env.dbPool, "UPDATE console_sessions SET last_seen = now() - interval '2 hours' WHERE user_id = $1", csUsername7ID)
		_, sh, rec := authenticate(t, cookie)
		if sh != nil {
			t.Fatal("an expired session was accepted")
		}
		requireCleared(t, rec)
		if n := countUserSessions(t, env.dbPool, csUsername7ID); n != 0 {
			t.Fatalf("%d expired sessions left", n)
		}
	})

	t.Run("touch", func(t *testing.T) {
		cookie := env.login(t, csAdminID)
		execSQL(t, env.dbPool, "UPDATE console_sessions SET last_seen = now() - interval '5 minutes' WHERE user_id = $1", csAdminID)
		if _, sh, _ := authenticate(t, cookie); sh == nil {
			t.Fatal("session rejected")
		}
		var recent bool
		err := env.dbPool.QueryRow(ctx, "SELECT now() - last_seen < interval '1 minute' FROM console_sessions WHERE user_id = $1", csAdminID).Scan(&recent)
		if err != nil {
			t.Fatal(err)
		}
		if !recent {
			t.Fatal("last_seen was not updated")
		}
	})

	// The membership rule of the org pages: superusers may use any org,
	// other users only their own. A stored selection the user may not use
	// is dropped from selectedOrgName, orgSelected stays true.
	t.Run("selected org follows the membership rule", func(t *testing.T) {
		org1 := mustPgUUID(t, csOrg1ID)
		org2 := mustPgUUID(t, csOrg2ID)

		userCookie := env.login(t, username1ID)
		userTok, err := consolesession.ParseToken(userCookie.Value)
		if err != nil {
			t.Fatal(err)
		}

		if err := env.store.SetSelectedOrg(ctx, userTok.ID, &org2); err != nil {
			t.Fatal(err)
		}
		if _, sh, _ := authenticate(t, userCookie); sh.selectedOrgName != "" || !sh.orgSelected {
			t.Fatalf("a non-member's selected org must be ignored, got %q (selected %t)", sh.selectedOrgName, sh.orgSelected)
		}

		if err := env.store.SetSelectedOrg(ctx, userTok.ID, &org1); err != nil {
			t.Fatal(err)
		}
		if _, sh, _ := authenticate(t, userCookie); sh.selectedOrgName != "org1" {
			t.Fatalf("own org: got %q", sh.selectedOrgName)
		}

		adminCookie := env.login(t, csAdminID)
		adminTok, err := consolesession.ParseToken(adminCookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.store.SetSelectedOrg(ctx, adminTok.ID, &org2); err != nil {
			t.Fatal(err)
		}
		if _, sh, _ := authenticate(t, adminCookie); sh.selectedOrgName != "org2" {
			t.Fatalf("superuser: got %q", sh.selectedOrgName)
		}
	})

	// A cancelled context makes the lookup fail without saying anything
	// about the session, as an unreachable database or a query timeout
	// would. Clearing the cookie on such an error would log users out
	// because of a database problem.
	t.Run("lookup error fails the request and keeps the cookie", func(t *testing.T) {
		cookie := env.login(t, csAdminID)
		r := testRequest(t, http.MethodGet, consolePath, cookie)
		cancelled, cancel := context.WithCancel(r.Context())
		cancel()

		rec := httptest.NewRecorder()
		_, sh, err := authenticateConsoleRequest(rec, r.WithContext(cancelled), env.dbc, env.store)
		if err == nil || sh != nil {
			t.Fatalf("expected an error and no session, got %v and %v", err, sh)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("a lookup error must not clear the session cookie")
		}
	})
}

// TestSessionRejectionLogLevels checks the level a rejected session cookie is
// logged at: warn for what normal use does not produce, info for what it
// does. An unknown id is info because swept and revoked sessions end there.
func TestSessionRejectionLogLevels(t *testing.T) {
	env := newSessionTestEnv(t)

	expired := env.login(t, csUsername7ID)
	execSQL(t, env.dbPool, "UPDATE console_sessions SET last_seen = now() - interval '2 hours' WHERE user_id = $1", csUsername7ID)
	valid := env.login(t, username1ID)
	idPart, secretPart, _ := strings.Cut(valid.Value, ".")

	tests := []struct {
		name   string
		value  string
		msg    string
		reason string
		level  string
	}{
		{name: "malformed", value: "not-a-session", msg: "session_invalid", reason: "malformed", level: "warn"},
		{name: "unknown id", value: uuid.NewV4().String() + "." + secretPart, msg: "session_invalid", reason: "unknown", level: "info"},
		{name: "wrong secret", value: idPart + "." + strings.Repeat("A", 43), msg: "session_invalid", reason: "bad_secret", level: "warn"},
		{name: "expired", value: expired.Value, msg: "session_expired", reason: "idle", level: "info"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := zerolog.New(&buf)
			r := httptest.NewRequest(http.MethodGet, consolePath, nil)
			r.AddCookie(newHostCookie(sessionCookieName, test.value))
			r = r.WithContext(logger.WithContext(r.Context()))

			_, sh, err := authenticateConsoleRequest(httptest.NewRecorder(), r, env.dbc, env.store)
			if err != nil || sh != nil {
				t.Fatalf("want an anonymous request, got %v, %v", sh, err)
			}

			var entry struct {
				Level   string `json:"level"`
				Message string `json:"message"`
				Reason  string `json:"reason"`
			}
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("want exactly one log line, got %q: %s", buf.String(), err)
			}
			if entry.Level != test.level || entry.Message != test.msg || entry.Reason != test.reason {
				t.Fatalf("got %s %s reason=%s, want %s %s reason=%s", entry.Level, entry.Message, entry.Reason, test.level, test.msg, test.reason)
			}
		})
	}
}

func TestStartConsoleSession(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()

	start := func(t *testing.T, userID string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		err := startConsoleSession(rec, testRequest(t, http.MethodPost, cdntypes.AuthLoginPath, cookies...), env.dbc, env.store, env.preLogin, mustPgUUID(t, userID), loginMethodLocal, nil)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}

	t.Run("new session", func(t *testing.T) {
		rec := start(t, csAdminID)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != consolePath {
			t.Fatalf("got %d to %q, want 302 to %s", rec.Code, rec.Header().Get("Location"), consolePath)
		}
		c := findCookie(t, rec.Result().Cookies(), sessionCookieName)
		requireNonPersistentHostCookie(t, c)
		if _, err := consolesession.ParseToken(c.Value); err != nil {
			t.Fatalf("the cookie is not a session token: %v", err)
		}
		if n := countUserSessions(t, env.dbPool, csAdminID); n != 1 {
			t.Fatalf("%d sessions, want 1", n)
		}
	})

	t.Run("return-to path", func(t *testing.T) {
		pre := writePreLogin(t, env.preLogin, preLoginData{ReturnTo: "/console/org/org1/domains"})
		rec := start(t, csUsername7ID, pre)
		if got := rec.Header().Get("Location"); got != "/console/org/org1/domains" {
			t.Fatalf("redirected to %q", got)
		}
		if c := findCookie(t, rec.Result().Cookies(), preLoginCookieName); c.MaxAge != -1 {
			t.Fatalf("the pre-login cookie must be cleared at login, got %+v", c)
		}
	})

	t.Run("previous session is destroyed", func(t *testing.T) {
		old := env.login(t, csAdminWithOrgID)
		rec := start(t, username1ID, old)
		if n := countUserSessions(t, env.dbPool, csAdminWithOrgID); n != 0 {
			t.Fatal("the session the browser held before login survived")
		}
		if findCookie(t, rec.Result().Cookies(), sessionCookieName).Value == old.Value {
			t.Fatal("login kept the old session cookie")
		}
	})

	t.Run("planted value is not adopted", func(t *testing.T) {
		planted := uuid.NewV4().String() + "." + strings.Repeat("A", 43)
		rec := start(t, username1ID, newHostCookie(sessionCookieName, planted))
		if findCookie(t, rec.Result().Cookies(), sessionCookieName).Value == planted {
			t.Fatal("login adopted the planted value")
		}
		plantedID, _, _ := strings.Cut(planted, ".")
		var exists bool
		err := env.dbPool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM console_sessions WHERE id = $1)", plantedID).Scan(&exists)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("a session with the planted id exists")
		}
	})

	t.Run("deleted user", func(t *testing.T) {
		// put-user-1 has no other references, so it can be deleted
		const deletedUserID = "00000014-0000-0000-0000-000000000001"
		execSQL(t, env.dbPool, "DELETE FROM users WHERE id = $1", deletedUserID)

		rec := httptest.NewRecorder()
		err := startConsoleSession(rec, testRequest(t, http.MethodPost, cdntypes.AuthLoginPath), env.dbc, env.store, env.preLogin, mustPgUUID(t, deletedUserID), loginMethodLocal, nil)
		if !errors.Is(err, cdnerrors.ErrBadPassword) {
			t.Fatalf("want ErrBadPassword, got %v", err)
		}
		if n := countUserSessions(t, env.dbPool, deletedUserID); n != 0 {
			t.Fatalf("a login for a deleted user created %d sessions", n)
		}
		if len(rec.Result().Cookies()) != 0 || rec.Body.Len() != 0 || len(rec.Header()) != 0 {
			t.Fatal("startConsoleSession wrote a response for a deleted user")
		}
	})
}

func TestLoginRacingPasswordChange(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()
	a2Slots, loginLimiter, loginCache := testLoginDeps(t)
	ipKey := netip.MustParsePrefix("192.0.2.1/32")
	logger := env.logger
	const newPassword = "a-new-password-for-username1" // #nosec G101 -- test password

	ad, verifiedKey, err := verifyLocalUserPassword(ctx, &logger, env.dbc, a2Slots, loginLimiter, loginCache, ipKey, "username1", validUserPassword)
	if err != nil {
		t.Fatal(err)
	}

	var storedKey []byte
	err = env.dbPool.QueryRow(ctx, "SELECT key FROM user_argon2keys WHERE user_id = $1", *ad.UserID).Scan(&storedKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedKey, verifiedKey) {
		t.Fatal("verifyLocalUserPassword did not return the key it checked")
	}

	// The password changes after it was verified, before the session is
	// created
	_, err = setLocalPassword(ctx, &logger, cdntypes.AuthData{Superuser: true}, env.dbc, a2Slots, loginLimiter, loginCache, netip.Prefix{}, *ad.UserID, "", newPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	err = startConsoleSession(rec, testRequest(t, http.MethodPost, cdntypes.AuthLoginPath), env.dbc, env.store, env.preLogin, *ad.UserID, loginMethodLocal, verifiedKey)
	if !errors.Is(err, cdnerrors.ErrBadPassword) {
		t.Fatalf("want ErrBadPassword, got %v", err)
	}
	if n := countUserSessions(t, env.dbPool, username1ID); n != 0 {
		t.Fatalf("a login with the old password created %d sessions", n)
	}
	// Nothing is written: loginHandler answers exactly as for a wrong
	// password
	if len(rec.Result().Cookies()) != 0 || rec.Body.Len() != 0 || len(rec.Header()) != 0 {
		t.Fatal("startConsoleSession wrote a response for a failed login")
	}

	// With the current key the login goes through
	ad, verifiedKey, err = verifyLocalUserPassword(ctx, &logger, env.dbc, a2Slots, loginLimiter, loginCache, ipKey, "username1", newPassword)
	if err != nil {
		t.Fatal(err)
	}
	err = startConsoleSession(httptest.NewRecorder(), testRequest(t, http.MethodPost, cdntypes.AuthLoginPath), env.dbc, env.store, env.preLogin, *ad.UserID, loginMethodLocal, verifiedKey)
	if err != nil {
		t.Fatal(err)
	}
	if n := countUserSessions(t, env.dbPool, username1ID); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}

func TestNoStoreMiddleware(t *testing.T) {
	rec := httptest.NewRecorder()
	noStoreMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control: got %q", got)
	}
}

func TestConsoleSessionSweeper(t *testing.T) {
	env := newSessionTestEnv(t)
	env.login(t, csAdminID)
	execSQL(t, env.dbPool, "UPDATE console_sessions SET time_created = now() - interval '9 hours' WHERE user_id = $1", csAdminID)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		consoleSessionSweeper(ctx, env.logger, env.store, 10*time.Millisecond)
	})

	deadline := time.Now().Add(10 * time.Second)
	for countUserSessions(t, env.dbPool, csAdminID) != 0 {
		if time.Now().After(deadline) {
			cancel()
			wg.Wait()
			t.Fatal("the sweeper did not remove the expired session")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The sweeper stops with its context
	cancel()
	wg.Wait()
}

// newSessionTestServer starts a test server on a new database. Both are
// closed when the test ends.
func newSessionTestServer(t *testing.T, tsi testServerInput) (*httptest.Server, *pgxpool.Pool) {
	t.Helper()
	ts, dbPool, err := prepareServer(t, tsi)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ts.Close()
		dbPool.Close()
	})
	return ts, dbPool
}

func newJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

// pageResult is a response read by doConsole.
type pageResult struct {
	status   int
	location string
	header   http.Header
	cookies  []*http.Cookie
	body     string
}

// doConsole sends a request the way a browser with jar (may be nil) would
// and returns the response without following redirects. A non-nil form is
// sent as the body.
func doConsole(t *testing.T, jar http.CookieJar, method string, target string, form url.Values) pageResult {
	t.Helper()

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return pageResult{
		status:   resp.StatusCode,
		location: resp.Header.Get("Location"),
		header:   resp.Header,
		cookies:  resp.Cookies(),
		body:     string(b),
	}
}

func loginFormValues(username string, password string) url.Values {
	return url.Values{"username": {username}, "password": {password}}
}

// loginJar logs in through the login form in a new cookie jar, as a browser
// without cookies would, and returns the jar holding the new session.
func loginJar(t *testing.T, tsURL string, username string, password string) http.CookieJar {
	t.Helper()
	client, _ := consoleLogin(t, tsURL, username, password)
	return client.Jar
}

// jarCookie returns the named cookie jar sends to tsURL, or nil.
func jarCookie(t *testing.T, jar http.CookieJar, tsURL string, name string) *http.Cookie {
	t.Helper()
	u, err := url.Parse(tsURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// setJarCookie puts a cookie in jar as if tsURL had set it.
func setJarCookie(t *testing.T, jar http.CookieJar, tsURL string, name string, value string) {
	t.Helper()
	u, err := url.Parse(tsURL)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{newHostCookie(name, value)})
}

// requireLoggedOut checks that the session in jar is no longer accepted.
func requireLoggedOut(t *testing.T, tsURL string, jar http.CookieJar) {
	t.Helper()
	res := doConsole(t, jar, http.MethodGet, tsURL+consolePath, nil)
	if res.status != http.StatusFound || res.location != cdntypes.AuthLoginPath {
		t.Fatalf("expected a redirect to the login page, got %d to %q", res.status, res.location)
	}
}

// requireLoggedIn checks that the session in jar is still accepted.
func requireLoggedIn(t *testing.T, tsURL string, jar http.CookieJar) {
	t.Helper()
	res := doConsole(t, jar, http.MethodGet, tsURL+consolePath, nil)
	if res.location == cdntypes.AuthLoginPath || res.status >= http.StatusBadRequest {
		t.Fatalf("expected the session to still work, got %d to %q", res.status, res.location)
	}
}

func TestConsoleLogout(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin", validAdminPassword)

	captured := jarCookie(t, jar, ts.URL, sessionCookieName)
	if captured == nil {
		t.Fatal("no session cookie after login")
	}

	res := doConsole(t, jar, http.MethodPost, ts.URL+cdntypes.AuthLogoutPath, url.Values{})
	if res.status != http.StatusSeeOther || res.location != consolePath {
		t.Fatalf("logout: got %d to %q, want 303 to %s", res.status, res.location, consolePath)
	}

	// Clear cached pages, but never every cookie of the registrable domain
	if got := res.header.Values("Clear-Site-Data"); len(got) != 1 || got[0] != `"cache"` {
		t.Fatalf(`logout must send exactly Clear-Site-Data: "cache", got %q`, got)
	}

	for _, name := range []string{sessionCookieName, preLoginCookieName} {
		c := findCookie(t, res.cookies, name)
		assertHostCookie(t, c)
		if c.MaxAge != -1 {
			t.Fatalf("logout must expire the %s cookie, got %+v", name, c)
		}
	}

	if n := countUserSessions(t, dbPool, csAdminID); n != 0 {
		t.Fatalf("%d sessions left after logout", n)
	}

	// A copy of the cookie taken before logout no longer works
	replay := newJar(t)
	setJarCookie(t, replay, ts.URL, sessionCookieName, captured.Value)
	requireLoggedOut(t, ts.URL, replay)
}

func TestConsoleLoginFixation(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})

	t.Run("planted value is not adopted", func(t *testing.T) {
		planted := uuid.NewV4().String() + "." + strings.Repeat("A", 43)
		jar := newJar(t)
		setJarCookie(t, jar, ts.URL, sessionCookieName, planted)

		res := doConsole(t, jar, http.MethodPost, ts.URL+cdntypes.AuthLoginPath, loginFormValues("username1", validUserPassword))
		if res.status != http.StatusFound {
			t.Fatalf("login: unexpected status %d", res.status)
		}
		if findCookie(t, res.cookies, sessionCookieName).Value == planted {
			t.Fatal("login kept the planted session cookie")
		}

		plantedID, _, _ := strings.Cut(planted, ".")
		var exists bool
		err := dbPool.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM console_sessions WHERE id = $1)", plantedID).Scan(&exists)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("a session with the planted id exists")
		}
	})

	t.Run("logging in as B ends A's session", func(t *testing.T) {
		jar := loginJar(t, ts.URL, "admin", validAdminPassword)
		before := jarCookie(t, jar, ts.URL, sessionCookieName)
		adminSessions := countUserSessions(t, dbPool, csAdminID)

		res := doConsole(t, jar, http.MethodPost, ts.URL+cdntypes.AuthLoginPath, loginFormValues("username1", validUserPassword))
		if res.status != http.StatusFound {
			t.Fatalf("login: unexpected status %d", res.status)
		}
		if n := countUserSessions(t, dbPool, csAdminID); n != adminSessions-1 {
			t.Fatalf("admin has %d sessions after logging in as another user, want %d", n, adminSessions-1)
		}
		if findCookie(t, res.cookies, sessionCookieName).Value == before.Value {
			t.Fatal("login kept A's session cookie")
		}
	})
}

func TestConsoleRejectsBadSessionCookies(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin", validAdminPassword)
	valid := jarCookie(t, jar, ts.URL, sessionCookieName)
	idPart, secretPart, _ := strings.Cut(valid.Value, ".")

	tests := []struct {
		name  string
		value string
	}{
		{name: "malformed", value: "not-a-session"},
		{name: "unknown id", value: uuid.NewV4().String() + "." + secretPart},
		{name: "tampered secret", value: idPart + "." + strings.Repeat("A", 43)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bad := newJar(t)
			setJarCookie(t, bad, ts.URL, sessionCookieName, test.value)
			res := doConsole(t, bad, http.MethodGet, ts.URL+consolePath, nil)
			if res.status != http.StatusFound || res.location != cdntypes.AuthLoginPath {
				t.Fatalf("got %d to %q, want a redirect to login", res.status, res.location)
			}
			if c := findCookie(t, res.cookies, sessionCookieName); c.MaxAge != -1 {
				t.Fatalf("a rejected session cookie must be cleared, got %+v", c)
			}
		})
	}

	// A wrong secret never ends the real session
	if n := countUserSessions(t, dbPool, csAdminID); n != 1 {
		t.Fatalf("admin has %d sessions, want 1", n)
	}
	requireLoggedIn(t, ts.URL, jar)

	t.Run("cookie from before server-side sessions", func(t *testing.T) {
		old := newJar(t)
		setJarCookie(t, old, ts.URL, "sunet-cdn-manager", "MTcxNjgwMDAwMHxEdi1CQkFFQ180SUFBUkFCRUFBQV8tLUJBQUlHYzNSeWFXNW58")
		res := doConsole(t, old, http.MethodGet, ts.URL+consolePath, nil)
		if res.status != http.StatusFound || res.location != cdntypes.AuthLoginPath {
			t.Fatalf("got %d to %q, want a redirect to login", res.status, res.location)
		}
	})
}

func TestConsoleCookieAttributes(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})

	// The pre-login cookie written for an anonymous request to a console page
	res := doConsole(t, newJar(t), http.MethodGet, ts.URL+"/console/org/org1/domains", nil)
	if res.status != http.StatusFound {
		t.Fatalf("anonymous request: unexpected status %d", res.status)
	}
	requireNonPersistentHostCookie(t, findCookie(t, res.cookies, preLoginCookieName))

	// The session cookie written at login
	jar := newJar(t)
	res = doConsole(t, jar, http.MethodPost, ts.URL+cdntypes.AuthLoginPath, loginFormValues("admin", validAdminPassword))
	if res.status != http.StatusFound {
		t.Fatalf("login: unexpected status %d", res.status)
	}
	requireNonPersistentHostCookie(t, findCookie(t, res.cookies, sessionCookieName))

	// The login page sends a browser with a session to the console
	// without creating another session
	res = doConsole(t, jar, http.MethodGet, ts.URL+cdntypes.AuthLoginPath, nil)
	if res.status != http.StatusFound || res.location != consolePath {
		t.Fatalf("login page with a session: got %d to %q", res.status, res.location)
	}
	if n := countUserSessions(t, dbPool, csAdminID); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
}

func TestPreLoginCookieExpiresInLoginFlow(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{preLoginMaxAge: time.Second})
	jar := newJar(t)

	res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/domains", nil)
	if res.status != http.StatusFound || res.location != cdntypes.AuthLoginPath {
		t.Fatalf("anonymous request: got %d to %q", res.status, res.location)
	}

	// securecookie counts whole seconds, wait until the 1s limit has
	// surely passed
	time.Sleep(2100 * time.Millisecond)

	res = doConsole(t, jar, http.MethodPost, ts.URL+cdntypes.AuthLoginPath, loginFormValues("admin", validAdminPassword))
	if res.status != http.StatusFound || res.location != consolePath {
		t.Fatalf("an expired pre-login cookie must not be used: got %d to %q", res.status, res.location)
	}
}

func TestNoSetCookieOnOrdinaryResponses(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin", validAdminPassword)

	res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil)
	if res.status != http.StatusOK {
		t.Fatalf("unexpected status %d", res.status)
	}
	if got := res.header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("an ordinary response set cookies: %q", got)
	}

	// A request that updates last_seen does not set cookies either
	execSQL(t, dbPool, "UPDATE console_sessions SET last_seen = now() - interval '10 minutes' WHERE user_id = $1", csAdminID)
	res = doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil)
	if got := res.header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a response that updated last_seen set cookies: %q", got)
	}

	var touched bool
	err := dbPool.QueryRow(context.Background(), "SELECT now() - last_seen < interval '1 minute' FROM console_sessions WHERE user_id = $1", csAdminID).Scan(&touched)
	if err != nil {
		t.Fatal(err)
	}
	if !touched {
		t.Fatal("last_seen was not updated")
	}
}

func TestConsoleCacheHeaders(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin", validAdminPassword)

	tests := []struct {
		name string
		jar  http.CookieJar
		path string
	}{
		{name: "console page", jar: jar, path: consoleSuperuserUsers},
		{name: "login page", jar: nil, path: cdntypes.AuthLoginPath},
		{name: "redirect to login", jar: nil, path: consolePath},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := doConsole(t, test.jar, http.MethodGet, ts.URL+test.path, nil)
			if got := res.header.Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control: got %q, want no-store", got)
			}
		})
	}
}

func TestConsoleSessionExpiry(t *testing.T) {
	tests := []struct {
		name string
		// expire backdates the user's session past one of the timeouts
		expire string
	}{
		{name: "idle", expire: "UPDATE console_sessions SET last_seen = now() - interval '2 hours' WHERE user_id = $1"},
		{name: "absolute", expire: "UPDATE console_sessions SET time_created = now() - interval '9 hours' WHERE user_id = $1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// prepareServer defaults: 1h idle and 8h absolute timeout
			ts, dbPool := newSessionTestServer(t, testServerInput{})
			jar := loginJar(t, ts.URL, "admin-with-org", validAdminPassword)
			execSQL(t, dbPool, test.expire, csAdminWithOrgID)

			const deepLink = "/console/org/org1/domains"
			res := doConsole(t, jar, http.MethodGet, ts.URL+deepLink, nil)
			if res.status != http.StatusFound || res.location != cdntypes.AuthLoginPath {
				t.Fatalf("expired session: got %d to %q", res.status, res.location)
			}
			if n := countUserSessions(t, dbPool, csAdminWithOrgID); n != 0 {
				t.Fatalf("the expired session was not deleted, %d left", n)
			}

			res = doConsole(t, jar, http.MethodPost, ts.URL+cdntypes.AuthLoginPath, loginFormValues("admin-with-org", validAdminPassword))
			if res.status != http.StatusFound || res.location != deepLink {
				t.Fatalf("login after expiry: got %d to %q, want %s", res.status, res.location, deepLink)
			}
			if c := findCookie(t, res.cookies, preLoginCookieName); c.MaxAge != -1 {
				t.Fatalf("the pre-login cookie must be cleared at login, got %+v", c)
			}
			if jarCookie(t, jar, ts.URL, preLoginCookieName) != nil {
				t.Fatal("the browser kept the pre-login cookie after login")
			}
		})
	}
}

func TestConsoleFlashScoping(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin-with-org", validAdminPassword)
	const domain = "example-delete-1.se"

	res := doConsole(t, jar, http.MethodDelete, ts.URL+"/console/org/org1/domains/"+domain, nil)
	if res.status != http.StatusSeeOther {
		t.Fatalf("domain delete: unexpected status %d (%s)", res.status, res.body)
	}

	if res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org2/domains", nil); strings.Contains(res.body, domain) {
		t.Fatal("org1's flash message was shown on org2's domains page")
	}
	if res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/domains", nil); !strings.Contains(res.body, domain) {
		t.Fatal("the flash message was not shown on org1's domains page")
	}
	if res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/domains", nil); strings.Contains(res.body, domain) {
		t.Fatal("the flash message was shown twice")
	}
}

func TestOIDCCallbackPreLoginChecks(t *testing.T) {
	preLogin := newTestPreLoginCookies(t, time.Second, newTestSessionKey(true))
	// None of these requests get as far as the token exchange, so no
	// provider, store or database is needed
	handler := oauth2CallbackHandler(&http.Client{}, preLogin, nil, oauth2.Config{}, nil, nil)
	oidcData := preLoginData{OIDC: &oidcCallbackData{State: "expected-state", Nonce: "nonce", PKCEVerifier: "verifier"}}

	call := func(t *testing.T, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, testRequest(t, http.MethodGet, "/auth"+keycloakCallbackPath+"?code=abc&state="+state, cookies...))
		return rec
	}

	t.Run("missing cookie", func(t *testing.T) {
		rec := call(t, "expected-state")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), oidcLoginExpired) {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("no OIDC data", func(t *testing.T) {
		rec := call(t, "expected-state", writePreLogin(t, preLogin, preLoginData{ReturnTo: consolePath}))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), oidcLoginExpired) {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("mismatched state", func(t *testing.T) {
		rec := call(t, "other-state", writePreLogin(t, preLogin, oidcData))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "state did not match") {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("expired cookie", func(t *testing.T) {
		c := writePreLogin(t, preLogin, oidcData)
		time.Sleep(2100 * time.Millisecond)
		rec := call(t, "expected-state", c)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), oidcLoginExpired) {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestOIDCStartKeepsReturnTo(t *testing.T) {
	preLogin := newTestPreLoginCookies(t, preLoginMaxAge, newTestSessionKey(true))
	oauth2Config := oauth2.Config{
		ClientID:    "sunet-cdn-manager-server",
		RedirectURL: "https://manager.example/auth/oidc/keycloak/callback",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example/auth"},
	}

	rec := httptest.NewRecorder()
	stored := writePreLogin(t, preLogin, preLoginData{ReturnTo: "/console/org/org1"})
	keycloakOIDCHandler(preLogin, oauth2Config).ServeHTTP(rec, testRequest(t, http.MethodGet, "/auth"+keycloakPath, stored))
	if rec.Code != http.StatusFound {
		t.Fatalf("unexpected status %d", rec.Code)
	}

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != "idp.example" {
		t.Fatalf("not redirected to the identity provider: %s", location)
	}

	pre, err := preLogin.read(testRequest(t, http.MethodGet, "/", findCookie(t, rec.Result().Cookies(), preLoginCookieName)))
	if err != nil {
		t.Fatal(err)
	}
	if pre.ReturnTo != "/console/org/org1" {
		t.Fatalf("starting an OIDC login dropped the return-to path: %+v", pre)
	}
	if pre.OIDC == nil || pre.OIDC.State != location.Query().Get("state") {
		t.Fatalf("the stored OIDC state does not match the redirect: %+v", pre.OIDC)
	}
}

func TestRedirectToLoginPageKeepsOIDCData(t *testing.T) {
	preLogin := newTestPreLoginCookies(t, preLoginMaxAge, newTestSessionKey(true))
	oidcData := &oidcCallbackData{State: "state", Nonce: "nonce", PKCEVerifier: "verifier"}

	readResponse := func(t *testing.T, rec *httptest.ResponseRecorder) preLoginData {
		t.Helper()
		pre, err := preLogin.read(testRequest(t, http.MethodGet, "/", findCookie(t, rec.Result().Cookies(), preLoginCookieName)))
		if err != nil {
			t.Fatal(err)
		}
		return pre
	}

	t.Run("GET stores the return-to path next to the OIDC data", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cookie := writePreLogin(t, preLogin, preLoginData{OIDC: oidcData})
		redirectToLoginPage(rec, testRequest(t, http.MethodGet, "/console/org/org1", cookie), preLogin)
		pre := readResponse(t, rec)
		if pre.ReturnTo != "/console/org/org1" || pre.OIDC == nil || *pre.OIDC != *oidcData {
			t.Fatalf("got %+v", pre)
		}
	})

	t.Run("POST drops the return-to path but keeps the OIDC data", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cookie := writePreLogin(t, preLogin, preLoginData{ReturnTo: "/console/org/org1", OIDC: oidcData})
		redirectToLoginPage(rec, testRequest(t, http.MethodPost, "/console/org/org1/create/domain", cookie), preLogin)
		pre := readResponse(t, rec)
		if pre.ReturnTo != "" || pre.OIDC == nil || *pre.OIDC != *oidcData {
			t.Fatalf("got %+v", pre)
		}
	})

	t.Run("POST without OIDC data clears the cookie", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cookie := writePreLogin(t, preLogin, preLoginData{ReturnTo: "/console"})
		redirectToLoginPage(rec, testRequest(t, http.MethodPost, "/console/org/org1/create/domain", cookie), preLogin)
		if c := findCookie(t, rec.Result().Cookies(), preLoginCookieName); c.MaxAge != -1 {
			t.Fatalf("expected the pre-login cookie to be cleared, got %+v", c)
		}
	})
}

const newTestPassword = "a-new-password-2026" // #nosec G101 -- test password

// apiJSON sends a request to the API with HTTP Basic auth, with body (if
// not nil) as JSON, and returns the status code and response body.
func apiJSON(t *testing.T, method string, target string, username string, password string, body any) (int, string) {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, target, reqBody)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, string(b)
}

// putUserBody is the body of PUT /api/v1/users/{userID}. A nil Org removes
// the user from their org.
type putUserBody struct {
	Org         *string `json:"org,omitempty"`
	Role        string  `json:"role"`
	DisplayName string  `json:"display_name"`
}

// requireOrgAccess checks whether the user of jar may view the org's
// domains page. A refused org page is a 200 with the org-not-found message.
func requireOrgAccess(t *testing.T, tsURL string, jar http.CookieJar, org string, want bool) {
	t.Helper()
	res := doConsole(t, jar, http.MethodGet, tsURL+"/console/org/"+org+"/domains", nil)
	if res.status != http.StatusOK {
		t.Fatalf("org %s domains page: got %d to %q", org, res.status, res.location)
	}
	allowed := !strings.Contains(res.body, consoleOrgNotFound)
	if allowed != want {
		t.Fatalf("org %s domains page: allowed=%t, want %t", org, allowed, want)
	}
}

// selectedOrgOption returns the org marked as selected in the org switcher
// of a console page, "" if none is.
func selectedOrgOption(t *testing.T, body string) string {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc.Find(`select[name="org"] option[selected]`).First().AttrOr("value", "")
}

func TestSessionAfterDemotion(t *testing.T) {
	org1 := "org1"

	t.Run("through the API the session ends", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "admin-with-org", validAdminPassword)
		requireLoggedIn(t, ts.URL, jar)

		status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+csAdminWithOrgID, "admin", validAdminPassword, putUserBody{Org: &org1, Role: "user", DisplayName: "admin-with-org"})
		if status != http.StatusOK {
			t.Fatalf("PUT user: %d (%s)", status, body)
		}

		requireLoggedOut(t, ts.URL, jar)
		if n := countUserSessions(t, dbPool, csAdminWithOrgID); n != 0 {
			t.Fatalf("%d sessions left after the demotion", n)
		}
	})

	t.Run("in the database the next request has the new rights", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "admin-with-org", validAdminPassword)
		requireLoggedIn(t, ts.URL, jar)

		if res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil); res.status != http.StatusOK {
			t.Fatalf("superuser page before the change: %d", res.status)
		}

		execSQL(t, dbPool, "UPDATE users SET role_id = $1 WHERE id = $2", csUserRoleID, csAdminWithOrgID)

		if res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil); res.status != http.StatusForbidden {
			t.Fatalf("superuser page after the demotion: got %d, want 403", res.status)
		}
		requireOrgAccess(t, ts.URL, jar, "org1", true)
	})
}

func TestSessionAfterPromotion(t *testing.T) {
	org1 := "org1"

	t.Run("through the API the session ends", func(t *testing.T) {
		ts, _ := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		requireLoggedIn(t, ts.URL, jar)

		status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+username1ID, "admin", validAdminPassword, putUserBody{Org: &org1, Role: "admin", DisplayName: "username1"})
		if status != http.StatusOK {
			t.Fatalf("PUT user: %d (%s)", status, body)
		}

		// The token from before the promotion never reaches a superuser page
		res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil)
		if res.status != http.StatusFound || res.location != cdntypes.AuthLoginPath {
			t.Fatalf("old session after the promotion: got %d to %q", res.status, res.location)
		}

		fresh := loginJar(t, ts.URL, "username1", validUserPassword)
		requireLoggedIn(t, ts.URL, fresh)
		if res := doConsole(t, fresh, http.MethodGet, ts.URL+consoleSuperuserUsers, nil); res.status != http.StatusOK {
			t.Fatalf("superuser page after logging in again: %d", res.status)
		}
	})

	t.Run("in the database the next request has the new rights", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		requireLoggedIn(t, ts.URL, jar)

		if res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil); res.status != http.StatusForbidden {
			t.Fatalf("superuser page before the change: got %d, want 403", res.status)
		}

		execSQL(t, dbPool, "UPDATE users SET role_id = $1 WHERE id = $2", csAdminRoleID, username1ID)

		if res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil); res.status != http.StatusOK {
			t.Fatalf("superuser page after the promotion: got %d, want 200", res.status)
		}
	})
}

func TestSessionAfterOrgChange(t *testing.T) {
	org2 := "org2"
	org3 := "org3"

	t.Run("moved to another org through the API", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		requireLoggedIn(t, ts.URL, jar)

		status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+username1ID, "admin", validAdminPassword, putUserBody{Org: &org2, Role: "user", DisplayName: "username1"})
		if status != http.StatusOK {
			t.Fatalf("PUT user: %d (%s)", status, body)
		}

		requireLoggedOut(t, ts.URL, jar)
		if n := countUserSessions(t, dbPool, username1ID); n != 0 {
			t.Fatalf("%d sessions left after the org change", n)
		}
	})

	t.Run("org removed through the API", func(t *testing.T) {
		ts, _ := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username7", validUserPassword)
		requireLoggedIn(t, ts.URL, jar)

		status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+csUsername7ID, "admin", validAdminPassword, putUserBody{Role: "user", DisplayName: "username7"})
		if status != http.StatusOK {
			t.Fatalf("PUT user: %d (%s)", status, body)
		}

		requireLoggedOut(t, ts.URL, jar)
	})

	t.Run("org set through the API", func(t *testing.T) {
		ts, _ := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "admin", validAdminPassword)
		requireLoggedIn(t, ts.URL, jar)

		status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+csAdminID, "admin", validAdminPassword, putUserBody{Org: &org3, Role: "admin", DisplayName: "admin"})
		if status != http.StatusOK {
			t.Fatalf("PUT user: %d (%s)", status, body)
		}

		requireLoggedOut(t, ts.URL, jar)
	})

	t.Run("moved in the database", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		requireLoggedIn(t, ts.URL, jar)

		requireOrgAccess(t, ts.URL, jar, "org1", true)
		requireOrgAccess(t, ts.URL, jar, "org2", false)

		execSQL(t, dbPool, "UPDATE users SET org_id = $1 WHERE id = $2", csOrg2ID, username1ID)

		requireOrgAccess(t, ts.URL, jar, "org1", false)
		requireOrgAccess(t, ts.URL, jar, "org2", true)
		if n := countUserSessions(t, dbPool, username1ID); n != 1 {
			t.Fatalf("a change in the database must not end sessions, %d left", n)
		}
	})
}

func TestSessionAfterOrgRename(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin-with-org", validAdminPassword)

	// The dashboard selects the superuser's own org on the first visit
	if res := doConsole(t, jar, http.MethodGet, ts.URL+consolePath, nil); res.location != "/console/org/org1" {
		t.Fatalf("dashboard: got %d to %q", res.status, res.location)
	}
	if got := selectedOrgOption(t, doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil).body); got != "org1" {
		t.Fatalf("selected org before the rename: %q", got)
	}

	execSQL(t, dbPool, "UPDATE orgs SET name = 'org1-renamed' WHERE id = $1", csOrg1ID)

	res := doConsole(t, jar, http.MethodGet, ts.URL+consoleSuperuserUsers, nil)
	if res.status != http.StatusOK {
		t.Fatalf("after the rename: got %d to %q", res.status, res.location)
	}
	if got := selectedOrgOption(t, res.body); got != "org1-renamed" {
		t.Fatalf("selected org after the rename: %q", got)
	}
	if n := countUserSessions(t, dbPool, csAdminWithOrgID); n != 1 {
		t.Fatalf("a rename must not end sessions, %d left", n)
	}
}

func TestSelectedOrgIgnoredAfterDemotion(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin-with-org", validAdminPassword)
	requireLoggedIn(t, ts.URL, jar)

	res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org-switcher?org=org2", nil)
	if res.status != http.StatusFound || res.location != "/console/org/org2" {
		t.Fatalf("org switcher: got %d to %q", res.status, res.location)
	}
	cookie := jarCookie(t, jar, ts.URL, sessionCookieName)

	dbc, err := newDBConn(dbPool, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	store, err := consolesession.NewStore(dbPool, time.Hour, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	authenticate := func(t *testing.T) (cdntypes.AuthData, *sessionHandle) {
		t.Helper()
		ad, sh, err := authenticateConsoleRequest(httptest.NewRecorder(), testRequest(t, http.MethodGet, consolePath, cookie), dbc, store)
		if err != nil || sh == nil {
			t.Fatalf("the session was not accepted: %v", err)
		}
		return ad, sh
	}

	if _, sh := authenticate(t); sh.selectedOrgName != "org2" {
		t.Fatalf("selected org before the demotion: %q", sh.selectedOrgName)
	}

	execSQL(t, dbPool, "UPDATE users SET role_id = $1 WHERE id = $2", csUserRoleID, csAdminWithOrgID)

	ad, sh := authenticate(t)
	if ad.Superuser {
		t.Fatal("still a superuser after the demotion")
	}
	if sh.selectedOrgName != "" {
		t.Fatalf("a demoted user must not keep org2 selected, got %q", sh.selectedOrgName)
	}
	if !sh.orgSelected {
		t.Fatal("the stored choice itself must be left alone")
	}
}

func TestSessionAfterUserEdit(t *testing.T) {
	t.Run("display name only keeps the session", func(t *testing.T) {
		ts, _ := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		requireLoggedIn(t, ts.URL, jar)
		org1 := "org1"

		status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+username1ID, "admin", validAdminPassword, putUserBody{Org: &org1, Role: "user", DisplayName: "username1-renamed"})
		if status != http.StatusOK {
			t.Fatalf("PUT user: %d (%s)", status, body)
		}

		requireLoggedIn(t, ts.URL, jar)
	})

	t.Run("console form, another user's role", func(t *testing.T) {
		ts, _ := newSessionTestServer(t, testServerInput{})
		admin := loginJar(t, ts.URL, "admin", validAdminPassword)
		changed := loginJar(t, ts.URL, "username1", validUserPassword)
		other := loginJar(t, ts.URL, "username7", validUserPassword)
		requireLoggedIn(t, ts.URL, admin)
		requireLoggedIn(t, ts.URL, changed)
		requireLoggedIn(t, ts.URL, other)

		res := doConsole(t, admin, http.MethodPost, ts.URL+"/console/superuser/users/"+username1ID+"/edit", url.Values{
			"display_name": {"username1"},
			"role":         {"admin"},
			"org":          {"org1"},
		})
		if res.status != http.StatusSeeOther {
			t.Fatalf("edit user: got %d (%s)", res.status, res.body)
		}

		requireLoggedOut(t, ts.URL, changed)
		requireLoggedIn(t, ts.URL, other)
		requireLoggedIn(t, ts.URL, admin)
	})

	t.Run("console form, own org", func(t *testing.T) {
		ts, _ := newSessionTestServer(t, testServerInput{})
		admin := loginJar(t, ts.URL, "admin", validAdminPassword)
		requireLoggedIn(t, ts.URL, admin)

		res := doConsole(t, admin, http.MethodPost, ts.URL+"/console/superuser/users/"+csAdminID+"/edit", url.Values{
			"display_name": {"admin"},
			"role":         {"admin"},
			"org":          {"org2"},
		})
		// The flash message for the ended session is dropped, the
		// response is still the redirect
		if res.status != http.StatusSeeOther {
			t.Fatalf("edit own user: got %d (%s)", res.status, res.body)
		}

		requireLoggedOut(t, ts.URL, admin)
	})
}

func TestSessionAfterUserDeletion(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "username1", validUserPassword)
	requireLoggedIn(t, ts.URL, jar)

	status, body := apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/users/"+username1ID, "admin", validAdminPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("DELETE user: %d (%s)", status, body)
	}

	requireLoggedOut(t, ts.URL, jar)
	if n := countUserSessions(t, dbPool, username1ID); n != 0 {
		t.Fatalf("%d sessions left after deleting the user", n)
	}
}

func TestSessionAfterPasswordReset(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{})
	admin := loginJar(t, ts.URL, "admin", validAdminPassword)
	first := loginJar(t, ts.URL, "username1", validUserPassword)
	second := loginJar(t, ts.URL, "username1", validUserPassword)
	other := loginJar(t, ts.URL, "username7", validUserPassword)
	requireLoggedIn(t, ts.URL, admin)
	requireLoggedIn(t, ts.URL, first)
	requireLoggedIn(t, ts.URL, second)
	requireLoggedIn(t, ts.URL, other)
	resetForm := url.Values{"password": {newTestPassword}, "confirm-password": {newTestPassword}}

	res := doConsole(t, admin, http.MethodPost, ts.URL+"/console/superuser/users/"+username1ID+"/reset-password", resetForm)
	if res.status != http.StatusSeeOther {
		t.Fatalf("reset password: got %d (%s)", res.status, res.body)
	}

	requireLoggedOut(t, ts.URL, first)
	requireLoggedOut(t, ts.URL, second)
	requireLoggedIn(t, ts.URL, other)
	requireLoggedIn(t, ts.URL, admin)
	loginJar(t, ts.URL, "username1", newTestPassword)

	// An admin resetting their own password loses their session too
	res = doConsole(t, admin, http.MethodPost, ts.URL+"/console/superuser/users/"+csAdminID+"/reset-password", resetForm)
	if res.status != http.StatusSeeOther {
		t.Fatalf("reset own password: got %d (%s)", res.status, res.body)
	}
	requireLoggedOut(t, ts.URL, admin)
}

func TestSessionAfterOwnPasswordChange(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "username1", validUserPassword)
	requireLoggedIn(t, ts.URL, jar)

	status, body := apiJSON(t, http.MethodPut, ts.URL+"/api/v1/users/"+username1ID+"/local-password", "username1", validUserPassword, map[string]string{"old": validUserPassword, "new": newTestPassword})
	if status != http.StatusNoContent {
		t.Fatalf("PUT local-password: %d (%s)", status, body)
	}

	requireLoggedOut(t, ts.URL, jar)
}

func TestPasswordChangeEndsEarlierLogin(t *testing.T) {
	env := newSessionTestEnv(t)
	ctx := context.Background()
	a2Slots, loginLimiter, loginCache := testLoginDeps(t)
	logger := env.logger

	ad, verifiedKey, err := verifyLocalUserPassword(ctx, &logger, env.dbc, a2Slots, loginLimiter, loginCache, netip.MustParsePrefix("192.0.2.1/32"), "username1", validUserPassword)
	if err != nil {
		t.Fatal(err)
	}

	err = startConsoleSession(httptest.NewRecorder(), testRequest(t, http.MethodPost, cdntypes.AuthLoginPath), env.dbc, env.store, env.preLogin, *ad.UserID, loginMethodLocal, verifiedKey)
	if err != nil {
		t.Fatal(err)
	}
	if n := countUserSessions(t, env.dbPool, username1ID); n != 1 {
		t.Fatalf("%d sessions after login, want 1", n)
	}

	_, err = setLocalPassword(ctx, &logger, cdntypes.AuthData{Superuser: true}, env.dbc, a2Slots, loginLimiter, loginCache, netip.Prefix{}, *ad.UserID, "", newTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if n := countUserSessions(t, env.dbPool, username1ID); n != 0 {
		t.Fatalf("the password change left %d sessions", n)
	}
}

func TestAPIBasicAuthAfterRoleChange(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})

	countUsers := func(t *testing.T) int {
		t.Helper()
		status, body := apiJSON(t, http.MethodGet, ts.URL+"/api/v1/users", "username1", validUserPassword, nil)
		if status != http.StatusOK {
			t.Fatalf("GET users: %d (%s)", status, body)
		}
		var users []json.RawMessage
		if err := json.Unmarshal([]byte(body), &users); err != nil {
			t.Fatal(err)
		}
		return len(users)
	}

	if n := countUsers(t); n != 1 {
		t.Fatalf("a normal user sees %d users, want only themselves", n)
	}

	execSQL(t, dbPool, "UPDATE users SET role_id = $1 WHERE id = $2", csAdminRoleID, username1ID)

	if n := countUsers(t); n <= 1 {
		t.Fatalf("after the promotion the user still sees %d users", n)
	}
}

// TestConsoleOrgExistenceIsHidden checks that the org level console pages
// answer identically for an org that does not exist and for one the caller
// may not see.
func TestConsoleOrgExistenceIsHidden(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{})

	pages := []struct {
		name   string
		method string
		suffix string
	}{
		{"dashboard", http.MethodGet, ""},
		{"domains", http.MethodGet, "/domains"},
		{"api-tokens", http.MethodGet, "/api-tokens"},
		{"create domain", http.MethodGet, "/create/domain"},
		{"create domain POST", http.MethodPost, "/create/domain"},
		{"create service", http.MethodGet, "/create/service"},
		{"create service POST", http.MethodPost, "/create/service"},
		{"create api-token", http.MethodGet, "/create/api-token"},
		{"create api-token POST", http.MethodPost, "/create/api-token"},
	}

	do := func(t *testing.T, tsURL string, jar http.CookieJar, method string, org string, suffix string) pageResult {
		t.Helper()
		var form url.Values
		if method == http.MethodPost {
			form = url.Values{"name": {"x"}}
		}
		return doConsole(t, jar, method, tsURL+"/console/org/"+url.PathEscape(org)+suffix, form)
	}

	// An org2 member asking for org1 (exists, out of scope) or for names that do
	// not exist. The UUID of org1 must not be a way around the scoping.
	t.Run("member of another org", func(t *testing.T) {
		jar := loginJar(t, ts.URL, "username7", validUserPassword)
		for _, page := range pages {
			t.Run(page.name, func(t *testing.T) {
				outOfScope := do(t, ts.URL, jar, page.method, "org1", page.suffix)
				if outOfScope.status != http.StatusOK {
					t.Fatalf("another org: status %d, want 200 (%s)", outOfScope.status, outOfScope.body)
				}
				if !strings.Contains(outOfScope.body, consoleOrgNotFound) {
					t.Fatalf("another org: expected %q in body: %s", consoleOrgNotFound, outOfScope.body)
				}
				if strings.Contains(outOfScope.body, consoleNeedOrgMembershipMsg) {
					t.Fatal("another org: got the no-org membership page")
				}

				for _, unknown := range []string{"no-such-org", "Not_A_Valid-Name!", "00000002-0000-0000-0000-0000000000ff"} {
					res := do(t, ts.URL, jar, page.method, unknown, page.suffix)
					if res.status != outOfScope.status {
						t.Fatalf("%q: status %d, another org gave %d", unknown, res.status, outOfScope.status)
					}
					if res.body != outOfScope.body {
						t.Fatalf("%q: body differs from another org's:\n%s\n---\n%s", unknown, res.body, outOfScope.body)
					}
				}

				byID := do(t, ts.URL, jar, page.method, csOrg1ID, page.suffix)
				if byID.status != outOfScope.status || byID.body != outOfScope.body {
					t.Fatalf("another org by UUID differs from another org by name: %d\n%s", byID.status, byID.body)
				}
			})
		}
	})

	t.Run("no org", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		execSQL(t, dbPool, "UPDATE users SET org_id = NULL WHERE id = $1", username1ID)
		for _, page := range pages {
			t.Run(page.name, func(t *testing.T) {
				for _, org := range []string{"org1", "no-such-org"} {
					res := do(t, ts.URL, jar, page.method, org, page.suffix)
					if res.status != http.StatusOK {
						t.Fatalf("%s: status %d (%s), want %d", org, res.status, res.body, http.StatusOK)
					}
					if !strings.Contains(res.body, consoleNeedOrgMembershipMsg) {
						t.Fatalf("%s: expected the membership page: %s", org, res.body)
					}
				}
			})
		}
	})

	t.Run("superuser", func(t *testing.T) {
		jar := loginJar(t, ts.URL, "admin", validAdminPassword)
		for _, page := range pages {
			t.Run(page.name, func(t *testing.T) {
				res := do(t, ts.URL, jar, page.method, "no-such-org", page.suffix)
				if res.status != http.StatusOK {
					t.Fatalf("status %d (%s), want %d", res.status, res.body, http.StatusOK)
				}
				if !strings.Contains(res.body, consoleOrgNotFound) {
					t.Fatalf("expected %q in body: %s", consoleOrgNotFound, res.body)
				}
			})
		}
	})
}

// TestConsoleEditOrgNotFoundTitleIgnoresURL checks that the edit-org error
// page does not reflect the URL-supplied org name in its title.
func TestConsoleEditOrgNotFoundTitleIgnoresURL(t *testing.T) {
	ts, _ := newSessionTestServer(t, testServerInput{})
	jar := loginJar(t, ts.URL, "admin", validAdminPassword)

	const orgName = "no-such-org"
	res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/superuser/orgs/"+orgName+"/edit", nil)
	if res.status != http.StatusOK {
		t.Fatalf("status %d (%s), want %d", res.status, res.body, http.StatusOK)
	}
	if !strings.Contains(res.body, consoleOrgNotFound) {
		t.Fatalf("expected %q in body: %s", consoleOrgNotFound, res.body)
	}
	start := strings.Index(res.body, "<title>")
	end := strings.Index(res.body, "</title>")
	if start < 0 || end < start {
		t.Fatalf("no <title> in body: %s", res.body)
	}
	if title := res.body[start:end]; strings.Contains(title, orgName) {
		t.Fatalf("title reflects URL-supplied org name: %q", title)
	}
}

// TestConsoleServiceExistenceIsHidden checks that on the console service
// pages an org or service that does not exist and one the caller may not see
// give the same page: same status and byte-identical body. The page must take
// nothing from the URL, which includes the breadcrumbs.
func TestConsoleServiceExistenceIsHidden(t *testing.T) {
	const (
		org1Service1ID = "00000003-0000-0000-0000-000000000001"
		unknownID      = "00000003-0000-0000-0000-0000000000ff"
	)

	ts, _ := newSessionTestServer(t, testServerInput{})

	// The two %s are the org and the service as they appear in the URL.
	pages := []struct {
		name     string
		method   string
		path     string
		notFound string
		// ownVersion is a URL of the caller's own org2-service1 with a
		// version that does not exist; it must give the same page.
		ownVersion string
	}{
		{"service", http.MethodGet, "/console/org/%s/services/%s", consoleServiceNotFound, ""},
		{"service version", http.MethodGet, "/console/org/%s/services/%s/3", "Service version not found", "/console/org/org2/services/org2-service1/999"},
		{"create service version", http.MethodGet, "/console/org/%s/create/service/version/%s", consoleServiceNotFound, ""},
		{"create service version POST", http.MethodPost, "/console/org/%s/create/service/version/%s", consoleServiceNotFound, ""},
		{"activate", http.MethodGet, "/console/org/%s/services/%s/3/activate", consoleServiceNotFound, ""},
		{"activate POST", http.MethodPost, "/console/org/%s/services/%s/3/activate", consoleServiceNotFound, ""},
		{"disable", http.MethodGet, "/console/org/%s/services/%s/disable", consoleServiceNotFound, ""},
		{"disable POST", http.MethodPost, "/console/org/%s/services/%s/disable", consoleServiceNotFound, ""},
		{"enable POST", http.MethodPost, "/console/org/%s/services/%s/enable", consoleServiceNotFound, ""},
	}

	do := func(t *testing.T, tsURL string, jar http.CookieJar, method string, path string, org string, service string) pageResult {
		t.Helper()
		var form url.Values
		if method == http.MethodPost {
			form = url.Values{"x": {"y"}}
		}
		return doConsole(t, jar, method, tsURL+fmt.Sprintf(path, url.PathEscape(org), url.PathEscape(service)), form)
	}

	// As an org2 member: another org with a real service, another org with
	// a missing service, missing org, own org with a missing service, and
	// the UUID of another org's service under the own org.
	targets := []struct {
		name    string
		org     string
		service string
	}{
		{"another org, existing service", "org1", "org1-service1"},
		{"another org by UUID, existing service by UUID", csOrg1ID, org1Service1ID},
		{"another org, missing service", "org1", "no-such-service"},
		{"missing org", "no-such-org", "org1-service1"},
		{"missing org, missing service", "no-such-org", "no-such-service"},
		{"own org, missing service", "org2", "no-such-service"},
		{"own org, missing service UUID", "org2", unknownID},
		{"own org, another org's service by UUID", "org2", org1Service1ID},
		{"malformed names", "Not_A_Valid-Name!", "Not_A_Valid-Name!"},
	}

	t.Run("member of another org", func(t *testing.T) {
		jar := loginJar(t, ts.URL, "username7", validUserPassword)
		for _, page := range pages {
			t.Run(page.name, func(t *testing.T) {
				first := do(t, ts.URL, jar, page.method, page.path, targets[0].org, targets[0].service)
				if first.status != http.StatusOK {
					t.Fatalf("%s: status %d, want 200 (%s)", targets[0].name, first.status, first.body)
				}
				if !strings.Contains(first.body, page.notFound) {
					t.Fatalf("%s: expected %q in body: %s", targets[0].name, page.notFound, first.body)
				}
				if strings.Contains(first.body, consoleNeedOrgMembershipMsg) {
					t.Fatalf("%s: got the no-org membership page", targets[0].name)
				}

				for _, target := range targets[1:] {
					res := do(t, ts.URL, jar, page.method, page.path, target.org, target.service)
					if res.status != first.status {
						t.Fatalf("%s: status %d, %s gave %d", target.name, res.status, targets[0].name, first.status)
					}
					if res.body != first.body {
						t.Fatalf("%s: body differs from %s:\n%s\n---\n%s", target.name, targets[0].name, res.body, first.body)
					}
				}

				if page.ownVersion != "" {
					res := doConsole(t, jar, page.method, ts.URL+page.ownVersion, nil)
					if res.status != first.status || res.body != first.body {
						t.Fatalf("unknown version of own service differs from another org's service page: %d\n%s", res.status, res.body)
					}
				}
			})
		}
	})

	t.Run("services list", func(t *testing.T) {
		jar := loginJar(t, ts.URL, "username7", validUserPassword)
		get := func(org string) pageResult {
			return doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/"+url.PathEscape(org)+"/services", nil)
		}
		outOfScope := get("org1")
		if outOfScope.status != http.StatusOK {
			t.Fatalf("another org: status %d, want 200 (%s)", outOfScope.status, outOfScope.body)
		}
		if !strings.Contains(outOfScope.body, consoleOrgNotFound) {
			t.Fatalf("expected %q in body: %s", consoleOrgNotFound, outOfScope.body)
		}
		for _, org := range []string{"no-such-org", "Not_A_Valid-Name!", csOrg1ID, "00000002-0000-0000-0000-0000000000ff"} {
			res := get(org)
			if res.status != outOfScope.status || res.body != outOfScope.body {
				t.Fatalf("%q differs from the page for another org: %d\n%s", org, res.status, res.body)
			}
		}
	})

	t.Run("no org", func(t *testing.T) {
		ts, dbPool := newSessionTestServer(t, testServerInput{})
		jar := loginJar(t, ts.URL, "username1", validUserPassword)
		execSQL(t, dbPool, "UPDATE users SET org_id = NULL WHERE id = $1", username1ID)
		for _, page := range pages {
			t.Run(page.name, func(t *testing.T) {
				for _, target := range targets[:4] {
					res := do(t, ts.URL, jar, page.method, page.path, target.org, target.service)
					if res.status != http.StatusOK {
						t.Fatalf("%s: status %d, want 200 (%s)", target.name, res.status, res.body)
					}
					if !strings.Contains(res.body, consoleNeedOrgMembershipMsg) {
						t.Fatalf("%s: expected the membership page: %s", target.name, res.body)
					}
				}
			})
		}
		res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/services", nil)
		if res.status != http.StatusOK || !strings.Contains(res.body, consoleNeedOrgMembershipMsg) {
			t.Fatalf("services list: status %d (want 200), expected the membership page: %s", res.status, res.body)
		}
	})

	t.Run("superuser", func(t *testing.T) {
		jar := loginJar(t, ts.URL, "admin", validAdminPassword)
		for _, page := range pages {
			t.Run(page.name, func(t *testing.T) {
				first := do(t, ts.URL, jar, page.method, page.path, "no-such-org", "no-such-service")
				if first.status != http.StatusOK {
					t.Fatalf("status %d, want 200 (%s)", first.status, first.body)
				}
				if !strings.Contains(first.body, page.notFound) {
					t.Fatalf("expected %q in body: %s", page.notFound, first.body)
				}
				for _, target := range []struct{ org, service string }{{"org1", "no-such-service"}, {"no-such-org", "org1-service1"}, {"org1", unknownID}} {
					res := do(t, ts.URL, jar, page.method, page.path, target.org, target.service)
					if res.status != first.status || res.body != first.body {
						t.Fatalf("%s/%s differs from the unknown org page: %d\n%s", target.org, target.service, res.status, res.body)
					}
				}
			})
		}

		res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/no-such-org/services", nil)
		if res.status != http.StatusOK || !strings.Contains(res.body, consoleOrgNotFound) {
			t.Fatalf("services list: status %d (want 200), expected %q: %s", res.status, consoleOrgNotFound, res.body)
		}

		// The delete page is superuser only, so it is only reachable here.
		const deletePath = "/console/org/%s/services/%s/delete"
		del := do(t, ts.URL, jar, http.MethodGet, deletePath, "no-such-org", "no-such-service")
		if del.status != http.StatusOK || !strings.Contains(del.body, consoleServiceNotFound) {
			t.Fatalf("delete: status %d (want 200), expected %q: %s", del.status, consoleServiceNotFound, del.body)
		}
		delOrg1 := do(t, ts.URL, jar, http.MethodGet, deletePath, "org1", "no-such-service")
		if delOrg1.status != del.status || delOrg1.body != del.body {
			t.Fatalf("delete of a missing service in a real org differs: %d\n%s", delOrg1.status, delOrg1.body)
		}
	})
}
