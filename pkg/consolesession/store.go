package consolesession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FlashLifetime is how long a flash message waits to be shown before it is
// dropped.
const FlashLifetime = 5 * time.Minute

// maxTouchInterval is the longest time between two last_seen updates, so an
// active session causes at most one write a minute. See touchInterval in
// NewStore.
const maxTouchInterval = time.Minute

var (
	// ErrNotFound means there is no session with the token's id.
	ErrNotFound = errors.New("consolesession: unknown session")
	// ErrBadSecret means the session exists but the token's secret does
	// not match. The session is left alone: ids are public, so acting on
	// an id alone would let anyone who can read the logs end other users'
	// sessions.
	ErrBadSecret = errors.New("consolesession: session secret does not match")
	// ErrIdleExpired means the session was not used within the idle
	// timeout.
	ErrIdleExpired = errors.New("consolesession: session idle timeout reached")
	// ErrAbsoluteExpired means the session is older than the absolute
	// timeout.
	ErrAbsoluteExpired = errors.New("consolesession: session absolute timeout reached")
)

// Store checks and changes console sessions.
type Store struct {
	pool            *pgxpool.Pool
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	touchInterval   time.Duration
	flashLifetime   time.Duration
}

// NewStore returns a Store. A session ends when it has not been used for
// idleTimeout, or absoluteTimeout after it was created.
func NewStore(pool *pgxpool.Pool, idleTimeout time.Duration, absoluteTimeout time.Duration) (*Store, error) {
	if pool == nil {
		return nil, errors.New("consolesession: pool must not be nil")
	}
	if idleTimeout <= 0 {
		return nil, fmt.Errorf("consolesession: idle timeout must be positive, got %s", idleTimeout)
	}
	if absoluteTimeout < idleTimeout {
		return nil, fmt.Errorf("consolesession: absolute timeout %s is shorter than idle timeout %s", absoluteTimeout, idleTimeout)
	}

	return &Store{
		pool:            pool,
		idleTimeout:     idleTimeout,
		absoluteTimeout: absoluteTimeout,
		// touchInterval is a tenth of idleTimeout, but at most
		// maxTouchInterval.
		//
		// last_seen is only written when it is at least touchInterval
		// old, so most requests cause no database write. last_seen can
		// therefore lag the last request by up to touchInterval, and a
		// session can end up to touchInterval before idleTimeout has
		// passed, never after.
		//
		// A tenth of idleTimeout keeps that early end within 10% of
		// idleTimeout: a fixed touchInterval of one minute would end a
		// session with a 2 minute idleTimeout after 1 minute of
		// inactivity. The divisor is a judgment call, a smaller one
		// means fewer writes and a larger early end. maxTouchInterval
		// caps the early end for long idle timeouts, at the cost of
		// more frequent writes.
		touchInterval: min(maxTouchInterval, idleTimeout/10),
		flashLifetime: FlashLifetime,
	}, nil
}

// Session is the data of a console session. It is only valid when Lookup
// returns a nil error: with ErrIdleExpired or ErrAbsoluteExpired Lookup
// returns it just to tell who the expired session belonged to.
type Session struct {
	ID     pgtype.UUID
	UserID pgtype.UUID
	// OrgSelected is false if the org switcher was never used.
	// SelectedOrgID is nil for "no org", including when the selected org
	// was deleted.
	OrgSelected   bool
	SelectedOrgID *pgtype.UUID
	// TouchDue means the caller should call Touch.
	TouchDue bool
	// HasFlashes means PopFlashes may return messages.
	HasFlashes bool
}

type sessionRow struct {
	secretHash      []byte
	session         Session
	idleExpired     bool
	absoluteExpired bool
}

// CreateTx adds a session for userID in tx and returns its token. The secret
// only exists in the returned token, the database gets its SHA-256.
func CreateTx(ctx context.Context, tx pgx.Tx, userID pgtype.UUID) (Token, error) {
	secret, err := newSecret()
	if err != nil {
		return Token{}, err
	}

	tok := Token{secret: secret}
	err = tx.QueryRow(
		ctx,
		"INSERT INTO console_sessions (secret_hash, user_id) VALUES ($1, $2) RETURNING id",
		tok.secretHash(),
		userID,
	).Scan(&tok.ID)
	if err != nil {
		return Token{}, fmt.Errorf("consolesession: unable to create session: %w", err)
	}

	return tok, nil
}

// Lookup checks tok and returns its session. A session that has reached a
// timeout is deleted, and Lookup then returns ErrIdleExpired or
// ErrAbsoluteExpired together with the session, so the caller can log who
// it belonged to. Lookup never updates a valid session, see
// Session.TouchDue.
func (s *Store) Lookup(ctx context.Context, tok Token) (Session, error) {
	row, err := s.lookupRow(ctx, tok.ID)
	if err != nil {
		return Session{}, err
	}

	if !tok.matches(row.secretHash) {
		return Session{}, ErrBadSecret
	}

	var expired error
	switch {
	case row.absoluteExpired:
		expired = ErrAbsoluteExpired
	case row.idleExpired:
		expired = ErrIdleExpired
	default:
		return row.session, nil
	}

	// The secret matched, so ending the session is safe
	if err := s.delete(ctx, tok.ID); err != nil {
		return row.session, errors.Join(expired, err)
	}

	return row.session, expired
}

// Touch records that a session was used now. It does nothing if last_seen
// is younger than touchInterval: concurrent requests can all see TouchDue,
// and only the first of them needs to write. An UPDATE that waited for the
// row lock of another Touch checks the condition again against the row that
// Touch committed, so it skips the write too.
func (s *Store) Touch(ctx context.Context, id pgtype.UUID) error {
	_, err := s.pool.Exec(
		ctx,
		"UPDATE console_sessions SET last_seen = now() WHERE id = $1 AND now() - last_seen >= $2::interval",
		id,
		s.touchInterval,
	)
	if err != nil {
		return fmt.Errorf("consolesession: unable to update last_seen: %w", err)
	}
	return nil
}

// Destroy ends the session of tok if its secret matches, and returns the
// user it belonged to. Otherwise it returns ErrNotFound or ErrBadSecret and
// leaves the session alone.
func (s *Store) Destroy(ctx context.Context, tok Token) (pgtype.UUID, error) {
	row, err := s.lookupRow(ctx, tok.ID)
	if err != nil {
		return pgtype.UUID{}, err
	}

	if !tok.matches(row.secretHash) {
		return pgtype.UUID{}, ErrBadSecret
	}

	if err := s.delete(ctx, tok.ID); err != nil {
		return pgtype.UUID{}, err
	}

	return row.session.UserID, nil
}

// DeleteForUserTx ends all sessions of userID in tx and returns how many
// there were. If tx is rolled back the sessions stay.
func DeleteForUserTx(ctx context.Context, tx pgx.Tx, userID pgtype.UUID) (int64, error) {
	tag, err := tx.Exec(ctx, "DELETE FROM console_sessions WHERE user_id = $1", userID)
	if err != nil {
		return 0, fmt.Errorf("consolesession: unable to delete sessions of user: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) delete(ctx context.Context, id pgtype.UUID) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM console_sessions WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("consolesession: unable to delete session: %w", err)
	}
	return nil
}

// lookupRow reads a session row. All time checks use the database clock.
func (s *Store) lookupRow(ctx context.Context, id pgtype.UUID) (sessionRow, error) {
	row := sessionRow{session: Session{ID: id}}
	err := s.pool.QueryRow(
		ctx,
		`SELECT s.secret_hash, s.user_id, s.org_selected, s.selected_org_id,
		        now() - s.last_seen >= $2::interval,
		        now() - s.time_created >= $3::interval,
		        now() - s.last_seen >= $4::interval,
		        EXISTS (SELECT 1 FROM console_session_flashes f
		                WHERE f.session_id = s.id
		                  AND f.time_created > now() - $5::interval)
		 FROM console_sessions s WHERE s.id = $1`,
		id,
		s.idleTimeout,
		s.absoluteTimeout,
		s.touchInterval,
		s.flashLifetime,
	).Scan(
		&row.secretHash,
		&row.session.UserID,
		&row.session.OrgSelected,
		&row.session.SelectedOrgID,
		&row.idleExpired,
		&row.absoluteExpired,
		&row.session.TouchDue,
		&row.session.HasFlashes,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sessionRow{}, ErrNotFound
		}
		return sessionRow{}, fmt.Errorf("consolesession: session lookup failed: %w", err)
	}

	return row, nil
}

// SetSelectedOrg stores the org picked in the org switcher. A nil orgID
// stores an explicit "no org", which differs from never having picked one.
func (s *Store) SetSelectedOrg(ctx context.Context, sessionID pgtype.UUID, orgID *pgtype.UUID) error {
	_, err := s.pool.Exec(ctx, "UPDATE console_sessions SET org_selected = true, selected_org_id = $2 WHERE id = $1", sessionID, orgID)
	if err != nil {
		return fmt.Errorf("consolesession: unable to store selected org: %w", err)
	}
	return nil
}

// Sweep deletes expired sessions and stale flash messages, and returns how
// many of each it deleted. Correctness does not depend on it, Lookup and
// PopFlashes enforce the timeouts themselves.
func (s *Store) Sweep(ctx context.Context) (int64, int64, error) {
	sessions, err := s.pool.Exec(
		ctx,
		"DELETE FROM console_sessions WHERE last_seen <= now() - $1::interval OR time_created <= now() - $2::interval",
		s.idleTimeout,
		s.absoluteTimeout,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("consolesession: unable to delete expired sessions: %w", err)
	}

	flashes, err := s.pool.Exec(ctx, "DELETE FROM console_session_flashes WHERE time_created <= now() - $1::interval", s.flashLifetime)
	if err != nil {
		return sessions.RowsAffected(), 0, fmt.Errorf("consolesession: unable to delete stale flash messages: %w", err)
	}

	return sessions.RowsAffected(), flashes.RowsAffected(), nil
}
