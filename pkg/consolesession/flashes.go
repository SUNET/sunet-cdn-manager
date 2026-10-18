package consolesession

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// foreign_key_violation, see
// https://www.postgresql.org/docs/current/errcodes-appendix.html
const pgForeignKeyViolation = "23503"

// ErrFlashTargetGone is returned by AddFlash when the session or org the
// message belongs to no longer exists, e.g. because the request that adds
// the message ended the user's own sessions.
var ErrFlashTargetGone = errors.New("consolesession: session or org of flash message no longer exists")

// FlashCategory names the page a flash message is shown on. The store only
// compares categories, the caller defines them.
type FlashCategory string

// AddFlash stores a message to show once on the next page of category for
// sessionID. orgID is nil for global (superuser) pages, so a message for one
// org is never shown on another org's page.
func (s *Store) AddFlash(ctx context.Context, sessionID pgtype.UUID, category FlashCategory, orgID *pgtype.UUID, message string) error {
	_, err := s.pool.Exec(
		ctx,
		"INSERT INTO console_session_flashes (session_id, category, org_id, message) VALUES ($1, $2, $3, $4)",
		sessionID,
		category,
		orgID,
		message,
	)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgForeignKeyViolation {
			return ErrFlashTargetGone
		}
		return fmt.Errorf("consolesession: unable to add flash message: %w", err)
	}
	return nil
}

// PopFlashes deletes the messages of sessionID for category and orgID and
// returns those younger than FlashLifetime, oldest first. The ids are
// random, so the order comes from time_created.
func (s *Store) PopFlashes(ctx context.Context, sessionID pgtype.UUID, category FlashCategory, orgID *pgtype.UUID) ([]string, error) {
	rows, err := s.pool.Query(
		ctx,
		`WITH popped AS (
		     DELETE FROM console_session_flashes
		     WHERE session_id = $1 AND category = $2
		       AND org_id IS NOT DISTINCT FROM $3
		     RETURNING message, time_created
		 )
		 SELECT message FROM popped
		 WHERE time_created > now() - $4::interval
		 ORDER BY time_created`,
		sessionID,
		category,
		orgID,
		s.flashLifetime,
	)
	if err != nil {
		return nil, fmt.Errorf("consolesession: unable to read flash messages: %w", err)
	}

	messages, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("consolesession: unable to collect flash messages: %w", err)
	}

	return messages, nil
}
