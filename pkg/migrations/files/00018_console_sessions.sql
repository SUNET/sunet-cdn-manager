-- +goose up

-- Console login sessions. The id is public (it is in the cookie and in
-- logs), only the SHA-256 of the session secret is stored. Idle and absolute
-- expiry are computed from last_seen and time_created when a session is
-- checked, so changed timeouts apply to existing sessions.
CREATE TABLE console_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_hash bytea NOT NULL CONSTRAINT secret_hash_length CHECK(length(secret_hash) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    time_created timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    -- org_selected = false: the org switcher was never used. true with a
    -- NULL selected_org_id: explicitly "no org". Deleting the selected org
    -- only clears selected_org_id, so the session becomes "no org", not
    -- "never selected". Otherwise the dashboard would again move a
    -- superuser to their own org, which is meant to happen once per login.
    org_selected boolean NOT NULL DEFAULT false,
    selected_org_id uuid REFERENCES orgs(id) ON DELETE SET NULL,
    CONSTRAINT selected_org_requires_flag CHECK (org_selected OR selected_org_id IS NULL)
);

-- For ending all sessions of a user (DeleteForUserTx) and the cascade when
-- the user is deleted. last_seen is not indexed, e.g. for the sweeper, as
-- that would make every Touch also write to the index.
CREATE INDEX console_sessions_user_id_idx ON console_sessions (user_id);

-- Messages shown once on the next page of their category. The categories
-- are listed in flashMessageKeys in pkg/server. org_id is NULL for global
-- (superuser) pages.
CREATE TABLE console_session_flashes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id uuid NOT NULL REFERENCES console_sessions(id) ON DELETE CASCADE,
    org_id uuid REFERENCES orgs(id) ON DELETE CASCADE,
    time_created timestamptz NOT NULL DEFAULT now(),
    category text NOT NULL,
    message text NOT NULL
);

-- lookupRow checks for flash messages on every console request, and
-- PopFlashes and the cascade from console_sessions also find them by
-- session. Flashes are deleted when shown and swept after FlashLifetime, so
-- the table stays small, but the index keeps these lookups cheap even if
-- the sweeper falls behind. A session rarely has more than a message or
-- two, so time_created would not narrow the lookup.
CREATE INDEX console_session_flashes_session_id_idx ON console_session_flashes (session_id);
