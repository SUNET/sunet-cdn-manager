-- +goose up

-- A user can be a member of any number of orgs, including none, so the
-- single users.org_id column is replaced by this join table. Roles stay on
-- users: a membership only says that the user is in the org.
--
-- org_id has no ON DELETE action, so an org that still has members cannot be
-- deleted. Memberships then only ever change through the user update code,
-- which also ends the user's console sessions, rather than disappearing
-- silently along with an org while sessions issued under them live on.
--
-- user_id cascades: a deleted user has no memberships left to keep, and the
-- user's console sessions cascade away with the user as well.
--
-- UNIQUE(user_id, org_id) keeps a membership from being recorded twice. Its
-- index leads with user_id, so it also serves looking up the orgs of a user,
-- which the authentication queries do on every request.
CREATE TABLE user_orgs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id uuid NOT NULL REFERENCES orgs(id),
    UNIQUE(user_id, org_id)
);

-- Serves looking up the members of an org, including the foreign key check
-- run when an org row is deleted, which would otherwise scan the table.
CREATE INDEX user_orgs_org_id_idx ON user_orgs (org_id);

INSERT INTO user_orgs (user_id, org_id) SELECT id, org_id FROM users WHERE org_id IS NOT NULL;

ALTER TABLE users DROP COLUMN org_id;
