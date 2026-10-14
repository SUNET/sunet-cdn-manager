-- +goose up

-- argon2.IDKey panics for time or threads below 1, make sure such settings
-- can never be stored.
ALTER TABLE user_argon2keys ADD CONSTRAINT argon2_time_positive CHECK (time >= 1);
ALTER TABLE user_argon2keys ADD CONSTRAINT argon2_threads_positive CHECK (threads >= 1);
