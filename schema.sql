BEGIN;
CREATE TABLE IF NOT EXISTS fufa_users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL, username text NOT NULL,
 password_hash text NOT NULL, email_verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS fufa_sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES fufa_users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fufa_sessions_user ON fufa_sessions(user_id);
CREATE TABLE IF NOT EXISTS fufa_tokens (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES fufa_users(id) ON DELETE CASCADE,
 purpose text NOT NULL CHECK (purpose IN ('verify','reset')), expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS fufa_tokens_user ON fufa_tokens(user_id);
CREATE TABLE IF NOT EXISTS fufa_rate_limits (
 key text PRIMARY KEY, hits integer NOT NULL, expires_at timestamptz NOT NULL
);
COMMIT;
