CREATE TABLE users (
  id UUID PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
);

CREATE TABLE password_credentials (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  username VARCHAR(255) NOT NULL UNIQUE,
  hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
);

CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  name VARCHAR(255) NOT NULL,
  key_prefix VARCHAR(32) NOT NULL,
  hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_user_id ON api_keys (user_id);

CREATE INDEX idx_api_keys_key_prefix ON api_keys (key_prefix);

CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);

CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE ON UPDATE CASCADE,
  hash TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);

CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

CREATE TABLE opaque_tokens (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE ON UPDATE CASCADE,
  hash TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_opaque_tokens_user_id ON opaque_tokens (user_id);

CREATE INDEX idx_opaque_tokens_session_id ON opaque_tokens (session_id);

CREATE INDEX idx_opaque_tokens_expires_at ON opaque_tokens (expires_at);
