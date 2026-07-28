-- Run this file against your postgreSQL database to create the initial schema.
-- Command: psql $DATABASE_URL -f migrations/initial_schema.sql
-- Or use your DB dashboard SQL editor to run it manually.

-- gen_random_uuid() is built into PostgreSQL 13+.
-- Neon runs PostgreSQL 16 so no extension is needed. In some,extension is needed

-- Temporary storage for unverified registrations.
-- Data moves to the users table only after OTP verification.
-- Rows older than 3 days are cleaned up automatically by the server.

CREATE TABLE IF NOT EXISTS pending_registrations (
  id            SERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  otp_hash      TEXT NOT NULL,
  otp_expires_at TIMESTAMPTZ NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0,   -- failed OTP attempts counter
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT,                        -- NULL for OAuth users
  provider      TEXT NOT NULL DEFAULT 'local',
  provider_id   TEXT,                        -- NULL for local users
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  avatar_url    TEXT,
  is_verified   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  timezone      TEXT,
  last_login_at TIMESTAMPTZ,
  deleted_at    TIMESTAMPTZ                  -- NULL means active, timestamp means soft-deleted
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         SERIAL PRIMARY KEY,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  family_id  TEXT NOT NULL,
  is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id         SERIAL PRIMARY KEY,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at    TIMESTAMPTZ,           -- NULL means unused. timestamp means already used.
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Covers the token hash lookup on every authenticated request
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash
  ON refresh_tokens(token_hash);

-- Covers login lookup by email
CREATE INDEX IF NOT EXISTS idx_users_email
  ON users(email);

-- Covers password reset token lookup by hash during password reset flow
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash
  ON password_reset_tokens(token_hash);

-- Covers pending registration lookup by email during OTP verification
CREATE INDEX IF NOT EXISTS idx_pending_registrations_email
  ON pending_registrations(email);

-- Cron job to delete pending registration from db after 3 days. i did this on SUPABASE db
SELECT cron.schedule(
  'cleanup-pending-registrations',
  '0 4 * * *',
  $$ DELETE FROM pending_registrations WHERE created_at < NOW() - INTERVAL '3 days' $$
);

-- To delete every revoked refresh token in the db after 24hrs
SELECT cron.schedule(
  'cleanup-revoked-refresh-tokens',
  '0 5 * * *',
  $$ DELETE FROM refresh_tokens WHERE is_revoked = TRUE AND revoked_at < NOW() - INTERVAL '24 hours' $$
);