-- Seeds of Success — D1 Auth Schema (Invite Token + Users)
-- One-time login using single-use invite tokens.
-- Run this in your D1 database (via the Supabase-like SQL tab in Cloudflare, or d1 CLI).

-- Invite tokens table
CREATE TABLE IF NOT EXISTS login_invites (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  role_to_grant TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

-- Minimal user accounts table (role-based)
-- Passwords are not stored because login is via token consumption.
CREATE TABLE IF NOT EXISTS user_accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  display_name TEXT,
  created_at TEXT NOT NULL
);

-- User sessions table for cookie sessions
-- (Stored server-side so logout + expiry are manageable)
CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  FOREIGN KEY (user_id) REFERENCES user_accounts(id)
);

-- Helper indexes (performance)
CREATE INDEX IF NOT EXISTS idx_login_invites_token ON login_invites(token);
CREATE INDEX IF NOT EXISTS idx_login_invites_email ON login_invites(email);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);

