-- Donations table: stores intended donation submissions (no payment processing).

CREATE TABLE IF NOT EXISTS donations (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
