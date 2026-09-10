-- Store donation amounts in dollars while preserving all existing donation data.
-- SQLite table rebuild is used so the obsolete cents column is removed.
CREATE TABLE donations_new (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  amount_dollars REAL NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'pending',
  verified_at TEXT,
  verified_by TEXT
);

INSERT INTO donations_new (
  id, full_name, email, amount_dollars, created_at, status, verified_at, verified_by
)
SELECT
  id, full_name, email, amount_cents / 100.0, created_at,
  COALESCE(status, 'pending'), verified_at, verified_by
FROM donations;

DROP TABLE donations;

ALTER TABLE donations_new RENAME TO donations;
