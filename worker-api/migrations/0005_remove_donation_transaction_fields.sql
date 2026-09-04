-- Remove transaction_reference and payment_submitted_at columns from donations.
-- SQLite (D1) does not support DROP COLUMN in all cases, so we rebuild the table.

-- 1. Create the new table with only the needed columns.
CREATE TABLE donations_new (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'pending',
  verified_at TEXT,
  verified_by TEXT
);

-- 2. Copy existing data (omitting the removed columns).
INSERT INTO donations_new (id, full_name, email, amount_cents, created_at, status, verified_at, verified_by)
SELECT id, full_name, email, amount_cents, created_at, COALESCE(status, 'pending'), verified_at, verified_by
FROM donations;

-- 3. Drop the old table.
DROP TABLE donations;

-- 4. Rename the new table.
ALTER TABLE donations_new RENAME TO donations;
