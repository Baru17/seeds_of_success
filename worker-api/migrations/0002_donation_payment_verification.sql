-- Add payment reference and verification fields to donations

ALTER TABLE donations ADD COLUMN transaction_reference TEXT;

ALTER TABLE donations ADD COLUMN payment_submitted_at TEXT;

ALTER TABLE donations ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';

ALTER TABLE donations ADD COLUMN verified_at TEXT;

ALTER TABLE donations ADD COLUMN verified_by TEXT;