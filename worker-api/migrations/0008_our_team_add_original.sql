-- Allow 'original' source type for backfilled team members
PRAGMA defer_foreign_keys = ON;

CREATE TABLE IF NOT EXISTS our_team_new (
  id TEXT PRIMARY KEY,
  source_application_id TEXT,
  source_application_type TEXT CHECK (source_application_type IN ('tutor', 'volunteer', 'original') OR source_application_type IS NULL),
  name TEXT NOT NULL,
  role TEXT,
  bio TEXT,
  image_url TEXT,
  display_at_team INTEGER NOT NULL DEFAULT 0 CHECK (display_at_team IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT
);

INSERT INTO our_team_new (id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at)
SELECT id, source_application_id, source_application_type, name, role, bio, image_url, display_at_team, created_at, updated_at
FROM our_team;

DROP TABLE our_team;

ALTER TABLE our_team_new RENAME TO our_team;

CREATE UNIQUE INDEX IF NOT EXISTS idx_our_team_source_app
  ON our_team(source_application_id, source_application_type)
  WHERE source_application_id IS NOT NULL AND source_application_type IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_our_team_display ON our_team(display_at_team);
CREATE INDEX IF NOT EXISTS idx_our_team_created ON our_team(created_at);
