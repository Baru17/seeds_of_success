DROP TABLE IF EXISTS volunteer_applications;

CREATE TABLE volunteer_applications (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  role TEXT NOT NULL,
  skills TEXT,
  message TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  reviewed_at TEXT,
  created_at TEXT NOT NULL
);

DROP TABLE IF EXISTS tutor_applications;

CREATE TABLE tutor_applications (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  skills TEXT,
  availability TEXT,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  reviewed_at TEXT,
  created_at TEXT NOT NULL
);