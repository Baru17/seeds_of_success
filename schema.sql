-- Seeds of Success D1 schema additions for dashboard management.

CREATE TABLE IF NOT EXISTS user_accounts (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  role TEXT NOT NULL CHECK (role IN ('admin', 'tutor', 'volunteer')),
  password_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'inactive', 'rejected')),
  notification_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS tutor_applications (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  skills TEXT,
  availability TEXT,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS volunteer_applications (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  role TEXT NOT NULL CHECK (role IN ('Curriculum Developer', 'Technology Implementer', 'Teaching Helper', 'Well Wisher', 'Supporter')),
  skills TEXT,
  message TEXT,
  password_hash TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  grade TEXT,
  school TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'inactive')),
  created_by_admin_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (created_by_admin_id) REFERENCES user_accounts(id)
);

CREATE TABLE IF NOT EXISTS student_assignments (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  tutor_id TEXT,
  assigned_by_admin_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reassigned', 'inactive')),
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (student_id) REFERENCES students(id),
  FOREIGN KEY (tutor_id) REFERENCES user_accounts(id),
  FOREIGN KEY (assigned_by_admin_id) REFERENCES user_accounts(id)
);

CREATE TABLE IF NOT EXISTS student_topics (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  topic_name TEXT NOT NULL,
  score INTEGER DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
  completed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id)
);

CREATE TABLE IF NOT EXISTS tutoring_sessions (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL,
  tutor_id TEXT NOT NULL,
  session_time TEXT NOT NULL,
  notes TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('scheduled', 'completed', 'missed')),
  created_at TEXT NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id),
  FOREIGN KEY (tutor_id) REFERENCES user_accounts(id)
);

CREATE TABLE IF NOT EXISTS volunteer_tasks (
  id TEXT PRIMARY KEY,
  volunteer_id TEXT NOT NULL,
  assigned_by_admin_id TEXT,
  task_title TEXT NOT NULL,
  task_notes TEXT,
  due_at TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed', 'cancelled')),
  created_at TEXT NOT NULL,
  updated_at TEXT,
  FOREIGN KEY (volunteer_id) REFERENCES user_accounts(id),
  FOREIGN KEY (assigned_by_admin_id) REFERENCES user_accounts(id)
);

CREATE TABLE IF NOT EXISTS parent_feedback (
  id TEXT PRIMARY KEY,
  student_id TEXT,
  parent_name TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  thank_you_sent_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id)
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  recipient_user_id TEXT,
  recipient_email TEXT,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'read')),
  created_at TEXT NOT NULL,
  sent_at TEXT,
  FOREIGN KEY (recipient_user_id) REFERENCES user_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_user_accounts_role_status ON user_accounts(role, status);
CREATE INDEX IF NOT EXISTS idx_student_assignments_student ON student_assignments(student_id);
CREATE INDEX IF NOT EXISTS idx_student_assignments_tutor ON student_assignments(tutor_id);
CREATE INDEX IF NOT EXISTS idx_student_topics_student ON student_topics(student_id);
CREATE INDEX IF NOT EXISTS idx_tutoring_sessions_student ON tutoring_sessions(student_id);
CREATE INDEX IF NOT EXISTS idx_tutoring_sessions_tutor ON tutoring_sessions(tutor_id);
CREATE INDEX IF NOT EXISTS idx_volunteer_tasks_volunteer ON volunteer_tasks(volunteer_id);
