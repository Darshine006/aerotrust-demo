CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  event_type TEXT NOT NULL,
  repository TEXT,
  pr_number INTEGER,
  contributor TEXT,
  source_type TEXT,
  changed_files TEXT,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decisions_created_at
ON decisions(created_at);
