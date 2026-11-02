CREATE TABLE IF NOT EXISTS policy_settings (
  policy_key TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO policy_settings (policy_key, enabled) VALUES
  ('block_external_workflows', 1),
  ('review_external_infrastructure', 1),
  ('review_unknown_files', 1);
