ALTER TABLE decisions ADD COLUMN delivery_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_delivery_id ON decisions(delivery_id);
CREATE INDEX IF NOT EXISTS idx_decisions_repository_pr ON decisions(repository, pr_number);
