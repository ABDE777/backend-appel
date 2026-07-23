-- Database Optimization for Call Registry App
-- Run these queries in Supabase SQL Editor to improve query performance

-- Create archived_entries table for data archival
CREATE TABLE IF NOT EXISTS archived_entries (
  LIKE entries INCLUDING ALL
);

-- Add index on archived_entries date for queries
CREATE INDEX IF NOT EXISTS idx_archived_entries_date ON archived_entries(date);

-- Add comment to table
COMMENT ON TABLE archived_entries IS 'Archived call entries older than specified retention period';

-- Index on date for period-based queries
CREATE INDEX IF NOT EXISTS idx_entries_date ON entries(date);

-- Index on agent for agent-based filtering
CREATE INDEX IF NOT EXISTS idx_entries_agent ON entries(agent);

-- Index on motif_id for motif-based filtering
CREATE INDEX IF NOT EXISTS idx_entries_motif_id ON entries(motif_id);

-- Index on reference for reference-based queries
CREATE INDEX IF NOT EXISTS idx_entries_ref ON entries(ref);

-- Composite index for common query patterns (date + agent)
CREATE INDEX IF NOT EXISTS idx_entries_date_agent ON entries(date, agent);

-- Composite index for common query patterns (date + motif_id)
CREATE INDEX IF NOT EXISTS idx_entries_date_motif ON entries(date, motif_id);

-- Index on caller_type for caller-based filtering
CREATE INDEX IF NOT EXISTS idx_entries_caller_type ON entries(caller_type);

-- Index on ts for timestamp-based queries
CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries(ts);

-- Index for settings table (key lookups)
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);

-- Index for agents table (name lookups)
CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(name);

-- Index for agents table (role lookups - if role column exists)
-- Note: agents table may not have a role column, remove if not applicable
-- CREATE INDEX IF NOT EXISTS idx_agents_role ON agents(role);

-- Index for admins table (name lookups)
CREATE INDEX IF NOT EXISTS idx_admins_name ON admins(name);

-- Note: Partial index for recent entries removed due to IMMUTABLE function requirement
-- The regular date index (idx_entries_date) will provide good performance for recent queries

-- Analyze tables to update statistics
ANALYZE entries;
ANALYZE settings;
ANALYZE agents;
ANALYZE admins;

-- Check index usage (run this after some time to see which indexes are being used)
-- SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch 
-- FROM pg_stat_user_indexes 
-- WHERE schemaname = 'public' 
-- ORDER BY idx_scan DESC;
