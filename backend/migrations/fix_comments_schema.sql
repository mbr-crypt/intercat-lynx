-- Migration: Fix comments table schema to match model
-- Issue: The original project's older databases have comments.vulnerability_id
-- (integer) and comments.edited, while the model expects cve_id (string) and
-- is_edited.
-- Date: 2025-10-19
--
-- Only runs on such an old database. Marker: the old column "edited" still
-- exists. A fresh installation creates comments with the current columns
-- through Alembic, so there is nothing to fix and this file does nothing
-- (before, it failed with "column c.vulnerability_id does not exist" and logged
-- an error at every start). After a successful run "edited" is renamed, so
-- later starts skip it as well.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'comments' AND column_name = 'edited'
    ) THEN
        RETURN;
    END IF;

    -- Step 1: Add the cve_id column
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS cve_id VARCHAR(50);

    -- Step 2: Populate cve_id from vulnerability_id by joining with vulnerabilities
    UPDATE comments c
    SET cve_id = v.cve_id
    FROM vulnerabilities v
    WHERE c.vulnerability_id = v.id;

    -- Step 3: Make cve_id NOT NULL after data migration
    ALTER TABLE comments ALTER COLUMN cve_id SET NOT NULL;

    -- Step 4: Add foreign key constraint
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'comments_cve_id_fkey') THEN
        ALTER TABLE comments
            ADD CONSTRAINT comments_cve_id_fkey
            FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id);
    END IF;

    -- Step 5: Create index on cve_id for performance
    CREATE INDEX IF NOT EXISTS idx_comments_cve_id ON comments(cve_id);
    CREATE INDEX IF NOT EXISTS idx_comments_cve_created ON comments(cve_id, created_at);

    -- Step 6: Drop old indexes and constraints related to vulnerability_id
    DROP INDEX IF EXISTS idx_comments_vulnerability_created;
    DROP INDEX IF EXISTS ix_comments_vulnerability_id;
    ALTER TABLE comments DROP CONSTRAINT IF EXISTS comments_vulnerability_id_fkey;

    -- Step 7: Rename columns to match model
    ALTER TABLE comments RENAME COLUMN edited TO is_edited;

    -- Step 8: Add missing columns if they don't exist
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS upvotes INTEGER DEFAULT 0 NOT NULL;
    ALTER TABLE comments ADD COLUMN IF NOT EXISTS downvotes INTEGER DEFAULT 0 NOT NULL;

    -- Step 9: Make vulnerability_id nullable (since we're using cve_id now)
    ALTER TABLE comments ALTER COLUMN vulnerability_id DROP NOT NULL;

    -- Step 10: Fix comment_votes table - add updated_at if missing
    ALTER TABLE comment_votes
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL;

    -- Step 11: Fix comment_votes.vote_type to be INTEGER instead of VARCHAR
    ALTER TABLE comment_votes
        ALTER COLUMN vote_type TYPE INTEGER
        USING CASE
            WHEN vote_type = 'upvote' THEN 1
            WHEN vote_type = 'downvote' THEN -1
            ELSE vote_type::INTEGER
        END;

    -- Note: vulnerability_id is kept as a backup. It can be dropped in a
    -- future migration after verifying everything works.
END
$$;
