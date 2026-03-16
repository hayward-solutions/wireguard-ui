-- Drop FOREIGN KEY constraint on peers.created_by
ALTER TABLE peers DROP CONSTRAINT IF EXISTS peers_created_by_fkey;
ALTER TABLE peers ALTER COLUMN created_by SET DEFAULT '';
