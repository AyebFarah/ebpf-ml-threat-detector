ALTER TABLE observation_runs ADD COLUMN scenario TEXT;
ALTER TABLE observation_runs ADD COLUMN label TEXT DEFAULT 'benign';
ALTER TABLE observation_runs ADD COLUMN notes TEXT;
ALTER TABLE observation_runs ADD COLUMN duration_seconds INTEGER;