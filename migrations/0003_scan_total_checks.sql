-- Apply before deploying the Worker so async results preserve check totals.
ALTER TABLE scans ADD COLUMN total_checks INTEGER NOT NULL DEFAULT 0;
