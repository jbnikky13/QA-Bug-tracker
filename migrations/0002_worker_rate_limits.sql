-- Apply to the existing qa-bug-tracker D1 database before deploying this Worker.
CREATE TABLE IF NOT EXISTS worker_rate_limits (
    ip_hash TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0
);
