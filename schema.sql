CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,               -- job id (uuid)
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',   -- queued | running | complete | failed
    max_pages INTEGER NOT NULL DEFAULT 10,
    test_mobile INTEGER NOT NULL DEFAULT 1,
    include_accessibility INTEGER NOT NULL DEFAULT 1,
    pages_tested INTEGER NOT NULL DEFAULT 0,
    passed_checks INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    url TEXT NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    screenshot_key TEXT              -- R2 object key
);

CREATE TABLE IF NOT EXISTS bugs (
    id TEXT NOT NULL,                -- BUG-001 etc, unique within a scan
    scan_id TEXT NOT NULL REFERENCES scans(id),
    title TEXT,
    severity TEXT NOT NULL,
    priority TEXT,
    type TEXT,
    page TEXT,
    message TEXT,
    evidence TEXT,
    wcag TEXT,
    selector TEXT,
    html_snippet TEXT,
    remediation TEXT,
    steps TEXT,
    expected TEXT,
    actual TEXT,
    help_url TEXT,
    screenshot_key TEXT,              -- R2 object key
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_bugs_scan_id ON bugs(scan_id);
CREATE INDEX IF NOT EXISTS idx_pages_scan_id ON pages(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
