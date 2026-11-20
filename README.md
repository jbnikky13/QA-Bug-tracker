# QA Bug Tracker

Automated website/web-app QA scanner built with Python, Streamlit and Playwright.

## Features

- Crawl internal pages
- HTTP error detection
- JavaScript console error detection
- Failed network request detection
- Broken image detection
- Missing page title detection
- Basic accessibility checks
- Mobile viewport testing
- Screenshots as evidence
- Upload an entire project as one ZIP
- Basic static inspection of uploaded HTML/JS/CSS source
- PDF and DOCX report generation

## Local setup

```bash
pip install -r requirements.txt
playwright install chromium
streamlit run app.py
```

Enter a URL you own or are authorized to test.

## Deployment

For Streamlit Community Cloud, `requirements.txt` and `packages.txt` are included. The first deployment may need Chromium setup depending on the platform image.

## Scope

This is a QA/defect scanner, not an exploit or penetration-testing tool. Only scan applications you own or have permission to test.


## Cloudflare Worker security configuration

The Worker API on the `security/shared-network-boundary` branch requires a server-side bearer token.

Before deploying that branch:

1. Apply `migrations/0002_worker_rate_limits.sql` to the existing D1 database:
   `wrangler d1 execute qa-bug-tracker --remote --file=migrations/0002_worker_rate_limits.sql`
2. Generate a cryptographically random token with at least 32 random bytes.
3. Set the Worker secret: `wrangler secret put WORKER_API_TOKEN`.
4. Set `CLOUDFLARE_WORKER_URL` and `CLOUDFLARE_WORKER_TOKEN` in Streamlit server-side Secrets. Never expose the token in client-side code or commit it.
5. Only configure `ALLOWED_ORIGINS` if a browser origin needs CORS access; use exact origins, not a wildcard.

The Worker enforces 30 requests per IP per minute, a maximum of five active/queued scans, a 16 KiB request body, a 2,048-character URL, 1–50 pages, a 15-second outbound fetch timeout, and a 2 MiB HTML response limit.

**Important:** DNS preflight checks do not pin the address used by the Worker fetch connection. Complete DNS-rebinding/SSRF protection still requires a separately provisioned connection-level egress proxy or equivalent network control. See [SECURITY.md](SECURITY.md). Do not treat this branch as production-hardened until that control and the deployed Worker setup are independently verified.
