# Outbound scanning security policy

QA Bug Tracker applies a shared outbound-request policy to website scanning.

## Policy
- Only HTTP and HTTPS URLs are allowed.
- Embedded URL credentials are rejected.
- Only standard ports 80 and 443 are allowed.
- Localhost, local/internal hostnames, non-public IPs, and hostnames with any non-public DNS answers are blocked.
- Redirects are disabled at the transport layer and handled manually; each destination is revalidated.
- Worker scan fetches are restricted to the original site origin.
- Python Worker-client calls and screenshot downloads are restricted to the configured Worker origin.
- Browser requests are intercepted and destination-validated.
- Crawl links are revalidated and same-host crawl scope is maintained.

## Important residual risk
DNS validation is not DNS pinning. A destination could change DNS answers between validation and connection. This boundary is defense-in-depth and must not be described as complete SSRF protection until an enforced outbound egress layer blocks private, loopback, link-local, reserved, and cloud metadata addresses at connection time for both the Python scanner and Worker/browser path.

The Worker uses DNS-over-HTTPS validation before fetching. Cloudflare Worker fetch still resolves the hostname independently; this does not provide connection-level IP pinning.

## Tests
Run the Python unit tests:

```sh
python -m unittest discover -s tests -v
```

Tests cover URL scheme and credential rejection, unsafe IPs, local hostnames, DNS answers, redirects, and origin restrictions. The Worker policy also requires dedicated runtime tests before this branch can be considered release-ready.


## Worker API controls added on the security branch

- All API routes, including scan submission, scan polling, and screenshot retrieval, require `Authorization: Bearer <token>`.
- The Worker secret is named `WORKER_API_TOKEN`; it must be set with Wrangler and must never be committed.
- The Streamlit/server environment must contain `CLOUDFLARE_WORKER_TOKEN` with the same value. Do not put this token in browser-side JavaScript or public repository files.
- D1-backed per-IP rate limiting allows at most 30 requests per minute.
- A global cap of five queued/running scans is enforced.
- Request bodies are capped at 16 KiB; URLs at 2,048 characters; page counts at 1–50.
- Worker fetches have a 15-second timeout and HTML responses are capped at 2 MiB.
- CORS no longer grants wildcard access. Configure `ALLOWED_ORIGINS` only for browser origins that genuinely need it. Server-to-server Streamlit calls do not need browser CORS.

### Required operator setup (not performed by this code change)

1. Apply the D1 migration:
   `wrangler d1 execute qa-bug-tracker --remote --file=migrations/0002_worker_rate_limits.sql`
2. Generate a high-entropy random token (at least 32 random bytes).
3. Set the Worker secret:
   `wrangler secret put WORKER_API_TOKEN`
4. Set the same value as the server-side Streamlit secret/environment variable `CLOUDFLARE_WORKER_TOKEN`.
5. If browser origins are required, set `ALLOWED_ORIGINS` to an explicit comma-separated allowlist. Never use `*`.
6. Verify authenticated scan, unauthenticated rejection, rate limiting, scan capacity, polling and screenshot access in the deployed staging Worker before production use.

## Connection-level SSRF limitation — not yet solved

The Worker runtime's standard `fetch()` API resolves a hostname independently of the preceding DNS-over-HTTPS validation. This code cannot pin the actual connection to the validated IP. A hostile DNS answer can therefore change between validation and connection. A real connection-level guarantee requires routing outbound target traffic through a separately controlled egress proxy/gateway that resolves once, rejects non-public destinations, pins the chosen IP for the connection while preserving TLS hostname verification, and repeats validation on every redirect. The proxy itself must be the only permitted outbound path from the scanner runtime.

No such egress proxy or Cloudflare network policy is provisioned by this repository change. Until that infrastructure exists and is penetration-tested, SSRF protection remains defense-in-depth rather than complete. Do not deploy this branch as a claim of complete SSRF elimination.
