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
