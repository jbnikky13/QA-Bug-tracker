"""Shared outbound network safety policy for QA Bug Tracker.

This module is a defense-in-depth SSRF boundary. DNS validation does not pin the
resolved address used by the eventual connection; deployments must also enforce
network egress controls to prevent DNS rebinding and private-address access.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
ALLOWED_PORTS = {80, 443}
USER_AGENT = "QA-Bug-Tracker/1.0"


class UnsafeTarget(ValueError):
    """Target violates the outbound network policy."""


def _public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return address.is_global and not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    )


def validate_url(url: str, *, resolve_dns: bool = True) -> str:
    """Validate and canonicalize a URL, rejecting unsafe hosts and ports."""
    if not isinstance(url, str) or not url.strip():
        raise UnsafeTarget("A URL is required.")
    value = url.strip()
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsafeTarget("Only HTTP and HTTPS URLs are allowed.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTarget("URLs containing embedded credentials are not allowed.")
    if not parts.hostname:
        raise UnsafeTarget("URL must include a hostname.")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeTarget("URL contains an invalid port.") from exc
    if port is not None and port not in ALLOWED_PORTS:
        raise UnsafeTarget("Only ports 80 and 443 are permitted.")
    host = parts.hostname.rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        raise UnsafeTarget("Localhost destinations are blocked.")
    if host.endswith(".local") or host.endswith(".internal"):
        raise UnsafeTarget("Local or internal hostnames are blocked.")
    # Literal IPs must be public. Hostnames are resolved and all answers checked.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _public_ip(str(literal)):
            raise UnsafeTarget("Non-public IP destinations are blocked.")
    elif resolve_dns:
        try:
            answers = socket.getaddrinfo(host, port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UnsafeTarget("Hostname DNS resolution failed.") from exc
        addresses = {answer[4][0] for answer in answers}
        if not addresses:
            raise UnsafeTarget("Hostname did not resolve.")
        if any(not _public_ip(address) for address in addresses):
            raise UnsafeTarget("Hostname resolves to a non-public address.")
    # Normalize scheme/host while preserving path, query, and fragment.
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def safe_request(
    url: str,
    *,
    method: str = "GET",
    session: requests.Session | None = None,
    timeout: int | float = 15,
    max_redirects: int = MAX_REDIRECTS,
    stream: bool = False,
    headers: dict | None = None,
    json_body: dict | list | None = None,
) -> requests.Response:
    """Perform a request with redirects disabled and each hop revalidated."""
    client = session or requests.Session()
    current = validate_url(url)
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    for hop in range(max_redirects + 1):
        response = client.request(
            method, current, headers=request_headers, timeout=timeout,
            allow_redirects=False, stream=stream, json=json_body,
        )
        if response.status_code not in REDIRECT_CODES:
            response.url = current
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            raise UnsafeTarget("Redirect response omitted Location.")
        if hop >= max_redirects:
            raise UnsafeTarget("Maximum redirect count exceeded.")
        current = validate_url(urljoin(current, location))
        if response.status_code == 303 or (response.status_code in (301, 302) and method.upper() not in ("GET", "HEAD")):
            method = "GET"
    raise UnsafeTarget("Maximum redirect count exceeded.")
