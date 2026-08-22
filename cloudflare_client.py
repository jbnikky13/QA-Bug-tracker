"""
cloudflare_client.py — drop-in replacement for scanner.run_scan() that calls
the Cloudflare Worker (Browser Run + Playwright) instead of running a local
headless browser. Returns the same {target, pages, bugs, passed} dict shape
your existing app.py and reports.py already expect, so nothing else in the
app needs to change.

Usage in app.py:
    from cloudflare_client import run_scan_cloudflare as run_scan
    # everything else stays the same

Set the Worker URL via environment variable or Streamlit secrets:
    CLOUDFLARE_WORKER_URL = "https://qa-bug-tracker-worker.<you>.workers.dev"
"""

import os
import tempfile
import time
from pathlib import Path

import requests

WORKER_URL = os.environ.get("CLOUDFLARE_WORKER_URL", "").rstrip("/")


def _download_screenshot(screenshot_url: str, dest_dir: Path) -> str | None:
    """Downloads a screenshot from the Worker's R2-backed endpoint to a local
    temp file, since reports.py expects a local filesystem path."""
    if not screenshot_url:
        return None
    try:
        resp = requests.get(screenshot_url, timeout=15)
        resp.raise_for_status()
        # Use a stable-ish filename derived from the URL tail
        fname = screenshot_url.rstrip("/").split("/")[-1] or f"shot_{int(time.time()*1000)}.png"
        if not fname.endswith(".png"):
            fname += ".png"
        path = dest_dir / fname
        path.write_bytes(resp.content)
        return str(path)
    except Exception:
        return None


def _normalize(raw: dict) -> dict:
    """Converts the Worker's JSON (screenshot_url per page/bug) into the
    local-path shape reports.py and app.py expect."""
    shots_dir = Path(tempfile.mkdtemp(prefix="qa_cf_shots_"))
    url_to_local: dict[str, str] = {}

    def local_shot(screenshot_url):
        if not screenshot_url:
            return None
        if screenshot_url not in url_to_local:
            local_path = _download_screenshot(screenshot_url, shots_dir)
            url_to_local[screenshot_url] = local_path
        return url_to_local[screenshot_url]

    pages = [
        {"url": p["url"], "status": p["status"], "screenshot": local_shot(p.get("screenshot_url"))}
        for p in raw.get("pages", [])
    ]
    bugs = [
        {**{k: v for k, v in b.items() if k != "screenshot_url"},
         "screenshot": local_shot(b.get("screenshot_url"))}
        for b in raw.get("bugs", [])
    ]

    return {
        "target": raw.get("target", ""),
        "pages": pages,
        "bugs": bugs,
        "passed": raw.get("passed", 0),
    }


def run_scan_cloudflare(
    target: str,
    max_pages: int = 10,
    test_mobile: bool = True,
    include_accessibility: bool = True,
    project_dir=None,          # unused here; ZIP inspection stays local-only for now
    progress_callback=None,    # unused for the sync endpoint; see run_scan_cloudflare_async below
    timeout: int = 120,
) -> dict:
    """Synchronous scan — one HTTP call, blocks until the Worker finishes.
    Good for small/medium sites. For larger crawls that might exceed a
    single Worker invocation's execution time, use run_scan_cloudflare_async."""
    if not WORKER_URL:
        raise RuntimeError(
            "CLOUDFLARE_WORKER_URL is not set. Set it as an environment variable "
            "or in Streamlit secrets to point at your deployed Worker."
        )

    resp = requests.post(
        f"{WORKER_URL}/scan",
        json={
            "url": target,
            "maxPages": max_pages,
            "testMobile": test_mobile,
            "includeAccessibility": include_accessibility,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return _normalize(resp.json())


def run_scan_cloudflare_async(
    target: str,
    max_pages: int = 10,
    test_mobile: bool = True,
    include_accessibility: bool = True,
    progress_callback=None,
    poll_interval: float = 2.0,
    max_wait: int = 600,
) -> dict:
    """Async scan — submits the job to the Worker's Queue and polls until
    complete. Use this for large crawls (max_pages > ~15) to avoid hitting
    the synchronous endpoint's execution time limit."""
    if not WORKER_URL:
        raise RuntimeError("CLOUDFLARE_WORKER_URL is not set.")

    submit = requests.post(
        f"{WORKER_URL}/scan/async",
        json={
            "url": target,
            "maxPages": max_pages,
            "testMobile": test_mobile,
            "includeAccessibility": include_accessibility,
        },
        timeout=30,
    )
    submit.raise_for_status()
    job_id = submit.json()["id"]

    waited = 0.0
    while waited < max_wait:
        poll = requests.get(f"{WORKER_URL}/scan/{job_id}", timeout=30)
        poll.raise_for_status()
        data = poll.json()

        if progress_callback:
            try:
                progress_callback(data.get("status", "unknown"), job_id)
            except Exception:
                pass

        if data.get("status") == "complete":
            return _normalize(data)
        if data.get("status") == "failed":
            raise RuntimeError(f"Scan failed: {data.get('error')}")

        time.sleep(poll_interval)
        waited += poll_interval

    raise TimeoutError(f"Scan {job_id} did not complete within {max_wait}s")
