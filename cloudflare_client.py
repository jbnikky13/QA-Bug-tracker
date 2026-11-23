"""Client for the Cloudflare Worker scanner, using the shared network boundary."""
import os
import tempfile
import time
from pathlib import Path

from security_boundary import safe_request

def _setting(name: str) -> str:
    value = os.environ.get(name, "")
    if value:
        return value
    try:
        import streamlit as st
        return str(st.secrets.get(name, ""))
    except Exception:
        return ""


WORKER_URL = _setting("CLOUDFLARE_WORKER_URL").rstrip("/")


def _worker_headers() -> dict[str, str]:
    token = _setting("CLOUDFLARE_WORKER_TOKEN")
    if not token:
        raise RuntimeError("CLOUDFLARE_WORKER_TOKEN is not set; configure it as a server-side secret.")
    return {"Authorization": f"Bearer {token}"}


def _download_screenshot(screenshot_url: str, dest_dir: Path) -> str | None:
    if not screenshot_url:
        return None
    try:
        resp = safe_request(screenshot_url, timeout=15, allowed_origin=WORKER_URL, headers=_worker_headers())
        resp.raise_for_status()
        fname = screenshot_url.rstrip("/").split("/")[-1] or f"shot_{int(time.time()*1000)}.png"
        if not fname.endswith(".png"):
            fname += ".png"
        path = dest_dir / fname
        path.write_bytes(resp.content)
        resp.close()
        return str(path)
    except Exception:
        return None


def _normalize(raw: dict) -> dict:
    shots_dir = Path(tempfile.mkdtemp(prefix="qa_cf_shots_"))
    url_to_local: dict[str, str | None] = {}

    def local_shot(screenshot_url):
        if not screenshot_url:
            return None
        if screenshot_url not in url_to_local:
            url_to_local[screenshot_url] = _download_screenshot(screenshot_url, shots_dir)
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
        "total_checks": raw.get("total_checks", 0),
    }


def run_scan_cloudflare(
    target: str,
    max_pages: int = 10,
    test_mobile: bool = True,
    include_accessibility: bool = True,
    project_dir=None,
    progress_callback=None,
    timeout: int = 120,
) -> dict:
    if not WORKER_URL:
        raise RuntimeError("CLOUDFLARE_WORKER_URL is not set.")
    resp = safe_request(
        f"{WORKER_URL}/scan", method="POST",
        json_body={
            "url": target,
            "maxPages": max_pages,
            "testMobile": test_mobile,
            "includeAccessibility": include_accessibility,
        },
        timeout=timeout, allowed_origin=WORKER_URL, headers=_worker_headers(),
    )
    try:
        resp.raise_for_status()
        return _normalize(resp.json())
    finally:
        resp.close()


def run_scan_cloudflare_async(
    target: str,
    max_pages: int = 10,
    test_mobile: bool = True,
    include_accessibility: bool = True,
    progress_callback=None,
    poll_interval: float = 2.0,
    max_wait: int = 600,
) -> dict:
    if not WORKER_URL:
        raise RuntimeError("CLOUDFLARE_WORKER_URL is not set.")
    submit = safe_request(
        f"{WORKER_URL}/scan/async", method="POST",
        json_body={
            "url": target,
            "maxPages": max_pages,
            "testMobile": test_mobile,
            "includeAccessibility": include_accessibility,
        },
        timeout=30, allowed_origin=WORKER_URL, headers=_worker_headers(),
    )
    try:
        submit.raise_for_status()
        job_id = submit.json()["id"]
    finally:
        submit.close()

    waited = 0.0
    while waited < max_wait:
        poll = safe_request(f"{WORKER_URL}/scan/{job_id}", timeout=30, allowed_origin=WORKER_URL, headers=_worker_headers())
        try:
            poll.raise_for_status()
            data = poll.json()
        finally:
            poll.close()
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
