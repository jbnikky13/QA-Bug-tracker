"""
url_bug_scanner.py

Scans a live URL for common bugs:
  1. Broken links / 404s (internal + external links found on the page)
  2. Console errors (JS) & failed network requests
  3. Basic visual/layout issues (horizontal overflow, off-screen or
     zero-size-but-should-be-visible elements)
  4. Accessibility issues (via axe-core)

Requires:
    pip install playwright requests beautifulsoup4
    playwright install chromium

NOTE ON STREAMLIT CLOUD:
Streamlit Community Cloud does not reliably support installing Playwright's
browser binaries (no persistent root / apt access at runtime). This module
runs fine locally, on Streamlit-in-Docker, or on Fly.io/Render/etc.
On Streamlit Cloud specifically, you'd typically need to either:
  - use a `packages.txt` with the chromium deps + a postinstall step, or
  - offload scanning to a small external service/API your Streamlit app calls.
Test on Streamlit Cloud before shipping; it's the most common snag with this
kind of feature.
"""

import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

AXE_CORE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js"


def scan_url(url: str, check_external_links: bool = True, timeout_ms: int = 30000) -> dict:
    """
    Run a full bug scan on `url`. Returns a dict of results:
    {
        "url": str,
        "console_errors": [str, ...],
        "network_failures": [{"url": str, "status": int|None, "error": str|None}, ...],
        "broken_links": [{"url": str, "status": int|None, "error": str|None, "text": str}, ...],
        "layout_issues": [str, ...],
        "accessibility_issues": [{"impact": str, "description": str, "help": str, "nodes": int}, ...],
        "errors": [str, ...],  # scan-level errors, e.g. page failed to load
    }
    """
    results = {
        "url": url,
        "console_errors": [],
        "network_failures": [],
        "broken_links": [],
        "layout_issues": [],
        "accessibility_issues": [],
        "errors": [],
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # --- 1. Console errors ---
        page.on("console", lambda msg: (
            results["console_errors"].append(msg.text)
            if msg.type == "error" else None
        ))
        page.on("pageerror", lambda exc: results["console_errors"].append(str(exc)))

        # --- 2. Network failures ---
        def handle_response(response):
            if response.status >= 400:
                results["network_failures"].append({
                    "url": response.url,
                    "status": response.status,
                    "error": None,
                })

        page.on("requestfailed", lambda req: results["network_failures"].append({
            "url": req.url,
            "status": None,
            "error": req.failure,
        }))
        page.on("response", handle_response)

        try:
            page.goto(url, timeout=timeout_ms, wait_until="networkidle")
        except Exception as e:
            results["errors"].append(f"Failed to load page: {e}")
            browser.close()
            return results

        html = page.content()

        # --- 3. Layout issues (heuristic checks) ---
        layout_checks = page.evaluate("""
        () => {
            const issues = [];
            if (document.documentElement.scrollWidth > window.innerWidth + 5) {
                issues.push('Horizontal overflow detected: page is wider than viewport.');
            }
            document.querySelectorAll('*').forEach(el => {
                const style = getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                if (style.display !== 'none' && style.visibility !== 'hidden' &&
                    rect.width === 0 && rect.height === 0 &&
                    el.textContent.trim().length > 0 &&
                    el.children.length === 0) {
                    issues.push('Zero-size element with text content: "' +
                        el.textContent.trim().slice(0, 60) + '"');
                }
                if (rect.left < -50 || rect.top < -50) {
                    // Element rendered significantly off-screen
                    const tag = el.tagName.toLowerCase();
                    if (['img','button','a','input'].includes(tag)) {
                        issues.push('Interactive/media element rendered off-screen: <' + tag + '>');
                    }
                }
            });
            return [...new Set(issues)].slice(0, 25); // dedupe, cap output
        }
        """)
        results["layout_issues"] = layout_checks

        # --- 4. Accessibility issues via axe-core ---
        try:
            page.add_script_tag(url=AXE_CORE_CDN)
            axe_results = page.evaluate("async () => { return await axe.run(); }")
            for v in axe_results.get("violations", []):
                results["accessibility_issues"].append({
                    "impact": v.get("impact"),
                    "description": v.get("description"),
                    "help": v.get("help"),
                    "nodes": len(v.get("nodes", [])),
                })
        except Exception as e:
            results["errors"].append(f"Accessibility scan failed: {e}")

        browser.close()

    # --- Broken links (done outside the browser, via requests, in parallel) ---
    results["broken_links"] = _check_links(html, url, check_external_links)

    return results


def _check_links(html: str, base_url: str, check_external: bool) -> list:
    soup = BeautifulSoup(html, "html.parser")
    base_netloc = urlparse(base_url).netloc

    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full_url = urljoin(base_url, href)
        if not check_external and urlparse(full_url).netloc != base_netloc:
            continue
        links.add((full_url, a.get_text(strip=True)[:60]))

    broken = []

    def check(link_text_pair):
        link, text = link_text_pair
        try:
            resp = requests.head(link, allow_redirects=True, timeout=8)
            if resp.status_code >= 400:
                # some servers don't support HEAD properly, retry with GET
                resp = requests.get(link, allow_redirects=True, timeout=8, stream=True)
            if resp.status_code >= 400:
                return {"url": link, "status": resp.status_code, "error": None, "text": text}
        except requests.RequestException as e:
            return {"url": link, "status": None, "error": str(e), "text": text}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(check, links):
            if result:
                broken.append(result)

    return broken
