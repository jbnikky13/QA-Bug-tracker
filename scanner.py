import asyncio, re, tempfile
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright

AXE_CORE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js"

SEVERITY_TO_PRIORITY = {"Critical": "P1", "High": "P1", "Medium": "P2", "Low": "P3"}


async def _scan(target, max_pages, test_mobile, include_accessibility, project_dir=None, progress_callback=None):
    root = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    queue, seen, pages, bugs = [target], set(), [], []
    passed = 0
    shots = Path(tempfile.mkdtemp(prefix="qa_shots_"))

    if project_dir:
        project = Path(project_dir)
        source_files = [p for p in project.rglob("*")
                         if p.is_file() and p.suffix.lower() in {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".css"}]
        for src in source_files[:500]:
            try:
                data = src.read_text(errors="ignore")
                if re.search(r"console\.error\s*\(", data):
                    bugs.append(_bug(
                        "Low", "Static source warning", str(src.relative_to(project)),
                        "Source contains console.error().", "Static project inspection"
                    ))
            except Exception:
                pass

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            viewport={"width": 390, "height": 844} if test_mobile else {"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        # Some sites detect the automation flag and serve reduced or blank content
        # to headless browsers. Hiding it isn't foolproof but fixes the common case.
        await context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )

        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen or urlparse(url).netloc != urlparse(target).netloc:
                continue
            seen.add(url)

            page = await context.new_page()
            console_errors, failed_requests = [], []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("requestfailed", lambda req: failed_requests.append(f"{req.url} — {req.failure}"))

            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                # domcontentloaded fires before JS-heavy frameworks (React/Angular/etc.)
                # finish painting, which is what left screenshots blank. Give the page a
                # chance to settle; don't hard-fail the whole scan if it never goes idle
                # (some sites keep long-poll/analytics connections open forever).
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                await page.wait_for_timeout(1000)
                status = response.status if response else 0
                pages.append({"url": url, "status": status})

                if status >= 400:
                    bugs.append(_bug(
                        "High" if status >= 500 else "Medium", "HTTP error", url,
                        f"Page returned HTTP {status}.",
                        f"HTTP status code {status}",
                        steps=f"1. Navigate to {url}.\n2. Observe the server response status.",
                        expected="Page should return HTTP 200.",
                        actual=f"Page returned HTTP {status}."
                    ))
                else:
                    passed += 1

                links = await page.locator("a[href]").evaluate_all(
                    "(els) => els.map(e => e.href).filter(Boolean)")
                for href in links:
                    if href.startswith(root) and href not in seen and href not in queue:
                        queue.append(href.split("#")[0])

                imgs = await page.locator("img[src]").evaluate_all("(els) => els.map(e => e.src)")
                for src in imgs:
                    try:
                        r = await context.request.get(src, timeout=10000)
                        if r.status >= 400:
                            bugs.append(_bug(
                                "Medium", "Broken image", url,
                                f"Image failed to load: {src} returned HTTP {r.status}.", src,
                                steps=f"1. Navigate to {url}.\n2. Locate <img src=\"{src}\">.\n3. Observe it fails to load.",
                                expected="Image should load with HTTP 200.",
                                actual=f"Image returned HTTP {r.status}."
                            ))
                    except Exception as e:
                        bugs.append(_bug(
                            "Medium", "Image request failed", url, str(e), src
                        ))

                for err in console_errors[:10]:
                    bugs.append(_bug(
                        "High", "JavaScript console error", url, err, "Browser console",
                        steps=f"1. Open {url} in a browser with dev tools open.\n2. Check the Console tab.",
                        expected="No errors logged to console.",
                        actual=err
                    ))
                for err in failed_requests[:10]:
                    bugs.append(_bug(
                        "High", "Failed network request", url, err, "Playwright requestfailed",
                        steps=f"1. Open {url} in a browser with dev tools open.\n2. Check the Network tab for failed requests.",
                        expected="All network requests succeed.",
                        actual=err
                    ))

                title = await page.title()
                if not title.strip():
                    bugs.append(_bug(
                        "Low", "Missing page title", url, "The page has no document title.",
                        "<title> missing/empty",
                        steps=f"1. View page source of {url}.\n2. Inspect the <title> element.",
                        expected="Page should have a descriptive, non-empty <title>.",
                        actual="Title is missing or empty."
                    ))
                else:
                    passed += 1

                layout_issues = await page.evaluate("""
                () => {
                    const issues = [];
                    if (document.documentElement.scrollWidth > window.innerWidth + 5) {
                        issues.push({msg: 'Horizontal overflow: page content is wider than the viewport.', sel: 'html'});
                    }
                    document.querySelectorAll('*').forEach(el => {
                        const style = getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        if (style.display !== 'none' && style.visibility !== 'hidden' &&
                            rect.width === 0 && rect.height === 0 &&
                            el.textContent.trim().length > 0 &&
                            el.children.length === 0) {
                            issues.push({
                                msg: 'Zero-size element with text content: "' + el.textContent.trim().slice(0, 60) + '"',
                                sel: el.tagName.toLowerCase() + (el.id ? '#' + el.id : '')
                            });
                        }
                        if ((rect.left < -50 || rect.top < -50)) {
                            const tag = el.tagName.toLowerCase();
                            if (['img','button','a','input'].includes(tag)) {
                                issues.push({
                                    msg: 'Interactive/media element rendered off-screen: <' + tag + '>',
                                    sel: tag + (el.id ? '#' + el.id : '')
                                });
                            }
                        }
                    });
                    const seenMsgs = new Set(); const out = [];
                    for (const i of issues) { if (!seenMsgs.has(i.msg)) { seenMsgs.add(i.msg); out.push(i); } }
                    return out.slice(0, 15);
                }
                """)
                for issue in layout_issues:
                    bugs.append(_bug(
                        "Medium", "Layout issue", url, issue["msg"], issue["sel"],
                        steps=f"1. Open {url} at the tested viewport.\n2. Inspect element `{issue['sel']}`.",
                        expected="Element renders fully within the viewport.",
                        actual=issue["msg"]
                    ))
                if not layout_issues:
                    passed += 1

                if include_accessibility:
                    images_without_alt = await page.locator("img:not([alt])").count()
                    if images_without_alt:
                        bugs.append(_bug(
                            "Low", "Accessibility", url,
                            f"{images_without_alt} image(s) have no alt attribute.", "img:not([alt])",
                            wcag="WCAG 1.1.1 (Non-text Content)",
                            steps=f"1. Open {url}.\n2. Inspect <img> elements for a missing alt attribute.",
                            expected="All meaningful images have descriptive alt text.",
                            actual=f"{images_without_alt} image(s) missing alt text."
                        ))
                    else:
                        passed += 1

                    try:
                        await page.add_script_tag(url=AXE_CORE_CDN)
                        axe_results = await page.evaluate("async () => { return await axe.run(); }")
                        violations = axe_results.get("violations", [])
                        for v in violations[:15]:
                            nodes = v.get("nodes", [])
                            selector = nodes[0]["target"][0] if nodes and nodes[0].get("target") else "N/A"
                            snippet = nodes[0].get("html", "")[:200] if nodes else ""
                            wcag_tags = [t.upper() for t in v.get("tags", []) if t.startswith("wcag")]
                            bugs.append(_bug(
                                {"critical": "High", "serious": "High",
                                 "moderate": "Medium", "minor": "Low"}.get(v.get("impact"), "Medium"),
                                "Accessibility (axe-core)", url,
                                f'{v.get("help")} ({len(nodes)} element(s))',
                                v.get("id", "axe-core"),
                                wcag=", ".join(wcag_tags) if wcag_tags else "See axe-core rule documentation",
                                selector=selector,
                                html_snippet=snippet,
                                steps=f"1. Open {url}.\n2. Run an axe-core accessibility scan.\n3. Locate rule `{v.get('id')}` on element `{selector}`.",
                                expected=v.get("description", "Element should pass the accessibility rule."),
                                actual=f'{len(nodes)} element(s) fail: {v.get("help")}',
                                help_url=v.get("helpUrl", "")
                            ))
                        if not violations:
                            passed += 1
                    except Exception as e:
                        bugs.append(_bug("Low", "Accessibility scan failed", url, str(e), "axe-core"))

                # Scroll to the bottom and back to trigger any lazy-loaded/scroll-in
                # content, then let animations/transitions settle before capturing.
                try:
                    await page.evaluate("""
                    async () => {
                        const distance = 400;
                        const delay = 120;
                        let total = 0;
                        const height = document.body.scrollHeight;
                        while (total < height) {
                            window.scrollBy(0, distance);
                            total += distance;
                            await new Promise(r => setTimeout(r, delay));
                        }
                        window.scrollTo(0, 0);
                    }
                    """)
                except Exception:
                    pass
                await page.add_style_tag(content="*, *::before, *::after { animation: none !important; transition: none !important; }")
                await page.wait_for_timeout(500)

                shot = shots / f"page_{len(pages):03d}.png"
                await page.screenshot(path=str(shot), full_page=True)
                pages[-1]["screenshot"] = str(shot)
                for b in bugs:
                    if b["page"] == url and not b.get("screenshot"):
                        b["screenshot"] = str(shot)

            except Exception as e:
                pages.append({"url": url, "status": 0})
                bugs.append(_bug("High", "Navigation failure", url, str(e), "page.goto"))
            finally:
                await page.close()

            if progress_callback:
                try:
                    progress_callback(len(seen), max_pages, url, len(bugs), len(queue))
                except Exception:
                    pass

        await browser.close()

    unique, keys = [], set()
    for b in bugs:
        k = (b["type"], b["page"], b["message"])
        if k not in keys:
            keys.add(k)
            b["id"] = f"BUG-{len(unique)+1:03d}"
            unique.append(b)

    return {"target": target, "pages": pages, "bugs": unique, "passed": passed}


REMEDIATION = {
    "HTTP error": "Investigate the server/application logs for this route and ensure it returns a successful (2xx) or an intentional redirect (3xx) response. If the resource is meant to be removed, return a proper 410 Gone or update all internal links pointing to it.",
    "Broken image": "Verify the image asset exists at the referenced path and is deployed correctly. Update or remove the reference if the asset was moved or renamed.",
    "Image request failed": "Check that the resource is reachable, not blocked by CORS/mixed-content rules, and that the hosting CDN or server is responding.",
    "JavaScript console error": "Review the stack trace in the browser console, reproduce locally, and patch the underlying script error. Add error boundary handling where appropriate.",
    "Failed network request": "Confirm the endpoint is deployed and reachable, check for CORS misconfiguration, and verify authentication/session requirements are met by the client.",
    "Missing page title": "Add a unique, descriptive <title> element to the page's <head> for SEO and accessibility (screen readers announce it first).",
    "Layout issue": "Adjust the responsible CSS (fix fixed widths, overflow rules, or absolute positioning) so content reflows within the viewport at the tested breakpoint.",
    "Accessibility": "Add descriptive alt attributes to all meaningful images; use alt=\"\" for purely decorative images so screen readers skip them.",
    "Accessibility (axe-core)": "Refer to the linked axe-core rule documentation for the specific WCAG success criterion and recommended fix pattern for this violation.",
    "Navigation failure": "Confirm the URL is reachable, the server is not timing out, and there are no redirect loops or SSL/TLS certificate issues.",
    "Static source warning": "Review the flagged source file and remove or properly handle the console.error() call before production deployment.",
    "Scan failure": "Manually verify the target URL is reachable and correctly formatted; re-run the scan once resolved.",
}


def _title(type_, page, message):
    short_msg = message.strip().split(".")[0][:70]
    return f"{type_} — {short_msg}" if short_msg else f"{type_} on {page}"


def _bug(severity, type_, page, message, evidence, wcag=None, selector=None,
         html_snippet=None, steps=None, expected=None, actual=None, help_url=None,
         screenshot=None, remediation=None):
    return {
        "title": _title(type_, page, message),
        "severity": severity,
        "priority": SEVERITY_TO_PRIORITY.get(severity, "P3"),
        "type": type_,
        "page": page,
        "message": message,
        "evidence": evidence,
        "wcag": wcag or "N/A",
        "selector": selector or "N/A",
        "html_snippet": html_snippet or "",
        "remediation": remediation or REMEDIATION.get(type_, "Review the finding and apply an appropriate fix; retest to confirm resolution."),
        "steps": steps or f"1. Navigate to {page}.\n2. Reproduce the condition described in the message.",
        "expected": expected or "No issue should be present.",
        "actual": actual or message,
        "help_url": help_url or "",
        "screenshot": screenshot,
    }


def run_scan(target, max_pages=10, test_mobile=True, include_accessibility=True, project_dir=None, progress_callback=None):
    return asyncio.run(_scan(
        target, max_pages, test_mobile, include_accessibility, project_dir, progress_callback
    ))
