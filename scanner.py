import asyncio, re, tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright

AXE_CORE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js"


async def _scan(target, max_pages, test_mobile, include_accessibility, project_dir=None):
    root = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    queue, seen, pages, bugs = [target], set(), [], []
    passed = 0
    shots = Path(tempfile.mkdtemp(prefix="qa_shots_"))

    # Basic static project inspection when a ZIP was supplied.
    if project_dir:
        project = Path(project_dir)
        source_files = [p for p in project.rglob("*")
                         if p.is_file() and p.suffix.lower() in {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".css"}]
        for src in source_files[:500]:
            try:
                data = src.read_text(errors="ignore")
                if re.search(r"console\.error\s*\(", data):
                    bugs.append({
                        "severity": "Low", "type": "Static source warning",
                        "page": str(src.relative_to(project)),
                        "message": "Source contains console.error().",
                        "evidence": "Static project inspection"
                    })
            except Exception:
                pass

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 390, "height": 844} if test_mobile else {"width": 1280, "height": 800}
        )

        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen or urlparse(url).netloc != urlparse(target).netloc:
                continue
            seen.add(url)

            # A fresh page per URL keeps console/network listeners scoped to
            # this page only, so errors from a previous page can't leak into
            # this page's results.
            page = await context.new_page()
            console_errors, failed_requests = [], []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("requestfailed", lambda req: failed_requests.append(f"{req.url} — {req.failure}"))

            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                status = response.status if response else 0
                pages.append({"url": url, "status": status})

                if status >= 400:
                    bugs.append({"severity": "High" if status >= 500 else "Medium", "type": "HTTP error",
                                 "page": url, "message": f"Page returned HTTP {status}", "evidence": str(status)})
                else:
                    passed += 1

                # Broken links
                links = await page.locator("a[href]").evaluate_all(
                    "(els) => els.map(e => e.href).filter(Boolean)")
                for href in links:
                    if href.startswith(root) and href not in seen and href not in queue:
                        queue.append(href.split("#")[0])

                # Images/resources
                imgs = await page.locator("img[src]").evaluate_all("(els) => els.map(e => e.src)")
                for src in imgs:
                    try:
                        r = await context.request.get(src, timeout=10000)
                        if r.status >= 400:
                            bugs.append({"severity": "Medium", "type": "Broken image", "page": url,
                                         "message": f"{src} returned HTTP {r.status}", "evidence": src})
                    except Exception as e:
                        bugs.append({"severity": "Medium", "type": "Image request failed", "page": url,
                                     "message": str(e), "evidence": src})

                for err in console_errors[:10]:
                    bugs.append({"severity": "High", "type": "JavaScript console error", "page": url,
                                 "message": err, "evidence": "Browser console"})
                for err in failed_requests[:10]:
                    bugs.append({"severity": "High", "type": "Failed network request", "page": url,
                                 "message": err, "evidence": "Playwright requestfailed"})

                title = await page.title()
                if not title.strip():
                    bugs.append({"severity": "Low", "type": "Missing page title", "page": url,
                                 "message": "The page has no document title.", "evidence": "<title> missing/empty"})
                else:
                    passed += 1

                # --- Layout / visual issues (heuristic, in-browser) ---
                layout_issues = await page.evaluate("""
                () => {
                    const issues = [];
                    if (document.documentElement.scrollWidth > window.innerWidth + 5) {
                        issues.push('Horizontal overflow: page content is wider than the viewport.');
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
                        if ((rect.left < -50 || rect.top < -50)) {
                            const tag = el.tagName.toLowerCase();
                            if (['img','button','a','input'].includes(tag)) {
                                issues.push('Interactive/media element rendered off-screen: <' + tag + '>');
                            }
                        }
                    });
                    return [...new Set(issues)].slice(0, 15);
                }
                """)
                for issue in layout_issues:
                    bugs.append({"severity": "Medium", "type": "Layout issue", "page": url,
                                 "message": issue, "evidence": "In-browser layout check"})
                if not layout_issues:
                    passed += 1

                if include_accessibility:
                    images_without_alt = await page.locator("img:not([alt])").count()
                    if images_without_alt:
                        bugs.append({"severity": "Low", "type": "Accessibility", "page": url,
                                     "message": f"{images_without_alt} image(s) have no alt attribute.",
                                     "evidence": "img:not([alt])"})
                    else:
                        passed += 1

                    # Deeper accessibility scan via axe-core (contrast, labels,
                    # heading order, ARIA misuse, etc.)
                    try:
                        await page.add_script_tag(url=AXE_CORE_CDN)
                        axe_results = await page.evaluate("async () => { return await axe.run(); }")
                        violations = axe_results.get("violations", [])
                        for v in violations[:15]:
                            bugs.append({
                                "severity": {"critical": "High", "serious": "High",
                                             "moderate": "Medium", "minor": "Low"}.get(v.get("impact"), "Medium"),
                                "type": "Accessibility (axe-core)",
                                "page": url,
                                "message": f'{v.get("help")} ({len(v.get("nodes", []))} element(s))',
                                "evidence": v.get("id", "axe-core"),
                            })
                        if not violations:
                            passed += 1
                    except Exception as e:
                        bugs.append({"severity": "Low", "type": "Accessibility scan failed", "page": url,
                                     "message": str(e), "evidence": "axe-core"})

                shot = shots / f"page_{len(pages):03d}.png"
                await page.screenshot(path=str(shot), full_page=True)
                pages[-1]["screenshot"] = str(shot)

            except Exception as e:
                pages.append({"url": url, "status": 0})
                bugs.append({"severity": "High", "type": "Navigation failure", "page": url,
                             "message": str(e), "evidence": "page.goto"})
            finally:
                await page.close()

        await browser.close()

    # De-duplicate findings
    unique, keys = [], set()
    for b in bugs:
        k = (b["type"], b["page"], b["message"])
        if k not in keys:
            keys.add(k)
            b["id"] = f"BUG-{len(unique)+1:03d}"
            unique.append(b)

    return {"target": target, "pages": pages, "bugs": unique, "passed": passed}


def run_scan(target, max_pages=10, test_mobile=True, include_accessibility=True, project_dir=None):
    return asyncio.run(_scan(
        target, max_pages, test_mobile, include_accessibility, project_dir
    ))
