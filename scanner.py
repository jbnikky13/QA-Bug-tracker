"""Website scanner with browser-enhanced mode and HTTP fallback."""
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None

AXE_CORE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.1/axe.min.js"

def _check_links(html, base_url, check_external=True):
    soup = BeautifulSoup(html, "html.parser")
    base_netloc = urlparse(base_url).netloc
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")): continue
        full = urljoin(base_url, href)
        if not check_external and urlparse(full).netloc != base_netloc: continue
        links.add((full, a.get_text(strip=True)[:60]))
    def check(pair):
        link, text = pair
        try:
            try:
                r = requests.head(link, allow_redirects=True, timeout=8)
                if r.status_code in (405, 501): r = requests.get(link, allow_redirects=True, timeout=8, stream=True)
            except requests.RequestException:
                r = requests.get(link, allow_redirects=True, timeout=8, stream=True)
            if r.status_code >= 400: return {"url":link,"status":r.status_code,"error":None,"text":text}
        except requests.RequestException as e:
            return {"url":link,"status":None,"error":str(e),"text":text}
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        return [x for x in ex.map(check, links) if x]

def _basic_scan(url, check_external_links=True, timeout_ms=30000):
    result = {"url":url,"console_errors":[],"network_failures":[],"broken_links":[],"layout_issues":[],"accessibility_issues":[],"errors":[]}
    try:
        r = requests.get(url, timeout=max(5, timeout_ms//1000), headers={"User-Agent":"QA-Bug-Tracker/1.0"})
        if r.status_code >= 400: result["errors"].append(f"Page returned HTTP {r.status_code}")
        soup = BeautifulSoup(r.text, "html.parser")
        if not soup.title or not soup.title.get_text(strip=True):
            result["accessibility_issues"].append({"impact":"moderate","description":"Page has no document title.","help":"Add a descriptive <title>.","nodes":1})
        imgs = soup.find_all("img", alt=False)
        if imgs:
            result["accessibility_issues"].append({"impact":"moderate","description":"Images are missing alternative text.","help":"Add meaningful alt attributes.","nodes":len(imgs)})
        result["broken_links"] = _check_links(r.text, url, check_external_links)
    except requests.RequestException as e:
        result["errors"].append(f"Failed to load page: {e}")
    return result

def scan_url(url, check_external_links=True, timeout_ms=30000):
    if sync_playwright is None: return _basic_scan(url, check_external_links, timeout_ms)
    results = {"url":url,"console_errors":[],"network_failures":[],"broken_links":[],"layout_issues":[],"accessibility_issues":[],"errors":[]}
    try:
        with sync_playwright() as p:
            try: browser = p.chromium.launch(headless=True)
            except Exception as e:
                out = _basic_scan(url, check_external_links, timeout_ms)
                out["errors"].insert(0, f"Browser unavailable; used HTTP fallback: {e}")
                return out
            page = browser.new_page()
            page.on("console", lambda m: results["console_errors"].append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: results["console_errors"].append(str(e)))
            page.on("requestfailed", lambda q: results["network_failures"].append({"url":q.url,"status":None,"error":q.failure}))
            page.on("response", lambda r: results["network_failures"].append({"url":r.url,"status":r.status,"error":None}) if r.status >= 400 else None)
            html = ""
            try:
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                try: page.wait_for_load_state("networkidle", timeout=5000)
                except Exception: pass
                html = page.content()
                results["layout_issues"] = page.evaluate("""() => { const x=[]; if(document.documentElement.scrollWidth>window.innerWidth+5)x.push('Horizontal overflow detected.'); document.querySelectorAll('img').forEach(i=>{if(!i.alt)x.push('Image missing alt text.');}); return [...new Set(x)].slice(0,25); }""")
                try:
                    page.add_script_tag(url=AXE_CORE_CDN)
                    axe = page.evaluate("async () => await axe.run()")
                    for v in axe.get("violations", []):
                        results["accessibility_issues"].append({"impact":v.get("impact"),"description":v.get("description"),"help":v.get("help"),"nodes":len(v.get("nodes",[]))})
                except Exception as e: results["errors"].append(f"Accessibility scan failed: {e}")
            except Exception as e:
                results["errors"].append(f"Failed to load page: {e}")
            browser.close()
        if html: results["broken_links"] = _check_links(html, url, check_external_links)
        return results
    except Exception as e:
        out = _basic_scan(url, check_external_links, timeout_ms)
        out["errors"].insert(0, f"Browser scanner failed; used HTTP fallback: {e}")
        return out

def _bug(severity, kind, page, message, evidence=""):
    return {"severity":severity,"type":kind,"page":page,"message":message,"evidence":evidence}

def run_scan(target, max_pages=10, test_mobile=True, include_accessibility=True, project_dir=None, progress_callback=None):
    max_pages = max(1, min(int(max_pages), 50))
    queue, visited, pages, bugs = [target], set(), [], []
    while queue and len(visited) < max_pages:
        current = queue.pop(0)
        if current in visited: continue
        purl = urlparse(current)
        if purl.scheme not in ("http","https"): continue
        visited.add(current)
        raw = scan_url(current, check_external_links=False)
        status = 200
        for err in raw.get("errors", []):
            if "HTTP " in err:
                try: status = int(err.split("HTTP ",1)[1].split()[0])
                except Exception: status = 0
        pages.append({"url":current,"status":status,"screenshot":None})
        for e in raw.get("errors",[]): bugs.append(_bug("High","Page load",current,e))
        for x in raw.get("network_failures",[]): bugs.append(_bug("High","Network failure",current,f"{x['url']} returned {x.get('status') or x.get('error')}",str(x)))
        for x in raw.get("broken_links",[]): bugs.append(_bug("Medium","Broken link",current,f"{x['url']} returned {x.get('status') or x.get('error')}",str(x)))
        for x in raw.get("console_errors",[]): bugs.append(_bug("Medium","Console error",current,x))
        for x in raw.get("layout_issues",[]): bugs.append(_bug("Medium","Layout issue",current,x))
        if include_accessibility:
            for x in raw.get("accessibility_issues",[]): bugs.append(_bug((x.get("impact") or "medium").title(),"Accessibility",current,x.get("description","Accessibility issue"),x.get("help","")))
        try:
            html = requests.get(current, timeout=15, headers={"User-Agent":"QA-Bug-Tracker/1.0"}).text
            soup = BeautifulSoup(html,"html.parser")
            for a in soup.find_all("a", href=True):
                nxt = urljoin(current,a["href"].strip()); np = urlparse(nxt)
                if np.scheme in ("http","https") and np.netloc == purl.netloc and nxt not in visited and nxt not in queue:
                    queue.append(nxt)
                    if len(queue)+len(visited) >= max_pages: break
        except Exception: pass
        if progress_callback: progress_callback(len(visited),max_pages,current,len(bugs),len(queue))
    for i,b in enumerate(bugs,1): b["id"] = f"BUG-{i:03d}"
    return {"target":target,"pages":pages,"bugs":bugs,"passed":max(0,len(pages)-len(bugs))}
