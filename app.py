import subprocess
import sys
import streamlit as st

# --- Streamlit Community Cloud fix ---
# Streamlit Cloud builds the environment from requirements.txt but does NOT
# run `playwright install` automatically, so the Chromium binary Playwright
# needs is missing at runtime. We install it once per container startup,
# cached via session_state so it doesn't re-run on every rerun of the script.
if "playwright_installed" not in st.session_state:
    with st.spinner("Setting up browser engine (first run only, ~30s)..."):
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            st.error("Failed to install Playwright's browser. Scans will fail until this is resolved.")
            st.code(result.stderr[-2000:])
        st.session_state["playwright_installed"] = True

from scanner import run_scan
from reports import make_pdf, make_docx
from pathlib import Path
import tempfile
import zipfile
import shutil

st.set_page_config(page_title="QA Bug Tracker", page_icon="🧪", layout="wide")

st.title("🧪 QA Bug Tracker")
st.caption("Paste a website, scan it, and get a downloadable bug report in minutes.")

# =====================================================================
# PRIMARY WORKFLOW — paste a URL, scan, watch progress, view bugs, download
# =====================================================================

col_url, col_btn = st.columns([4, 1])
with col_url:
    target = st.text_input(
        "Website URL", placeholder="https://example.com",
        label_visibility="collapsed"
    )
with col_btn:
    scan_clicked = st.button("🚀 Scan Website", type="primary", use_container_width=True)

# --- Secondary / advanced options, tucked out of the way of the primary flow ---
with st.expander("⚙️ Scan settings"):
    max_pages = st.slider(
        "Maximum pages to crawl per site", 1, 50, 10,
        help="Applies to the single-URL scan, each pasted link, and ZIP-assisted scans alike."
    )
    test_mobile = st.checkbox("Test mobile viewport", True)
    include_accessibility = st.checkbox("Basic + axe-core accessibility checks", True)

with st.expander("📋 Scan multiple links at once"):
    bulk_urls = st.text_area(
        "One URL per line",
        placeholder="https://example.com/page1\nhttps://example.com/page2\nhttps://another-site.com",
        height=120,
    )
    bulk_start = st.button("🚀 Scan all pasted links", use_container_width=True)

with st.expander("📦 Upload a full project ZIP (optional)"):
    uploaded_zip = st.file_uploader(
        "Upload one ZIP containing the entire website/web-app project",
        type=["zip"],
        help="The ZIP is extracted into a temporary workspace. The scanner can inspect project files in addition to testing the supplied live URL."
    )
    if uploaded_zip:
        upload_dir = Path(tempfile.gettempdir()) / "qa_uploaded_project"
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
        upload_dir.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(uploaded_zip) as z:
                # Prevent path traversal when extracting ZIP files.
                base = upload_dir.resolve()
                for member in z.infolist():
                    destination = (upload_dir / member.filename).resolve()
                    if not str(destination).startswith(str(base)):
                        raise ValueError("Unsafe ZIP path detected.")
                z.extractall(upload_dir)
            file_count = sum(1 for p in upload_dir.rglob("*") if p.is_file())
            st.success(f"ZIP uploaded successfully — {file_count} project files extracted.")
            st.session_state["uploaded_project"] = str(upload_dir)
        except Exception as e:
            st.error(f"Could not read the ZIP: {e}")


def _parse_bulk_urls(raw: str) -> list:
    urls = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.startswith(("http://", "https://")):
            line = "https://" + line
        urls.append(line)
    return urls


# --- Scan a single pasted URL, with a live progress readout ---
if scan_clicked:
    if not target.startswith(("http://", "https://")):
        st.error("Enter a complete URL beginning with http:// or https://")
        st.stop()

    with st.status("Scanning website...", expanded=True) as status:
        progress_bar = st.progress(0)

        def _progress(scanned, total, current_url, bug_count, queued):
            pct = min(scanned / max(total, 1), 1.0)
            progress_bar.progress(pct)
            status.update(label=f"Scanned {scanned}/{total} page(s) — {bug_count} issue(s) found so far")
            st.write(f"🔎 {current_url}")

        result = run_scan(
            target,
            max_pages=max_pages,
            test_mobile=test_mobile,
            include_accessibility=include_accessibility,
            project_dir=st.session_state.get("uploaded_project"),
            progress_callback=_progress,
        )
        status.update(label=f"Scan complete — {len(result['bugs'])} issue(s) found", state="complete")

    st.session_state["result"] = result

# --- Scan multiple pasted links, each crawled up to the configured depth ---
if bulk_start:
    urls = _parse_bulk_urls(bulk_urls)
    if not urls:
        st.error("Paste at least one valid URL, one per line.")
        st.stop()

    combined = {"target": f"{len(urls)} pasted links", "pages": [], "bugs": [], "passed": 0}

    with st.status("Scanning pasted links...", expanded=True) as status:
        overall_progress = st.progress(0)
        for i, url in enumerate(urls):
            status.update(label=f"Scanning link {i+1}/{len(urls)}: {url}")

            def _progress(scanned, total, current_url, bug_count, queued):
                st.write(f"🔎 {current_url}")

            try:
                r = run_scan(
                    url,
                    max_pages=max_pages,
                    test_mobile=test_mobile,
                    include_accessibility=include_accessibility,
                    project_dir=None,
                    progress_callback=_progress,
                )
                combined["pages"].extend(r["pages"])
                combined["bugs"].extend(r["bugs"])
                combined["passed"] += r["passed"]
            except Exception as e:
                combined["bugs"].append({
                    "severity": "High",
                    "type": "Scan failure",
                    "page": url,
                    "message": str(e),
                    "evidence": "run_scan",
                })
            overall_progress.progress((i + 1) / len(urls))

        for idx, b in enumerate(combined["bugs"]):
            b["id"] = f"BUG-{idx+1:03d}"

        status.update(label=f"Scan complete — {len(combined['bugs'])} issue(s) across {len(urls)} link(s)", state="complete")

    st.session_state["result"] = combined

# =====================================================================
# RESULTS — view bugs, then download report
# =====================================================================

result = st.session_state.get("result")
if result:
    bugs = result["bugs"]
    pages = result["pages"]

    st.divider()
    st.subheader("📋 Findings")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Pages tested", len(pages))
    c2.metric("Issues", len(bugs))
    c3.metric("Critical/High", sum(b["severity"] in ("Critical", "High") for b in bugs))
    c4.metric("Passed checks", result["passed"])

    if bugs:
        st.dataframe(
            [{"ID": b["id"], "Severity": b["severity"], "Type": b["type"],
              "Page": b["page"], "Message": b["message"]} for b in bugs],
            use_container_width=True, hide_index=True
        )
        for b in bugs:
            with st.expander(f'{b["id"]} · {b["severity"]} · {b["type"]}'):
                st.write("**Page:**", b["page"])
                st.write("**Message:**", b["message"])
                st.write("**Evidence:**", b.get("evidence", ""))
                if b.get("screenshot") and Path(b["screenshot"]).exists():
                    st.image(b["screenshot"], caption=b["page"])
    else:
        st.success("No automated issues were detected.")

    st.divider()
    st.subheader("📥 Download report")
    tmp = Path(tempfile.gettempdir())
    pdf = make_pdf(result, tmp / "qa_report.pdf")
    docx = make_docx(result, tmp / "qa_report.docx")
    dl1, dl2 = st.columns(2)
    with dl1:
        with open(pdf, "rb") as f:
            st.download_button("📄 Download PDF", f, "qa_report.pdf", "application/pdf", use_container_width=True)
    with dl2:
        with open(docx, "rb") as f:
            st.download_button("📝 Download DOCX", f, "qa_report.docx",
                                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                use_container_width=True)
else:
    st.info("👆 Paste a website URL above and click **Scan Website** to get started.")
