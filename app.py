import streamlit as st
from scanner import run_scan
from reports import make_pdf, make_docx
from pathlib import Path
import tempfile
import zipfile
import shutil

st.set_page_config(page_title="QA Bug Tracker", page_icon="🧪", layout="wide")
st.title("🧪 QA Bug Tracker")
st.caption("Automated website/web-app QA scanner with evidence and downloadable reports.")

st.subheader("📦 Upload a complete project")
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

with st.sidebar:
    st.header("Test settings")
    target = st.text_input("Website / web-app URL", placeholder="https://example.com")
    max_pages = st.slider("Maximum pages", 1, 50, 10)
    test_mobile = st.checkbox("Test mobile viewport", True)
    include_accessibility = st.checkbox("Basic accessibility checks", True)
    start = st.button("🚀 Start scan", type="primary", use_container_width=True)

if start:
    if not target.startswith(("http://", "https://")):
        st.error("Enter a complete URL beginning with http:// or https://")
        st.stop()
    with st.spinner("Crawling and testing..."):
        result = run_scan(
            target,
            max_pages=max_pages,
            test_mobile=test_mobile,
            include_accessibility=include_accessibility,
            project_dir=st.session_state.get("uploaded_project")
        )
    st.session_state["result"] = result

result = st.session_state.get("result")
if result:
    bugs = result["bugs"]
    pages = result["pages"]
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Pages tested", len(pages))
    c2.metric("Issues", len(bugs))
    c3.metric("Critical/High", sum(b["severity"] in ("Critical","High") for b in bugs))
    c4.metric("Passed checks", result["passed"])

    st.subheader("Findings")
    if bugs:
        st.dataframe(
            [{"ID":b["id"],"Severity":b["severity"],"Type":b["type"],
              "Page":b["page"],"Message":b["message"]} for b in bugs],
            use_container_width=True, hide_index=True
        )
        for b in bugs:
            with st.expander(f'{b["id"]} · {b["severity"]} · {b["type"]}'):
                st.write("**Page:**", b["page"])
                st.write("**Message:**", b["message"])
                st.write("**Evidence:**", b.get("evidence",""))
                if b.get("screenshot") and Path(b["screenshot"]).exists():
                    st.image(b["screenshot"], caption=b["page"])
    else:
        st.success("No automated issues were detected.")

    st.subheader("Reports")
    tmp = Path(tempfile.gettempdir())
    pdf = make_pdf(result, tmp / "qa_report.pdf")
    docx = make_docx(result, tmp / "qa_report.docx")
    with open(pdf, "rb") as f: st.download_button("📄 Download PDF", f, "qa_report.pdf", "application/pdf")
    with open(docx, "rb") as f: st.download_button("📝 Download DOCX", f, "qa_report.docx",
                                                     "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
else:
    st.info("Enter a website URL and start a scan.")
