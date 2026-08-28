import streamlit as st
from scanner import run_scan as run_scan_local
try:
    from cloudflare_client import run_scan_cloudflare
    CLOUDFLARE_AVAILABLE = True
except ImportError:
    CLOUDFLARE_AVAILABLE = False
from reports import make_pdf, make_docx
from smart_contract_scanner import scan_solidity, scan_files
from pathlib import Path
import tempfile, zipfile, shutil

st.set_page_config(page_title="QA Bug Tracker", page_icon="🧪", layout="wide")
st.title("🧪 QA Bug Tracker")
st.caption("Test websites and Solidity smart contracts with defensive automated QA/security checks.")

site_tab, contract_tab = st.tabs(["🌐 Website Scanner", "🔐 Smart Contract Scanner"])

with site_tab:
    col_url, col_btn = st.columns([4, 1])
    with col_url:
        target = st.text_input("Website URL", placeholder="https://example.com", label_visibility="collapsed")
    with col_btn:
        scan_clicked = st.button("🚀 Scan Website", type="primary", use_container_width=True)

    with st.expander("⚙️ Scan settings"):
        max_pages = st.slider("Maximum pages to crawl per site", 1, 50, 10)
        test_mobile = st.checkbox("Test mobile viewport", True)
        include_accessibility = st.checkbox("Accessibility checks", True)
        use_cloudflare = False
        if CLOUDFLARE_AVAILABLE:
            use_cloudflare = st.toggle("☁️ Use Cloudflare Browser Run", value=False)
        run_scan = run_scan_cloudflare if use_cloudflare else run_scan_local

    with st.expander("📋 Scan multiple links at once"):
        bulk_urls = st.text_area("One URL per line", placeholder="https://example.com/page1\nhttps://example.com/page2", height=120)
        bulk_start = st.button("🚀 Scan all pasted links", use_container_width=True)

    with st.expander("📦 Upload a full project ZIP (optional)"):
        uploaded_zip = st.file_uploader("Upload one ZIP containing the website/web-app project", type=["zip"])
        if uploaded_zip:
            upload_dir = Path(tempfile.gettempdir()) / "qa_uploaded_project"
            if upload_dir.exists(): shutil.rmtree(upload_dir)
            upload_dir.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(uploaded_zip) as z:
                    base = upload_dir.resolve()
                    for member in z.infolist():
                        destination = (upload_dir / member.filename).resolve()
                        if not str(destination).startswith(str(base)):
                            raise ValueError("Unsafe ZIP path detected.")
                    z.extractall(upload_dir)
                st.success(f"ZIP uploaded successfully — {sum(1 for p in upload_dir.rglob('*') if p.is_file())} project files extracted.")
                st.session_state["uploaded_project"] = str(upload_dir)
            except Exception as e:
                st.error(f"Could not read the ZIP: {e}")

    def _parse_bulk_urls(raw):
        urls=[]
        for line in raw.splitlines():
            line=line.strip()
            if line: urls.append(line if line.startswith(("http://","https://")) else "https://"+line)
        return urls

    def _do_scan(url):
        return run_scan(url,max_pages=max_pages,test_mobile=test_mobile,include_accessibility=include_accessibility,project_dir=st.session_state.get("uploaded_project"))

    if scan_clicked:
        if not target.startswith(("http://","https://")):
            st.error("Enter a complete URL beginning with http:// or https://")
            st.stop()
        with st.status("Scanning website...", expanded=True) as status:
            progress_bar=st.progress(0)
            def progress(scanned,total,current_url,bug_count,queued):
                progress_bar.progress(min(scanned/max(total,1),1.0))
                status.update(label=f"Scanned {scanned}/{total} page(s) — {bug_count} issue(s) found")
            try:
                result=run_scan(target,max_pages=max_pages,test_mobile=test_mobile,include_accessibility=include_accessibility,project_dir=st.session_state.get("uploaded_project"),progress_callback=progress)
                status.update(label=f"Scan complete — {len(result['bugs'])} issue(s) found",state="complete")
                st.session_state["result"]=result
            except Exception as e:
                status.update(label="Scan failed",state="error")
                st.error(f"Scanner error: {e}")

    if bulk_start:
        urls=_parse_bulk_urls(bulk_urls)
        if not urls: st.error("Paste at least one valid URL.")
        else:
            combined={"target":f"{len(urls)} pasted links","pages":[],"bugs":[],"passed":0}
            with st.status("Scanning pasted links...",expanded=True) as status:
                bar=st.progress(0)
                for i,url in enumerate(urls):
                    status.update(label=f"Scanning link {i+1}/{len(urls)}: {url}")
                    try:
                        r=_do_scan(url); combined["pages"].extend(r["pages"]); combined["bugs"].extend(r["bugs"]); combined["passed"]+=r["passed"]
                    except Exception as e:
                        combined["bugs"].append({"severity":"High","type":"Scan failure","page":url,"message":str(e),"evidence":"run_scan"})
                    bar.progress((i+1)/len(urls))
                for i,b in enumerate(combined["bugs"],1): b["id"]=f"BUG-{i:03d}"
                status.update(label=f"Scan complete — {len(combined['bugs'])} issue(s)",state="complete")
            st.session_state["result"]=combined

    result=st.session_state.get("result")
    if result:
        bugs=result["bugs"]; pages=result["pages"]
        st.divider(); st.subheader("📋 Findings")
        c1,c2,c3,c4=st.columns(4)
        c1.metric("Pages tested",len(pages)); c2.metric("Issues",len(bugs)); c3.metric("Critical/High",sum(b.get("severity") in ("Critical","High") for b in bugs)); c4.metric("Passed checks",result["passed"])
        if bugs:
            st.dataframe([{"ID":b.get("id"),"Severity":b.get("severity"),"Type":b.get("type"),"Page":b.get("page"),"Message":b.get("message")} for b in bugs],use_container_width=True,hide_index=True)
            for b in bugs:
                with st.expander(f'{b.get("id")} · {b.get("severity")} · {b.get("type")}'):
                    st.write("**Page:**",b.get("page")); st.write("**Message:**",b.get("message")); st.write("**Evidence:**",b.get("evidence", ""))
        else: st.success("No automated issues were detected.")
        st.divider(); st.subheader("📥 Download report")
        tmp=Path(tempfile.gettempdir()); pdf=make_pdf(result,tmp/"qa_report.pdf"); docx=make_docx(result,tmp/"qa_report.docx")
        a,b=st.columns(2)
        with a:
            with open(pdf,"rb") as f: st.download_button("📄 Download PDF",f,"qa_report.pdf","application/pdf",use_container_width=True)
        with b:
            with open(docx,"rb") as f: st.download_button("📝 Download DOCX",f,"qa_report.docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document",use_container_width=True)
    else:
        st.info("👆 Paste a website URL above and click **Scan Website** to get started.")

with contract_tab:
    st.subheader("🔐 Smart Contract Security Scanner")
    st.caption("Defensive Solidity source-code analysis. Use only contracts/source code you own or are authorized to review.")
    contract_files = st.file_uploader("Upload Solidity source files", type=["sol"], accept_multiple_files=True, key="solidity_files")
    pasted = st.text_area("Or paste Solidity source", height=280, placeholder="pragma solidity ^0.8.20;\n\ncontract Example { ... }")
    contract_name = st.text_input("Contract filename", value="PastedContract.sol")
    contract_scan = st.button("🔎 Scan Smart Contract", type="primary", use_container_width=True)

    if contract_scan:
        sources=[]
        if pasted.strip(): sources.append((contract_name if contract_name.endswith('.sol') else contract_name+'.sol', pasted))
        for f in contract_files or []:
            try: sources.append((f.name, f.getvalue().decode('utf-8', errors='replace')))
            except Exception as e: st.warning(f"Could not read {f.name}: {e}")
        if not sources:
            st.error("Upload at least one .sol file or paste Solidity source.")
        else:
            result_sc = scan_files(sources)
            st.session_state["contract_result"] = result_sc

    contract_result = st.session_state.get("contract_result")
    if contract_result:
        findings=contract_result["findings"]; summary=contract_result["summary"]
        st.divider(); st.subheader("Security Findings")
        c1,c2,c3,c4=st.columns(4)
        c1.metric("Files",len(contract_result["files"])); c2.metric("High",summary.get("High",0)); c3.metric("Medium",summary.get("Medium",0)); c4.metric("Low",summary.get("Low",0))
        if findings:
            st.dataframe([{"ID":x["id"],"Severity":x["severity"],"File":x["file"],"Line":x["line"],"Finding":x["message"]} for x in findings],use_container_width=True,hide_index=True)
            for x in findings:
                with st.expander(f'{x["id"]} · {x["severity"]} · {x["message"]}'):
                    st.write("**File:**",x["file"]); st.write("**Line:**",x["line"])
                    st.code(x["evidence"], language="solidity")
                    st.write("**Recommended review:**",x["remediation"])
        else:
            st.success("No heuristic findings were detected. This is not proof that the contract is secure; manual review and a dedicated audit are still recommended.")
