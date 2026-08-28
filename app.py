import json, os, tempfile
from pathlib import Path
import streamlit as st
from scanner import run_scan as run_scan_local
from reports import make_pdf, make_docx
from smart_contract_scanner import scan_solidity, scan_files
from contract_address_scanner import CHAINS, scan_contract_address
from security_reports import make_security_pdf
from scan_history import enabled as history_enabled, save_scan, list_scans, get_scan
try:
    from cloudflare_client import run_scan_cloudflare
    CLOUDFLARE_AVAILABLE=True
except ImportError: CLOUDFLARE_AVAILABLE=False

st.set_page_config(page_title="QA Bug Tracker",page_icon="🧪",layout="wide")
st.title("🧪 QA Bug Tracker")
st.caption("Web QA + defensive smart-contract security analysis")

def record_scan(scan_type, target, result, network=None):
    if history_enabled():
        sid=save_scan(scan_type,target,result,network=network)
        if sid: st.session_state["last_scan_id"]=sid
    return st.session_state.get("last_scan_id")

site_tab,source_tab,address_tab,history_tab=st.tabs(["🌐 Website Scanner","🔐 Source Scanner","⛓️ Contract Address Scanner","📚 Scan History"])

with site_tab:
    c1,c2=st.columns([4,1])
    with c1: target=st.text_input("Website URL",placeholder="https://example.com",label_visibility="collapsed")
    with c2: go=st.button("🚀 Scan Website",type="primary",use_container_width=True)
    with st.expander("⚙️ Scan settings"):
        max_pages=st.slider("Maximum pages",1,50,10); mobile=st.checkbox("Test mobile viewport",True); accessibility=st.checkbox("Accessibility checks",True)
        cloud=st.toggle("☁️ Use Cloudflare Browser Run",False) if CLOUDFLARE_AVAILABLE else False
    if go:
        if not target.startswith(("http://","https://")): st.error("Enter a complete URL beginning with http:// or https://")
        else:
            try:
                fn=run_scan_cloudflare if cloud else run_scan_local
                with st.spinner("Scanning website..."):
                    result=fn(target,max_pages=max_pages,test_mobile=mobile,include_accessibility=accessibility)
                st.session_state["result"]=result
                sid=record_scan("website",target,result)
                if sid: st.success(f"Scan saved: {sid}")
            except Exception as e: st.error(f"Scanner error: {e}")
    r=st.session_state.get("result")
    if r:
        bugs=r.get("bugs",[]); pages=r.get("pages",[]); a,b,c,d=st.columns(4); a.metric("Pages",len(pages)); b.metric("Issues",len(bugs)); c.metric("Critical/High",sum(x.get("severity") in ("Critical","High") for x in bugs)); d.metric("Passed",r.get("passed",0))
        if bugs: st.dataframe([{"ID":x.get("id"),"Severity":x.get("severity"),"Type":x.get("type"),"Page":x.get("page"),"Message":x.get("message")} for x in bugs],use_container_width=True,hide_index=True)
        else: st.success("No automated issues detected.")
        with tempfile.TemporaryDirectory() as td:
            p=make_pdf(r,Path(td)/"qa_report.pdf"); doc=make_docx(r,Path(td)/"qa_report.docx"); x,y=st.columns(2)
            with open(p,"rb") as f: x.download_button("📄 Download PDF",f,"qa_report.pdf",use_container_width=True)
            with open(doc,"rb") as f: y.download_button("📝 Download DOCX",f,"qa_report.docx",use_container_width=True)

with source_tab:
    st.subheader("🔐 Solidity Source Vulnerability Scanner")
    files=st.file_uploader("Upload .sol files",type=["sol"],accept_multiple_files=True,key="source_files"); source=st.text_area("Or paste Solidity source",height=260); name=st.text_input("Filename","Contract.sol")
    if st.button("🔎 Scan Solidity",type="primary",use_container_width=True):
        inputs=[]
        if source.strip(): inputs.append((name if name.endswith(".sol") else name+".sol",source))
        for f in files or []: inputs.append((f.name,f.getvalue().decode("utf-8",errors="replace")))
        if inputs:
            sr=scan_files(inputs); st.session_state["source_result"]=sr
            sid=record_scan("solidity",", ".join(x[0] for x in inputs),sr)
            if sid: st.success(f"Scan saved: {sid}")
        else: st.error("Upload a .sol file or paste Solidity source.")
    sr=st.session_state.get("source_result")
    if sr:
        s=sr["summary"]; x1,x2,x3,x4,x5=st.columns(5); x1.metric("Risk score",f'{sr.get("risk_score",0)}/100'); x2.metric("Files",len(sr["files"])); x3.metric("Critical",s.get("Critical",0)); x4.metric("High",s.get("High",0)); x5.metric("Medium",s.get("Medium",0)); st.info(sr.get("risk_label",""))
        if sr["findings"]:
            st.dataframe([{"ID":f["id"],"Severity":f["severity"],"File":f["file"],"Line":f["line"],"Finding":f["message"]} for f in sr["findings"]],use_container_width=True,hide_index=True)
            for f in sr["findings"]:
                with st.expander(f'{f["id"]} · {f["severity"]} · {f["message"]}'): st.code(f["evidence"],language="solidity"); st.write("**Recommended review:**",f["remediation"])
        else: st.success("No heuristic findings detected. This is not proof of security.")

with address_tab:
    st.subheader("⛓️ Contract Address Security Scanner")
    st.caption("Read-only explorer metadata, verified source and deployed-bytecode triage. No transactions are sent.")
    chain=st.selectbox("Network",list(CHAINS.keys())); address=st.text_input("Contract address",placeholder="0x...")
    default_key=os.getenv("ETHERSCAN_API_KEY","")
    try: default_key=st.secrets.get("ETHERSCAN_API_KEY",default_key)
    except Exception: pass
    api_key=st.text_input("Etherscan API V2 key",value=default_key,type="password",help="Store ETHERSCAN_API_KEY in Streamlit Secrets.")
    if st.button("🔎 Analyze Contract Address",type="primary",use_container_width=True):
        if not api_key: st.error("Add ETHERSCAN_API_KEY in Streamlit Secrets.")
        else:
            try:
                with st.spinner(f"Analyzing {chain} contract..."):
                    ar=scan_contract_address(chain,address,api_key=api_key,static_scanner=scan_solidity)
                st.session_state["address_result"]=ar
                sid=record_scan("contract_address",address,ar,network=chain)
                if sid: st.success(f"Scan saved: {sid}")
            except Exception as e: st.error(f"Address scan failed: {e}")
    ar=st.session_state.get("address_result")
    if ar:
        findings=ar.get("findings",[]); counts={k:sum(f.get("severity")==k for f in findings) for k in ["Critical","High","Medium","Low","Info"]}; score=ar.get("risk_score",0); label=ar.get("risk_label",ar.get("risk",""))
        st.divider(); st.subheader("🛡️ Contract Security Report")
        q1,q2=st.columns([1.2,3])
        with q1:
            st.metric("Risk Score",f"{score}/100"); st.progress(min(score,100)/100)
            if score>=35: st.warning(label)
            elif score>0: st.info(label)
            else: st.success(label)
        with q2:
            a,b,c,d,e=st.columns(5); a.metric("Critical",counts["Critical"]); b.metric("High",counts["High"]); c.metric("Medium",counts["Medium"]); d.metric("Low",counts["Low"]); e.metric("Info",counts["Info"])
            st.write(f'**Contract:** {ar.get("contract_name","Unknown")} • **Network:** {ar.get("network")} • **Chain ID:** {ar.get("chain_id")}')
        st.markdown("### Verification & Deployment")
        a,b,c,d=st.columns(4); a.metric("Source","Verified" if ar.get("verified") else "Unverified"); b.metric("Bytecode","Available" if ar.get("bytecode_available") else "Unavailable"); c.metric("Proxy","Yes" if ar.get("proxy") else "No"); d.metric("Runtime bytes",f'{ar.get("bytecode_size",0):,}')
        m1,m2=st.columns(2)
        with m1: st.write("**Compiler:**",ar.get("compiler","Unknown")); st.write("**Optimization:**",ar.get("optimization","Unknown")); st.write("**License:**",ar.get("license","Unknown"))
        with m2: st.write("**Implementation:**",ar.get("implementation") or "N/A"); st.write("**Analysis modes:**",", ".join(ar.get("analysis_modes",[])) or "Limited")
        if ar.get("explorer_url"): st.link_button("🔗 Open Block Explorer",ar["explorer_url"],use_container_width=True)
        if not ar.get("verified"): st.warning("Source is not verified. Bytecode indicators are limited and cannot establish source-level vulnerabilities.")
        st.markdown("### Vulnerability Tests")
        if findings:
            st.dataframe([{"ID":f.get("id"),"Severity":f.get("severity"),"Type":f.get("type"),"Location":f.get("file"),"Finding":f.get("message")} for f in findings],use_container_width=True,hide_index=True)
            for f in findings:
                with st.expander(f'{f.get("id")} · {f.get("severity")} · {f.get("message")}'):
                    st.write(f'**Location:** {f.get("file")}:{f.get("line")}'); st.code(f.get("evidence",""),language="solidity"); st.write("**Recommended review:**",f.get("remediation",""))
        else: st.success("No heuristic vulnerability findings detected.")
        export=dict(ar); export["finding_counts"]=counts
        st.download_button("📥 Download JSON Security Report",json.dumps(export,indent=2),"contract_security_report.json","application/json",use_container_width=True)
        with tempfile.TemporaryDirectory() as td:
            pdf=make_security_pdf(export,Path(td)/"contract_security_report.pdf")
            with open(pdf,"rb") as f: st.download_button("📄 Download PDF Security Report",f,"contract_security_report.pdf","application/pdf",use_container_width=True)
        st.caption("Automated heuristic triage only — not a formal smart-contract audit or guarantee of safety.")

with history_tab:
    st.subheader("📚 Scan History")
    if not history_enabled():
        st.warning("Persistent history is not configured yet. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to Streamlit Secrets, then run supabase_schema.sql in your Supabase SQL Editor.")
        st.code('SUPABASE_URL = "https://YOUR_PROJECT.supabase.co"\nSUPABASE_SERVICE_ROLE_KEY = "YOUR_SERVER_ONLY_KEY"',language="toml")
    else:
        h1,h2=st.columns([2,1])
        with h1: filter_type=st.selectbox("Filter",["All","Website","Solidity","Contract address"])
        with h2: limit=st.number_input("Records",5,100,25,5)
        type_map={"All":None,"Website":"website","Solidity":"solidity","Contract address":"contract_address"}
        rows=list_scans(int(limit),type_map[filter_type])
        if not rows: st.info("No saved scans yet.")
        else:
            st.dataframe([{"Scan ID":x["scan_id"],"Type":x["scan_type"],"Target":x["target"],"Network":x.get("network") or "—","Risk":x.get("risk_score") if x.get("risk_score") is not None else "—","Findings":x.get("finding_count",0),"Created":x.get("created_at","")} for x in rows],use_container_width=True,hide_index=True)
            choices=[x["scan_id"] for x in rows]
            selected=st.selectbox("Open saved scan",choices)
            if st.button("📖 Load Scan Details",use_container_width=True):
                detail=get_scan(selected)
                if detail:
                    st.session_state["history_detail"]=detail
            detail=st.session_state.get("history_detail")
            if detail:
                st.markdown(f'### {detail.get("scan_id")}')
                st.write(f'**Target:** {detail.get("target")}  •  **Type:** {detail.get("scan_type")}  •  **Network:** {detail.get("network") or "—"}')
                if detail.get("risk_score") is not None: st.metric("Risk Score",f'{detail["risk_score"]}/100')
                findings=detail.get("findings") or []
                if findings: st.dataframe([{"Severity":f.get("severity"),"Finding":f.get("message"),"Location":f.get("file") or f.get("page") or "—"} for f in findings],use_container_width=True,hide_index=True)
                st.download_button("📥 Download Saved JSON",json.dumps(detail.get("report",detail),indent=2),f'{detail.get("scan_id","scan")}.json',"application/json",use_container_width=True)
