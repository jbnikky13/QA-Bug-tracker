import json, os, shutil, tempfile, zipfile
from pathlib import Path
import streamlit as st
from scanner import run_scan as run_scan_local
from reports import make_pdf, make_docx
from smart_contract_scanner import scan_solidity, scan_files
from contract_address_scanner import CHAINS, scan_contract_address
try:
    from cloudflare_client import run_scan_cloudflare
    CLOUDFLARE_AVAILABLE = True
except ImportError:
    CLOUDFLARE_AVAILABLE = False

st.set_page_config(page_title="QA Bug Tracker", page_icon="🧪", layout="wide")
st.title("🧪 QA Bug Tracker")
st.caption("Web QA + defensive smart-contract security analysis")

site_tab, source_tab, address_tab = st.tabs(["🌐 Website Scanner", "🔐 Source Scanner", "⛓️ Contract Address Scanner"])

with site_tab:
    c1,c2=st.columns([4,1])
    with c1: target=st.text_input("Website URL",placeholder="https://example.com",label_visibility="collapsed")
    with c2: go=st.button("🚀 Scan Website",type="primary",use_container_width=True)
    with st.expander("⚙️ Scan settings"):
        max_pages=st.slider("Maximum pages",1,50,10)
        mobile=st.checkbox("Test mobile viewport",True)
        accessibility=st.checkbox("Accessibility checks",True)
        cloud=st.toggle("☁️ Use Cloudflare Browser Run",False) if CLOUDFLARE_AVAILABLE else False
    if go:
        if not target.startswith(("http://","https://")): st.error("Enter a complete URL beginning with http:// or https://")
        else:
            try:
                fn=run_scan_cloudflare if cloud else run_scan_local
                with st.spinner("Scanning website..."):
                    st.session_state["result"]=fn(target,max_pages=max_pages,test_mobile=mobile,include_accessibility=accessibility)
            except Exception as e: st.error(f"Scanner error: {e}")
    r=st.session_state.get("result")
    if r:
        bugs=r.get("bugs",[]); pages=r.get("pages",[])
        a,b,c,d=st.columns(4); a.metric("Pages",len(pages)); b.metric("Issues",len(bugs)); c.metric("Critical/High",sum(x.get("severity") in ("Critical","High") for x in bugs)); d.metric("Passed",r.get("passed",0))
        if bugs: st.dataframe([{"ID":x.get("id"),"Severity":x.get("severity"),"Type":x.get("type"),"Page":x.get("page"),"Message":x.get("message")} for x in bugs],use_container_width=True,hide_index=True)
        else: st.success("No automated issues detected.")

with source_tab:
    st.subheader("🔐 Solidity Source Vulnerability Scanner")
    files=st.file_uploader("Upload .sol files",type=["sol"],accept_multiple_files=True,key="source_files")
    source=st.text_area("Or paste Solidity source",height=260)
    name=st.text_input("Filename", "Contract.sol")
    if st.button("🔎 Scan Solidity",type="primary",use_container_width=True):
        inputs=[]
        if source.strip(): inputs.append((name if name.endswith(".sol") else name+".sol",source))
        for f in files or []: inputs.append((f.name,f.getvalue().decode("utf-8",errors="replace")))
        if inputs: st.session_state["source_result"]=scan_files(inputs)
        else: st.error("Upload a .sol file or paste Solidity source.")
    sr=st.session_state.get("source_result")
    if sr:
        s=sr["summary"]; x1,x2,x3,x4,x5=st.columns(5); x1.metric("Risk score",f'{sr.get("risk_score",0)}/100'); x2.metric("Files",len(sr["files"])); x3.metric("Critical",s.get("Critical",0)); x4.metric("High",s.get("High",0)); x5.metric("Medium",s.get("Medium",0))
        st.info(sr.get("risk_label",""))
        if sr["findings"]:
            st.dataframe([{"ID":f["id"],"Severity":f["severity"],"File":f["file"],"Line":f["line"],"Finding":f["message"]} for f in sr["findings"]],use_container_width=True,hide_index=True)
            for f in sr["findings"]:
                with st.expander(f'{f["id"]} · {f["severity"]} · {f["message"]}'):
                    st.code(f["evidence"],language="solidity"); st.write("**Recommended review:**",f["remediation"])
        else: st.success("No heuristic findings detected. This is not proof of security.")

with address_tab:
    st.subheader("⛓️ Contract Address Security Scanner")
    st.caption("Retrieves public explorer metadata/source and runs defensive static checks. No transactions are sent.")
    chain=st.selectbox("Network",list(CHAINS.keys()))
    address=st.text_input("Contract address",placeholder="0x...")
    default_key=os.getenv("ETHERSCAN_API_KEY","")
    try: default_key=st.secrets.get("ETHERSCAN_API_KEY",default_key)
    except Exception: pass
    api_key=st.text_input("Etherscan API V2 key",value=default_key,type="password",help="Store it as ETHERSCAN_API_KEY in Streamlit Secrets for deployment.")
    if st.button("🔎 Analyze Contract Address",type="primary",use_container_width=True):
        if not api_key: st.error("Add ETHERSCAN_API_KEY in Streamlit Secrets.")
        else:
            try:
                with st.spinner(f"Analyzing {chain} contract..."):
                    st.session_state["address_result"]=scan_contract_address(chain,address,api_key=api_key,static_scanner=scan_solidity)
            except Exception as e: st.error(f"Address scan failed: {e}")
    ar=st.session_state.get("address_result")
    if ar:
        findings=ar.get("findings",[])
        high=sum(f.get("severity")=="High" for f in findings); med=sum(f.get("severity")=="Medium" for f in findings); crit=sum(f.get("severity")=="Critical" for f in findings); low=sum(f.get("severity")=="Low" for f in findings)
        # A transparent triage score: weighted findings, capped at 100. Unverified source is explicitly separated.
        score=min(100,crit*30+high*15+med*7+low*2)
        if not ar.get("verified"): score=max(score,10); label="Unverified source — limited analysis"
        elif score>=60: label="Critical review priority"
        elif score>=35: label="High review priority"
        elif score>=15: label="Medium review priority"
        elif score>0: label="Low review priority"
        else: label="No heuristic findings"
        st.divider(); st.subheader("🛡️ Contract Security Report")
        score_col, details_col=st.columns([1.2,2.8])
        with score_col:
            st.metric("Risk Score",f"{score}/100")
            st.progress(score/100)
            st.warning(label) if score>=35 else st.info(label)
        with details_col:
            a,b,c,d,e=st.columns(5); a.metric("Critical",crit); b.metric("High",high); c.metric("Medium",med); d.metric("Low",low); e.metric("Verification","Verified" if ar.get("verified") else "Unverified")
            st.write(f'**Contract:** {ar.get("contract_name","Unknown")}  •  **Network:** {ar.get("network")}  •  **Chain ID:** {ar.get("chain_id")}')
        st.markdown("### Contract Metadata")
        m1,m2=st.columns(2)
        with m1:
            st.write("**Compiler:**",ar.get("compiler","Unknown")); st.write("**Optimization:**",ar.get("optimization","Unknown")); st.write("**License:**",ar.get("license","Unknown"))
        with m2:
            st.write("**Proxy:**","Yes" if ar.get("proxy") else "No"); st.write("**Implementation:**",ar.get("implementation") or "N/A"); st.write("**Address:**",ar.get("address"))
        if ar.get("explorer_url"): st.link_button("🔗 Open Block Explorer",ar["explorer_url"],use_container_width=True)
        if not ar.get("verified"): st.warning("Source is not verified by the explorer. The score is therefore limited and should not be interpreted as a full audit.")
        st.markdown("### Vulnerability Checks")
        if findings:
            st.dataframe([{"ID":f["id"],"Severity":f["severity"],"File":f["file"],"Line":f["line"],"Finding":f["message"]} for f in findings],use_container_width=True,hide_index=True)
            for f in findings:
                with st.expander(f'{f["id"]} · {f["severity"]} · {f["message"]}'):
                    st.write(f'**File:** {f["file"]}  |  **Line:** {f["line"]}')
                    st.code(f["evidence"],language="solidity")
                    st.write("**Recommended review:**",f["remediation"])
        else: st.success("No heuristic vulnerability findings detected.")
        export=dict(ar); export["risk_score"]=score; export["risk_label"]=label; export["finding_counts"]={"Critical":crit,"High":high,"Medium":med,"Low":low}
        st.download_button("📥 Download Security JSON",json.dumps(export,indent=2),"contract_security_report.json","application/json",use_container_width=True)
        st.caption("Automated heuristic analysis only; not a formal smart-contract audit or guarantee of safety.")
