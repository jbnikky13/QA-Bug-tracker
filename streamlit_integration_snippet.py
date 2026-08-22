"""
Drop this into your existing Streamlit app (or adapt the relevant parts).
Assumes url_bug_scanner.py is in the same directory.
"""

import streamlit as st
from url_bug_scanner import scan_url

st.subheader("🔗 Scan a URL for bugs")

url = st.text_input("Paste a website link", placeholder="https://example.com")
check_external = st.checkbox("Also check external links (slower)", value=False)

if st.button("Scan", type="primary") and url:
    with st.spinner("Loading page and running checks..."):
        results = scan_url(url, check_external_links=check_external)

    if results["errors"]:
        for err in results["errors"]:
            st.error(err)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Console errors", len(results["console_errors"]))
    col2.metric("Network failures", len(results["network_failures"]))
    col3.metric("Broken links", len(results["broken_links"]))
    col4.metric("Accessibility issues", len(results["accessibility_issues"]))

    with st.expander(f"Console errors ({len(results['console_errors'])})"):
        for e in results["console_errors"]:
            st.code(e, language="text")

    with st.expander(f"Network failures ({len(results['network_failures'])})"):
        for n in results["network_failures"]:
            st.write(f"`{n['status'] or 'failed'}` — {n['url']}" + (f" ({n['error']})" if n["error"] else ""))

    with st.expander(f"Broken links ({len(results['broken_links'])})"):
        for b in results["broken_links"]:
            st.write(f"`{b['status'] or 'error'}` — [{b['text'] or b['url']}]({b['url']})" +
                      (f" — {b['error']}" if b["error"] else ""))

    with st.expander(f"Layout issues ({len(results['layout_issues'])})"):
        for l in results["layout_issues"]:
            st.write(f"⚠️ {l}")

    with st.expander(f"Accessibility issues ({len(results['accessibility_issues'])})"):
        for a in results["accessibility_issues"]:
            st.write(f"**[{a['impact']}]** {a['help']} — {a['description']} ({a['nodes']} elements)")
