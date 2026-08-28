"""Optional persistent scan history for Streamlit + Supabase.

The service-role key is read only on the server from Streamlit Secrets/environment.
Never expose it in the browser or commit it to GitHub.
"""
import os
import uuid
from datetime import datetime, timezone
import requests


def _settings():
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    try:
        import streamlit as st
        url = st.secrets.get("SUPABASE_URL", url).rstrip("/")
        key = st.secrets.get("SUPABASE_SERVICE_ROLE_KEY", key)
    except Exception:
        pass
    return url, key


def enabled():
    url, key = _settings()
    return bool(url and key)


def _headers():
    _, key = _settings()
    return {"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json", "Prefer": "return=representation"}


def make_scan_id(prefix="SCAN"):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:8].upper()}"


def save_scan(scan_type, target, result, network=None):
    url, key = _settings()
    if not (url and key):
        return None
    findings = result.get("findings", result.get("bugs", [])) or []
    summary = result.get("summary", {}) or {}
    risk_score = result.get("risk_score")
    risk_label = result.get("risk_label")
    if risk_score is None and scan_type == "website":
        high = sum(f.get("severity") in ("Critical", "High") for f in findings)
        risk_score = min(100, high * 10)
        risk_label = "Website issue triage"
    scan_id = make_scan_id({"website":"WEB","solidity":"SOL","contract_address":"CON"}.get(scan_type, "SCAN"))
    payload = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "target": str(target)[:1000],
        "network": network,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "status": "completed",
        "finding_count": len(findings),
        "summary": summary,
        "findings": findings[:500],
        "report": result,
    }
    try:
        response = requests.post(f"{url}/rest/v1/scan_history", headers=_headers(), json=payload, timeout=15)
        response.raise_for_status()
        return scan_id
    except requests.RequestException:
        return None


def list_scans(limit=50, scan_type=None):
    url, key = _settings()
    if not (url and key):
        return []
    params = {"select":"id,scan_id,scan_type,target,network,risk_score,risk_label,status,finding_count,summary,created_at", "order":"created_at.desc", "limit":str(min(max(limit,1),100))}
    if scan_type:
        params["scan_type"] = f"eq.{scan_type}"
    try:
        response = requests.get(f"{url}/rest/v1/scan_history", headers=_headers(), params=params, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return []


def get_scan(scan_id):
    url, key = _settings()
    if not (url and key):
        return None
    params = {"select":"*", "scan_id":f"eq.{scan_id}", "limit":"1"}
    try:
        response = requests.get(f"{url}/rest/v1/scan_history", headers=_headers(), params=params, timeout=15)
        response.raise_for_status()
        rows = response.json()
        return rows[0] if rows else None
    except requests.RequestException:
        return None
