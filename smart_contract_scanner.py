"""Defensive Solidity vulnerability scanner.
Static source analysis only. It never deploys, executes, exploits, or sends transactions.
"""
import re
from pathlib import Path

RULES = [
    ("Reentrancy", "High", r"\.call\s*\{[^}]*value\s*:", "External value transfer detected; review state updates before external calls and consider a reentrancy guard."),
    ("tx.origin authorization", "High", r"\btx\.origin\b", "Avoid tx.origin for authorization; use msg.sender and explicit access control."),
    ("Delegatecall", "High", r"\.(delegatecall|callcode)\s*\(", "Review delegatecall target control, storage layout, and upgrade authorization."),
    ("Selfdestruct", "High", r"\bselfdestruct\s*\(", "Review reachability and authorization of contract-destruction logic."),
    ("Unchecked low-level call", "Medium", r"(?m)\b\w+\.(call|send)\s*(?:\{|\()", "Verify the returned success value and handle failed calls explicitly."),
    ("Timestamp dependence", "Medium", r"\bblock\.timestamp\b|\bnow\b", "Review whether timestamps influence security-sensitive decisions or randomness."),
    ("Weak randomness", "High", r"\b(block\.timestamp|block\.number|block\.prevrandao)\b[^\n;]*(?:random|rand|seed)|(?:random|rand|seed)[^\n;]*\b(block\.timestamp|block\.number|block\.prevrandao)\b", "Do not use predictable blockchain values as security-sensitive randomness."),
    ("Unbounded loop", "Medium", r"for\s*\([^;]*;[^;]*(?:\.length|length)[^;]*;", "Review loops over growing storage collections for gas-exhaustion/DoS risk."),
    ("Floating compiler pragma", "Low", r"pragma\s+solidity\s+\^", "Pin the production compiler version."),
    ("Potential missing access control", "High", r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)[^{;]*\{[^}]{0,700}(?:_mint|mint\(|withdraw\(|upgrade|setOwner|setAdmin|pause\(", "Review privileged state-changing functions for onlyOwner/role checks."),
    ("Inline assembly", "Low", r"\bassembly\s*\{", "Manually review assembly because normal Solidity safety checks are reduced."),
    ("Dangerous delegate target", "High", r"delegatecall\s*\([^)]*\b(address|target|implementation)\b", "Confirm the delegatecall target cannot be controlled by an unauthorized party."),
    ("External call before state update", "High", r"\.call\s*(?:\{|\()[\s\S]{0,800}(?:=\s*false|=\s*true|[-+]=|\+=|-=)", "Review checks-effects-interactions ordering around external calls."),
    ("Unprotected initializer", "High", r"function\s+(?:initialize|init)\s*\([^)]*\)[^{]*\{", "For upgradeable contracts, ensure initialization is one-time and properly authorized."),
    ("Arbitrary token approval", "Medium", r"\.approve\s*\([^,]+,\s*(?:type\(uint\)\.max|uint\(-?1\)|2\*\*256)", "Review unlimited approvals and spender trust boundaries."),
    ("Hard-coded privileged address", "Medium", r"(?:onlyOwner|owner|admin)[^\n;]*0x[a-fA-F0-9]{40}", "Review hard-coded privileged addresses and upgrade/admin recovery procedures."),
]


def _line_number(source, index):
    return source.count("\n", 0, index) + 1


def _snippet(source, line, radius=1):
    lines = source.splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))


def _summary(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.get("severity", "Low")] = counts.get(f.get("severity", "Low"), 0) + 1
    return counts


def _risk_score(findings):
    weights = {"Critical": 30, "High": 15, "Medium": 7, "Low": 2}
    score = min(100, sum(weights.get(f.get("severity"), 1) for f in findings))
    if score >= 60: label = "Critical review priority"
    elif score >= 35: label = "High review priority"
    elif score >= 15: label = "Medium review priority"
    elif score > 0: label = "Low review priority"
    else: label = "No heuristic findings"
    return score, label


def scan_solidity(source, filename="Contract.sol"):
    findings = []
    if not source.strip():
        return {"filename": filename, "lines": 0, "findings": [], "summary": _summary([]), "risk_score": 0, "risk_label": "No source"}

    for title, severity, pattern, remediation in RULES:
        try:
            matches = list(re.finditer(pattern, source, re.IGNORECASE | re.MULTILINE | re.DOTALL))
        except re.error:
            matches = []
        seen_lines = set()
        for match in matches[:10]:
            line = _line_number(source, match.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append({
                "id": "", "severity": severity, "type": "Smart contract vulnerability check",
                "file": filename, "line": line, "message": title,
                "evidence": _snippet(source, line), "remediation": remediation,
            })

    if not re.search(r"pragma\s+solidity", source, re.IGNORECASE):
        findings.append({"id":"","severity":"Low","type":"Smart contract quality","file":filename,"line":1,"message":"No Solidity pragma detected","evidence":"No pragma solidity statement found.","remediation":"Declare a supported and pinned Solidity compiler version."})
    if not re.search(r"\b(contract|interface|library)\s+\w+", source):
        findings.append({"id":"","severity":"Low","type":"Smart contract quality","file":filename,"line":1,"message":"No contract/interface/library declaration detected","evidence":"The uploaded source does not appear to contain a Solidity declaration.","remediation":"Confirm that the intended Solidity source was supplied."})

    order = {"Critical":0,"High":1,"Medium":2,"Low":3}
    findings.sort(key=lambda x: (order.get(x["severity"], 9), x["line"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"SC-{i:03d}"
    score, label = _risk_score(findings)
    return {"filename": filename, "lines": len(source.splitlines()), "findings": findings, "summary": _summary(findings), "risk_score": score, "risk_label": label}


def scan_files(files):
    results = []
    for filename, source in files:
        if Path(filename).suffix.lower() == ".sol":
            results.append(scan_solidity(source, filename))
    findings = [f for r in results for f in r["findings"]]
    score, label = _risk_score(findings)
    return {"files": results, "findings": findings, "summary": _summary(findings), "risk_score": score, "risk_label": label}
