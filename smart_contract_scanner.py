"""Defensive Solidity smart-contract static analyzer.

This scanner performs source-code pattern checks only. It does not deploy,
execute, exploit, or send transactions to contracts.
"""
import re
from pathlib import Path

RULES = [
    ("SC-001", "High", "Reentrancy risk", r"\.call\s*\{[^}]*value\s*:", "Review external calls and follow checks-effects-interactions or use a trusted reentrancy guard."),
    ("SC-002", "High", "tx.origin used for authorization", r"\btx\.origin\b", "Do not use tx.origin for access control; prefer msg.sender with explicit authorization."),
    ("SC-003", "High", "Delegatecall usage", r"\.(delegatecall|callcode)\s*\(", "Review delegatecall carefully for storage, target-control, and upgradeability risks."),
    ("SC-004", "High", "Self-destruct capability", r"\bselfdestruct\s*\(", "Review who can reach this code path and whether destruction is still intended."),
    ("SC-005", "Medium", "Unchecked low-level call", r"(?m)(?<!require\()(?<!assert\()\b\w+\.(call|send)\s*(?:\{|\()", "Check the returned success value from low-level calls and handle failure explicitly."),
    ("SC-006", "Medium", "Block timestamp used", r"\bblock\.timestamp\b|\bnow\b", "Do not rely on block timestamps for security-critical randomness or precise timing."),
    ("SC-007", "Medium", "Weak randomness pattern", r"\b(block\.timestamp|block\.number|block\.prevrandao)\b[^\n;]*(?:random|rand|seed)|(?:random|rand|seed)[^\n;]*\b(block\.timestamp|block\.number|block\.prevrandao)\b", "Blockchain values are predictable/manipulable enough to be unsafe for security-sensitive randomness."),
    ("SC-008", "Medium", "Unbounded loop over storage", r"for\s*\([^;]*;[^;]*(?:\.length|length)[^;]*;", "Review loops over growing storage arrays; they can become too expensive to execute."),
    ("SC-009", "Medium", "Floating pragma", r"pragma\s+solidity\s+\^", "Pin compiler versions for production deployments to reduce unexpected compiler changes."),
    ("SC-010", "Medium", "Potential missing access control", r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)[^{;]*\{[^}]{0,500}(?:_mint|mint\(|withdraw\(|upgrade|setOwner|setAdmin|pause\(", "Review privileged functions for explicit authorization such as onlyOwner or role checks."),
    ("SC-011", "Low", "Deprecated block.number/now timing pattern", r"\bnow\b", "Use block.timestamp on supported Solidity versions and avoid time-based security assumptions."),
    ("SC-012", "Low", "Inline assembly", r"\bassembly\s*\{", "Review assembly manually because compiler and type safety guarantees are reduced."),
]


def _line_number(source, index):
    return source.count("\n", 0, index) + 1


def _snippet(source, line, radius=1):
    lines = source.splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))


def scan_solidity(source, filename="Contract.sol"):
    findings = []
    if not source.strip():
        return {"filename": filename, "lines": 0, "findings": [], "summary": _summary([])}

    for rule_id, severity, title, pattern, remediation in RULES:
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
                "id": rule_id,
                "severity": severity,
                "type": "Smart contract security",
                "file": filename,
                "line": line,
                "message": title,
                "evidence": _snippet(source, line),
                "remediation": remediation,
            })

    if not re.search(r"pragma\s+solidity", source, re.IGNORECASE):
        findings.append({"id":"SC-013","severity":"Low","type":"Smart contract security","file":filename,"line":1,"message":"No Solidity pragma detected","evidence":"No pragma solidity statement found.","remediation":"Declare and pin a supported Solidity compiler version."})
    if not re.search(r"\bcontract\s+\w+", source):
        findings.append({"id":"SC-014","severity":"Low","type":"Smart contract security","file":filename,"line":1,"message":"No contract declaration detected","evidence":"No contract/interface/library declaration was detected.","remediation":"Confirm the uploaded source is the intended Solidity source file."})

    findings.sort(key=lambda x: ("Critical High Medium Low".split().index(x["severity"]) if x["severity"] in "Critical High Medium Low" else 9, x["line"]))
    for i, finding in enumerate(findings, 1):
        finding["id"] = f"SC-{i:03d}"
    return {"filename": filename, "lines": len(source.splitlines()), "findings": findings, "summary": _summary(findings)}


def scan_files(files):
    results = []
    for filename, source in files:
        if Path(filename).suffix.lower() == ".sol":
            results.append(scan_solidity(source, filename))
    all_findings = [f for r in results for f in r["findings"]]
    return {"files": results, "findings": all_findings, "summary": _summary(all_findings)}


def _summary(findings):
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for finding in findings:
        counts[finding.get("severity","Low")] = counts.get(finding.get("severity","Low"),0) + 1
    return counts
