"""Defensive contract-address scanner for EVM chains.
Uses Etherscan API V2 to retrieve verified public source metadata, then runs
local static analysis. It never sends transactions or executes contract code.
"""
import os
import re
import requests

CHAINS = {
    "Ethereum": {"chainid": "1", "explorer": "https://etherscan.io"},
    "Base": {"chainid": "8453", "explorer": "https://basescan.org"},
    "BNB Smart Chain": {"chainid": "56", "explorer": "https://bscscan.com"},
    "Polygon": {"chainid": "137", "explorer": "https://polygonscan.com"},
    "Arbitrum One": {"chainid": "42161", "explorer": "https://arbiscan.io"},
    "Optimism": {"chainid": "10", "explorer": "https://optimistic.etherscan.io"},
}

API_URL = "https://api.etherscan.io/v2/api"


def validate_address(address):
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", address.strip()))


def _api_get(chainid, address, api_key):
    params = {
        "chainid": chainid,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    response = requests.get(API_URL, params=params, timeout=20)
    response.raise_for_status()
    return response.json()


def scan_contract_address(chain_name, address, api_key=None, static_scanner=None):
    if chain_name not in CHAINS:
        raise ValueError("Unsupported network")
    address = address.strip()
    if not validate_address(address):
        raise ValueError("Invalid EVM contract address")
    api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
    if not api_key:
        raise ValueError("ETHERSCAN_API_KEY is required for address scanning")

    chain = CHAINS[chain_name]
    payload = _api_get(chain["chainid"], address, api_key)
    if str(payload.get("status")) != "1":
        raise RuntimeError(payload.get("result") or payload.get("message") or "Explorer API request failed")
    rows = payload.get("result") or []
    if not rows:
        raise RuntimeError("No contract metadata returned")
    meta = rows[0]
    source = meta.get("SourceCode") or ""
    verified = bool(source.strip())

    # Etherscan may wrap Standard JSON input in an extra pair of braces.
    source_for_scan = source
    if source.startswith("{{") and source.endswith("}}"):
        source_for_scan = source[1:-1]

    findings = []
    if verified and static_scanner:
        findings = static_scanner(source_for_scan, meta.get("ContractName") or "VerifiedContract.sol").get("findings", [])

    risk = "Unverified"
    if verified:
        high = sum(1 for x in findings if x.get("severity") == "High")
        medium = sum(1 for x in findings if x.get("severity") == "Medium")
        if high:
            risk = "High review priority"
        elif medium:
            risk = "Medium review priority"
        else:
            risk = "No heuristic findings"

    return {
        "network": chain_name,
        "chain_id": chain["chainid"],
        "address": address,
        "explorer_url": f"{chain['explorer']}/address/{address}",
        "verified": verified,
        "contract_name": meta.get("ContractName") or "Unknown",
        "compiler": meta.get("CompilerVersion") or "Unknown",
        "optimization": meta.get("OptimizationUsed") or "Unknown",
        "proxy": meta.get("Proxy") == "1",
        "implementation": meta.get("Implementation") or "",
        "license": meta.get("LicenseType") or "Unknown",
        "risk": risk,
        "findings": findings,
        "source_available": verified,
        "note": "Heuristic analysis only; absence of findings is not proof of security.",
    }
