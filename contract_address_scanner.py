"""Defensive EVM contract-address intelligence.
Uses Etherscan API V2 for public explorer metadata/source and read-only deployed bytecode.
No transactions are sent and no contract code is executed by this application.
"""
import os
import re
import requests

CHAINS={
 "Ethereum":{"chainid":"1","explorer":"https://etherscan.io"},
 "Base":{"chainid":"8453","explorer":"https://basescan.org"},
 "BNB Smart Chain":{"chainid":"56","explorer":"https://bscscan.com"},
 "Polygon":{"chainid":"137","explorer":"https://polygonscan.com"},
 "Arbitrum One":{"chainid":"42161","explorer":"https://arbiscan.io"},
 "Optimism":{"chainid":"10","explorer":"https://optimistic.etherscan.io"},
}
API_URL="https://api.etherscan.io/v2/api"

def validate_address(address): return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}",(address or "").strip()))

def _get(params):
    r=requests.get(API_URL,params=params,timeout=25); r.raise_for_status(); return r.json()

def _source(chainid,address,key):
    return _get({"chainid":chainid,"module":"contract","action":"getsourcecode","address":address,"apikey":key})

def _bytecode(chainid,address,key):
    return _get({"chainid":chainid,"module":"proxy","action":"eth_getCode","address":address,"tag":"latest","apikey":key})

def _bytecode_findings(bytecode):
    code=(bytecode or "").lower(); code=code[2:] if code.startswith("0x") else code
    if not code: return []
    findings=[]; size=len(code)//2
    selectors={"3659cfe6":"upgradeToAndCall(address,bytes)","4f1ef286":"upgradeTo(address)","5c60da1b":"implementation()","8da5cb5b":"owner()","715018a6":"renounceOwnership()","f2fde38b":"transferOwnership(address)"}
    for selector,name in selectors.items():
        if selector in code:
            findings.append({"id":"","severity":"Info","type":"Bytecode indicator","file":"deployed bytecode","line":"-","message":f"Known function selector detected: {name}","evidence":f"Selector 0x{selector}","remediation":"Review whether the interface is intended and whether access control/upgrade authorization is correct."})
    if size>24000:
        findings.append({"id":"","severity":"Medium","type":"Deployment quality","file":"deployed bytecode","line":"-","message":f"Large runtime bytecode ({size:,} bytes)","evidence":f"Runtime bytecode size: {size:,} bytes","remediation":"Review contract complexity and deployment architecture."})
    return findings

def _risk(findings):
    weights={"Critical":30,"High":15,"Medium":7,"Low":2,"Info":0}
    score=min(100,sum(weights.get(x.get("severity"),0) for x in findings))
    label="Critical review priority" if score>=60 else "High review priority" if score>=35 else "Medium review priority" if score>=15 else "Low review priority" if score else "No heuristic findings"
    return score,label

def scan_contract_address(chain_name,address,api_key=None,static_scanner=None):
    if chain_name not in CHAINS: raise ValueError("Unsupported network")
    address=(address or "").strip()
    if not validate_address(address): raise ValueError("Invalid EVM contract address")
    api_key=api_key or os.getenv("ETHERSCAN_API_KEY","")
    if not api_key: raise ValueError("ETHERSCAN_API_KEY is required for address scanning")
    chain=CHAINS[chain_name]; source_error=None; bytecode_error=None; meta={}
    try:
        payload=_source(chain["chainid"],address,api_key)
        if str(payload.get("status"))!="1": raise RuntimeError(payload.get("result") or payload.get("message") or "Source API request failed")
        rows=payload.get("result") or []; meta=rows[0] if rows else {}
    except Exception as exc: source_error=str(exc)
    source=meta.get("SourceCode") or ""; verified=bool(source.strip())
    source_for_scan=source[1:-1] if source.startswith("{{") and source.endswith("}}") else source
    findings=[]
    if verified and static_scanner: findings=static_scanner(source_for_scan,meta.get("ContractName") or "VerifiedContract.sol").get("findings",[])
    bytecode=""
    try:
        rpc=_bytecode(chain["chainid"],address,api_key); bytecode=rpc.get("result") or ""
        if bytecode=="0x": bytecode=""
    except Exception as exc: bytecode_error=str(exc)
    if bytecode: findings.extend(_bytecode_findings(bytecode))
    score,label=_risk(findings)
    if not verified:
        label="Unverified source — bytecode-limited analysis" if bytecode else "Unverified source — limited analysis"; score=max(score,10 if bytecode else 5)
    return {"network":chain_name,"chain_id":chain["chainid"],"address":address,"explorer_url":f"{chain['explorer']}/address/{address}","verified":verified,"contract_name":meta.get("ContractName") or "Unknown","compiler":meta.get("CompilerVersion") or "Unknown","optimization":meta.get("OptimizationUsed") or "Unknown","proxy":meta.get("Proxy")=="1","implementation":meta.get("Implementation") or "","license":meta.get("LicenseType") or "Unknown","risk":label,"risk_score":score,"risk_label":label,"findings":findings,"source_available":verified,"bytecode_available":bool(bytecode),"bytecode_size":len(bytecode[2:])//2 if bytecode.startswith("0x") else len(bytecode)//2,"source_error":source_error,"bytecode_error":bytecode_error,"analysis_modes":[x for x,ok in (("verified source",verified),("deployed bytecode",bool(bytecode))) if ok],"note":"Automated heuristic triage only; absence of findings is not proof of security and unverified bytecode cannot reveal source-level intent."}
