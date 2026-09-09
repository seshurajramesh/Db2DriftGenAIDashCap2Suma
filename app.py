import os
import io
import csv
import json
import socket
import asyncio
import requests
import logger
import time
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Request, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import ClusterTopology, AuditLog, GoldenBaseline
from auth import require_api_key, require_api_key_ws
from ssh_utils import run_ssh_command, fetch_live_node_configs
from command_safety import validate_command, UnsafeCommandError
from notify import notify_high_risk_drift,notify_db2_incident
from rag_search import get_db2_documentation

app = FastAPI(title="DB2 Enterprise AI Drift Advisor V2", root_path="/v2", openapi_url="/openapi.json")
templates = Jinja2Templates(directory="templates")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title="DB2 LUW AI Configuration Drift Engine V2",
        version="3.1.0",
        description="3-Way Drift Remediation, RAG-Grounded Analysis, Realtime Diagnostics & ServiceNow CR Generation",
        routes=app.routes,
    )
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi


# ---------------------------------------------------------------------------
# Foundry / AI call
# ---------------------------------------------------------------------------
def call_foundry_ai(system_prompt: str, user_payload: dict, max_retries: int = 2) -> dict:
    url = f"{os.getenv('FOUNDRY_ENDPOINT')}/models/chat/completions?api-version=2024-05-01-preview"
    headers = {"api-key": os.getenv("FOUNDRY_API_KEY"), "Content-Type": "application/json"}
    body = {
        "model": os.getenv("FOUNDRY_DEPLOYMENT"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, indent=2)},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }

    last_err = None
    for attempt in range(max_retries + 1):
        try:

            resp = requests.post(url, json=body, headers=headers, timeout=(10, 120))

            if resp.status_code == 429 or resp.status_code >= 500:
                resp.raise_for_status()
            elif resp.status_code >= 400:
                resp.raise_for_status()  # raises immediately, falls through to non-retryable branch below

            content = resp.json()["choices"][0]["message"]["content"]
            content = content.replace("```json", "").replace("```", "").strip()
            try:
                return json.loads(content)
            except json.JSONDecodeError as parse_err:

                last_err = parse_err
                logger.warning("Foundry returned unparseable JSON (attempt %d): %s", attempt + 1, content[:500])
                if attempt < max_retries:
                    continue
                raise

        except requests.exceptions.HTTPError as ex:
            status = ex.response.status_code if ex.response is not None else None
            if status is not None and status < 500 and status != 429:

                raise
            last_err = ex
            if attempt < max_retries:
                wait = 2 ** attempt  # 1s, then 2s
                logger.warning("Foundry call failed (status=%s), retrying in %ss (attempt %d/%d)",
                                status, wait, attempt + 1, max_retries)
                time.sleep(wait)
                continue
            raise

        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as ex:
            last_err = ex
            if attempt < max_retries:
                wait = 2 ** attempt
                logger.warning("Foundry call timed out, retrying in %ss (attempt %d/%d)", wait, attempt + 1, max_retries)
                time.sleep(wait)
                continue
            raise

    raise last_err


def _param_names(cfg: dict) -> set:
    """Pull parameter names out of the nested {db_cfg: {...}, dbm_cfg: {...}} shape
    returned by fetch_live_node_configs / stored on GoldenBaseline.parameters."""
    names = set()
    for section in ("db_cfg", "dbm_cfg"):
        names.update((cfg or {}).get(section, {}).keys())
    return names


# Node-specific HADR networking parameters to ignore during drift pre-scan —
# these are *expected* to differ between primary and standby (each points at
# the other), so flagging them would waste a RAG lookup and confuse the DBA.
EXCLUDED_ROUTING_PARAMS = {
    "hadr_local_host",
    "hadr_remote_host",
    "hadr_local_svc",
    "hadr_remote_svc",
    "hadr_remote_inst",
    "spm_name"
}


def _normalize_cfg(cfg_dict: dict) -> dict:
    """Normalizes all keys to lowercase and unwraps nested value dicts."""
    if not isinstance(cfg_dict, dict):
        return {}
    clean = {}
    for k, v in cfg_dict.items():
        key_lower = str(k).strip().lower()
        if isinstance(v, dict):
            # If nested like {"value": "AUTOMATIC", ...}
            raw_val = v.get("value", "")
        else:
            raw_val = v
        # Normalize value to stripped uppercase string; None becomes None
        clean[key_lower] = str(raw_val).strip().upper() if raw_val is not None else ""
    return clean


def _values_in_sync(a: str, b: str) -> bool:
    """
    True if two config values match identically or both resolve to AUTOMATIC.
    Both must be present; if one is missing, they do NOT match.
    """
    if a == b:
        return True
    
    # Handle AUTOMATIC equivalences like "8192 AUTOMATIC" vs "AUTOMATIC"
    if a and b and ("AUTOMATIC" in a and "AUTOMATIC" in b):
        return True
        
    return False


def _param_drifted(p_val: str, s_val: str, b_val: str, has_b: bool) -> bool:
    """
    Evaluates drift:
    - Tier 1: Primary vs Standby mismatch (must be identical)
    - Tier 2: If Baseline is specified for this param, both nodes must match Baseline
    """
    # Check Tier 1: Live mismatch between nodes
    if not _values_in_sync(p_val, s_val):
        return True

    # Check Tier 2: Deviation from golden baseline (only if baseline defines this param)
    if has_b:
        if not _values_in_sync(p_val, b_val) or not _values_in_sync(s_val, b_val):
            return True

    return False


def _extract_drifted_param_names(base_cfg: dict, pri_cfg: dict, stby_cfg: dict) -> list:
    drifted = set()

    # 1. Normalize all dictionaries (case-insensitive keys)
    pri_db = _normalize_cfg(pri_cfg.get("db_cfg", {}))
    stby_db = _normalize_cfg(stby_cfg.get("db_cfg", {}))
    base_db = _normalize_cfg(base_cfg.get("db_cfg", {}) if isinstance(base_cfg, dict) else {})

    pri_dbm = _normalize_cfg(pri_cfg.get("dbm_cfg", {}))
    stby_dbm = _normalize_cfg(stby_cfg.get("dbm_cfg", {}))
    base_dbm = _normalize_cfg(base_cfg.get("dbm_cfg", {}) if isinstance(base_cfg, dict) else {})

    # 2. Check Database Configuration
    all_db_keys = set(pri_db.keys()) | set(stby_db.keys()) | set(base_db.keys())
    for k in all_db_keys:
        if k in EXCLUDED_ROUTING_PARAMS:
            continue

        p_val = pri_db.get(k, "")
        s_val = stby_db.get(k, "")
        has_b = k in base_db
        b_val = base_db.get(k, "")

        if _param_drifted(p_val, s_val, b_val, has_b):
            drifted.add(k.upper())

    # 3. Check Database Manager Configuration
    all_dbm_keys = set(pri_dbm.keys()) | set(stby_dbm.keys()) | set(base_dbm.keys())
    for k in all_dbm_keys:
        if k in EXCLUDED_ROUTING_PARAMS:
            continue

        p_val = pri_dbm.get(k, "")
        s_val = stby_dbm.get(k, "")
        has_b = k in base_dbm
        b_val = base_dbm.get(k, "")

        if _param_drifted(p_val, s_val, b_val, has_b):
            drifted.add(k.upper())

    return sorted(list(drifted))


def build_system_prompt(c: ClusterTopology, rag_context: str = "") -> str:
    m_start, m_end = "00:00", "04:00"
    if "-" in (c.maintenance_window or ""):
        parts = c.maintenance_window.split("-")
        m_start, m_end = parts[0].strip(), parts[1].strip()

    # Dynamic target resolution
    target_db = (c.db_name or "").strip().upper()
    target_inst = getattr(c, "instance_name", None) or getattr(c, "instance", "db2inst1")

    rag_section = ""
    if rag_context:
        rag_section = f"""
=========================================
OFFICIAL DB2 DOCUMENTATION (SOURCE OF TRUTH for online configurability, performance impact, and definitions):
{rag_context}
=========================================
"""

    return f"""
You are an expert IBM Db2 12.1 HADR advisor, advanced Db2 LUW DBA, and a ServiceNow Change Management expert.
Your audience is a Senior DBA. You are providing actionable insights and a complete, ready-to-deploy Change Request (CR) grounded strictly in official IBM Db2 12.1 documentation.
Do not use terms like 'junior' in your response. Ensure precise, error-free technical syntax and strictly no spelling or grammatical errors.

{rag_section}

Input Data:
- App Name: {c.app_name}
- App Criticality: {c.app_criticality}
- Maintenance Window: {m_start} - {m_end}
- App Team Support Group: {c.app_group}
- DBA Support Group: {c.dba_group}
- Target Database / CI: {target_db}
- Target Instance: {target_inst}

Input Payload Structure (sent as the user message, JSON):
The user message is a single JSON object with exactly three top-level keys:
  - "golden_baseline": {{"db_cfg": {{PARAM: value, ...}}, "dbm_cfg": {{PARAM: value, ...}}}} (TIER 2 source of truth)
  - "primary_live": {{"db_cfg": {{...}}, "dbm_cfg": {{...}}, "hadr_health": {{"state", "role", "connect_status", "syncmode"}}}} (TIER 1 source of truth)
  - "standby_live": {{"db_cfg": {{...}}, "dbm_cfg": {{...}}, "hadr_health": {{...}}}}

Core Rules & Logic:

1. HADR STATE VALIDATION:
   - Expected Healthy State: HADR_STATE = 'PEER' and HADR_CONNECT_STATUS = 'CONNECTED', read from primary_live.hadr_health.
   - If HADR_STATE is NOT 'PEER': Set `hadrHealthy` to false, force `overallRisk` to "High", and populate `hadrWarning` with inspection steps: `db2pd -db {target_db} -hadr`. State clearly that HADR health must be restored before running configuration CRs.

2. SOURCE OF TRUTH & DRIFT EVALUATION:
   - EXCLUSIONS: Ignore differences in `hadr_local_host`, `hadr_remote_host`, `hadr_local_svc`, `hadr_remote_svc`, and `hadr_remote_inst`.
   - TIER 1 (Node Mismatch): primary_live is the source of truth. If standby differs from primary, `remediationTarget` is "STANDBY".
   - TIER 2 (Baseline Violation): golden_baseline is the source of truth. If primary and standby agree with each other but both differ from golden_baseline, `remediationTarget` MUST be "BOTH".
   - If all three values differ: Treat as TIER 1 first (align standby to primary), and note in `impact` that primary also deviates from baseline.

3. AUTOMATIC VALUES: If two compared values evaluate to an "AUTOMATIC" state (e.g., "8192 AUTOMATIC" vs "AUTOMATIC"), treat them as IN SYNC (NO_DRIFT).

4. STRICT REMEDIATION SYNTAX (MANDATORY & ZERO TOLERANCE FOR HALLUCINATIONS):
   The `remediation` field must strictly follow one of the four exact patterns below. Statements MUST be separated by a single semicolon (';') with NO spaces around the semicolon and NO markdown or conversational text:

   A) Dynamic DBM CFG (CONFIGURABLE ONLINE: Yes):
      db2 attach to {target_inst};db2 update dbm cfg using <PARAM> <VAL> IMMEDIATE;db2 detach

   B) Static / Deferred DBM CFG (CONFIGURABLE ONLINE: No):
      Note: Db2 does NOT start databases automatically after an instance restart. You MUST reactivate the target database immediately after db2start:
      db2 update dbm cfg using <PARAM> <VAL> DEFERRED;db2stop force;db2start;db2 activate db {target_db}

   C) Dynamic DB CFG (CONFIGURABLE ONLINE: Yes):
      db2 connect to {target_db};db2 update db cfg for {target_db} using <PARAM> <VAL> IMMEDIATE;db2 connect reset

   D) Static / Deferred DB CFG (CONFIGURABLE ONLINE: No):
      db2 update db cfg for {target_db} using <PARAM> <VAL> DEFERRED;db2 deactivate db {target_db};db2 activate db {target_db}

5. ROLLING TAKEOVER FOR DEFERRED CHANGES:
   If any parameter update requires DEFERRED and targets PRIMARY or BOTH, the `implementationPlan` must describe an HADR rolling restart:
   Update Standby -> Deactivate/Activate Standby -> Perform Graceful Takeover (`db2 takeover hadr on db {target_db}`) -> Update Old Primary -> Deactivate/Activate Old Primary -> Fallback Takeover.

6. STRICT EXCLUSION: Output ONLY parameters in `items` and the CR that have confirmed TIER 1 or TIER 2 drift. Exclude all synchronized parameters.

7. RISK & IMPACT GROUNDING:
   - Check `DOCUMENTED PERFORMANCE IMPACT` and the `DESCRIPTION` in the documentation section.
   - Map High performance impact or recovery/failover threats to `risk: "High"`.
   - Map Medium performance impact or concurrency behavior to `risk: "Medium"`.
   - Map Low or None impact (e.g. informational/diagnostic flags) to `risk: "Low"`.
   - If documentation is missing for a parameter, explicitly state: "Not covered by retrieved documentation excerpts; classified from general Db2 administration knowledge."

Output Schema Constraints:
STRICTLY return a valid JSON object matching this structure. Ensure all strings are properly escaped.

{{
  "driftStatus": "DRIFT | NO_DRIFT",
  "overallRisk": "High | Medium | Low | None",
  "hadrHealthy": true,
  "hadrSummary": "Short text of HADR State across nodes (e.g., PEER / CONNECTED)",
  "hadrWarning": "Warning and action plan if HADR is unhealthy, otherwise empty",
  "mentorSummary": "Clear, expert explanation of the drift impact.",
  "monitoringAdvice": "If NO_DRIFT, provide best practices here. Otherwise, empty.",
  "topDifferences": [
    {{
      "parameter": "parameter_name",
      "impactArea": "Performance | Recovery Time | Failover Reliability",
      "explanation": "Why this difference matters"
    }}
  ],
  "items": [
    {{
      "application": "{c.app_name}",
      "parameter": "db_cfg.param OR dbm_cfg.param",
      "driftType": "NODE_MISMATCH | BASELINE_VIOLATION",
      "updateType": "IMMEDIATE | DEFERRED",
      "primaryValue": "string",
      "standbyValue": "string",
      "baselineValue": "string",
      "risk": "High | Medium | Low",
      "impact": "Explanation grounded in official documentation",
      "remediationTarget": "PRIMARY | STANDBY | BOTH",
      "remediation": "Single command sequence matching Rule 4 exactly. No other text."
    }}
  ],
  "validationCheck": "Step-by-step commands to validate sync post-remediation.",
  "servicenowCR": {{
    "coreFields": {{
      "shortDescription": "Db2 Parameter Alignment for {c.app_name} ({target_db})",
      "description": "Explicit list of all parameters out of sync, displaying Old Value -> New Value.",
      "category": "Database",
      "ci": "{target_db}",
      "risk": "High | Medium | Low",
      "assignmentGroup": "{c.dba_group}",
      "requiresOutage": true
    }},
    "schedule": {{
      "maintenanceWindowStart": "{m_start}",
      "maintenanceWindowEnd": "{m_end}",
      "implementationEndTarget": "Time marking 75% into the window",
      "backoutStartTime": "Time marking the last 25% of the window"
    }},
    "implementationPlan": "Chronological execution steps for each parameter, including rolling takeover if DEFERRED updates are present.",
    "backoutPlan": "Chronological backout steps to revert each parameter to its original value.",
    "testPlan": "Pre-test and post-test verification steps.",
    "ctasks": [
      {{
        "taskName": "DBA Execution Tasks",
        "assignmentGroup": "{c.dba_group}",
        "expectedState": "Work in Progress"
      }}
    ]
  }}
}}
"""


RISK_ORDER = {"High": 3, "Medium": 2, "Low": 1, "None": 0, None: 0}


def _node_key(app_name: str, role: str) -> str:
    return f"{app_name.lower().replace(' ', '')}_{role}"


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    # request.scope["root_path"] reflects the FastAPI root_path="/v2" set
    # above (and/or uvicorn's --root-path flag). The frontend needs this
    # to build correct absolute URLs when mounted behind nginx's /v2/
    # location block, instead of hardcoding "/v2" in the JS.
    base_path = request.scope.get("root_path", "") or ""
    return templates.TemplateResponse(request, "index.html", {"base_path": base_path})


@app.get("/api/node-status")
async def node_status(db: Session = Depends(get_db), actor: str = Depends(require_api_key)):
    clusters = db.query(ClusterTopology).all()
    nodes = {}
    for c in clusters:
        for role, ip in (("primary", c.primary_ip), ("standby", c.standby_ip)):
            key = _node_key(c.app_name, role)
            online = False
            try:
                with socket.create_connection((ip, c.port or 50000), timeout=2):
                    online = True
            except OSError:
                online = False
            nodes[key] = {
                "host": ip, "port": c.port or 50000, "role": role.upper(),
                "app_name": c.app_name, "status": "online" if online else "offline",
            }
    return {"status": "success", "nodes": nodes}


class DriftCheckReq(BaseModel):
    nodes: List[str] = []


@app.post("/api/run-drift-check")
async def run_drift_check(req: DriftCheckReq, db: Session = Depends(get_db), actor: str = Depends(require_api_key)):
    clusters = db.query(ClusterTopology).all()

    selected_apps = set()
    for c in clusters:
        if not req.nodes or _node_key(c.app_name, "primary") in req.nodes or _node_key(c.app_name, "standby") in req.nodes:
            selected_apps.add(c.app_name)

    target_clusters = [c for c in clusters if c.app_name in selected_apps]
    if not target_clusters:
        raise HTTPException(status_code=400, detail="No matching clusters for the selected nodes.")

    per_cluster_results = {}
    errors = {}

    for c in target_clusters:
        try:
            pri_cfg = fetch_live_node_configs(c.primary_ip, c.db_name)
            stby_cfg = fetch_live_node_configs(c.standby_ip, c.db_name)
            base_cfg = c.baseline.parameters if c.baseline else {}

            # RAG: only fetch documentation for parameters that look drifted
            # in a fast Python pre-scan, instead of every parameter in the
            # scan — keeps Azure AI Search + embedding calls (and prompt
            # tokens) proportional to what's actually wrong. See
            # _extract_drifted_param_names for why this is safe even when
            # the heuristic disagrees with the model's own, more careful
            # determination.
            drifted_params = _extract_drifted_param_names(base_cfg, pri_cfg, stby_cfg)
            print(drifted_params)
            rag_docs = get_db2_documentation(drifted_params)

            payload = {"golden_baseline": base_cfg, "primary_live": pri_cfg, "standby_live": stby_cfg}
            system_prompt = build_system_prompt(c, rag_context=rag_docs)
            ai_res = call_foundry_ai(system_prompt, payload)
            per_cluster_results[c.app_name] = ai_res

            db.add(AuditLog(
                event_type="DRIFT_SCAN", cluster_app=c.app_name,
                overall_risk=ai_res.get("overallRisk", "None"),
                status=ai_res.get("driftStatus", "UNKNOWN"),
                ai_rca=ai_res.get("mentorSummary", ""), actor=actor, raw_payload=ai_res,
            ))
            db.commit()

            if ai_res.get("overallRisk") == "Medium":
                notify_high_risk_drift(c.app_name, c.db_name, ai_res.get("mentorSummary", ""))

        except Exception as ex:
            errors[c.app_name] = str(ex)
            db.add(AuditLog(
                event_type="DRIFT_SCAN", cluster_app=c.app_name,
                overall_risk="Unknown", status="SCAN_FAILED",
                ai_rca=str(ex), actor=actor, raw_payload={"error": str(ex)},
            ))
            db.commit()

    if not per_cluster_results:
        return {"status": "error", "message": f"All selected clusters failed to scan: {errors}"}

    node_map = {c.app_name: {"primary": c.primary_ip, "standby": c.standby_ip} for c in target_clusters}
    aggregate = _aggregate_results(per_cluster_results, errors)
    aggregate["clusterNodeMap"] = node_map
    return {"status": "success", "data": aggregate}


def _aggregate_results(per_cluster: dict, errors: dict) -> dict:
    any_drift = any(r.get("driftStatus") == "DRIFT" for r in per_cluster.values())
    worst_risk = "None"
    for r in per_cluster.values():
        risk = r.get("overallRisk", "None")
        if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(worst_risk, 0):
            worst_risk = risk

    hadr_healthy = all(r.get("hadrHealthy", True) for r in per_cluster.values())
    hadr_warnings = [f"[{app}] {r.get('hadrSummary','')}" for app, r in per_cluster.items() if not r.get("hadrHealthy", True)]

    mentor_parts = [f"{app}: {r.get('mentorSummary','')}" for app, r in per_cluster.items()]
    if errors:
        mentor_parts.append("Scan incomplete for: " + ", ".join(f"{a} ({e})" for a, e in errors.items()))

    items = []
    top_diffs = []
    ctasks = []
    cr_core = None
    plans = {"implementationPlan": [], "backoutPlan": [], "testPlan": []}

    for app, r in per_cluster.items():
        for item in r.get("items", []) or []:
            item = dict(item)
            item["application"] = app
            items.append(item)
        for td in r.get("topDifferences", []) or []:
            td = dict(td)
            td["parameter"] = f"[{app}] {td.get('parameter','')}"
            top_diffs.append(td)
        cr = r.get("servicenowCR")
        if cr:
            core = cr.get("coreFields", {})
            if cr_core is None:
                cr_core = dict(core)
                cr_core["shortDescription"] = f"Align DB2 Parameters — {', '.join(per_cluster.keys())}"
            for k in plans:
                if cr.get(k):
                    plans[k].append(f"[{app}]\n{cr.get(k)}")
            for t in cr.get("ctasks", []) or []:
                t = dict(t)
                t["taskName"] = f"[{app}] {t.get('taskName','')}"
                ctasks.append(t)

    result = {
        "driftStatus": "DRIFT" if any_drift else "NO_DRIFT",
        "driftDetected": any_drift,
        "overallRisk": worst_risk,
        "hadrHealthy": hadr_healthy,
        "hadrWarning": " | ".join(hadr_warnings),
        "mentorSummary": " \n".join(mentor_parts),
        "topDifferences": top_diffs,
        "items": items,
        "validationCheck": "\n".join(r.get("validationCheck", "") for r in per_cluster.values() if r.get("validationCheck")),
        "monitoringAdvice": "\n".join(r.get("monitoringAdvice", "") for r in per_cluster.values() if r.get("monitoringAdvice")),
    }
    if any_drift and cr_core:
        result["servicenowCR"] = {
            "coreFields": cr_core,
            "implementationPlan": "\n\n".join(plans["implementationPlan"]),
            "backoutPlan": "\n\n".join(plans["backoutPlan"]),
            "testPlan": "\n\n".join(plans["testPlan"]),
            "ctasks": ctasks,
        }
    return result


class HITLReq(BaseModel):
    node_ips: List[str]
    command: str
    app_name: str
    reason: str


# Statements that stop/start the whole instance need an explicit, separate
# confirmation from the DBA beyond the normal "Authorize & execute" click —
# they affect every database on the node, not just the one being fixed.
_INSTANCE_WIDE_RE = None
def _touches_instance_wide(statements: list) -> bool:
    import re as _re
    global _INSTANCE_WIDE_RE
    if _INSTANCE_WIDE_RE is None:
        _INSTANCE_WIDE_RE = _re.compile(r"^db2(stop|start)\b", _re.IGNORECASE)
    return any(_INSTANCE_WIDE_RE.match(s) for s in statements)


@app.post("/api/agent/remediate/execute")
async def execute_hitl(req: HITLReq, db: Session = Depends(get_db), actor: str = Depends(require_api_key)):
    known_ips = set()
    for c in db.query(ClusterTopology).all():
        known_ips.add(c.primary_ip)
        known_ips.add(c.standby_ip)

    for ip in req.node_ips:
        if ip not in known_ips:
            raise HTTPException(status_code=400, detail=f"node_ip {ip} is not a recognized cluster node.")

    try:
        statements = validate_command(req.command)
    except UnsafeCommandError as ex:
        db.add(AuditLog(
            event_type="HITL_EXECUTION", cluster_app=req.app_name, node_ip=",".join(req.node_ips),
            executed_command=req.command, ai_rca=req.reason, status="BLOCKED", actor=actor,
            raw_payload={"reason": str(ex)},
        ))
        db.commit()
        raise HTTPException(status_code=400, detail=str(ex))

    execution_results = []
    overall_success = True
    instance_wide = _touches_instance_wide(statements)

    for ip in req.node_ips:
        out = run_ssh_command(ip, req.command)
        status_label = "SUCCESS" if out.startswith("MULTI_STATEMENT_RESULT: SUCCESS") else "FAILED"

        if status_label != "SUCCESS":
            overall_success = False

        db.add(AuditLog(
            event_type="HITL_EXECUTION", cluster_app=req.app_name, node_ip=ip,
            executed_command=req.command, ai_rca=req.reason, status=status_label, actor=actor,
            raw_payload={"ssh_output": out, "instance_wide": instance_wide},
        ))
        db.commit()

        execution_results.append(f"--- Execution on {ip} ---\n{out}")

        # If a statement affecting the whole instance failed, don't proceed
        # to the next node in the list — stop and surface it immediately.
        if instance_wide and status_label != "SUCCESS":
            break

    return {
        "status": "success" if overall_success else "error",
        "output": "\n\n".join(execution_results),
    }


class LogFixReq(BaseModel):
    log_snippet: str
    db_name: str
    cluster_app: str
    node_ip: str


@app.post("/api/agent/logs/analyze")
async def analyze_log(req: LogFixReq, actor: str = Depends(require_api_key)):
    system_prompt = f"""
You are an autonomous L3 IBM Db2 LUW Database Reliability Engineer (DBRE).
Analyze the provided db2diag.log snippet for database '{req.db_name}' and produce an operational triage and remediation plan.

### Core Objectives:
1. Extract key telemetry: Message ID (e.g., ADM6044E, ADM1823E), ZRC return codes (e.g., SQLB_END_OF_CONTAINER), SQLCODE, process/EDU name, and targeted database entities (tablespace, bufferpool, table, connection, or lock).
2. Classify the issue category (e.g., STORAGE_EXHAUSTION, TRANSACTION_LOG_FULL, LOCK_TIMEOUT_DEADLOCK, HADR_STATE_CHANGE, MEMORY_HEAP_EXHAUSTION, CRASH_RECOVERY, AUTHENTICATION_COMMUNICATION).
3. Generate a non-destructive verification query or monitoring command (e.g., MON_GET_*, db2pd) to inspect live state before taking action.
4. Formulate a staged remediation command or recovery procedure.
5. Evaluate operational risk and assign approval requirements.

### Safety Guardrails:
- NEVER generate destructive DDL or DML (e.g., DROP, TRUNCATE, DELETE, FORCE APPLICATION without verification).
- For transient conditions (deadlocks, lock timeouts), staged_command should typically be null or diagnostic, as the engine already rolls back the victim transaction.
- In HADR environments, ensure staged DDL/storage changes are compatible with standby replay (e.g., mirrored paths or automatic storage).
- Mark requires_approval as true for any state-altering command (ALTER, UPDATE DB CFG, REORG, RESTART DB).

### Output Format:
Respond STRICTLY with valid JSON. Do not include markdown code fences, prose, or introductory greetings.

{{
  "error_category": "<STORAGE_EXHAUSTION | LOG_FULL | CONCURRENCY | HADR | MEMORY | OTHER>",
  "primary_message_id": "<e.g., ADM6044E or null>",
  "zrc_code": "<e.g., 0x85020021 or null>",
  "rca": "<Clear, root-cause explanation specifying what failed and why>",
  "affected_object": "<Name of object, parameter, or component, e.g., DIAGDEMO, LOGPRIMARY, or HADR_STANDBY>",
  "verification_command": "<Read-only SQL or db2pd/monitoring command to inspect live condition>",
  "staged_command": "<Exact db2 CLI command to fix/mitigate, or null if no command applies>",
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "requires_approval": true | false,
  "fallback_plan": "<Next step or human DBA escalation instructions if the command fails>"
}}
"""
    res = call_foundry_ai(system_prompt, {"log": req.log_snippet})
    print(res)
    if res :
        notify_db2_incident(req.cluster_app, req.db_name, res)

        return {"status": "success", "analysis": res}


@app.get("/api/audit-log/recent")
async def recent_activity(limit: int = 20, db: Session = Depends(get_db), actor: str = Depends(require_api_key)):
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(min(limit, 100)).all()
    events = [
        {
            "id": r.id, "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "event_type": r.event_type, "cluster_app": r.cluster_app, "node_ip": r.node_ip,
            "overall_risk": r.overall_risk, "status": r.status, "actor": r.actor,
        } for r in rows
    ]
    return {"status": "success", "events": events}


@app.get("/api/download-audit-log")
async def download_audit_log(db: Session = Depends(get_db), actor: str = Depends(require_api_key)):
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "event_type", "cluster_app", "node_ip", "overall_risk", "status", "actor", "executed_command", "ai_rca"])
    for r in rows:
        writer.writerow([
            r.id, r.timestamp.isoformat() if r.timestamp else "", r.event_type, r.cluster_app,
            r.node_ip or "", r.overall_risk or "", r.status or "", r.actor or "",
            (r.executed_command or "").replace("\n", " "), (r.ai_rca or "").replace("\n", " "),
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=db2_drift_audit_{datetime.utcnow().date()}.csv"},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}