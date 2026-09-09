import os
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from database import get_db
from models import ClusterTopology
from ssh_utils import run_ssh_command

app = FastAPI(title="DB2 Realtime Log Streaming Microservice")


def _get_valid_api_keys() -> set:
    """Parses format: 'user:secret,user2:secret2' or comma-separated secrets."""
    raw = os.getenv("API_KEYS", "")
    keys = set()
    for entry in raw.split(","):
        entry = entry.strip()
        if ":" in entry:
            # Splits "seshu:seshusecret" -> takes "seshusecret"
            keys.add(entry.split(":", 1)[1].strip())
        elif entry:
            keys.add(entry)
    return keys


def _get_cluster_nodes():
    db_gen = get_db()
    db = next(db_gen)
    try:
        clusters = db.query(ClusterTopology).all()
        nodes = []
        for c in clusters:
            nodes.append({"ip": c.primary_ip, "app": f"{c.app_name} (PRI)", "db": c.db_name})
            nodes.append({"ip": c.standby_ip, "app": f"{c.app_name} (STBY)", "db": c.db_name})
        return nodes
    finally:
        db.close()


@app.websocket("/v2/ws/logs/stream/all")
async def stream_logs(websocket: WebSocket):
    if websocket.client_state == WebSocketState.CONNECTING:
        await websocket.accept()

    valid_keys = _get_valid_api_keys()
    client_key = (websocket.query_params.get("api_key") or "").strip()

    if client_key not in valid_keys:
        await websocket.close(code=1008, reason="Unauthorized")
        return

    nodes = await asyncio.to_thread(_get_cluster_nodes)
    last_seen_records = {node["ip"]: "" for node in nodes}

    cmd = (
        "tail -n 60 /home/db2inst1/sqllib/db2dump/DIAG0000/db2diag.log "
        "| grep -E -B 2 -A 12 'LEVEL: (Error|Severe)'"
    )

    try:
        while True:
            for node in nodes:
                log_out = await asyncio.to_thread(run_ssh_command, node["ip"], cmd, skip_allowlist=True)

                if log_out and not log_out.startswith(("SSH_EXCEPTION", "BLOCKED", "ERROR")):
                    stripped = log_out.strip()
                    if stripped != last_seen_records.get(node["ip"]):
                        last_seen_records[node["ip"]] = stripped
                        await websocket.send_json({
                            "ip": node["ip"],
                            "app": node["app"],
                            "db": node["db"],
                            "content": log_out,
                        })

            await asyncio.sleep(5)
    except (WebSocketDisconnect, RuntimeError):
        pass


@app.get("/v2/ws/health")
@app.get("/health")
async def health():
    return {"status": "ok", "service": "ws-streamer"}