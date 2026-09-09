import os
import re
import paramiko
from command_safety import safe_quote, validate_command, validate_db_name, UnsafeCommandError

SSH_USER = os.getenv("SSH_USER", "azureuser")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH")
KNOWN_HOSTS_PATH = os.getenv("SSH_KNOWN_HOSTS_PATH", os.path.expanduser("~/.ssh/known_hosts"))
# Explicit opt-in only — never silently trust unknown hosts. Set to "true" only
# during first-time provisioning of a new node, then turn it back off.
ALLOW_TOFU = os.getenv("SSH_ALLOW_TRUST_ON_FIRST_USE", "false").lower() == "true"

_SQL_ERROR = re.compile(r"sql\d{3,5}[nw]", re.IGNORECASE)


def _connect(host: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if os.path.exists(KNOWN_HOSTS_PATH):
        client.load_host_keys(KNOWN_HOSTS_PATH)
    client.set_missing_host_key_policy(
        paramiko.WarningPolicy() if ALLOW_TOFU else paramiko.RejectPolicy()
    )
    client.connect(hostname=host, username=SSH_USER, key_filename=SSH_KEY_PATH, timeout=10)
    return client


def _statement_ok(out: str) -> bool:
    low = out.lower()
    # DB2's own success phrasing varies by command family:
    #   "DB20000I  The UPDATE DATABASE CONFIGURATION command completed successfully."
    #   "SQL1064N  DB2STOP processing was successful."  <- note: SQL....N code on SUCCESS
    return ("db20000i" in low) or ("completed successfully" in low) or ("was successful" in low)


def _statement_failed(out: str) -> bool:
    if out.startswith(("SSH_EXCEPTION", "BLOCKED", "ERROR")):
        return True
    if _statement_ok(out):
        return False
    return bool(_SQL_ERROR.search(out)) or ("error" in out.lower())


def run_ssh_command(host: str, command: str, skip_allowlist: bool = False) -> str:
    """
    Execute `command` as db2inst1 on `host`.

    - skip_allowlist=True: run the raw string as a single statement,
      unvalidated. Used ONLY for the two fixed, internally-built read-only
      diagnostic commands in this module (never for user/AI-supplied text).
    - skip_allowlist=False (default): `command` may be ';'-separated. Each
      statement is validated, then executed one at a time over a single
      SSH connection. If a statement doesn't report success, execution
      stops immediately and remaining statements are NOT run — this
      matters most for DEFERRED chains (db2stop force; db2start) where
      running db2start after a failed db2stop would be actively harmful.
    """
    client = None
    try:
        client = _connect(host)

        if skip_allowlist:
            remote_cmd = f"sudo su - db2inst1 -c {safe_quote(command)}"
            stdin, stdout, stderr = client.exec_command(remote_cmd, timeout=30)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return out.strip() if not err.strip() else f"ERROR: {err.strip()}"

        statements = validate_command(command)
        results = []
        aborted = False

        for i, stmt in enumerate(statements, 1):
            remote_cmd = f"sudo su - db2inst1 -c {safe_quote(stmt)}"
            stdin, stdout, stderr = client.exec_command(remote_cmd, timeout=60)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            combined = out if not err else f"{out}\nSTDERR: {err}".strip()
            results.append(f"[{i}/{len(statements)}] {stmt}\n{combined or '(no output)'}")

            if _statement_failed(combined):
                aborted = True
                results.append(f"ABORTED after statement {i}/{len(statements)} — remaining statements were not executed.")
                break

        header = "MULTI_STATEMENT_RESULT: " + ("FAILED" if aborted else "SUCCESS")
        return header + "\n\n" + "\n\n".join(results)

    except UnsafeCommandError as ex:
        return f"BLOCKED: {ex}"
    except paramiko.ssh_exception.SSHException as ex:
        return f"SSH_EXCEPTION: {ex}"
    except Exception as ex:
        return f"SSH_EXCEPTION: {ex}"
    finally:
        if client is not None:
            client.close()


def fetch_live_node_configs(host: str, db_name: str) -> dict:
    db_name = validate_db_name(db_name)

    # Database-level configuration. A bare `db2 get db cfg for <db> show detail`
    # can fail with an authorization/catalog error in a non-interactive `su -c`
    # session on some instances unless the shell already has a connection
    # context, so we connect first in the same statement.
    db_command = f"db2 connect to {db_name} && db2 get db cfg for {db_name} show detail"
    raw_db = run_ssh_command(host, db_command, skip_allowlist=False)

    # Instance-level configuration. Attaching to the instance first avoids the
    # same class of non-interactive-session issue for dbm cfg.
    dbm_command = "db2 attach to db2inst1 && db2 get dbm cfg show detail"
    raw_dbm = run_ssh_command(host, dbm_command, skip_allowlist=False)

    # HADR status — read-only, no connection context required.
    raw_hadr = run_ssh_command(host, f"db2pd -db {db_name} -hadr", skip_allowlist=False)

    pattern = re.compile(r'\(\s*([A-Z0-9_]+)\s*\)\s*=\s*(\S+)')
    db_cfg = {m.group(1).upper(): m.group(2) for m in pattern.finditer(raw_db)}
    dbm_cfg = {m.group(1).upper(): m.group(2) for m in pattern.finditer(raw_dbm)}

    hadr_health = {"state": "UNKNOWN", "connect_status": "UNKNOWN", "role": "UNKNOWN", "syncmode": "UNKNOWN"}
    if "HADR_STATE" in raw_hadr:
        s_m = re.search(r'HADR_STATE\s*=\s*(\S+)', raw_hadr)
        r_m = re.search(r'HADR_ROLE\s*=\s*(\S+)', raw_hadr)
        c_m = re.search(r'HADR_CONNECT_STATUS\s*=\s*(\S+)', raw_hadr)
        y_m = re.search(r'HADR_SYNCMODE\s*=\s*(\S+)', raw_hadr)
        if s_m: hadr_health["state"] = s_m.group(1)
        if r_m: hadr_health["role"] = r_m.group(1)
        if c_m: hadr_health["connect_status"] = c_m.group(1)
        if y_m: hadr_health["syncmode"] = y_m.group(1)

    return {
        "db_cfg": db_cfg,
        "dbm_cfg": dbm_cfg,
        "hadr_health": hadr_health,
        "raw_errors": [e for e in (raw_db, raw_dbm, raw_hadr) if e.startswith(("SSH_EXCEPTION", "BLOCKED", "ERROR"))],
    }