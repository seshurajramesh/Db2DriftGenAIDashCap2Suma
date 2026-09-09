"""
Server-side validation for any command that will be executed on a DB2
node, regardless of whether it came from the AI, a human typing in the
modal, or an API caller.
"""
import re
import shlex

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$")

_ALLOWED_PATTERNS = [
    # Parameter updates (trailing IMMEDIATE/DEFERRED optional)
    re.compile(r"^db2\s+update\s+db\s+cfg\s+for\s+[A-Za-z0-9_]+\s+using\s+[A-Z0-9_]+\s+[A-Za-z0-9_:./,\-]+(\s+(IMMEDIATE|DEFERRED))?$", re.IGNORECASE),
    re.compile(r"^db2\s+update\s+dbm\s+cfg\s+using\s+[A-Z0-9_]+\s+[A-Za-z0-9_:./,\-]+(\s+(IMMEDIATE|DEFERRED))?$", re.IGNORECASE),

    # Connection & Attachment management
    re.compile(r"^db2\s+attach(\s+to\s+[A-Za-z0-9_]+)?$", re.IGNORECASE),
    re.compile(r"^db2\s+detach$", re.IGNORECASE),
    re.compile(r"^db2\s+connect\s+to\s+[A-Za-z0-9_]+$", re.IGNORECASE),
    re.compile(r"^db2\s+connect\s+reset$", re.IGNORECASE),

    # Read-only diagnostics & chained verification checks
    re.compile(r"^db2\s+get\s+db\s+cfg\s+for\s+[A-Za-z0-9_]+(\s+show\s+detail)?$", re.IGNORECASE),
    re.compile(r"^db2\s+get\s+dbm\s+cfg(\s+show\s+detail)?$", re.IGNORECASE),
    re.compile(r"^db2pd\s+-db\s+[A-Za-z0-9_]+\s+-hadr$", re.IGNORECASE),
    re.compile(r"^db2\s+attach\s+to\s+[A-Za-z0-9_]+\s*&&\s*db2\s+get\s+dbm\s+cfg\s+show\s+detail$", re.IGNORECASE),
    re.compile(r"^db2\s+connect\s+to\s+[A-Za-z0-9_]+\s*&&\s*db2\s+get\s+db\s+cfg\s+for\s+[A-Za-z0-9_]+\s+show\s+detail$", re.IGNORECASE),

    # Lifecycle operations & HADR operations
    re.compile(r"^db2stop\s+force$", re.IGNORECASE),
    re.compile(r"^db2start$", re.IGNORECASE),
    re.compile(r"^db2\s+deactivate\s+db\s+[A-Za-z0-9_]+$", re.IGNORECASE),
    re.compile(r"^db2\s+activate\s+db\s+[A-Za-z0-9_]+$", re.IGNORECASE),
    re.compile(r"^db2\s+takeover\s+hadr\s+on\s+db\s+[A-Za-z0-9_]+$", re.IGNORECASE),
]


class UnsafeCommandError(ValueError):
    pass


def validate_db_name(db_name: str) -> str:
    if not _IDENTIFIER.match(db_name or ""):
        raise UnsafeCommandError(f"Rejected unsafe database identifier: {db_name!r}")
    return db_name


def validate_command(command: str) -> list[str]:
    raw = (command or "").strip()
    if not raw:
        raise UnsafeCommandError("Empty command.")

    statements = [s.strip() for s in raw.split(";") if s.strip()]
    if not statements:
        raise UnsafeCommandError("Empty command.")

    for stmt in statements:
        if not any(p.match(stmt) for p in _ALLOWED_PATTERNS):
            raise UnsafeCommandError(f"Statement not allowlisted and was blocked: {stmt!r}")

    return statements


def safe_quote(value: str) -> str:
    """Shell-quote a value that will be interpolated into a remote command string."""
    return shlex.quote(value)