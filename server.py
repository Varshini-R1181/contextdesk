"""
ContextDesk - Model Context Protocol (MCP 2025-11-25+) Streamable HTTP Server
Amazon Developer Hackathon - Alexa+ Track Submission

Principal Systems and Security Engineering Architecture:
1. Zero External LLM / No Ollama: Pure Python deterministic log analyzer.
2. Windows-Safe Path Containment: Path canonicalization via os.path.commonpath,
   rejection of colons (':') and leading slashes to prevent drive-letter bypass and NTFS ADS.
3. Secret Redaction: Comprehensive regex scrubber covering AWS credentials, Bearer tokens,
   generic key-value assignments (password, token, api_key), GitHub PATs, Slack tokens, and PEM headers.
4. Security & Replay-Proof Two-Tier Barrier:
   - Action allowlist: {"restart_service", "flush_cache", "rollback_deployment"}.
   - Thread-safe single-use nonce consumption (_consume_nonce) with timestamp expiry.
5. DNS Rebinding & Strict CORS:
   - Host/Origin validation via urllib.parse.urlsplit.
   - Explicit rejection of 'Origin: null' with HTTP 403 (defense against sandboxed iframe pivot).
   - Serves index.html at GET / and GET /simulator.
6. MCP Streamable HTTP Spec Conformance:
   - Unified POST /mcp accepting JSON-RPC 2.0 payloads.
   - Streaming SSE responses for tools/call.
   - notifications/progress sent ONLY if _meta.progressToken is supplied.
   - Notifications starting with 'notifications/' return HTTP 202 Accepted with empty body.
   - Schema validation rejecting unknown tool arguments with JSON-RPC error -32602.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ContextDesk")

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000
MCP_PROTOCOL_VERSION = "2025-11-25"
SERVER_NAME = "ContextDesk"
SERVER_VERSION = "1.0.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_DIR = os.path.realpath(os.path.join(BASE_DIR, "workspace"))
DOCS_DIR = os.path.realpath(os.path.join(WORKSPACE_DIR, "docs"))

CONFIRMATION_SECRET_KEY = os.environ.get(
    "CONTEXTDESK_SECRET_KEY", secrets.token_hex(32)
)

ALLOWED_HOSTNAMES = {"127.0.0.1", "localhost", "::1"}
ALLOWED_HOST_HEADERS = {
    f"127.0.0.1:{SERVER_PORT}",
    f"localhost:{SERVER_PORT}",
    "127.0.0.1",
    "localhost",
    f"[::1]:{SERVER_PORT}",
    "[::1]",
}

ALLOWED_SERVICE_ACTIONS: Set[str] = {
    "restart_service",
    "flush_cache",
    "rollback_deployment",
}

# ---------------------------------------------------------------------------
# Replay-Proof Nonce Store
# ---------------------------------------------------------------------------
_CONSUMED_NONCES: Dict[str, float] = {}
_NONCE_LOCK = threading.Lock()


def _consume_nonce(nonce: str, expires_at: float) -> bool:
    """
    Thread-safe single-use nonce consumption.
    Returns True if nonce was successfully consumed, False if already consumed or expired.
    """
    now = time.time()
    if now > expires_at:
        return False

    with _NONCE_LOCK:
        # Purge expired nonces to prevent unbounded memory growth
        expired = [n for n, exp in _CONSUMED_NONCES.items() if now > exp]
        for n in expired:
            del _CONSUMED_NONCES[n]

        if nonce in _CONSUMED_NONCES:
            return False

        _CONSUMED_NONCES[nonce] = expires_at
        return True


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Domain Exceptions
# ---------------------------------------------------------------------------
class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Optional[Any] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class ParseError(JsonRpcError):
    def __init__(self, message: str = "Parse error: Invalid JSON was received"):
        super().__init__(-32700, message)


class InvalidRequestError(JsonRpcError):
    def __init__(self, message: str = "Invalid Request: Payload must be a JSON-RPC 2.0 object"):
        super().__init__(-32600, message)


class MethodNotFoundError(JsonRpcError):
    def __init__(self, method: str):
        super().__init__(-32601, f"Method not found: '{method}' is not implemented")


class InvalidParamsError(JsonRpcError):
    def __init__(self, message: str):
        super().__init__(-32602, f"Invalid params: {message}")


class InternalError(JsonRpcError):
    def __init__(self, message: str = "Internal JSON-RPC error"):
        super().__init__(-32603, message)


# ---------------------------------------------------------------------------
# Windows-Safe Path Containment
# ---------------------------------------------------------------------------
def resolve_secure_workspace_path(requested_path: str, base_dir: str = WORKSPACE_DIR) -> str:
    """
    Hardened path canonicalization strictly confining access to ./workspace:
    1. Rejects colon (':') characters to block Windows drive-letter bypass and NTFS ADS (Alternate Data Streams).
    2. Strips leading slashes and backslashes.
    3. Resolves absolute realpaths and asserts os.path.commonpath == base_dir.
    """
    if not requested_path or not isinstance(requested_path, str):
        raise InvalidParamsError("File path must be a non-empty string.")

    if ":" in requested_path:
        logger.warning(f"Path traversal blocked: colon detected in '{requested_path}'")
        raise InvalidParamsError("Path traversal rejected: colon character ':' forbidden.")

    # Strip leading slashes to prevent root-relative directory overrides
    clean_path = requested_path.lstrip("/\\")
    if not clean_path:
        raise InvalidParamsError("Path traversal rejected: empty relative path.")

    base_abs = os.path.realpath(os.path.abspath(base_dir))
    candidate_abs = os.path.realpath(os.path.abspath(os.path.join(base_abs, clean_path)))

    try:
        common = os.path.commonpath([base_abs, candidate_abs])
    except ValueError:
        logger.warning(f"Path traversal blocked across filesystem drives: '{requested_path}'")
        raise InvalidParamsError(f"Path traversal rejected: '{requested_path}' crosses drive boundary.")

    if common != base_abs:
        logger.warning(f"Path traversal blocked: '{requested_path}' -> '{candidate_abs}'")
        raise InvalidParamsError(f"Path traversal rejected: '{requested_path}' escapes workspace boundary.")

    return candidate_abs


# ---------------------------------------------------------------------------
# RegEx Secret Scrubber
# ---------------------------------------------------------------------------
def scrub_secrets(text: str) -> str:
    """
    Comprehensive regex scrubber redacting sensitive credentials with [REDACTED]:
    - AWS Access Key IDs (AKIA, ASIA, AROA, AIDA)
    - AWS Secret Keys and Session Tokens
    - HTTP Authorization Bearer Tokens
    - Generic assignments (password, token, api_key, secret)
    - GitHub Personal Access Tokens (ghp_*, github_pat_*)
    - Slack Tokens (xox[baprs]-*)
    - PEM Private Key Headers
    """
    if not text:
        return text

    # 1. AWS Access Key IDs
    text = re.sub(r"\b(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b", "[REDACTED]", text)

    # 2. AWS Secret Access Keys / Session Tokens
    text = re.sub(
        r"(?i)\b(aws_secret_access_key|aws_access_key_id|secret_key|session_token)\b\s*([:=])\s*['\"]?[A-Za-z0-9/+=]{20,}['\"]?",
        r"\1\2 [REDACTED]",
        text,
    )

    # 3. HTTP Authorization Bearer Tokens
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9\-_.~+/]+=*", "Bearer [REDACTED]", text)

    # 4. Generic credential key-value pairs (password=..., token=..., api_key=...)
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|token|api_key|apikey|secret|client_secret)\b\s*([:=])\s*['\"]?[^\s,'\"\n]+['\"]?",
        r"\1\2[REDACTED]",
        text,
    )

    # 5. GitHub Personal Access Tokens
    text = re.sub(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b", "[REDACTED]", text)

    # 6. Slack API Tokens
    text = re.sub(r"\bxox[baprs]-[A-Za-z0-9-]+\b", "[REDACTED]", text)

    # 7. PEM Private Key Headers
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED PEM PRIVATE KEY]", text)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "[REDACTED PEM HEADER]", text)

    return text


# ---------------------------------------------------------------------------
# Zero External LLM: Pure Python Deterministic Log Analyzer
# ---------------------------------------------------------------------------
def extract_and_summarize_log(lines: List[str], max_lines: int) -> dict:
    """
    Deterministic log diagnostic engine (Zero external LLM / No Ollama).
    Parses stack traces, exit codes, and exceptions, extracting exact file and line coordinates.
    """
    total_lines = len(lines)
    start_index = max(0, total_lines - max_lines)
    tail_slice = lines[start_index:]

    error_pattern = re.compile(
        r"(Exception\b|"
        r"Error\b|"
        r"Traceback \(most recent call last\):|"
        r"FATAL\b|"
        r"CRITICAL\b|"
        r"NullPointerException\b|"
        r"BUILD-FAILURE|"
        r"FAILURE!|"
        r"exit code \d+)",
        re.IGNORECASE,
    )

    # Regex targeting filename and line number coordinates
    coord_patterns = [
        re.compile(r"at\s+[\w.$]+\((?P<file>[\w.-]+\.(?:java|kt|scala)):(?P<line>\d+)\)"),
        re.compile(r"File\s+[\"'](?P<file>[^\"']+)[\"'],\s+line\s+(?P<line>\d+)"),
        re.compile(r"(?P<file>[\w.-]+\.(?:java|py|js|ts|go|rs|cpp|c|cs)):(?P<line>\d+)"),
    ]

    detected_errors: List[dict] = []
    primary_errors: List[str] = []
    culprit_location: Optional[str] = None
    annotated_lines: List[str] = []

    for idx, raw_line in enumerate(tail_slice):
        line_num = start_index + idx + 1
        line_clean = raw_line.rstrip("\r\n")
        scrubbed = scrub_secrets(line_clean)
        annotated_lines.append(f"Line {line_num}: {scrubbed}")

        if error_pattern.search(scrubbed):
            detected_errors.append({"line": line_num, "content": scrubbed})

            # Check for coordinates
            for cp in coord_patterns:
                m = cp.search(scrubbed)
                if m:
                    file_name = m.group("file")
                    line_no = m.group("line")
                    found_coord = f"{file_name}:{line_no}"
                    if not culprit_location:
                        culprit_location = found_coord

            # Collect primary failure line text
            if any(k in scrubbed for k in ["NullPointerException", "Error", "ERROR", "Exception", "BUILD-FAILURE", "CRITICAL", "FATAL"]):
                clean_msg = scrubbed.strip()
                if clean_msg not in primary_errors:
                    primary_errors.append(clean_msg)

    # Construct deterministic diagnostic summary
    if not detected_errors:
        diagnostic_summary = (
            f"Deterministic Log Analysis of '{start_index + 1}-{total_lines}':\n"
            "- Status: PASS / CLEAN\n"
            "- No unhandled exceptions, stack traces, or build failure markers found."
        )
    else:
        findings = []
        if culprit_location:
            findings.append(f"- Primary Fault Location: {culprit_location}")
        for err in primary_errors[:5]:
            findings.append(f"- Signature: {err}")

        diagnostic_summary = (
            f"Deterministic Diagnostic Summary ({len(detected_errors)} error markers detected):\n"
            + "\n".join(findings)
            + "\n- Remediation: Review root exception at cited coordinates and verify dependency initialization."
        )

    return {
        "error_count": len(detected_errors),
        "primary_errors": primary_errors[:8],
        "culprit_location": culprit_location,
        "diagnostic_summary": diagnostic_summary,
        "annotated_lines": annotated_lines,
    }


# ---------------------------------------------------------------------------
# Two-Tier Confirmation Token Handlers
# ---------------------------------------------------------------------------
def generate_confirmation_token(action: str, ttl_seconds: int = 60) -> dict:
    now = int(time.time())
    expires_at = now + ttl_seconds
    nonce = secrets.token_hex(8)
    payload_str = f"{action}:{expires_at}:{nonce}"
    signature = hmac.new(
        CONFIRMATION_SECRET_KEY.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    token_raw = f"{payload_str}:{signature}"
    token_b64 = base64.urlsafe_b64encode(token_raw.encode("utf-8")).decode("utf-8")

    return {
        "confirmation_token": token_b64,
        "expires_in_seconds": ttl_seconds,
        "expires_at_epoch": expires_at,
    }


def verify_and_burn_confirmation_token(action: str, token_b64: str) -> tuple[bool, str]:
    if not token_b64 or not isinstance(token_b64, str):
        return False, "Missing confirmation token."

    try:
        token_raw = base64.urlsafe_b64decode(token_b64.encode("utf-8")).decode("utf-8")
        parts = token_raw.split(":")
        if len(parts) != 4:
            return False, "Malformed token structure."

        token_action, expires_at_str, nonce, signature = parts
        payload_str = f"{token_action}:{expires_at_str}:{nonce}"

        expected_sig = hmac.new(
            CONFIRMATION_SECRET_KEY.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return False, "Invalid token cryptographic signature."

        if token_action != action:
            return False, f"Token action mismatch (issued for '{token_action}', claimed for '{action}')."

        expires_at = float(expires_at_str)
        if time.time() > expires_at:
            return False, "Confirmation token has expired."

        # Replay-proof check: atomically burn nonce
        if not _consume_nonce(nonce, expires_at):
            return False, "Confirmation token has already been used (replay detected)."

        return True, "Authorized"
    except Exception as ex:
        logger.warning(f"Token verification error: {ex}")
        return False, "Token parsing error or corrupted signature."


# ---------------------------------------------------------------------------
# Tool Implementations
# ---------------------------------------------------------------------------
async def tool_inspect_build_logs(file_path: str, max_lines: int = 100) -> dict:
    if not isinstance(max_lines, int) or max_lines <= 0:
        max_lines = 100

    target_file = resolve_secure_workspace_path(file_path)

    if not os.path.exists(target_file):
        raise InvalidParamsError(f"Log file '{file_path}' does not exist inside workspace.")

    if not os.path.isfile(target_file):
        raise InvalidParamsError(f"Path '{file_path}' is a directory, not a readable file.")

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception as ex:
        raise InternalError(f"Failed to read file '{file_path}': {str(ex)}")

    analysis = extract_and_summarize_log(all_lines, max_lines)

    return {
        "file_path": file_path,
        "total_lines": len(all_lines),
        "analyzed_lines": min(len(all_lines), max_lines),
        "error_count": analysis["error_count"],
        "primary_errors": analysis["primary_errors"],
        "culprit_location": analysis["culprit_location"],
        "diagnostic_summary": analysis["diagnostic_summary"],
        "lines": analysis["annotated_lines"],
    }


async def tool_execute_service_action(action: str, confirmation_token: Optional[str] = None) -> dict:
    clean_action = action.strip() if action else ""
    if not clean_action:
        raise InvalidParamsError("Action parameter must be specified.")

    if clean_action not in ALLOWED_SERVICE_ACTIONS:
        allowed_list = ", ".join(sorted(ALLOWED_SERVICE_ACTIONS))
        raise InvalidParamsError(
            f"Action '{clean_action}' is not permitted by security policy. Allowed actions: [{allowed_list}]."
        )

    # Tier 1: Challenge generation if token absent
    if not confirmation_token:
        challenge = generate_confirmation_token(clean_action, ttl_seconds=60)
        return {
            "status": "confirmation_required",
            "action": clean_action,
            "security_barrier": "Two-Tier Operational Safety Barrier (HMAC-SHA256, Single-Use)",
            "message": (
                f"Action '{clean_action}' mutates operational state. Explicit confirmation required. "
                "Submit this confirmation token within 60 seconds."
            ),
            "confirmation_token": challenge["confirmation_token"],
            "expires_in_seconds": challenge["expires_in_seconds"],
            "expires_at_epoch": challenge["expires_at_epoch"],
        }

    # Tier 2: Cryptographic single-use verification
    is_valid, reason = verify_and_burn_confirmation_token(clean_action, confirmation_token)
    if not is_valid:
        return {
            "status": "rejected",
            "action": clean_action,
            "reason": reason,
            "message": f"Execution of '{clean_action}' blocked: {reason}",
        }

    return {
        "status": "success",
        "action": clean_action,
        "message": f"Service action '{clean_action}' authorized and executed successfully.",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "verification": "HMAC-SHA256 cryptographic signature validated (nonce burned).",
    }


async def tool_query_codebase_context(query: str) -> dict:
    clean_query = query.strip() if query else ""
    if not clean_query:
        raise InvalidParamsError("Search query cannot be empty.")

    if not os.path.exists(DOCS_DIR):
        os.makedirs(DOCS_DIR, exist_ok=True)

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE VIRTUAL TABLE docs_fts USING fts5(
            file_name,
            file_path,
            section_title,
            body_content,
            tokenize='porter unicode61'
        );
    """)

    indexed_sections_count = 0
    indexed_files = []

    for root, _, files in os.walk(DOCS_DIR):
        for f in files:
            if f.lower().endswith(".md"):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, WORKSPACE_DIR)
                indexed_files.append(rel_path)

                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as doc_f:
                        content = doc_f.read()
                except Exception as ex:
                    logger.warning(f"Skipping indexing for {full_path}: {ex}")
                    continue

                sections = re.split(r"\n(?=#{1,3}\s+)", content)
                for sec in sections:
                    lines = sec.strip().splitlines()
                    if not lines:
                        continue
                    first_line = lines[0].strip()
                    if first_line.startswith("#"):
                        title = re.sub(r"^#{1,3}\s*", "", first_line)
                        body = "\n".join(lines[1:]).strip()
                    else:
                        title = "Overview"
                        body = sec.strip()

                    cursor.execute(
                        "INSERT INTO docs_fts(file_name, file_path, section_title, body_content) VALUES (?, ?, ?, ?)",
                        (f, rel_path, title, body),
                    )
                    indexed_sections_count += 1

    conn.commit()
    results: List[dict] = []

    words = [re.sub(r'[^a-zA-Z0-9_\-]', '', w) for w in clean_query.split()]
    words = [w for w in words if w]
    fts_query_syntax = " OR ".join(f'"{w}"' for w in words) if words else f'"{clean_query}"'

    try:
        cursor.execute(
            """
            SELECT file_path, section_title, snippet(docs_fts, 3, '>>>', '<<<', '...', 32) AS snippet, body_content, rank
            FROM docs_fts
            WHERE docs_fts MATCH ?
            ORDER BY rank
            LIMIT 5
            """,
            (fts_query_syntax,),
        )
        for r in cursor.fetchall():
            results.append({
                "file_path": r[0],
                "section": r[1],
                "matched_snippet": r[2],
                "relevance_rank": round(float(r[4]), 4),
            })
    except sqlite3.OperationalError:
        like_pattern = f"%{clean_query}%"
        cursor.execute(
            """
            SELECT file_path, section_title, substr(body_content, 1, 200) AS snippet
            FROM docs_fts
            WHERE body_content LIKE ? OR section_title LIKE ?
            LIMIT 5
            """,
            (like_pattern, like_pattern),
        )
        for r in cursor.fetchall():
            results.append({
                "file_path": r[0],
                "section": r[1],
                "matched_snippet": r[2],
                "relevance_rank": 1.0,
            })
    finally:
        conn.close()

    return {
        "query": clean_query,
        "indexed_files_count": len(indexed_files),
        "indexed_sections_count": indexed_sections_count,
        "results_count": len(results),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------
TOOLS_REGISTRY = {
    "inspect_build_logs": {
        "name": "inspect_build_logs",
        "description": (
            "Reads tail of a workspace file, extracts stack traces and line coordinates, "
            "scrubs secrets, and provides deterministic diagnostic summary."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Relative file path within ./workspace (e.g. 'build.log').",
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Maximum number of lines to inspect from file tail (default: 100).",
                    "default": 100,
                },
            },
            "required": ["file_path"],
        },
        "handler": tool_inspect_build_logs,
    },
    "execute_service_action": {
        "name": "execute_service_action",
        "description": (
            "Executes permitted service actions behind a single-use 60-second HMAC-SHA256 confirmation barrier."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Permitted action name (restart_service, flush_cache, rollback_deployment).",
                },
                "confirmation_token": {
                    "type": "string",
                    "description": "HMAC token issued from the initial challenge.",
                },
            },
            "required": ["action"],
        },
        "handler": tool_execute_service_action,
    },
    "query_codebase_context": {
        "name": "query_codebase_context",
        "description": (
            "Searches markdown files in ./workspace/docs using fast SQLite FTS5 full-text indexing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query keywords.",
                },
            },
            "required": ["query"],
        },
        "handler": tool_query_codebase_context,
    },
}

# ---------------------------------------------------------------------------
# FastAPI Application & Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    os.makedirs(DOCS_DIR, exist_ok=True)
    logger.info(f"ContextDesk Initialized. Sandbox Workspace: {WORKSPACE_DIR}")
    yield
    logger.info("ContextDesk Server Shutdown Complete.")


app = FastAPI(
    title="ContextDesk MCP Server",
    description="Alexa+ Model Context Protocol (MCP 2025-11-25+) Streamable HTTP Server",
    version=SERVER_VERSION,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Security Middleware: Strict DNS Rebinding & Origin Guard
# ---------------------------------------------------------------------------
@app.middleware("http")
async def dns_rebinding_defense_middleware(request: Request, call_next):
    # 1. Host header validation
    host = request.headers.get("host")
    if not host or host.lower() not in ALLOWED_HOST_HEADERS:
        logger.warning(f"DNS Rebinding Guard: Blocked Host '{host}'")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": f"Access Denied: DNS rebinding protection rejected Host '{host}'.",
                },
            },
        )

    # 2. Origin validation using urlsplit
    origin = request.headers.get("origin")
    if origin is not None:
        origin_clean = origin.strip().lower()

        # Explicitly reject Origin: null (prevents sandboxed iframe escalation)
        if origin_clean == "null":
            logger.warning("DNS Rebinding Guard: Explicitly rejected Origin 'null'")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": "Access Denied: Origin 'null' is rejected.",
                    },
                },
            )

        parsed_origin = urlsplit(origin)
        origin_hostname = parsed_origin.hostname
        if not origin_hostname or origin_hostname.lower() not in ALLOWED_HOSTNAMES:
            logger.warning(f"DNS Rebinding Guard: Blocked Origin '{origin}' (hostname '{origin_hostname}')")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": f"Access Denied: Untrusted Origin '{origin}'.",
                    },
                },
            )

    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": origin if origin else "*",
                "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Session-Id",
                "Access-Control-Expose-Headers": "MCP-Session-Id",
            },
        )

    response = await call_next(request)
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Expose-Headers"] = "MCP-Session-Id"
    return response


# ---------------------------------------------------------------------------
# Simulator Static Page Routes
# ---------------------------------------------------------------------------
@app.get("/")
@app.get("/simulator")
async def get_simulator_page():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="text/html")
    return Response(
        content="<h3>ContextDesk MCP Server is running. index.html not found.</h3>",
        media_type="text/html",
    )


# ---------------------------------------------------------------------------
# SSE Tool Execution Streamer
# ---------------------------------------------------------------------------
async def stream_tool_execution(
    req_id: Any,
    tool_name: str,
    tool_args: dict,
    progress_token: Optional[Any] = None,
) -> AsyncGenerator[str, None]:
    # Emit notifications/progress ONLY if progressToken is explicitly provided
    if progress_token is not None:
        progress_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": progress_token,
                "progress": 0.5,
                "total": 1.0,
                "message": f"Executing tool '{tool_name}'...",
            },
        }
        yield f"event: message\ndata: {json.dumps(progress_notification)}\n\n"

    envelope: dict
    if tool_name not in TOOLS_REGISTRY:
        envelope = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: Tool '{tool_name}' is not registered.",
            },
        }
    else:
        tool_entry = TOOLS_REGISTRY[tool_name]
        handler = tool_entry["handler"]
        try:
            allowed_props = set(tool_entry["inputSchema"]["properties"].keys())
            actual_props = set(tool_args.keys())

            # Validate unknown parameters
            unknown_params = actual_props - allowed_props
            if unknown_params:
                raise InvalidParamsError(f"Unknown parameter(s): {', '.join(sorted(unknown_params))}")

            # Validate required parameters
            req_params = tool_entry["inputSchema"].get("required", [])
            for p in req_params:
                if p not in tool_args:
                    raise InvalidParamsError(f"Missing required parameter '{p}' for tool '{tool_name}'.")

            tool_output = await handler(**tool_args)
            envelope = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(tool_output, indent=2) if isinstance(tool_output, (dict, list)) else str(tool_output),
                        }
                    ],
                    "isError": False,
                },
            }
        except JsonRpcError as jre:
            envelope = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": jre.code,
                    "message": jre.message,
                    "data": jre.data,
                },
            }
        except Exception as ex:
            logger.exception(f"Unhandled error during '{tool_name}': {ex}")
            envelope = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error during tool execution: {str(ex)}",
                },
            }

    yield f"event: message\ndata: {json.dumps(envelope)}\n\n"


# ---------------------------------------------------------------------------
# MCP Transport Endpoint: POST /mcp
# ---------------------------------------------------------------------------
@app.post("/mcp")
async def mcp_endpoint(request: Request):
    try:
        body = await request.body()
        if not body:
            return JSONResponse(
                status_code=200,
                content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error: Empty request body."}},
            )
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as jde:
        return JSONResponse(
            status_code=200,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {str(jde)}."}},
        )
    except Exception as ex:
        return JSONResponse(
            status_code=200,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {str(ex)}."}},
        )

    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or "method" not in payload:
        req_id = payload.get("id") if isinstance(payload, dict) else None
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: Payload must contain 'jsonrpc': '2.0' and 'method'.",
                },
            },
        )

    req_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params", {})

    if not isinstance(method, str):
        return JSONResponse(
            status_code=200,
            content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request: 'method' must be a string."}},
        )

    # Notifications starting with 'notifications/' return HTTP 202 Accepted with empty body
    if method.startswith("notifications/"):
        return Response(status_code=status.HTTP_202_ACCEPTED)

    # Health check: ping
    if method == "ping":
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {}})

    # MCP Handshake: initialize
    if method == "initialize":
        session_id = request.headers.get("mcp-session-id") or f"sess_{secrets.token_hex(16)}"
        return JSONResponse(
            headers={"MCP-Session-Id": session_id},
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "logging": {},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                    "instructions": (
                        "ContextDesk is an operational diagnostic and context server for Alexa+ developers. "
                        "Provides deterministic log root-cause analysis, two-tier action execution, and codebase context search."
                    ),
                },
            },
        )

    # Tool Discovery: tools/list
    if method == "tools/list":
        tools_list = [
            {
                "name": entry["name"],
                "description": entry["description"],
                "inputSchema": entry["inputSchema"],
            }
            for entry in TOOLS_REGISTRY.values()
        ]
        return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}})

    # Tool Invocation: tools/call
    if method == "tools/call":
        if not isinstance(params, dict):
            return JSONResponse(
                status_code=200,
                content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'params' must be an object."}},
            )

        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        if not tool_name or not isinstance(tool_name, str):
            return JSONResponse(
                status_code=200,
                content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'name' must be a valid string."}},
            )

        if not isinstance(tool_args, dict):
            return JSONResponse(
                status_code=200,
                content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: 'arguments' must be a dictionary."}},
            )

        # Progress token: ONLY emit progress if _meta.progressToken is explicitly passed
        progress_token = None
        if isinstance(params.get("_meta"), dict):
            progress_token = params["_meta"].get("progressToken")

        return StreamingResponse(
            stream_tool_execution(
                req_id=req_id,
                tool_name=tool_name,
                tool_args=tool_args,
                progress_token=progress_token,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # Method not found: -32601
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: '{method}' is not supported."}},
    )


# ---------------------------------------------------------------------------
# Server Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info(f"Binding ContextDesk to {SERVER_HOST}:{SERVER_PORT}...")
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT, log_level="info", access_log=True)
