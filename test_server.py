"""
test_server.py - Hardened Test Suite for ContextDesk MCP Server
Validates MCP (2025-11-25+) Streamable HTTP compliance, zero-LLM diagnostics,
Windows-safe path containment, secret redaction, and replay-proof token barriers.
"""

import json
import pytest
from httpx import ASGITransport, AsyncClient

from server import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
        yield c


def _final_envelope(resp) -> dict:
    """
    Helper function that parses SSE chunks from text/event-stream response
    and extracts the final JSON-RPC payload envelope.
    """
    chunks = resp.text.split("\n\n")
    final_payload = None

    for chunk in chunks:
        lines = chunk.strip().split("\n")
        for line in lines:
            if line.startswith("data: "):
                data_str = line[6:].strip()
                try:
                    parsed = json.loads(data_str)
                    # Filter out intermediate progress notifications
                    if parsed.get("method") != "notifications/progress":
                        final_payload = parsed
                except json.JSONDecodeError:
                    pass

    if final_payload is None:
        raise ValueError(f"No final JSON-RPC response envelope found in SSE stream:\n{resp.text}")

    return final_payload


# ---------------------------------------------------------------------------
# 1. Initialize Handshake
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_initialize_handshake(client: AsyncClient):
    """
    Verifies that POST /mcp with method 'initialize' returns:
    1. protocolVersion: '2025-11-25' in the JSON-RPC result.
    2. 'MCP-Session-Id' header in the HTTP response.
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        },
    )
    assert resp.status_code == 200
    assert "mcp-session-id" in resp.headers
    session_id = resp.headers["mcp-session-id"]
    assert len(session_id) > 0

    data = resp.json()
    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 1
    assert data["result"]["protocolVersion"] == "2025-11-25"
    assert data["result"]["serverInfo"]["name"] == "ContextDesk"
    assert "tools" in data["result"]["capabilities"]


# ---------------------------------------------------------------------------
# 2. Tool Discovery & Schemas
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_tools_list_schema(client: AsyncClient):
    """
    Verifies that tools/list returns schemas for all 3 tools:
    - inspect_build_logs
    - execute_service_action
    - query_codebase_context
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["jsonrpc"] == "2.0"

    tools = {t["name"]: t for t in data["result"]["tools"]}
    assert "inspect_build_logs" in tools
    assert "execute_service_action" in tools
    assert "query_codebase_context" in tools

    assert "file_path" in tools["inspect_build_logs"]["inputSchema"]["properties"]
    assert "action" in tools["execute_service_action"]["inputSchema"]["properties"]
    assert "query" in tools["query_codebase_context"]["inputSchema"]["properties"]


# ---------------------------------------------------------------------------
# 3. Path Traversal Containment (-32602)
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_path_traversal_returns_code_minus_32602(client: AsyncClient):
    """
    Passes '../../etc/passwd' with progressToken and asserts that path traversal
    is rejected with JSON-RPC error code -32602.
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "inspect_build_logs",
                "arguments": {"file_path": "../../etc/passwd"},
                "_meta": {"progressToken": "pt-3"},
            },
        },
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    envelope = _final_envelope(resp)
    assert envelope["id"] == 3
    assert "error" in envelope
    assert envelope["error"]["code"] == -32602
    assert "Path traversal rejected" in envelope["error"]["message"]


# ---------------------------------------------------------------------------
# 4. Deterministic Diagnostics, NPE Location & Secret Redaction
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_inspect_build_logs_redaction_and_fatal_npe(client: AsyncClient):
    """
    Asserts NullPointerException found, line 42 located, and secrets redacted
    (Bearer test-token-xyz and password=supersecretpassword not present in output).
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "inspect_build_logs",
                "arguments": {"file_path": "build.log", "max_lines": 45},
            },
        },
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    envelope = _final_envelope(resp)
    assert envelope["id"] == 4
    assert envelope["result"]["isError"] is False

    tool_result = json.loads(envelope["result"]["content"][0]["text"])

    # Verify deterministic extraction
    assert tool_result["culprit_location"] == "PaymentController.java:42"
    assert "NullPointerException" in tool_result["diagnostic_summary"]
    assert tool_result["error_count"] >= 1

    # Verify secret scrubbing
    raw_output = envelope["result"]["content"][0]["text"]
    assert "test-token-xyz" not in raw_output
    assert "supersecretpassword" not in raw_output
    assert "AKIAIOSFODNN7EXAMPLE" not in raw_output
    assert "[REDACTED]" in raw_output


# ---------------------------------------------------------------------------
# 5. Replay-Proof Single-Use Confirmation Barrier
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_confirmation_token_is_single_use(client: AsyncClient):
    """
    Verifies that the two-tier barrier generates a token, succeeds on the first call,
    and is rejected on the second call with 'already been used' (replay prevention).
    """
    # 1. Generate challenge token
    resp_challenge = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "execute_service_action",
                "arguments": {"action": "restart_service"},
            },
        },
    )
    assert resp_challenge.status_code == 200
    env_challenge = _final_envelope(resp_challenge)
    challenge_payload = json.loads(env_challenge["result"]["content"][0]["text"])
    assert challenge_payload["status"] == "confirmation_required"
    token = challenge_payload["confirmation_token"]
    assert token is not None

    # 2. First call: Should succeed and burn nonce
    resp_first = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "execute_service_action",
                "arguments": {
                    "action": "restart_service",
                    "confirmation_token": token,
                },
            },
        },
    )
    assert resp_first.status_code == 200
    env_first = _final_envelope(resp_first)
    first_result = json.loads(env_first["result"]["content"][0]["text"])
    assert first_result["status"] == "success"
    assert "authorized and executed successfully" in first_result["message"]

    # 3. Second call with same token: Must be rejected as already used
    resp_second = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "execute_service_action",
                "arguments": {
                    "action": "restart_service",
                    "confirmation_token": token,
                },
            },
        },
    )
    assert resp_second.status_code == 200
    env_second = _final_envelope(resp_second)
    second_result = json.loads(env_second["result"]["content"][0]["text"])
    assert second_result["status"] == "rejected"
    assert "already been used" in second_result["reason"]


# ---------------------------------------------------------------------------
# 6. Null Origin Rejection (HTTP 403)
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_null_origin_is_rejected(client: AsyncClient):
    """
    Asserts that Origin: null returns HTTP 403 Forbidden to block sandboxed iframe attacks.
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000", "Origin": "null"},
        json={"jsonrpc": "2.0", "id": 8, "method": "ping"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"]["code"] == -32600
    assert "Origin 'null' is rejected" in data["error"]["message"]


# ---------------------------------------------------------------------------
# 7. Unknown Parameter Rejection (-32602)
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_unknown_param_returns_minus_32602(client: AsyncClient):
    """
    Asserts that passing unknown parameters to a tool triggers JSON-RPC error -32602.
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "query_codebase_context",
                "arguments": {
                    "query": "architecture",
                    "unexpected_extra_field": "exploit_attempt",
                },
            },
        },
    )
    assert resp.status_code == 200
    envelope = _final_envelope(resp)
    assert envelope["id"] == 9
    assert "error" in envelope
    assert envelope["error"]["code"] == -32602
    assert "Unknown parameter(s)" in envelope["error"]["message"]
    assert "unexpected_extra_field" in envelope["error"]["message"]


# ---------------------------------------------------------------------------
# 8. Notifications Return HTTP 202
# ---------------------------------------------------------------------------
@pytest.mark.anyio
async def test_notifications_returns_202(client: AsyncClient):
    """
    Asserts that methods starting with 'notifications/' return HTTP 202 Accepted with empty body.
    """
    resp = await client.post(
        "/mcp",
        headers={"Host": "127.0.0.1:8000"},
        json={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
    )
    assert resp.status_code == 202
    assert resp.text == ""
