# ContextDesk — Alexa+ Operational Context MCP Server

Submitted to the **Alexa+ Track** of the **Build, Ship, Shape: Amazon Developer Hackathon**.

> **Honest Scope Disclaimer**: Target topology disclaimer. In this hackathon submission, only **ContextDesk (Port 8000)** runs as the standalone, hardened Model Context Protocol (MCP 2025-11-25+) Streamable HTTP server. Microservices referenced in documentation (Auth Service: `8080`, Payment Service: `8081`) reflect the reference fleet topology modeled in `./workspace/docs/architecture.md`.

---

## Architecture Overview

ContextDesk equips Alexa+ with high-assurance operational intelligence, deterministic diagnostic capabilities (zero external LLM dependencies), and a replay-proof two-tier confirmation barrier for mutating operations.

```mermaid
flowchart TD
    subgraph AlexaClient["Alexa+ Client Ecosystem"]
        Simulator["Alexa+ Web Simulator (index.html)"]
        VoiceAPI["Web Speech API (Recognition & Synthesis)"]
        Inspector["MCP Protocol Inspector (Live SSE Console)"]
        Simulator <--> VoiceAPI
        Simulator <--> Inspector
    end

    subgraph SecurityPerimeter["Amazon Principal Security Perimeter"]
        DNSGuard["DNS Rebinding & Origin Guard<br>(Host Whitelist, Rejection of Origin: null)"]
        PathSanitizer["Windows-Safe Path Containment<br>(os.path.commonpath, Colon ':' Rejection)"]
        SecretScrubber["Multi-Pattern Secret Scrubber<br>(AWS Keys, Bearer, Passwords, PATs)"]
        TokenBarrier["Replay-Proof Two-Tier Barrier<br>(HMAC-SHA256 + Atomic Nonce Burn)"]
    end

    subgraph CoreEngine["ContextDesk Server (server.py)"]
        Router["Streamable HTTP Transport (POST /mcp)"]
        SSEStreamer["Chunked SSE Engine (text/event-stream)"]
        ToolRegistry["Tool Registry (inspect_build_logs, execute_service_action, query_codebase_context)"]
        DiagEngine["Pure Python Deterministic Analyzer<br>(Zero External LLM / No Ollama)"]
        FTS5Engine["SQLite FTS5 In-Memory Search Engine"]
    end

    subgraph SandboxWorkspace["Isolated Workspace Sandbox (./workspace)"]
        BuildLog["./workspace/build.log (45 lines)"]
        Docs["./workspace/docs/architecture.md"]
    end

    Simulator -->|"POST /mcp (JSON-RPC 2.0)"| DNSGuard
    DNSGuard --> Router
    Router --> ToolRegistry
    ToolRegistry --> PathSanitizer
    ToolRegistry --> TokenBarrier
    PathSanitizer --> DiagEngine
    DiagEngine --> SecretScrubber
    DiagEngine <--> BuildLog
    ToolRegistry --> FTS5Engine
    FTS5Engine <--> Docs
    ToolRegistry --> SSEStreamer
    SSEStreamer -->|"text/event-stream (Progress & Envelopes)"| Inspector
```

---

## Threat Model & Security Controls

| Threat Vector | Naive / Reference MCP Implementation | ContextDesk Hardened Defense |
| :--- | :--- | :--- |
| **DNS Rebinding & Local Hijacking** | Accepts arbitrary `Host` and `Origin` headers, allowing malicious websites in developer browsers to issue local RPCs. | Validates `Host` and `Origin` using `urllib.parse.urlsplit` against a loopback whitelist (`127.0.0.1`, `localhost`, `::1`). |
| **Sandboxed Iframe Escalation** | Treats `Origin: null` as permitted local requests. | **Explicitly rejects `Origin: null` with HTTP 403 Forbidden**, stopping sandboxed iframe privilege escalation. |
| **Path Traversal & Drive Escape** | Simple string joining or prefix checks vulnerable to Windows drive letters (`C:\`) or NTFS Alternate Data Streams (`file:stream`). | Rejects colons (`:`) and leading slashes; uses `os.path.realpath(os.path.abspath(...))` and enforces `os.path.commonpath == base_dir`. Escapes trigger JSON-RPC `-32602`. |
| **Token Replay on Mutating Actions** | Tokens remain valid across their full lifetime, allowing network eavesdroppers or duplicate agent triggers to replay destructive actions. | **Atomic single-use nonce consumption (`_consume_nonce`)** backed by `threading.Lock`. After successful validation, the nonce is burned; replay attempts return an explicit rejection. |
| **Action Parameter Injection** | Unrestricted arbitrary commands passed to subprocess execution. | Enforces a strict action allowlist: `{"restart_service", "flush_cache", "rollback_deployment"}`. Unauthorized actions trigger `-32602`. |
| **Credential Exfiltration in Logs** | Raw stack traces and logs streamed to agent telemetry with credentials intact. | Multi-tier RegEx scrubber replaces AWS Access Keys (`AKIA...`), AWS secrets, Bearer tokens, generic key-value assignments (`password=...`, `token=...`), GitHub PATs, Slack tokens, and PEM private keys with `[REDACTED]`. |
| **Diagnostic Hallucination & External LLM Outages** | Unbounded external LLM API latency, network timeouts, or model hallucinations on syntax. | **Zero External LLM / No Ollama**. Pure Python deterministic regex parser extracts stack traces, exit codes, and exact coordinate locations (`PaymentController.java:42`). |

---

## Windows PowerShell Quickstart

All commands use Python module flags (`-m`) and full executable paths to eliminate Windows PowerShell execution policy restrictions, shim incompatibilities, and PATH ambiguities.

### 1. Install Dependencies
```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Initialize Workspace Environment
Generates `./workspace/build.log` (45 lines ending in `NullPointerException`) and `./workspace/docs/architecture.md`:
```powershell
.\venv\Scripts\python.exe setup_workspace.py
```

### 3. Execute Hardened Pytest Suite
Runs the 8 comprehensive security, protocol, and tool validation tests via `python.exe -m pytest`:
```powershell
.\venv\Scripts\python.exe -m pytest -v test_server.py
```

### 4. Launch ContextDesk MCP Server
```powershell
.\venv\Scripts\python.exe server.py
```
*Server binds to `http://127.0.0.1:8000`.*

### 5. Open Alexa+ Web Simulator
Navigate to **`http://127.0.0.1:8000/`** (or `http://127.0.0.1:8000/simulator`) in your browser.

---

## API Testing & Verification

> **Note on PowerShell**: In Windows PowerShell, `curl` is often aliased to `Invoke-WebRequest`. Use native `curl.exe` or `Invoke-RestMethod` as demonstrated below.

### A. Handshake (`initialize`) using PowerShell `Invoke-RestMethod`
```powershell
$body = @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
    params = @{ protocolVersion = "2025-11-25" }
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/mcp" -Method Post -ContentType "application/json" -Body $body
```

### B. Inspect Build Logs with SSE Streaming using native `curl.exe`
```powershell
curl.exe -N -X POST "http://127.0.0.1:8000/mcp" `
  -H "Host: 127.0.0.1:8000" `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_build_logs","arguments":{"file_path":"build.log","max_lines":45},"_meta":{"progressToken":"pt-build"}}}'
```

### C. Two-Tier Barrier: Challenge Generation & Single-Use Verification
```powershell
# Tier 1: Challenge generation (returns confirmation_token)
curl.exe -N -X POST "http://127.0.0.1:8000/mcp" `
  -H "Host: 127.0.0.1:8000" `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_service_action","arguments":{"action":"restart_service"}}}'

# Tier 2: First Execution (Succeeds)
curl.exe -N -X POST "http://127.0.0.1:8000/mcp" `
  -H "Host: 127.0.0.1:8000" `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"execute_service_action","arguments":{"action":"restart_service","confirmation_token":"<TOKEN_FROM_STEP_1>"}}}'

# Tier 3: Replay Attempt with Same Token (Rejected: already been used)
curl.exe -N -X POST "http://127.0.0.1:8000/mcp" `
  -H "Host: 127.0.0.1:8000" `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"execute_service_action","arguments":{"action":"restart_service","confirmation_token":"<TOKEN_FROM_STEP_1>"}}}'
```

### D. Verify Path Traversal Sandbox Rejection (-32602)
```powershell
curl.exe -N -X POST "http://127.0.0.1:8000/mcp" `
  -H "Host: 127.0.0.1:8000" `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"inspect_build_logs","arguments":{"file_path":"../../etc/passwd"}}}'
```

---

## Amazon Review Team: Structured Friction Logs

During the design and validation of this MCP 2025-11-25+ server, three critical engineering hurdles were identified and resolved:

### Friction Log 1: Streamable HTTP SSE Buffering & Progress Notification Semantics
* **Symptom**: Emitting unconditional `notifications/progress` chunks before every tool execution caused downstream client buffer desynchronization when clients had not requested or prepared for progress tokens.
* **Root Cause Analysis**: The MCP specification differentiates between fire-and-forget background executions and synchronous tool calls. In Streamable HTTP, intermediate SSE chunks require client opt-in.
* **Resolution**: Hardened `server.py` to inspect `_meta.progressToken`. `notifications/progress` is dispatched over SSE **strictly when `_meta.progressToken` is provided** by the client, preserving wire compatibility with standard non-streaming callers while supporting interactive Alexa+ status updates.

### Friction Log 2: Human-in-the-Loop Schema Bounds & Nonce Replay Vulnerability
* **Symptom**: Traditional two-tier confirmation challenges relying solely on timestamp expiry allow malicious network eavesdroppers or duplicate agent loops to replay destructive operations within the 60-second validity window.
* **Root Cause Analysis**: Without stateful consumption, idempotent tokens on mutating operations (`restart_service`, `flush_cache`) violate the Principle of Least Privilege.
* **Resolution**: Implemented an atomic in-memory nonce ledger (`_consume_nonce`) protected by `threading.Lock`. The HMAC-SHA256 signature binds the action, expiration timestamp, and an unguessable nonce. When validated, the nonce is burned immediately, rendering replay attempts invalid.

### Friction Log 3: Loopback CORS Defense vs. Sandboxed Iframe Pivot (`Origin: null`)
* **Symptom**: Allowing browser-based local developer simulator UIs to interact with loopback endpoints often leads developers to inadvertently permit `Origin: null` or wildcard origins.
* **Root Cause Analysis**: Sandboxed iframes (e.g. `<iframe sandbox="allow-scripts">`) generated by malicious external websites transmit an `Origin: null` header. If a local developer service trusts `null`, the malicious iframe can issue local cross-origin POST requests directly to developer tools.
* **Resolution**: Standardized strict URL parsing via `urllib.parse.urlsplit`. Explicitly checked and **rejected `Origin: null` with HTTP 403 Forbidden**, ensuring only trusted loopback origins (`127.0.0.1`, `localhost`, `::1`) can access the server.

---

## Reviewer Testing Invitation

We explicitly invite hackathon evaluators to verify the security boundaries:
1. **Test Path Traversal**: Attempt to read outside the sandbox by sending `../../` or absolute drive paths (`C:\Windows\win.ini`). Verify that `server.py` rejects the call with code `-32602`.
2. **Test Single-Use Tokens**: Obtain a confirmation token for `restart_service`, execute it, and immediately replay the same token. Verify that the second call returns `"Confirmation token has already been used (replay detected)"`.
3. **Test Secret Redaction**: Inspect the raw SSE output from `inspect_build_logs` on `build.log` and verify that `test-token-xyz`, `supersecretpassword`, and `AKIAIOSFODNN7EXAMPLE` are replaced with `[REDACTED]`.
