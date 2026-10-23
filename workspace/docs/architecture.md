# ContextDesk Microservice Architecture & Fleet Topography

> **Target topology. Only ContextDesk (8000) runs in this submission.**

## Fleet Service Ports & Purpose

The reference developer fleet defines the following designated network endpoints:

| Service | Port | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **Auth Service** | `8080` | HTTP / OAuth2 | User authentication, token issuance, and IAM role mapping |
| **Payment Service** | `8081` | HTTP / REST | Order checkout processing, transaction ledger, and Stripe integration |
| **ContextDesk MCP Server** | `8000` | Streamable HTTP | MCP JSON-RPC 2.0 operational server for Alexa+ developer agents |
| **PostgreSQL Database** | `5432` | TCP | Relational persistence for orders and payment ledger |

## Inbound Protocol & Boundary Protection
1. **Inbound Traffic**: The Alexa+ agent communicates exclusively over `POST http://127.0.0.1:8000/mcp`.
2. **Inter-Service Communication**:
   - `Payment Service` (Port `8081`) queries `Auth Service` (Port `8080`) to validate bearer tokens before invoking database transactions.
   - Any operational remediation triggered through Alexa+ (e.g. `restart_service`, `flush_cache`) targets the local microservice controllers.
3. **Sandbox Boundary**:
   - All filesystem tools are strictly confined to `./workspace` using canonical path validation.
   - Credentials (AWS keys, bearer tokens, passwords) are scrubbed before returning diagnostics.
