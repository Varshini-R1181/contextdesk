# Operational Runbooks & Incident Response

## Service Actions
ContextDesk supports executing critical operational workflows through the `execute_service_action` tool:
- `restart_service`: Gracefully restarts the internal service pipeline worker pool.
- `flush_cache`: Flushes Redis and local memory caches to clear corrupt diagnostic states.
- `rollback_deployment`: Rolls back the last deployment artifact to the previous green build.

## Incident Escalation Procedures
When diagnosing service breakages:
1. Use `inspect_build_logs` to tail the latest build or deployment logs.
2. Verify identified root causes against the stack traces and error line citations.
3. If remediation requires mutating state, issue `execute_service_action` to receive a confirmation challenge, then re-issue with the token.
