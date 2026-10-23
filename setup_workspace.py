"""
setup_workspace.py - Workspace Initializer for ContextDesk (Alexa+ Track)
Configures realistic build artifacts and documentation in ./workspace.

Generates:
1. ./workspace/docs/architecture.md:
   Includes the disclaimer "Target topology. Only ContextDesk (8000) runs in this submission."
   along with sample fleet service port descriptions (Auth: 8080, Payment: 8081).
2. ./workspace/build.log:
   A realistic 45-line Maven/Java build log ending in:
   java.lang.NullPointerException: Cannot invoke 'OrderRepository.findById()' at PaymentController.java:42
   and containing test tokens (Bearer test-token-xyz and password=supersecretpassword) to verify secret redaction.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_DIR = os.path.join(BASE_DIR, "workspace")
DOCS_DIR = os.path.join(WORKSPACE_DIR, "docs")

# 45-line Maven & Java microservice build log
BUILD_LOG_LINES = [
    "[INFO] Scanning for projects...",
    "[INFO] ------------------------------------------------------------------------",
    "[INFO] Building ContextDesk-PaymentService 2.4.0-SNAPSHOT",
    "[INFO] ------------------------------------------------------------------------",
    "[INFO] --- maven-enforcer-plugin:3.4.1:enforce (enforce-maven) @ paymentservice ---",
    "[INFO] --- maven-resources-plugin:3.3.1:resources (default-resources) @ paymentservice ---",
    "[INFO] Copying 14 resources from src/main/resources to target/classes",
    "[INFO] --- maven-compiler-plugin:3.11.0:compile (default-compile) @ paymentservice ---",
    "[INFO] Compiling 28 source files with javac [version 21.0.2] to target/classes",
    "[INFO] [AWS-SDK] Loading client credentials for profile 'developer-sandbox'...",
    "[ERROR] [AWS-SDK] Access Key expired during validation: AKIAIOSFODNN7EXAMPLE",
    "[ERROR] [DatabaseConfig] Database connection rejected for credentials: password=supersecretpassword",
    "[INFO] [AWS-SDK] Region selected: us-east-1",
    "[INFO] --- maven-resources-plugin:3.3.1:testResources (default-testResources) @ paymentservice ---",
    "[INFO] Copying 6 resources from src/test/resources to target/test-classes",
    "[INFO] --- maven-compiler-plugin:3.11.0:testCompile (default-testCompile) @ paymentservice ---",
    "[INFO] Compiling 12 test source files with javac [version 21.0.2] to target/test-classes",
    "[INFO] --- maven-surefire-plugin:3.2.5:test (default-test) @ paymentservice ---",
    "[INFO] Using auto-detected provider: org.apache.maven.surefire.junitplatform.JUnitPlatformProvider",
    "[INFO] Running com.amazon.contextdesk.payment.AuthTokenValidationTest",
    "[ERROR] [AuthFilter] Authentication check failed for header: Authorization: Bearer test-token-xyz",
    "[INFO] Tests run: 4, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 1.204 s -- in AuthTokenValidationTest",
    "[INFO] Running com.amazon.contextdesk.payment.HealthCheckControllerTest",
    "[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.412 s -- in HealthCheckControllerTest",
    "[INFO] Running com.amazon.contextdesk.payment.PaymentControllerTest",
    "[INFO] [PaymentController] Initializing Stripe & Alexa+ payment gateway integration...",
    "[INFO] [PaymentController] Attempting database connection to jdbc:postgresql://localhost:5432/payments",
    "[WARN] [ConnectionPool] Connection pool warmup took 1420ms (> 1000ms threshold)",
    "[INFO] [PaymentController] Processing test transaction TX-99482 for customer CUST-0021",
    "[INFO] [PaymentController] Invoking dependency: OrderRepository for order validation",
    "[ERROR] [PaymentController] Uncaught runtime exception thrown during checkout request execution:",
    "java.lang.NullPointerException: Cannot invoke 'OrderRepository.findById()' at PaymentController.java:42",
    "\tat com.amazon.contextdesk.payment.PaymentController.processPayment(PaymentController.java:42)",
    "\tat com.amazon.contextdesk.payment.PaymentController.checkout(PaymentController.java:28)",
    "\tat java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)",
    "\tat java.base/java.lang.reflect.Method.invoke(Method.java:580)",
    "\tat org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:255)",
    "\tat org.springframework.web.method.support.InvocableHandlerMethod.invokeForRequest(InvocableHandlerMethod.java:188)",
    "\tat org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod.invokeAndHandle(ServletInvocableHandlerMethod.java:118)",
    "\tat org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.invokeHandlerMethod(RequestMappingHandlerAdapter.java:926)",
    "\tat org.junit.jupiter.engine.execution.ExecutableInvoker.invoke(ExecutableInvoker.java:117)",
    "[ERROR] Tests run: 1, Failures: 0, Errors: 1, Skipped: 0, Time elapsed: 0.884 s <<< FAILURE! -- in PaymentControllerTest",
    "[ERROR] com.amazon.contextdesk.payment.PaymentControllerTest.testCheckout -- Time elapsed: 0.880 s <<< ERROR!",
    "[ERROR] [BUILD-FAILURE] PaymentController failed to initialize OrderRepository dependency.",
    "java.lang.NullPointerException: Cannot invoke 'OrderRepository.findById()' at PaymentController.java:42"
]

ARCHITECTURE_MD = """# ContextDesk Microservice Architecture & Fleet Topography

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
"""

def setup():
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    os.makedirs(DOCS_DIR, exist_ok=True)

    # 1. Write ./workspace/build.log
    build_log_path = os.path.join(WORKSPACE_DIR, "build.log")
    with open(build_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(BUILD_LOG_LINES) + "\n")

    # 2. Write ./workspace/docs/architecture.md
    arch_path = os.path.join(DOCS_DIR, "architecture.md")
    with open(arch_path, "w", encoding="utf-8") as f:
        f.write(ARCHITECTURE_MD)

    print(f"[SUCCESS] Workspace setup completed successfully.")
    print(f"  - Created: {build_log_path} ({len(BUILD_LOG_LINES)} lines)")
    print(f"  - Created: {arch_path}")

if __name__ == "__main__":
    setup()
