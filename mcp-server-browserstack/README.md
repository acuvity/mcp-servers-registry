<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://acuvity.ai/wp-content/uploads/2025/09/1.-Acuvity-Logo-Black-scaled-e1758135197226.png" height="90" alt="Acuvity logo"/>
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://discord.gg/BkU7fBkrNk">
    <img src="https://img.shields.io/badge/Acuvity-Join-7289DA?logo=discord&logoColor=fff" alt="Join Acuvity community" />
  </a>
<a href="https://www.linkedin.com/company/acuvity/">
    <img src="https://img.shields.io/badge/LinkedIn-Follow-7289DA" alt="Follow us on LinkedIn" />
  </a>
<a href="https://bsky.app/profile/acuvity.bsky.social">
    <img src="https://img.shields.io/badge/Bluesky-Follow-7289DA"?logo=bluesky&logoColor=fff" alt="Follow us on Bluesky" />
  </a>
</p>


# What is mcp-server-browserstack?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browserstack/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browserstack/1.2.8?logo=docker&logoColor=fff&label=1.2.8)](https://hub.docker.com/r/acuvity/mcp-server-browserstack)
[![PyPI](https://img.shields.io/badge/1.2.8-3775A9?logo=pypi&logoColor=fff&label=@browserstack/mcp-server)](https://github.com/browserstack/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browserstack/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserstack&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERSTACK_USERNAME%22%2C%22-e%22%2C%22BROWSERSTACK_ACCESS_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserstack%3A1.2.8%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Access BrowserStack's Test Platform to debug, write and fix tests, do accessibility testing.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @browserstack/mcp-server original [sources](https://github.com/browserstack/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-browserstack/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/charts/mcp-server-browserstack/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @browserstack/mcp-server run reliably and safely.

## 🔐 Key Security Features

### 📦 Isolated Immutable Sandbox

| Feature                   | Description                                                                                                            |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| Isolated Execution        | All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.         |
| Non-root by Default       | Enforces least-privilege principles, minimizing the impact of potential security breaches.                              |
| Read-only Filesystem      | Ensures runtime immutability, preventing unauthorized modification.                                                     |
| Version Pinning           | Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.                  |
| CVE Scanning              | Continuously scans images for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation. |
| SBOM & Provenance         | Delivers full supply chain transparency by embedding metadata and traceable build information.                          |
| Container Signing (Cosign) | Implements image signing using [Cosign](https://github.com/sigstore/cosign) to ensure integrity and authenticity of container images.                             |


### 🛡️ Runtime Security and Guardrails

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

#### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

#### 🛡️ Guardrails

##### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

##### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

##### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

##### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

##### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

##### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

#### Enable guardrails

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need.

| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |

Example: add `-e GUARDRAILS="secrets-redaction sensitive-pattern-detection"` to enable those guardrails.

#### 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, define `BASIC_AUTH_SECRET` environment variable with a shared secret.

Example: add `-e BASIC_AUTH_SECRET="supersecret"` to enable the basic authentication.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

> [!NOTE]
> By default, all guardrails except `resource integrity` are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-browserstack scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `BROWSERSTACK_USERNAME` required to be set
  - `BROWSERSTACK_ACCESS_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/browserstack/mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserstack&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERSTACK_USERNAME%22%2C%22-e%22%2C%22BROWSERSTACK_ACCESS_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserstack%3A1.2.8%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-browserstack": {
        "env": {
          "BROWSERSTACK_ACCESS_KEY": "TO_BE_SET",
          "BROWSERSTACK_USERNAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "BROWSERSTACK_USERNAME",
          "-e",
          "BROWSERSTACK_ACCESS_KEY",
          "docker.io/acuvity/mcp-server-browserstack:1.2.8"
        ]
      }
    }
  }
}
```

## Workspace scope

In your workspace create a file called `.vscode/mcp.json` and add the following section:

```json
{
  "servers": {
    "acuvity-mcp-server-browserstack": {
      "env": {
        "BROWSERSTACK_ACCESS_KEY": "TO_BE_SET",
        "BROWSERSTACK_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERSTACK_USERNAME",
        "-e",
        "BROWSERSTACK_ACCESS_KEY",
        "docker.io/acuvity/mcp-server-browserstack:1.2.8"
      ]
    }
  }
}
```

> To pass secrets you should use the `promptString` input type described in the [Visual Studio Code documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers).

</details>

<details>
<summary>Windsurf IDE</summary>

In `~/.codeium/windsurf/mcp_config.json` add the following section:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserstack": {
      "env": {
        "BROWSERSTACK_ACCESS_KEY": "TO_BE_SET",
        "BROWSERSTACK_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERSTACK_USERNAME",
        "-e",
        "BROWSERSTACK_ACCESS_KEY",
        "docker.io/acuvity/mcp-server-browserstack:1.2.8"
      ]
    }
  }
}
```

See [Windsurf documentation](https://docs.windsurf.com/windsurf/mcp) for more info.

</details>

<details>
<summary>Cursor IDE</summary>

Add the following JSON block to your mcp configuration file:
- `~/.cursor/mcp.json` for global scope
- `.cursor/mcp.json` for project scope

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserstack": {
      "env": {
        "BROWSERSTACK_ACCESS_KEY": "TO_BE_SET",
        "BROWSERSTACK_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERSTACK_USERNAME",
        "-e",
        "BROWSERSTACK_ACCESS_KEY",
        "docker.io/acuvity/mcp-server-browserstack:1.2.8"
      ]
    }
  }
}
```

See [cursor documentation](https://docs.cursor.com/context/model-context-protocol) for more information.

</details>
<details>

<summary>Claude Desktop</summary>

In the `claude_desktop_config.json` configuration file add the following section:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserstack": {
      "env": {
        "BROWSERSTACK_ACCESS_KEY": "TO_BE_SET",
        "BROWSERSTACK_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERSTACK_USERNAME",
        "-e",
        "BROWSERSTACK_ACCESS_KEY",
        "docker.io/acuvity/mcp-server-browserstack:1.2.8"
      ]
    }
  }
}
```

See [Anthropic documentation](https://docs.anthropic.com/en/docs/agents-and-tools/mcp) for more information.
</details>

<details>
<summary>OpenAI python SDK</summary>

## Running locally

```python
async with MCPServerStdio(
    params={
        "env": {"BROWSERSTACK_ACCESS_KEY":"TO_BE_SET","BROWSERSTACK_USERNAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BROWSERSTACK_USERNAME","-e","BROWSERSTACK_ACCESS_KEY","docker.io/acuvity/mcp-server-browserstack:1.2.8"]
    }
) as server:
    tools = await server.list_tools()
```

## Running remotely

```python
async with MCPServerSse(
    params={
        "url": "http://<ip>:<port>/sse",
    }
) as server:
    tools = await server.list_tools()
```

See [OpenAI Agents SDK docs](https://openai.github.io/openai-agents-python/mcp/) for more info.

</details>

## 🐳 Run it with Docker

<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e BROWSERSTACK_USERNAME -e BROWSERSTACK_ACCESS_KEY docker.io/acuvity/mcp-server-browserstack:1.2.8`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e BROWSERSTACK_USERNAME -e BROWSERSTACK_ACCESS_KEY docker.io/acuvity/mcp-server-browserstack:1.2.8
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserstack": {
      "url": "http://localhost:8000/sse"
    }
  }
}
```

You might have to use different ports for different tools.

</details>

<details>
<summary>Remotely with Websocket tunneling and MTLS </summary>

> This section assume you are familiar with TLS and certificates and will require:
> - a server certificate with proper DNS/IP field matching your tool deployment.
> - a client-ca used to sign client certificates

1. Start the server in `backend` mode
 - add an environment variable like `-e MINIBRIDGE_MODE=backend`
 - add the TLS certificates (recommended) through a volume let's say `/certs` ex (`-v $PWD/certs:/certs`)
 - instruct minibridge to use those certs with
   - `-e MINIBRIDGE_TLS_SERVER_CERT=/certs/server-cert.pem`
   - `-e MINIBRIDGE_TLS_SERVER_KEY=/certs/server-key.pem`
   - `-e MINIBRIDGE_TLS_SERVER_KEY_PASS=optional`
   - `-e MINIBRIDGE_TLS_SERVER_CLIENT_CA=/certs/client-ca.pem`

2. Start `minibridge` locally in frontend mode:
  - Get [minibridge](https://github.com/acuvity/minibridge) binary for your OS.

In your client configuration, Minibridge works like any other STDIO command.

Example for Claude Desktop:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserstack": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Minibridge offers a host of additional features. For step-by-step guidance, please visit the wiki. And if anything’s unclear, don’t hesitate to reach out!

</details>

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `BROWSERSTACK_ACCESS_KEY` secret to be set as secrets.BROWSERSTACK_ACCESS_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `BROWSERSTACK_USERNAME` environment variable to be set by env.BROWSERSTACK_USERNAME

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
````

Install with helm

```console
helm install mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
```

From there your MCP server mcp-server-browserstack will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-browserstack` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/charts/mcp-server-browserstack/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (35)
<details>
<summary>accessibilityExpert</summary>

**Description**:

```
🚨 REQUIRED: Use this tool for any accessibility/a11y/WCAG questions. Do NOT answer accessibility questions directly - always use this tool.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Any accessibility, a11y, WCAG, or web accessibility question | Yes
</details>
<details>
<summary>startAccessibilityScan</summary>

**Description**:

```
Start an accessibility scan via BrowserStack and retrieve a local CSV report path.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| authConfigId | number | Optional auth config ID for authenticated scans | No
| name | string | Name of the accessibility scan | Yes
| pageURL | string | The URL to scan for accessibility issues | Yes
</details>
<details>
<summary>createAccessibilityAuthConfig</summary>

**Description**:

```
Create an authentication configuration for accessibility scans. Supports both form-based and basic authentication.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name for the auth configuration | Yes
| password | string | Password for authentication | Yes
| passwordSelector | string | CSS selector for password field (required for form auth) | No
| submitSelector | string | CSS selector for submit button (required for form auth) | No
| type | string | Authentication type: 'form' for form-based auth, 'basic' for HTTP basic auth | Yes
| url | string | URL of the authentication page | Yes
| username | string | Username for authentication | Yes
| usernameSelector | string | CSS selector for username field (required for form auth) | No
</details>
<details>
<summary>getAccessibilityAuthConfig</summary>

**Description**:

```
Retrieve an existing authentication configuration by ID.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| configId | number | ID of the auth configuration to retrieve | Yes
</details>
<details>
<summary>fetchAccessibilityIssues</summary>

**Description**:

```
Fetch accessibility issues from a completed scan with pagination support. Use cursor parameter to get subsequent pages of results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | number | Character offset for pagination (default: 0) | No
| scanId | string | The scan ID from a completed accessibility scan | Yes
| scanRunId | string | The scan run ID from a completed accessibility scan | Yes
</details>
<details>
<summary>setupBrowserStackAutomateTests</summary>

**Description**:

```
Set up and run automated web-based tests on BrowserStack using the BrowserStack SDK. Use this tool for functional or integration test setup on BrowserStack only. For any visual testing or Percy integration, use the dedicated Percy setup tool. Example prompts: run this test on browserstack; set up this project for browserstack.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| detectedBrowserAutomationFramework | string | not set | Yes
| detectedLanguage | string | not set | Yes
| detectedTestingFramework | string | not set | Yes
| devices | array | Device objects array. Use the object format directly - no transformation needed. Add only when user explicitly requests devices. Examples: [{ platform: 'windows', osVersion: '11', browser: 'chrome', browserVersion: 'latest' }] or [{ platform: 'android', deviceName: 'Samsung Galaxy S24', osVersion: '14', browser: 'chrome' }]. | No
| projectName | string | A single name for your project to organize all your tests. | Yes
</details>
<details>
<summary>percyVisualTestIntegrationAgent</summary>

**Description**:

```
Integrate Percy visual testing into new projects and demonstrate visual change detection through a step-by-step simulation. This tool handles initial Percy integration, setup, and creates a working demonstration for new users. Primary tool for prompts like: "Integrate percy for this project", "Integrate percy in this project {project_name}"
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| detectedBrowserAutomationFramework | string | not set | Yes
| detectedLanguage | string | not set | Yes
| detectedTestingFramework | string | not set | Yes
| filePaths | array | An array of absolute file paths to specific UI test files. Use this when you want to target specific test files rather than entire folders. If not provided, will use folderPaths instead. | No
| folderPaths | array | An array of absolute folder paths containing UI test files. If not provided, analyze codebase for UI test folders by scanning for test patterns which contain UI test cases as per framework. Return empty array if none found. | No
| integrationType | string | Specify the Percy integration type: web (Percy Web) or automate (Percy Automate). If not provided, always prompt the user with: 'Please specify the Percy integration type.' Do not proceed without an explicit selection. Never use a default. | Yes
| projectName | string | A unique name for your Percy project. | Yes
</details>
<details>
<summary>expandPercyVisualTesting</summary>

**Description**:

```
Set up or expand Percy visual testing configuration with comprehensive coverage for existing projects that might have Percy integrated. This supports both Percy Web Standalone and Percy Automate. Example prompts: Expand percy coverage for this project {project_name}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| detectedBrowserAutomationFramework | string | not set | Yes
| detectedLanguage | string | not set | Yes
| detectedTestingFramework | string | not set | Yes
| filePaths | array | An array of absolute file paths to specific UI test files. Use this when you want to target specific test files rather than entire folders. If not provided, will use folderPaths instead. | No
| folderPaths | array | An array of absolute folder paths containing UI test files. If not provided, analyze codebase for UI test folders by scanning for test patterns which contain UI test cases as per framework. Return empty array if none found. | No
| integrationType | string | Specify the Percy integration type: web (Percy Web) or automate (Percy Automate). If not provided, always prompt the user with: 'Please specify the Percy integration type.' Do not proceed without an explicit selection. Never use a default. | Yes
| projectName | string | A unique name for your Percy project. | Yes
</details>
<details>
<summary>addPercySnapshotCommands</summary>

**Description**:

```
Adds Percy snapshot commands to the specified test files.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Index of the test file to update | Yes
</details>
<details>
<summary>listTestFiles</summary>

**Description**:

```
Lists all test files for a given set of directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>runPercyScan</summary>

**Description**:

```
Run a Percy visual test scan. Example prompts : Run this Percy build/scan. Never run percy scan/build without this tool
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| integrationType | string | Specifies whether to integrate with Percy Web or Percy Automate. If not explicitly provided, prompt the user to select the desired integration type. | Yes
| percyRunCommand | string | The test command to run with Percy. Optional — the LLM should try to infer it first from project context. | No
| projectName | string | The name of the project to run Percy on. | Yes
</details>
<details>
<summary>fetchPercyChanges</summary>

**Description**:

```
Retrieves and summarizes all visual changes detected by Percy AI between the latest and previous builds, helping quickly review what has changed in your project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_name | string | The name of the BrowserStack project. If not found, ask user directly. | Yes
</details>
<details>
<summary>managePercyBuildApproval</summary>

**Description**:

```
Approve or reject a Percy build
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | The action to perform on the Percy build. | Yes
| buildId | string | The ID of the Percy build to approve or reject. | Yes
</details>
<details>
<summary>runAppLiveSession</summary>

**Description**:

```
Use this tool when user wants to manually check their app on a particular mobile device using BrowserStack's cloud infrastructure. Can be used to debug crashes, slow performance, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appPath | string | The path to the .ipa or .apk file to install on the device. Always ask the user for the app path, do not assume it. | Yes
| desiredPhone | string | The full name of the device to run the app on. Example: 'iPhone 12 Pro' or 'Samsung Galaxy S20' or 'Google Pixel 6'. Always ask the user for the device they want to use, do not assume it.  | Yes
| desiredPlatform | string | Which platform to run on, examples: 'android', 'ios'. Set this based on the app path provided. | Yes
| desiredPlatformVersion | string | Specifies the platform version to run the app on. For example, use '12.0' for Android or '16.0' for iOS. If the user says 'latest', 'newest', or similar, normalize it to 'latest'. Likewise, convert terms like 'earliest' or 'oldest' to 'oldest'. | Yes
</details>
<details>
<summary>runBrowserLiveSession</summary>

**Description**:

```
Launch a BrowserStack Live session (desktop or mobile).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| desiredBrowser | string | Browser for desktop (Chrome, IE, Firefox, Safari, Edge) | Yes
| desiredBrowserVersion | string | Browser version for desktop (e.g. '133.2', 'latest'). If the user says 'latest', 'newest', or similar, normalize it to 'latest'. Likewise, convert terms like 'earliest' or 'oldest' to 'oldest'. | No
| desiredDevice | string | Device name for mobile | No
| desiredOS | string | Desktop OS ('Windows' or 'OS X') or mobile OS ('android','ios','winphone') | Yes
| desiredOSVersion | string | The OS version must be specified as a version number (e.g., '10', '14.0') or as a keyword such as 'latest' or 'oldest'. Normalize variations like 'newest' or 'most recent' to 'latest', and terms like 'earliest' or 'first' to 'oldest'. For macOS, version names (e.g., 'Sequoia') must be used instead of numeric versions. | Yes
| desiredURL | string | The URL to test | Yes
| platformType | string | Must be 'desktop' or 'mobile' | Yes
</details>
<details>
<summary>createProjectOrFolder</summary>

**Description**:

```
Create a project and/or folder in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folder_description | string | Description for the new folder. | No
| folder_name | string | Name of the folder to create. | No
| parent_id | number | Parent folder ID; if omitted, folder is created at root. | No
| project_description | string | Description for the new project. | No
| project_identifier | string | Existing project identifier to use for folder creation. | No
| project_name | string | Name of the project to create. | No
</details>
<details>
<summary>createTestCase</summary>

**Description**:

```
Use this tool to create a test case in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| automation_status | string | Automation status of the test case. Common values include 'not_automated', 'automated', 'automation_not_required'. | No
| custom_fields | object | Map of custom field names to values. | No
| description | string | Brief description of the test case. | No
| folder_id | string | The ID of the folder within the project where the test case should be created. If not provided, ask the user if they would like to create a new folder using the createProjectOrFolder tool. | Yes
| issue_tracker | object | not set | No
| issues | array | List of the linked Jira, Asana or Azure issues ID's. This should be strictly in array format not the string of json. | No
| name | string | Name of the test case. | Yes
| owner | string | Email of the test case owner. | No
| preconditions | string | Any preconditions (HTML allowed). | No
| project_identifier | string | The ID of the BrowserStack project where the test case should be created. If no project identifier is provided, ask the user if they would like to create a new project using the createProjectOrFolder tool. | Yes
| tags | array | Tags to attach to the test case. This should be strictly in array format not the string of json | No
| test_case_steps | array | List of steps and expected results. | Yes
</details>
<details>
<summary>listTestCases</summary>

**Description**:

```
List test cases in a project with optional filters (status, priority, custom fields, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| case_type | string | Comma-separated list of case types (e.g. functional,regression). | No
| folder_id | string | If provided, only return cases in this folder. | No
| p | number | Page number. | No
| priority | string | Comma-separated list of priorities (e.g. critical,medium,low). | No
| project_identifier | string | Identifier of the project to fetch test cases from. This id starts with a PR- and is followed by a number. | Yes
</details>
<details>
<summary>createTestRun</summary>

**Description**:

```
Create a test run in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project in which to create the test run. | Yes
| test_run | object | not set | Yes
</details>
<details>
<summary>listTestRuns</summary>

**Description**:

```
List test runs in a project with optional filters (date ranges, assignee, state, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project to fetch test runs from (usually starts with PR-). | Yes
| run_state | string | Return all test runs with this state (comma-separated) | No
</details>
<details>
<summary>updateTestRun</summary>

**Description**:

```
Update a test run in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project (Starts with 'PR-') | Yes
| test_run | object | not set | Yes
| test_run_id | string | Test run identifier (e.g., TR-678) | Yes
</details>
<details>
<summary>addTestResult</summary>

**Description**:

```
Add a test result to a specific test run via BrowserStack Test Management API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project (Starts with 'PR-') | Yes
| test_case_id | string | Identifier of the test case, e.g., 'TC-13'. | Yes
| test_result | object | not set | Yes
| test_run_id | string | Identifier of the test run (e.g., TR-678) | Yes
</details>
<details>
<summary>uploadProductRequirementFile</summary>

**Description**:

```
Upload files (e.g., PDRs, PDFs) to BrowserStack Test Management and retrieve a file mapping ID. This is utilized for generating test cases from files and is part of the Test Case Generator AI Agent in BrowserStack.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | Full path to the file that should be uploaded | Yes
| project_identifier | string | ID of the project where the file should be uploaded. Do not assume it, always ask user for it. | Yes
</details>
<details>
<summary>createTestCasesFromFile</summary>

**Description**:

```
Generate test cases from a file in BrowserStack Test Management using the Test Case Generator AI Agent.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| documentId | string | Internal document identifier | Yes
| folderId | string | BrowserStack folder ID | Yes
| projectReferenceId | string | The BrowserStack project reference ID is a unique identifier found in the project URL within the BrowserStack Test Management Platform. This ID is also returned by the Upload Document tool. | Yes
</details>
<details>
<summary>createLCASteps</summary>

**Description**:

```
Generate Low Code Automation (LCA) steps for a test case in BrowserStack Test Management using the Low Code Automation Agent.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base_url | string | Base URL for the test (e.g., 'google.com') | Yes
| credentials | object | Optional credentials for authentication. Extract from the test case details if provided in it. This is required for the test cases which require authentication. | No
| local_enabled | boolean | Whether local testing is enabled | No
| project_identifier | string | ID of the project (Starts with 'PR-') | Yes
| test_case_details | object | Test case details including steps | Yes
| test_case_identifier | string | Identifier of the test case (e.g., 'TC-12345') | Yes
| test_name | string | Name of the test | Yes
| wait_for_completion | boolean | Whether to wait for LCA build completion (default: true) | No
</details>
<details>
<summary>takeAppScreenshot</summary>

**Description**:

```
Use this tool to take a screenshot of an app running on a BrowserStack device. This is useful for visual testing and debugging.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appPath | string | The path to the .apk or .ipa file. Required for app installation. | Yes
| desiredPhone | string | The full name of the device to run the app on. Example: 'iPhone 12 Pro' or 'Samsung Galaxy S20'. Always ask the user for the device they want to use. | Yes
| desiredPlatform | string | Platform to run the app on. Either 'android' or 'ios'. | Yes
| desiredPlatformVersion | string | The platform version to run the app on. Use 'latest' or 'oldest' for dynamic resolution. | Yes
</details>
<details>
<summary>runAppTestsOnBrowserStack</summary>

**Description**:

```
Execute pre-built native mobile test suites (Espresso for Android, XCUITest for iOS) by direct upload to BrowserStack. ONLY for compiled .apk/.ipa test files. This is NOT for SDK integration or Appium tests. For Appium-based testing with SDK setup, use 'setupBrowserStackAppAutomateTests' instead.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appPath | string | Path to your application file:
If in development IDE directory:
• For Android: 'gradle assembleDebug'
• For iOS:
  xcodebuild clean -scheme YOUR_SCHEME && \
  xcodebuild archive -scheme YOUR_SCHEME -configuration Release -archivePath build/app.xcarchive && \
  xcodebuild -exportArchive -archivePath build/app.xcarchive -exportPath build/ipa -exportOptionsPlist exportOptions.plist

If in other directory, provide existing app path | Yes
| detectedAutomationFramework | string | The automation framework used in the project, such as 'espresso' (Android) or 'xcuitest' (iOS). | Yes
| devices | array | Tuples describing target mobile devices. Add device only when user asks explicitly for it. Defaults to [] . Example: [['android', 'Samsung Galaxy S24', '14'], ['ios', 'iPhone 15', '17']] | No
| project | string | Project name for organizing test runs on BrowserStack. | No
| testSuitePath | string | Path to your test suite file:
If in development IDE directory:
• For Android: 'gradle assembleAndroidTest'
• For iOS:
  xcodebuild test-without-building -scheme YOUR_SCHEME -destination 'generic/platform=iOS' && \
  cd ~/Library/Developer/Xcode/DerivedData/*/Build/Products/Debug-iphonesimulator/ && \
  zip -r Tests.zip *.xctestrun *-Runner.app

If in other directory, provide existing test file path | Yes
</details>
<details>
<summary>setupBrowserStackAppAutomateTests</summary>

**Description**:

```
Set up BrowserStack App Automate SDK integration for Appium-based mobile app testing. ONLY for Appium based framework . This tool configures SDK for various languages with appium. For pre-built Espresso or XCUITest test suites, use 'runAppTestsOnBrowserStack' instead.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appPath | string | Path to the mobile app file (.apk for Android, .ipa for iOS). Can be a local file path or a BrowserStack app URL (bs://) | Yes
| detectedFramework | string | The mobile automation framework configured in the project. Example: 'appium' | Yes
| detectedLanguage | string | The programming language used in the project. Supports Java and C#. Example: 'java', 'csharp' | Yes
| detectedTestingFramework | string | The testing framework used in the project. Be precise with framework selection Example: 'testng', 'behave', 'pytest', 'robot' | Yes
| devices | array | Tuples describing target mobile devices. Add device only when user asks explicitly for it. Defaults to [] . Example: [['android', 'Samsung Galaxy S24', '14'], ['ios', 'iPhone 15', '17']] | No
| project | string | Project name for organizing test runs on BrowserStack. | No
</details>
<details>
<summary>getFailureLogs</summary>

**Description**:

```
Fetch various types of logs from a BrowserStack session. Supports both automate and app-automate sessions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| buildId | string | Required only when sessionType is 'app-automate'. If sessionType is 'app-automate', always ask the user to provide the build ID before proceeding. | No
| logTypes | array | The types of logs to fetch. | Yes
| sessionId | string | The BrowserStack session ID. Must be explicitly provided by the user. | Yes
| sessionType | string | Type of BrowserStack session. Must be explicitly provided by the user. | Yes
</details>
<details>
<summary>fetchAutomationScreenshots</summary>

**Description**:

```
Fetch and process screenshots from a BrowserStack Automate session
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | The BrowserStack session ID to fetch screenshots from | Yes
| sessionType | string | Type of BrowserStack session | Yes
</details>
<details>
<summary>fetchSelfHealedSelectors</summary>

**Description**:

```
Retrieves AI-generated, self-healed selectors for a BrowserStack Automate session to resolve flaky tests caused by dynamic DOM changes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | The session ID of the test run | Yes
</details>
<details>
<summary>fetchBuildInsights</summary>

**Description**:

```
Fetches insights about a BrowserStack build by combining build details and quality gate results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| buildId | string | The build UUID of the BrowserStack build | Yes
</details>
<details>
<summary>fetchRCA</summary>

**Description**:

```
Retrieves AI-RCA (Root Cause Analysis) data for a BrowserStack Automate and App-Automate session and provides insights into test failures.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| testId | array | Array of integer test IDs to fetch RCA data for (maximum 3 IDs). These must be numeric test IDs, not session IDs or strings. If not provided, use the listTestIds tool to get all failed testcases. If more than 3 IDs are provided, only the first 3 will be processed. | Yes
</details>
<details>
<summary>getBuildId</summary>

**Description**:

```
Get the BrowserStack build ID for a given project and build name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| browserStackBuildName | string | The BrowserStack build name used during test run creation. Action: First, check browserstack.yml or any equivalent project configuration files. If the build name is found, extract and return it. If it is not found or if there is any uncertainty, immediately prompt the user to provide the value. Do not infer, guess, or assume a default. | Yes
| browserStackProjectName | string | The BrowserStack project name used during test run creation. Action: First, check browserstack.yml or any equivalent project configuration files. If the project name is found, extract and return it. If it is not found or if there is any uncertainty, immediately prompt the user to provide the value. Do not infer, guess, or assume a default. | Yes
</details>
<details>
<summary>listTestIds</summary>

**Description**:

```
List test IDs from a BrowserStack Automate build, optionally filtered by status
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| buildId | string | The Browserstack Build ID of the test run. If not known, use the getBuildId tool to fetch it using project and build name | Yes
| status | string | Filter tests by status. If not provided, all tests are returned. Example for RCA usecase always use failed status | Yes
</details>

## 📝 Prompts (1)
<details>
<summary>integrate-percy</summary>

**Description**:

```
<no value>
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| project_name | The name of the project to integrate with Percy |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | integrate-percy | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | integrate-percy | project_name | c3a563882c0fe67f9d15a4e90a6d01fb269ffd4e283666335017262e60c5034a |
| tools | accessibilityExpert | description | 86d84ea32f3f372eb2f6131bedae2c5e1cb5d55832e88400f39e9d66d0bbb299 |
| tools | accessibilityExpert | query | b9fd2dc351de3be69acd1403f6af9f3257374a1d63829ddaa6d5b58ea2348787 |
| tools | addPercySnapshotCommands | description | acea96f4e7be2c28a7d61bef83e7d1331d5a1294f343d9963963e726a283024e |
| tools | addPercySnapshotCommands | index | 4d0f3f55b80ce5e9bd99e3aee5633d60502e174047a3f9f35421f3893421d513 |
| tools | addTestResult | description | cc2109318c2f2f439c042097bd218c02441beaba6763a50f777b45ff1f9ee532 |
| tools | addTestResult | project_identifier | 6c62157d98f3a3579f77d8d19b65b8566108202987b5120eb459dc7319bbc86b |
| tools | addTestResult | test_case_id | a0bf11cfea84003e21cf57d8e5a471b50f6cfe1bf5fd67277ad3371d3d0479fc |
| tools | addTestResult | test_run_id | dd6796e0611b2656380232abc144a619b1b74bf20bf3b22fb68f235335dfdbf0 |
| tools | createAccessibilityAuthConfig | description | 8874700cb4f9e4159cf118144349f890789679a8c3204078ab6da9f8525315d0 |
| tools | createAccessibilityAuthConfig | name | b0a87e027d7e9a6b4ec1f7121df3c14a080a4a56ce251bb1f3c049e64ba3d2e9 |
| tools | createAccessibilityAuthConfig | password | f0922cd4793efcc12ac430ca424c83b8a63d7aa59a95e165d79bd50db4601286 |
| tools | createAccessibilityAuthConfig | passwordSelector | 8caa31029e66d24882f7f0dd21241fb0947a1d81e56adbfe7f241de1c3d42cb1 |
| tools | createAccessibilityAuthConfig | submitSelector | f69bba65a84d91839ef01eaaeea1dad2d35edd0f71fc933181d54d0dd4ef5bf4 |
| tools | createAccessibilityAuthConfig | type | dfdf75f9c17337de171291b2ebabf6b70751c1c1a2418556fe0417e8e94e4071 |
| tools | createAccessibilityAuthConfig | url | d69eee5cae201b38bd3ae7db74eac69736108851931674a0a312b3a49a0f9974 |
| tools | createAccessibilityAuthConfig | username | b2a34606c2ee6df5cbfa630e5b78f1d8dc69182722d7d5afb99c41b6eb926dbe |
| tools | createAccessibilityAuthConfig | usernameSelector | 75d9a6d8c48f4beab10fa46867d8362c72e090df6b3d62b709180aad70908586 |
| tools | createLCASteps | description | 3ab042e167faacf57685147c666092ef03afc65cce6455acbe3dbecea9e8df66 |
| tools | createLCASteps | base_url | 4c5c642f1b70dc39ffe77d1ff4f903802e7ad4ae5c745223e7d8adf159bb685e |
| tools | createLCASteps | credentials | 87b52bc90c9e6098cfa860d99603f9accf589b41839c1ce331cec252c4df0da1 |
| tools | createLCASteps | local_enabled | 72ae8ded36dc31c6da9f1be9871fe67a4ce4767445f45185a2fb4861840978c4 |
| tools | createLCASteps | project_identifier | 26c8444cca04215f8340f893afc14c7c808bff9b881341c42e724b506a104db7 |
| tools | createLCASteps | test_case_details | eb4b90368e172f31e2dd69a93a80235568e0f0f6e5eafce7d40c15133e20b5e5 |
| tools | createLCASteps | test_case_identifier | 40532c4b1b9e68fb66279c2c5e06193bcd3f18ca45fcdadcd4897cec61510f32 |
| tools | createLCASteps | test_name | 35a63342426914953ce6b18c0b896a975ae546642bb25ee9bd5818bf938111ef |
| tools | createLCASteps | wait_for_completion | 4513ed516d341581480e189e81c47994b7ec23f4de6669537dcd7932c4d3af58 |
| tools | createProjectOrFolder | description | b3e3165694a6aabfb78167fe03a224a0088fbe3dfdfc2bab6478618d2dc4cde1 |
| tools | createProjectOrFolder | folder_description | efbe2753d3d1783e698cc3c5b1c770b5b721645b91d5200aa05af31bdd87942a |
| tools | createProjectOrFolder | folder_name | 1fce48673414a3b22395d547a7e50ac225a819b36c63c91d117be6f3a2208d5b |
| tools | createProjectOrFolder | parent_id | de57230349700c0b401e5aa7981ae08b72e9de2435c39b21618c5018f3b07f0e |
| tools | createProjectOrFolder | project_description | 507f3ff1b6a036de2a0b311b1ea9d392b050f14639d9d6e4d7ac7fc4b02b593e |
| tools | createProjectOrFolder | project_identifier | bf678e9cd7bbe3bfd864e0ea804a12d70d509e66be1a51d2ce56d21936db79c8 |
| tools | createProjectOrFolder | project_name | c071c9fbe7923c941268d56c79fb0ac12e37edf18c7b68099b9c3490dbb291ef |
| tools | createTestCase | description | f79753f1cbee77f8ec15ef0b0772234e89d65c986bd6b82be0d5333d6ec5388e |
| tools | createTestCase | automation_status | ce2541a99bece8f5636f5d955d837557c429876641811d937b0db7ee04ff7751 |
| tools | createTestCase | custom_fields | 427a06f888b38e7210021bc459b99e7d5604fd42aa1b7ed81a99c4b7750510fb |
| tools | createTestCase | description | abf1b1eee12721a67b652f322487678db003d4bdf031cb0bad27b9deb94725b0 |
| tools | createTestCase | folder_id | a4ba636aa7f77cf6f2c0be168e1902bd0e2ba5645d4292f5ce3e96acca72cb2d |
| tools | createTestCase | issues | f618b3a688e1acfcfc72f7039e6293a82d3827f2bccd0007ebe28fc87d0bee62 |
| tools | createTestCase | name | 1ac73c91df75b429d366d02ba589f8912ab3a4fd6bdf1713a20d305e1017a7a7 |
| tools | createTestCase | owner | c60877252d5b1105e70647d2787af274ba801f51a0878b547b5fc9e2e53d0042 |
| tools | createTestCase | preconditions | 5e7d050fee674a09daeb0382bd426da764d6abbfbf8397a4d7332f4ead5a5d7f |
| tools | createTestCase | project_identifier | 60f040a16f19c3ebe8151ded87b86b7b6df17cd58f7eae9cf86d0e99ae86a451 |
| tools | createTestCase | tags | 5129ca1d1104d94f1052e948d9de68d4f647ba0162d4002d8564a6d3a71f5351 |
| tools | createTestCase | test_case_steps | 4a3f566047517e2e251aeb01cf987444bde104c20afa9d7f4ece89cd844717d1 |
| tools | createTestCasesFromFile | description | 0df41168f9e6612d4cafff96da9deb7b5aba5359fe9af65f93f5e340bad4fe33 |
| tools | createTestCasesFromFile | documentId | 6bc6f69713ac4766430d61e7c818a20347c9c754e1c45eef8344768cf9221fa2 |
| tools | createTestCasesFromFile | folderId | 16c1037533e9511a8e361f5f362aa06d5313f5456d295d90363fed5522422ac1 |
| tools | createTestCasesFromFile | projectReferenceId | 6feb12c1b9b037157845cb6137b840d5da4eeb31ef3521aa5a66cb205a97a86f |
| tools | createTestRun | description | 1b5b97bcc39017fa094f26eb56806082d82f687b7a1efa49aad565ba42df580f |
| tools | createTestRun | project_identifier | 958319b90d7375b48dde33224fa823fd5b91d21ba1e2a8adc2437fcc15650186 |
| tools | expandPercyVisualTesting | description | a1b248168b4856dd16bb540f85eddb8c1bd8fa0b2397b0aeffa7a60fe598fa02 |
| tools | expandPercyVisualTesting | filePaths | 241a623255f5e687b2eaaaeaae71301de3bc26d50f364b5a6738d87e41040f3e |
| tools | expandPercyVisualTesting | folderPaths | af4a360a53b9b2b49568200bdc77052f6d4549ad90e903c38caf44004abc79b8 |
| tools | expandPercyVisualTesting | integrationType | 18e46bbd00a50bd9d8d16c93653dec46948b74aa4222f5c881fdeb2e9eb2a386 |
| tools | expandPercyVisualTesting | projectName | 2eeac88ede3e647aefd0719de8b39c41ef3cfbb8d587ca9b5a1e691d36b3237b |
| tools | fetchAccessibilityIssues | description | e176e7e1b9e2aae79f396e82e292a7267169d67c1a0a7967e36a7c47c28d9613 |
| tools | fetchAccessibilityIssues | cursor | 86732ae3449318375d99c4aec25f74c31ce8396268ab3a723ef0837571378887 |
| tools | fetchAccessibilityIssues | scanId | 51ffc24ea01453921b93f1b34a3d00f062547eecb9e253ad317cf34a8fcd09ac |
| tools | fetchAccessibilityIssues | scanRunId | 104f0f61a57edfba95e696de03b82ac2e2de89c8646e4587c16c6f5444ddc3ff |
| tools | fetchAutomationScreenshots | description | 077697d1de82318656d57ab7020073e07d0483261ef18c23d0eb8dd90b93c43e |
| tools | fetchAutomationScreenshots | sessionId | 4a1a35e557a51bbcc1ee1da90be86fe09b2049104723f90c8c5ccc33940da414 |
| tools | fetchAutomationScreenshots | sessionType | 7db47afe5cb3150197365c91b30448e31eaa6b95a2ba9ae4a28fcdc553b44a10 |
| tools | fetchBuildInsights | description | 5ca3a18d52b77782c4c1f54f74635e80faedac43e277740e4831429525dcae5c |
| tools | fetchBuildInsights | buildId | 706a2d20ebb2b878acbceb5904364d6e0041cdfb12b5025181a5309bdf3f9b59 |
| tools | fetchPercyChanges | description | 295aaebfd2021db931aa635bf2f250d62333cc3400632dba8f6dae645d16e43c |
| tools | fetchPercyChanges | project_name | b9f33c33fec26e06c29afc9f32b6d60e0dbd5629eff5ede15d932512b73a9bd6 |
| tools | fetchRCA | description | ce1ec56ff718356febf26475a6cb421d6128fc3182a3b38b4928f9ce16eee4e2 |
| tools | fetchRCA | testId | d07d148bdca50d569926ca49a67f1a7f69e12e3a51f193aba8a8d47db0260103 |
| tools | fetchSelfHealedSelectors | description | 90260e3fb5a7f53c23ffd7718635ccc4d2b12f173fb2855c730087ab40a4a768 |
| tools | fetchSelfHealedSelectors | sessionId | faf61902787c70137dfbc121511ed7d9b7e27502bfdf5d1125f6efd5d3031a58 |
| tools | getAccessibilityAuthConfig | description | 385dcb32d42b0c0c08b494e3e6b13847c2037cd2f80ee68112a5423d1eb3872d |
| tools | getAccessibilityAuthConfig | configId | 844291ec23cf934ecee3e5686d2b89bd91650556686786f56d4a5ef7840dffd6 |
| tools | getBuildId | description | 7b7c8a539e0c45efa455702d1d3a3c41b67596537227da58a80126caeb32fba8 |
| tools | getBuildId | browserStackBuildName | 12a6b595abbdccb873326ebba46860c3b394b1051ac2d1d4bcae9760b696efa8 |
| tools | getBuildId | browserStackProjectName | d5c9c5adf292f49dc30a5e4678643456aefbf15656530f59431aab7acb1a5acf |
| tools | getFailureLogs | description | 8c144b60db6fac766d3330c216f56f6c893adfd32841a14f2412b25367d0758c |
| tools | getFailureLogs | buildId | ebc09c81c8f54829422701526f8ada1e09682f4026bc3ea12d7641541e8f7035 |
| tools | getFailureLogs | logTypes | 0051404276165eb04388eee6d8b28f4e97dc5e08af7b0ce1481388311c2a13c1 |
| tools | getFailureLogs | sessionId | 9c2bf31f67fa9193f1b87daa076709c6568a01fca182d2b3e92f6c04f9535655 |
| tools | getFailureLogs | sessionType | 76cbd444d004d58836eee26668d37d1e460ea90afb29b691bdb92e1017820b9a |
| tools | listTestCases | description | 3d88760fe6762812c4279aa496a673bf02cb3ff4664b555362e5d0890ba5520a |
| tools | listTestCases | case_type | aa032f5d744848a7b7347bd0c53259f585994a7f1c7988702a37bbb95aad16bb |
| tools | listTestCases | folder_id | f53650e6ad50a57020553beb3db2c0d5671c8bddfcee542c5ba684eab7ee8f93 |
| tools | listTestCases | p | a745ce57e9292ff9dbb392ddadbf3bf815e25da6d2402079cc6cde192ff1df19 |
| tools | listTestCases | priority | 8ac604f4c95f6ad728d7bf47873d8ce4c68d939b05d487e352d991231fdb5d2a |
| tools | listTestCases | project_identifier | 3ecb09b3a6128c8d676b805165762527ed12a633d5175b6c2fba8a2be293d3b5 |
| tools | listTestFiles | description | fdd10518cde068aa66f46a90fa9bc43d095b70804f6edc83eac2d45153ed02ae |
| tools | listTestIds | description | 1ff9ad34ce65a55d9baa5ebafe13049556757b6e516f9b51c5510165a7ec59d5 |
| tools | listTestIds | buildId | 0208789f7b69c217a073d6f7677f2868b48ee152562fe62c73a34423482b2c97 |
| tools | listTestIds | status | 91b1d05851d2bd328b554a3ae64d176662cee009216199fc49ece8a8fe4ee9a9 |
| tools | listTestRuns | description | 9deada7b36628686538fab266b3955e84eb3f95c2cadb7b84641510d2f985c40 |
| tools | listTestRuns | project_identifier | 6dd0a1641a0f0a8d1e3470f5fe14389a314d648ef4ac828c82eacf1f311819a8 |
| tools | listTestRuns | run_state | 2b4c984fc93afed3efceb0b41af2429aa7cd9d4e2baba18bdd57310f870eeb98 |
| tools | managePercyBuildApproval | description | 20bac6e8c9684e9d738b2b5c11514e270b8bdcb5ea5db5e706951228f6ecafff |
| tools | managePercyBuildApproval | action | e323f7b614f7162eec6f51915970fd43e1db741ff6bc55a415b587c445c173a7 |
| tools | managePercyBuildApproval | buildId | aa3be2f7b1261209d7f74cf961c5634c123cb64412f1b4d2f237b6c395bf13d2 |
| tools | percyVisualTestIntegrationAgent | description | 2ad1accb9c2d44008e681d5ece0eddf40b1c9424e7c38c23dd1a106b8f9245aa |
| tools | percyVisualTestIntegrationAgent | filePaths | 241a623255f5e687b2eaaaeaae71301de3bc26d50f364b5a6738d87e41040f3e |
| tools | percyVisualTestIntegrationAgent | folderPaths | af4a360a53b9b2b49568200bdc77052f6d4549ad90e903c38caf44004abc79b8 |
| tools | percyVisualTestIntegrationAgent | integrationType | 18e46bbd00a50bd9d8d16c93653dec46948b74aa4222f5c881fdeb2e9eb2a386 |
| tools | percyVisualTestIntegrationAgent | projectName | 2eeac88ede3e647aefd0719de8b39c41ef3cfbb8d587ca9b5a1e691d36b3237b |
| tools | runAppLiveSession | description | ae3d94db08fe1cd4697ec588ee8e5961460bb62a91f7be76313a33f526996895 |
| tools | runAppLiveSession | appPath | 4fbc294738a75df01476e73e83ac97ae2e66f3d4470e5d04196cded374e674c7 |
| tools | runAppLiveSession | desiredPhone | c7be751f195a60a46fc6831fdb6c2291d1f418385121310479140ee45d287b25 |
| tools | runAppLiveSession | desiredPlatform | bf34e3e4a3d9557a0c4c8365c4d84c3dae56a69d2633e09a4c73bf2ceefaab69 |
| tools | runAppLiveSession | desiredPlatformVersion | a6ec6d3f7fb930f84566a347db05834ccfb042d0275afbffe67740880f448a1a |
| tools | runAppTestsOnBrowserStack | description | 5865129af27a369b5664e1c137ae120834b9d8e4acc26caed5de149f760e67bd |
| tools | runAppTestsOnBrowserStack | appPath | 560924a3c4cacb2871596afe5c95ac0ae8275f137cdb32633098a39e8f91309b |
| tools | runAppTestsOnBrowserStack | detectedAutomationFramework | 992849219f8b596e2d7b8ca0432342b88cb8dfbdd4a0b2c9fc0b6b445e9720cf |
| tools | runAppTestsOnBrowserStack | devices | e9c59ac7ef73833d2b312be2acf00ca8c579b79cf03c77adfa59e9028fda42ab |
| tools | runAppTestsOnBrowserStack | project | cee150eaebe1a252ca303f6139ad065d1985de8bef0245db8ca7991ffedc0543 |
| tools | runAppTestsOnBrowserStack | testSuitePath | 4c768cdcc8ffe20f7f937b5c99dd6f64a0bf7bf061ebbc8ff36765c544b468d1 |
| tools | runBrowserLiveSession | description | 15d7be2d1e8aadf64d968aa1badd1000879f571e236d3dddb6ed1e5f2bc5e33b |
| tools | runBrowserLiveSession | desiredBrowser | d089ac36240f5ff99b74e8f423a09a4a1d8cba042aaa1863bb1757eef775d26e |
| tools | runBrowserLiveSession | desiredBrowserVersion | 45106d6349643b6fde55bb0a47da6621906c0483e7e999079744b60fb2fbbc93 |
| tools | runBrowserLiveSession | desiredDevice | f5a0aff6efde9298b7d97134f88decc76ced12643074ef2799346e49e14832b7 |
| tools | runBrowserLiveSession | desiredOS | 03c7fb4ad446d553a5938aded0ebcceded249d2b3513c2628928f30642113de9 |
| tools | runBrowserLiveSession | desiredOSVersion | 2cb723b7a5534fa4dbf8768d0875779d688735b25779d95bd674d174cd328ec1 |
| tools | runBrowserLiveSession | desiredURL | b85465cef9c8da1546ccd5e2e962887a60ade65e35e5be82ca6d4c6ae63884f3 |
| tools | runBrowserLiveSession | platformType | 77536906f9cb2b3e6ab78109451efddb605ac051931011ad0db2004bf5320539 |
| tools | runPercyScan | description | f5da7aed8f322a33ceb7f4309604f6cfaac03e6feb40483db180d4cfa56287a0 |
| tools | runPercyScan | integrationType | 5a166815338471d6234c9c80f53562e180adf7cd882c738b08f7f8f2d9b2933b |
| tools | runPercyScan | percyRunCommand | bd785655bb82624fd7498c4b0cb4d93b0c72e995584cd75d02775d4b034c94a3 |
| tools | runPercyScan | projectName | cde30e9d9bc784015735fd5589d9d252084cf6496afbf21139630282c2836e25 |
| tools | setupBrowserStackAppAutomateTests | description | ba9924788f7fc2de0ec3e4132f7c668d4a273d9f5fb860369f6224ba193617af |
| tools | setupBrowserStackAppAutomateTests | appPath | db14432d45fcc0fcfdcf0949bb582fd263fbee01758fb84b2432752238e948bd |
| tools | setupBrowserStackAppAutomateTests | detectedFramework | 9411fec7b53830609aee5e8f96b36ed468af0ae1bd2679224a01f664dd5c5931 |
| tools | setupBrowserStackAppAutomateTests | detectedLanguage | 16e185865e75c915256d3cfcc10a175f56b72174102005044bbf410df568ab03 |
| tools | setupBrowserStackAppAutomateTests | detectedTestingFramework | c74ea255228631d14502a45b7ea4e7499aa1fa2c7b03fb38fdba4a1f1f251d66 |
| tools | setupBrowserStackAppAutomateTests | devices | e9c59ac7ef73833d2b312be2acf00ca8c579b79cf03c77adfa59e9028fda42ab |
| tools | setupBrowserStackAppAutomateTests | project | cee150eaebe1a252ca303f6139ad065d1985de8bef0245db8ca7991ffedc0543 |
| tools | setupBrowserStackAutomateTests | description | 3e7683ab2c2417bed4667033cd2e8e87eea86322f23b8e383823ea15bde90a58 |
| tools | setupBrowserStackAutomateTests | devices | 6eef5e63e0038a4137cf1bdf3580aa642bb9f6ce7933fb78ed6d8302aa7993fd |
| tools | setupBrowserStackAutomateTests | projectName | cfab53689431e2db5d7ac73ad9bb76f6798d9da813bbcf71a47c77400be55901 |
| tools | startAccessibilityScan | description | 5c3a401cff7df900c2acc02fbb949568de1a52ba74e808767f896860fd47bbc2 |
| tools | startAccessibilityScan | authConfigId | 8d4b64138116aa336b651c14e17a6257f8982d6b67e981cd8eb5e9f47eefa9d0 |
| tools | startAccessibilityScan | name | 097628d59fa3cd14c2579fd01f92e133fab7e8f6ba709753610c19c22285a434 |
| tools | startAccessibilityScan | pageURL | 06094cfdd3276e53fb4b6d5ea609f635218b8ee5d458a2fdba645acac5b3dce3 |
| tools | takeAppScreenshot | description | 687870513f1c9e1627fc5c9cc4babe9d75b6388ef9e0554431378d09922ea90e |
| tools | takeAppScreenshot | appPath | 4f244b2c83f0c036b1e9e8e0a7b826e8c7ca36e15dd1abcdd227d1c1743c670b |
| tools | takeAppScreenshot | desiredPhone | 24f7659c53a043411bea6f4dd8b36e444e3808dc87183bf69e04d99952c28bef |
| tools | takeAppScreenshot | desiredPlatform | ac7dc0b131ce083fad560491bb400a57390ad1dda8ceab9b6338fdb80eca9859 |
| tools | takeAppScreenshot | desiredPlatformVersion | c985a19675f103fa387b9d6018be0ba68a7353a278381aa15ba7a136a57d0d0a |
| tools | updateTestRun | description | 06db6fa0b90d2ed6c5fc138cbdb6180b87a4b65295a9bbed275f00d8e8e7df57 |
| tools | updateTestRun | project_identifier | 6c62157d98f3a3579f77d8d19b65b8566108202987b5120eb459dc7319bbc86b |
| tools | updateTestRun | test_run_id | a4407ffe7486e68f2a54c7d5d9dd09272b8b5d391b2752a7253a17a27566f0bc |
| tools | uploadProductRequirementFile | description | c0e8abbdabcf86d9bec13d3dd7dcebda09971e966ace78dcb953addcc67fdda7 |
| tools | uploadProductRequirementFile | file_path | cf3b49711d7d77df068e036bd1e21dc8c2affd35eba4c7c6a40cbdcb9da52225 |
| tools | uploadProductRequirementFile | project_identifier | 44c537cceb4e4c13b69082b4bee57b363930d6bcaca13b4fc17de4502a268cc8 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
