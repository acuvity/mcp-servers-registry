<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://mma.prnewswire.com/media/2544052/Acuvity__Logo.jpg" height="90" alt="Acuvity logo"/>
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


# What is mcp-server-browserbase?
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browserbase/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browserbase/1.0.5?logo=docker&logoColor=fff&label=1.0.5)](https://hub.docker.com/r/acuvity/mcp-server-browserbase)
[![PyPI](https://img.shields.io/badge/1.0.5-3775A9?logo=pypi&logoColor=fff&label=@browserbasehq/mcp)](https://github.com/browserbase/mcp-server-browserbase)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browserbase/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A1.0.5%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Automate browser interactions in the cloud (e.g. web navigation, data extraction, form filling).

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @browserbasehq/mcp original [sources](https://github.com/browserbase/mcp-server-browserbase).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-browserbase/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/charts/mcp-server-browserbase/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @browserbasehq/mcp run reliably and safely.

## 🔐 Key Security Features

<details>
<summary>📦 Isolated Immutable Sandbox </summary>

- **Isolated Execution**: All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.
- **Non-root by Default**: Enforces least-privilege principles, minimizing the impact of potential security breaches.
- **Read-only Filesystem**: Ensures runtime immutability, preventing unauthorized modification.
- **Version Pinning**: Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.
- **CVE Scanning**: Continuously scans images for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation.
- **SBOM & Provenance**: Delivers full supply chain transparency by embedding metadata and traceable build information."
</details>

<details>
<summary>🛡️ Runtime Security and Guardrails</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Guardrails

#### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

#### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

#### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

#### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

#### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

#### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

### Enable guardrails

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

## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, define `BASIC_AUTH_SECRET` environment variable with a shared secret.

Example: add `-e BASIC_AUTH_SECRET="supersecret"` to enable the basic authentication.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-browserbase scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `BROWSERBASE_API_KEY` required to be set
  - `BROWSERBASE_PROJECT_ID` required to be set

For more information and extra configuration you can consult the [package](https://github.com/browserbase/mcp-server-browserbase) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A1.0.5%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-browserbase": {
        "env": {
          "BROWSERBASE_API_KEY": "TO_BE_SET",
          "BROWSERBASE_PROJECT_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "BROWSERBASE_API_KEY",
          "-e",
          "BROWSERBASE_PROJECT_ID",
          "docker.io/acuvity/mcp-server-browserbase:1.0.5"
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
    "acuvity-mcp-server-browserbase": {
      "env": {
        "BROWSERBASE_API_KEY": "TO_BE_SET",
        "BROWSERBASE_PROJECT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERBASE_API_KEY",
        "-e",
        "BROWSERBASE_PROJECT_ID",
        "docker.io/acuvity/mcp-server-browserbase:1.0.5"
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
    "acuvity-mcp-server-browserbase": {
      "env": {
        "BROWSERBASE_API_KEY": "TO_BE_SET",
        "BROWSERBASE_PROJECT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERBASE_API_KEY",
        "-e",
        "BROWSERBASE_PROJECT_ID",
        "docker.io/acuvity/mcp-server-browserbase:1.0.5"
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
    "acuvity-mcp-server-browserbase": {
      "env": {
        "BROWSERBASE_API_KEY": "TO_BE_SET",
        "BROWSERBASE_PROJECT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERBASE_API_KEY",
        "-e",
        "BROWSERBASE_PROJECT_ID",
        "docker.io/acuvity/mcp-server-browserbase:1.0.5"
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
    "acuvity-mcp-server-browserbase": {
      "env": {
        "BROWSERBASE_API_KEY": "TO_BE_SET",
        "BROWSERBASE_PROJECT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BROWSERBASE_API_KEY",
        "-e",
        "BROWSERBASE_PROJECT_ID",
        "docker.io/acuvity/mcp-server-browserbase:1.0.5"
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
        "env": {"BROWSERBASE_API_KEY":"TO_BE_SET","BROWSERBASE_PROJECT_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BROWSERBASE_API_KEY","-e","BROWSERBASE_PROJECT_ID","docker.io/acuvity/mcp-server-browserbase:1.0.5"]
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
- arguments: `run -i --rm --read-only -e BROWSERBASE_API_KEY -e BROWSERBASE_PROJECT_ID docker.io/acuvity/mcp-server-browserbase:1.0.5`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e BROWSERBASE_API_KEY -e BROWSERBASE_PROJECT_ID docker.io/acuvity/mcp-server-browserbase:1.0.5
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserbase": {
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
    "acuvity-mcp-server-browserbase": {
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
  - `BROWSERBASE_API_KEY` secret to be set as secrets.BROWSERBASE_API_KEY either by `.value` or from existing with `.valueFrom`
  - `BROWSERBASE_PROJECT_ID` secret to be set as secrets.BROWSERBASE_PROJECT_ID either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0
````

Install with helm

```console
helm install mcp-server-browserbase oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0
```

From there your MCP server mcp-server-browserbase will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-browserbase` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/charts/mcp-server-browserbase/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>browserbase_wait</summary>

**Description**:

```
Wait for a specified time in seconds
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| time | number | Time in seconds | Yes
</details>
<details>
<summary>browserbase_close</summary>

**Description**:

```
Close the current page...
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| random_string | string | Dummy parameter | No
</details>
<details>
<summary>browserbase_resize</summary>

**Description**:

```
Resize window...
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | not set | Yes
| width | number | not set | Yes
</details>
<details>
<summary>browserbase_snapshot</summary>

**Description**:

```
Capture a new accessibility snapshot of the current page state. Use this if the page has changed to ensure subsequent actions use an up-to-date page representation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_click</summary>

**Description**:

```
Perform click on a web page using ref
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
</details>
<details>
<summary>browserbase_drag</summary>

**Description**:

```
Perform drag and drop between two elements using ref.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| endElement | string | Target element description | Yes
| endRef | string | Exact target element reference from the page snapshot | Yes
| startElement | string | Source element description | Yes
| startRef | string | Exact source element reference from the page snapshot | Yes
</details>
<details>
<summary>browserbase_hover</summary>

**Description**:

```
Hover over element on page using ref.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
</details>
<details>
<summary>browserbase_type</summary>

**Description**:

```
Type text into editable element using ref.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
| slowly | boolean | Whether to type one character at a time. | No
| submit | boolean | Whether to submit entered text (press Enter after) | No
| text | string | Text to type into the element | Yes
</details>
<details>
<summary>browserbase_select_option</summary>

**Description**:

```
Select an option in a dropdown using ref.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
| values | array | Array of values to select in the dropdown. | Yes
</details>
<details>
<summary>browserbase_take_screenshot</summary>

**Description**:

```
Take a screenshot of the current page or element using ref.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description. | No
| raw | boolean | Whether to return without compression (PNG). Default is false (JPEG). | No
| ref | string | Exact target element reference from the page snapshot. | No
</details>
<details>
<summary>browserbase_press_key</summary>

**Description**:

```
Press a key on the keyboard
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | Name of the key to press or a character to generate, such as `ArrowLeft` or `a` | Yes
</details>
<details>
<summary>browserbase_get_text</summary>

**Description**:

```
Extract text content from the page or a specific element.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | Optional CSS selector to get text from. If omitted, gets text from the whole body. | No
| sessionId | string | not set | No
</details>
<details>
<summary>browserbase_navigate</summary>

**Description**:

```
Navigate to a URL
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | The URL to navigate to | Yes
</details>
<details>
<summary>browserbase_navigate_back</summary>

**Description**:

```
Go back to the previous page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_navigate_forward</summary>

**Description**:

```
Go forward to the next page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_session_create</summary>

**Description**:

```
Create or reuse a cloud browser session using Browserbase. Updates the active session.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | Optional session ID to use/reuse. If not provided or invalid, a new session is created. | No
</details>
<details>
<summary>browserbase_session_close</summary>

**Description**:

```
Closes the current Browserbase session by disconnecting the Playwright browser. This will terminate the recording for the session.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| random_string | string | Dummy parameter to ensure consistent tool call format. | No
</details>
<details>
<summary>browserbase_context_create</summary>

**Description**:

```
Create a new Browserbase context for reusing cookies, authentication, and cached data across browser sessions
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Optional friendly name to reference this context later (otherwise, you'll need to use the returned ID) | No
</details>
<details>
<summary>browserbase_context_delete</summary>

**Description**:

```
Delete a Browserbase context when you no longer need it
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contextId | string | The context ID to delete (required if name not provided) | No
| name | string | The friendly name of the context to delete (required if contextId not provided) | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | browserbase_click | description | 23eabf817ed05424ae6a9283669e721356f0b04f708ca7d5d1f0a22fec953b4b |
| tools | browserbase_click | element | 1694eb3252cb80b50f80fb3fb83ea61f19b1d85a30ebcc301029e13e9db6fd14 |
| tools | browserbase_click | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browserbase_close | description | 12be13a02fb51d37444cf489f570063e5e15f5757adf279093397544d31f3de2 |
| tools | browserbase_close | random_string | 518053fd1ac5b466071723b8a3088b525ba8f5f845cbdb4ef1e1a2963829c83c |
| tools | browserbase_context_create | description | 14ad364f58dac27c45d5d27fdf3ce50f45c3b39493dca538dfe5b0b8fcdcfae1 |
| tools | browserbase_context_create | name | e44527d80c80f069d86e60c41de4153bae112b0eefeb71932e04286a32363cfe |
| tools | browserbase_context_delete | description | 9797327409bec66e012ed5d0e89632be545ef59d3b122a76de8a810be6c92900 |
| tools | browserbase_context_delete | contextId | 4487437e618ff87bf006c67433745e99ec6c26920b615645197427404fa43f97 |
| tools | browserbase_context_delete | name | 2cc1b27e3fcccf0515e2f94669bb1c2bd3980f4b75bcaff08143b686bcae3126 |
| tools | browserbase_drag | description | 18a8d4a0d738d68b584ad5f5c8ee9c14d288f8017450381290ad748af47f4241 |
| tools | browserbase_drag | endElement | 2e12fa379751d8c237bd0612b5dd42f36f1964c0a2e21509d2a6443ea8269719 |
| tools | browserbase_drag | endRef | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browserbase_drag | startElement | aa162e9620fa27b204c29e276143accc0a8411ff3c8b30e90d8e2625a6e888d9 |
| tools | browserbase_drag | startRef | a2a0c2d0f7b7d8056a3aaaa53c71eba4f2bfeb35a02c5c6d860b52a9cccb9088 |
| tools | browserbase_get_text | description | 136f0744a4eed0487a4bd382c21c369b0eb998de238e7d7fcd14037202047edf |
| tools | browserbase_get_text | selector | f4be6318427b3b2a1c587d72c698b46ed5dac0806a7b22ca30913481827e6199 |
| tools | browserbase_hover | description | e53cd3c44908e91d35f071d4a414e52082d8385f1483e1c731d187b39846645f |
| tools | browserbase_hover | element | 1694eb3252cb80b50f80fb3fb83ea61f19b1d85a30ebcc301029e13e9db6fd14 |
| tools | browserbase_hover | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browserbase_navigate | description | 5e517ac29796df4781d6e8f8b3be061cc694f0c8e027f40e42ce0739e887b1d5 |
| tools | browserbase_navigate | url | 63d749360d127f3c1d0d108336745c687aaa08760a306f0dadbbef4e9fadf27f |
| tools | browserbase_navigate_back | description | 1070d603d3951f9282bc8e5111b7a6993fa05215c23ba5099429b567a9bdb467 |
| tools | browserbase_navigate_forward | description | 4f74235e282e3cba526b98047b02c344c6bc32566bb325d5408e897eadfc6a7e |
| tools | browserbase_press_key | description | aad8c3412d76c93e83c00bbe260068e5e2b988fb41080d148f31d49b5e7d2532 |
| tools | browserbase_press_key | key | 99b4b6f2c8718d62ab46cca9b057177560c7ba358835bde04cebfdb9380036a2 |
| tools | browserbase_resize | description | 8a048f66ca5985ffbe29b85a321269a7aa1d12663932dbb53ce37ddcf740d952 |
| tools | browserbase_select_option | description | 3e7335503efca3ef2f22d38c51e6cd89447a4a0caca18e0d8a0ef2b2c38a6c26 |
| tools | browserbase_select_option | element | 1694eb3252cb80b50f80fb3fb83ea61f19b1d85a30ebcc301029e13e9db6fd14 |
| tools | browserbase_select_option | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browserbase_select_option | values | fc0448dc32f6a5e89d930fb447d5f4411e31253d3e9fa9841edec2cb4618f8fb |
| tools | browserbase_session_close | description | c33af2ca6802a0e1c80d2430f86170b68c2e9ceb55621d8ca4b1b33ebd0f544e |
| tools | browserbase_session_close | random_string | 6f65b1a9a0e92e0bc83edd0f63ff030db3acf3f02ab0ea9bba4938307e3c00c0 |
| tools | browserbase_session_create | description | ea3a9035e2aa1743f77a76ef24175d7c66ad7a3afcdf080d004923acc19c5911 |
| tools | browserbase_session_create | sessionId | 2600a83521995510adcd784134a362806fe33f662254834faf3921034d05d68d |
| tools | browserbase_snapshot | description | 6dc78620771eccf0ab550879bb7ae6369de34114b673c111a4f7fbd8fab5076c |
| tools | browserbase_take_screenshot | description | 7c87de0df69fe81dbbf340f7ba062a60a9c436540dcb7ef67bbd43a54837262e |
| tools | browserbase_take_screenshot | element | fc545fc9093d9c26b52b0186745392d475ba2a517f5622bdff35a3d85c379fb6 |
| tools | browserbase_take_screenshot | raw | 7cd65c9a870086f58183b0fbe7eb0794e3ce3cc3a62dca3b30168abf7f02015e |
| tools | browserbase_take_screenshot | ref | 335ff2d7572b8831cdb68863866c4ba5f92c6436846295cf4e054eeb00b7edfe |
| tools | browserbase_type | description | b9dfec63c6922f5935627751dc97ae4e3d80993bf414b844f36f80648584b8d4 |
| tools | browserbase_type | element | 1694eb3252cb80b50f80fb3fb83ea61f19b1d85a30ebcc301029e13e9db6fd14 |
| tools | browserbase_type | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browserbase_type | slowly | 4dc8586a22406a330c309da2e8c10f90ee599b990993f654408b0e13d9001093 |
| tools | browserbase_type | submit | 2878d7dee713522a404fd189b76b7ce01b439e50b164a1e5c992b6ba2f577106 |
| tools | browserbase_type | text | 42bc9d6777b527b20636d608e53bc2cb9dc43f74c263b701827645bcc369d438 |
| tools | browserbase_wait | description | fb6ee71ce0454853bc08cbf2eb48241f4e3e8b1f29753fe13c72f91a563603ba |
| tools | browserbase_wait | time | ae02dada7574b65a44313329c9439160f19f9aca36734146c44ce857bfe80790 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
