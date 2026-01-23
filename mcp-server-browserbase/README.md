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


# What is mcp-server-browserbase?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browserbase/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browserbase/2.1.0?logo=docker&logoColor=fff&label=2.1.0)](https://hub.docker.com/r/acuvity/mcp-server-browserbase)
[![PyPI](https://img.shields.io/badge/2.1.0-3775A9?logo=pypi&logoColor=fff&label=@browserbasehq/mcp)](https://github.com/browserbase/mcp-server-browserbase)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browserbase/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A2.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A2.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-browserbase:2.1.0"
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
        "docker.io/acuvity/mcp-server-browserbase:2.1.0"
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
        "docker.io/acuvity/mcp-server-browserbase:2.1.0"
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
        "docker.io/acuvity/mcp-server-browserbase:2.1.0"
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
        "docker.io/acuvity/mcp-server-browserbase:2.1.0"
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
        "args": ["run","-i","--rm","--read-only","-e","BROWSERBASE_API_KEY","-e","BROWSERBASE_PROJECT_ID","docker.io/acuvity/mcp-server-browserbase:2.1.0"]
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
- arguments: `run -i --rm --read-only -e BROWSERBASE_API_KEY -e BROWSERBASE_PROJECT_ID docker.io/acuvity/mcp-server-browserbase:2.1.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e BROWSERBASE_API_KEY -e BROWSERBASE_PROJECT_ID docker.io/acuvity/mcp-server-browserbase:2.1.0
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

## 🧰 Tools (17)
<details>
<summary>multi_browserbase_stagehand_session_create</summary>

**Description**:

```
Create parallel browser session for multi-session workflows. Use this when you need multiple browser instances running simultaneously: parallel data scraping, concurrent automation, A/B testing, multiple user accounts, cross-site operations, batch processing, or any task requiring more than one browser. Creates an isolated browser session with independent cookies, authentication, and state. Always pair with session-specific tools (those ending with '_session'). Perfect for scaling automation tasks that require multiple browsers working in parallel.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| browserbaseSessionID | string | Resume an existing Browserbase session by providing its session ID. Use this to continue work in a previously created browser session that may have been paused or disconnected. | No
| name | string | Highly recommended: Descriptive name for tracking multiple sessions (e.g. 'amazon-scraper', 'user-login-flow', 'checkout-test-1'). Makes debugging and session management much easier! | No
</details>
<details>
<summary>multi_browserbase_stagehand_session_list</summary>

**Description**:

```
ONLY WORKS WITH MULTI-SESSION TOOLS! Track all parallel sessions: Critical tool for multi-session management! Shows all active browser sessions with their IDs, names, ages, and Browserbase session IDs. Use this frequently to monitor your parallel automation workflows, verify sessions are running, and get session IDs for session-specific tools. Essential for debugging and resource management in complex multi-browser scenarios.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>multi_browserbase_stagehand_session_close</summary>

**Description**:

```
Cleanup parallel session for multi-session workflows. Properly terminates a browser session, ends the Browserbase session, and frees cloud resources. Always use this when finished with a session to avoid resource waste and billing charges. Critical for responsible multi-session automation - each unclosed session continues consuming resources!
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | Exact session ID to close (get from 'multi_browserbase_stagehand_session_list'). Double-check this ID - once closed, the session cannot be recovered! | Yes
</details>
<details>
<summary>multi_browserbase_stagehand_navigate_session</summary>

**Description**:

```
Navigate to a URL in the browser. Only use this tool with URLs you're confident will work and stay up to date. Otherwise, use https://google.com as the starting point (for a specific session)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | The session ID to use | Yes
| url | string | The URL to navigate to | Yes
</details>
<details>
<summary>multi_browserbase_stagehand_act_session</summary>

**Description**:

```
Performs an action on a web page element. Act actions should be as atomic and specific as possible, i.e. "Click the sign in button" or "Type 'hello' into the search input". AVOID actions that are more than one step, i.e. "Order me pizza" or "Send an email to Paul asking him to call me". (for a specific session)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | The action to perform. Should be as atomic and specific as possible, i.e. 'Click the sign in button' or 'Type 'hello' into the search input'. AVOID actions that are more than one step, i.e. 'Order me pizza' or 'Send an email to Paul asking him to call me'. The instruction should be just as specific as possible, and have a strong correlation to the text on the page. If unsure, use observe before using act. | Yes
| sessionId | string | The session ID to use | Yes
| variables | object | Variables used in the action template. ONLY use variables if you're dealing with sensitive data or dynamic content. For example, if you're logging in to a website, you can use a variable for the password. When using variables, you MUST have the variable key in the action template. For example: {"action": "Fill in the password", "variables": {"password": "123456"}} | No
</details>
<details>
<summary>multi_browserbase_stagehand_extract_session</summary>

**Description**:

```
Extracts structured information and text content from the current web page based on specific instructions and a defined schema. This tool is ideal for scraping data, gathering information, or pulling specific content from web pages. Use this tool when you need to get text content, data, or information from a page rather than interacting with elements. For interactive elements like buttons, forms, or clickable items, use the observe tool instead. The extraction works best when you provide clear, specific instructions about what to extract and a well-defined JSON schema for the expected output format. This ensures the extracted data is properly structured and usable. (for a specific session)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instruction | string | The specific instruction for what information to extract from the current page. Be as detailed and specific as possible about what you want to extract. For example: 'Extract all product names and prices from the listing page' or 'Get the article title, author, and publication date from this blog post'. The more specific your instruction, the better the extraction results will be. Avoid vague instructions like 'get everything' or 'extract the data'. Instead, be explicit about the exact elements, text, or information you need. | Yes
| sessionId | string | The session ID to use | Yes
</details>
<details>
<summary>multi_browserbase_stagehand_observe_session</summary>

**Description**:

```
Observes and identifies specific interactive elements on the current web page that can be used for subsequent actions. This tool is specifically designed for finding actionable (interactable) elements such as buttons, links, form fields, dropdowns, checkboxes, and other UI components that you can interact with. Use this tool when you need to locate elements before performing actions with the act tool. DO NOT use this tool for extracting text content or data - use the extract tool instead for that purpose. The observe tool returns detailed information about the identified elements including their properties, location, and interaction capabilities. This information can then be used to craft precise actions. The more specific your observation instruction, the more accurate the element identification will be. Think of this as your 'eyes' on the page to find exactly what you need to interact with. (for a specific session)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instruction | string | Detailed instruction for what specific elements or components to observe on the web page. This instruction must be extremely specific and descriptive. For example: 'Find the red login button in the top right corner', 'Locate the search input field with placeholder text', or 'Identify all clickable product cards on the page'. The more specific and detailed your instruction, the better the observation results will be. Avoid generic instructions like 'find buttons' or 'see elements'. Instead, describe the visual characteristics, location, text content, or functionality of the elements you want to observe. This tool is designed to help you identify interactive elements that you can later use with the act tool for performing actions like clicking, typing, or form submission. | Yes
| returnAction | boolean | Whether to return the action to perform on the element. If true, the action will be returned as a string. If false, the action will not be returned. | No
| sessionId | string | The session ID to use | Yes
</details>
<details>
<summary>multi_browserbase_stagehand_get_url_session</summary>

**Description**:

```
Gets the current URL of the browser page. Returns the complete URL including protocol, domain, path, and any query parameters or fragments. (for a specific session)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | The session ID to use | Yes
</details>
<details>
<summary>browserbase_stagehand_get_all_urls</summary>

**Description**:

```
Gets the current URLs of all active browser sessions. Returns a mapping of session IDs to their current URLs.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_session_create</summary>

**Description**:

```
Create or reuse a single cloud browser session using Browserbase with fully initialized Stagehand. WARNING: This tool is for SINGLE browser workflows only. If you need multiple browser sessions running simultaneously (parallel scraping, A/B testing, multiple accounts), use 'multi_browserbase_stagehand_session_create' instead. This creates one browser session with all configuration flags (proxies, stealth, viewport, cookies, etc.) and initializes Stagehand to work with that session. Updates the active session.
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
Closes the current Browserbase session by properly shutting down the Stagehand instance, which handles browser cleanup and terminates the session recording.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_stagehand_navigate</summary>

**Description**:

```
Navigate to a URL in the browser. Only use this tool with URLs you're confident will work and stay up to date. Otherwise, use https://google.com as the starting point
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | The URL to navigate to | Yes
</details>
<details>
<summary>browserbase_stagehand_act</summary>

**Description**:

```
Performs an action on a web page element. Act actions should be as atomic and specific as possible, i.e. "Click the sign in button" or "Type 'hello' into the search input". AVOID actions that are more than one step, i.e. "Order me pizza" or "Send an email to Paul asking him to call me".
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | The action to perform. Should be as atomic and specific as possible, i.e. 'Click the sign in button' or 'Type 'hello' into the search input'. AVOID actions that are more than one step, i.e. 'Order me pizza' or 'Send an email to Paul asking him to call me'. The instruction should be just as specific as possible, and have a strong correlation to the text on the page. If unsure, use observe before using act. | Yes
| variables | object | Variables used in the action template. ONLY use variables if you're dealing with sensitive data or dynamic content. For example, if you're logging in to a website, you can use a variable for the password. When using variables, you MUST have the variable key in the action template. For example: {"action": "Fill in the password", "variables": {"password": "123456"}} | No
</details>
<details>
<summary>browserbase_stagehand_extract</summary>

**Description**:

```
Extracts structured information and text content from the current web page based on specific instructions and a defined schema. This tool is ideal for scraping data, gathering information, or pulling specific content from web pages. Use this tool when you need to get text content, data, or information from a page rather than interacting with elements. For interactive elements like buttons, forms, or clickable items, use the observe tool instead. The extraction works best when you provide clear, specific instructions about what to extract and a well-defined JSON schema for the expected output format. This ensures the extracted data is properly structured and usable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instruction | string | The specific instruction for what information to extract from the current page. Be as detailed and specific as possible about what you want to extract. For example: 'Extract all product names and prices from the listing page' or 'Get the article title, author, and publication date from this blog post'. The more specific your instruction, the better the extraction results will be. Avoid vague instructions like 'get everything' or 'extract the data'. Instead, be explicit about the exact elements, text, or information you need. | Yes
</details>
<details>
<summary>browserbase_stagehand_observe</summary>

**Description**:

```
Observes and identifies specific interactive elements on the current web page that can be used for subsequent actions. This tool is specifically designed for finding actionable (interactable) elements such as buttons, links, form fields, dropdowns, checkboxes, and other UI components that you can interact with. Use this tool when you need to locate elements before performing actions with the act tool. DO NOT use this tool for extracting text content or data - use the extract tool instead for that purpose. The observe tool returns detailed information about the identified elements including their properties, location, and interaction capabilities. This information can then be used to craft precise actions. The more specific your observation instruction, the more accurate the element identification will be. Think of this as your 'eyes' on the page to find exactly what you need to interact with.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instruction | string | Detailed instruction for what specific elements or components to observe on the web page. This instruction must be extremely specific and descriptive. For example: 'Find the red login button in the top right corner', 'Locate the search input field with placeholder text', or 'Identify all clickable product cards on the page'. The more specific and detailed your instruction, the better the observation results will be. Avoid generic instructions like 'find buttons' or 'see elements'. Instead, describe the visual characteristics, location, text content, or functionality of the elements you want to observe. This tool is designed to help you identify interactive elements that you can later use with the act tool for performing actions like clicking, typing, or form submission. | Yes
| returnAction | boolean | Whether to return the action to perform on the element. If true, the action will be returned as a string. If false, the action will not be returned. | No
</details>
<details>
<summary>browserbase_screenshot</summary>

**Description**:

```
Takes a screenshot of the current page. Use this tool to learn where you are on the page when controlling the browser with Stagehand. Only use this tool when the other tools are not sufficient to get the information you need.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | The name of the screenshot | No
</details>
<details>
<summary>browserbase_stagehand_get_url</summary>

**Description**:

```
Gets the current URL of the browser page. Returns the complete URL including protocol, domain, path, and any query parameters or fragments.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>

## 📝 Prompts (3)
<details>
<summary>browserbase_system</summary>

**Description**:

```
System prompt defining the scope and capabilities of Browserbase MCP server
```
<details>
<summary>multi_session_guidance</summary>

**Description**:

```
Guidance on when and how to use multi-session browser automation
```
<details>
<summary>stagehand_usage</summary>

**Description**:

```
Guidelines on how to use Stagehand's act, observe, and extract utilities effectively
```

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | browserbase_system | description | 6d348ed160a8f58e3de7ad133706e869e00e07c2113e323ec745dd1e43410488 |
| prompts | multi_session_guidance | description | 420ef61b9df1d610b9549343718a75d43c4750988cf335739e18b01a9a04a6b9 |
| prompts | stagehand_usage | description | 9609ec0d2225d3d70bbe9088706f1a2d37b45b6e2a08b58b5aacfce076c20dc6 |
| tools | browserbase_screenshot | description | 89360a2d914c21b0aed0f28c62c5d131b676834581fcda547d8ee68bade107f8 |
| tools | browserbase_screenshot | name | 13cd9e5fd467a04eb3cc620b853c65d16744c185cd00d767e3688f0172bf9bdc |
| tools | browserbase_session_close | description | 5881398eb991606ce9baa8c3d1628d78699882b8cad4e7323adea7470d9572b8 |
| tools | browserbase_session_create | description | 0ca8b8ce03c8ce64812b90ab4f8963b87067e5d70174fa2956e32d58a82df41f |
| tools | browserbase_session_create | sessionId | 2600a83521995510adcd784134a362806fe33f662254834faf3921034d05d68d |
| tools | browserbase_stagehand_act | description | a7d0922d73e82e2be5d47104e8e04724e64e6e2b1fcc83965e6bf00a2f750b4d |
| tools | browserbase_stagehand_act | action | e9293cb61ac49f2aec9f63dc4b2dba31527d104cf9bca2a4980e0d01e4d71000 |
| tools | browserbase_stagehand_act | variables | 82720b385db08e15c989c2efd014ccf8fe21190e18b0449a52edacbd2236fea8 |
| tools | browserbase_stagehand_extract | description | 20612537693105b321844ab528bb199e0f568252ce320e56507029ba4c8a553a |
| tools | browserbase_stagehand_extract | instruction | fb886260dfe51ddbca92dfdaf8ed971d83ce07fb1964cfb7511a8203f79d2732 |
| tools | browserbase_stagehand_get_all_urls | description | 4e7f019e65e8afa9cd0ad480d5183dd41598256a5f916f69c54fdd8af2a0d9e3 |
| tools | browserbase_stagehand_get_url | description | cf27467545bacb13bb3fb2eff73de10b4f5ea0c175c2b69c770c648d304c7fc7 |
| tools | browserbase_stagehand_navigate | description | b518399dc910c7b93674f142e674f45be8ecbb6738cb6f16b74b31ed3e24ff11 |
| tools | browserbase_stagehand_navigate | url | 63d749360d127f3c1d0d108336745c687aaa08760a306f0dadbbef4e9fadf27f |
| tools | browserbase_stagehand_observe | description | 714aea3ccc8218d4f40ae7528fe54efeded59d5653196dc83bbf099120298095 |
| tools | browserbase_stagehand_observe | instruction | cdd01fd5dabafb7ea35d7cc4714d017fc345168bc23fc12f2e8d592f940a4eed |
| tools | browserbase_stagehand_observe | returnAction | 7db15bc1c9ef1f5b1be8a019d5c22afb833d0452d105d345b3741f9722e19a90 |
| tools | multi_browserbase_stagehand_act_session | description | 86149c7dcccb259cf7e5f750c899e9d05f8a318700c7e78fd24f31ef24d3d82b |
| tools | multi_browserbase_stagehand_act_session | action | e9293cb61ac49f2aec9f63dc4b2dba31527d104cf9bca2a4980e0d01e4d71000 |
| tools | multi_browserbase_stagehand_act_session | sessionId | e4f7fd1a01e3e8b3f27936a848aaf39631e1ad5b6536f50bff3fb21551e63161 |
| tools | multi_browserbase_stagehand_act_session | variables | 82720b385db08e15c989c2efd014ccf8fe21190e18b0449a52edacbd2236fea8 |
| tools | multi_browserbase_stagehand_extract_session | description | 48ca615ffc668790a7f974f096e4147cf92c6aa9753d2dca03760d784ca686be |
| tools | multi_browserbase_stagehand_extract_session | instruction | fb886260dfe51ddbca92dfdaf8ed971d83ce07fb1964cfb7511a8203f79d2732 |
| tools | multi_browserbase_stagehand_extract_session | sessionId | e4f7fd1a01e3e8b3f27936a848aaf39631e1ad5b6536f50bff3fb21551e63161 |
| tools | multi_browserbase_stagehand_get_url_session | description | b89170720896e8da9910ff7ff516b2b2047da4ccb86655987f17c2f15b046b12 |
| tools | multi_browserbase_stagehand_get_url_session | sessionId | e4f7fd1a01e3e8b3f27936a848aaf39631e1ad5b6536f50bff3fb21551e63161 |
| tools | multi_browserbase_stagehand_navigate_session | description | 55ae60a2f61fd150e20dbc13ffde071b6430393d3ec6c1e5d20a3f5527e2d99a |
| tools | multi_browserbase_stagehand_navigate_session | sessionId | e4f7fd1a01e3e8b3f27936a848aaf39631e1ad5b6536f50bff3fb21551e63161 |
| tools | multi_browserbase_stagehand_navigate_session | url | 63d749360d127f3c1d0d108336745c687aaa08760a306f0dadbbef4e9fadf27f |
| tools | multi_browserbase_stagehand_observe_session | description | 84a1becd4973d9dc3052d05afcc286bcdec47ebff296b3ccb12f27d3113a1109 |
| tools | multi_browserbase_stagehand_observe_session | instruction | cdd01fd5dabafb7ea35d7cc4714d017fc345168bc23fc12f2e8d592f940a4eed |
| tools | multi_browserbase_stagehand_observe_session | returnAction | 7db15bc1c9ef1f5b1be8a019d5c22afb833d0452d105d345b3741f9722e19a90 |
| tools | multi_browserbase_stagehand_observe_session | sessionId | e4f7fd1a01e3e8b3f27936a848aaf39631e1ad5b6536f50bff3fb21551e63161 |
| tools | multi_browserbase_stagehand_session_close | description | fd30fd248aeac94864f5e1c7c74c615f6df65010b391bac965ab1263e0f97b27 |
| tools | multi_browserbase_stagehand_session_close | sessionId | 038007064db96d543ef8bc7ca34730b9a85c763d2ada531df79755d254a0829f |
| tools | multi_browserbase_stagehand_session_create | description | 7540fd99a9c78dfee7c2d89a6fee7712c56869559010b66bbf08172e3f3362cd |
| tools | multi_browserbase_stagehand_session_create | browserbaseSessionID | b75f24d2d1fbf71243a3c3844b6a727ca346fd13db2d9229daaa141274c440ce |
| tools | multi_browserbase_stagehand_session_create | name | 8759f2f0098eca37aa865f88db61ca3cdfd37e7646245c210f5b054986b2ed6d |
| tools | multi_browserbase_stagehand_session_list | description | 3dbbb019380ebf54b6912b2854e8572128959d9f0068c90e3385773cf4fa6940 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
