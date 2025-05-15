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


# What is mcp-server-playwright?

[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-playwright/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-playwright/0.0.25?logo=docker&logoColor=fff&label=0.0.25)](https://hub.docker.com/r/acuvity/mcp-server-playwright)
[![PyPI](https://img.shields.io/badge/0.0.25-3775A9?logo=pypi&logoColor=fff&label=@playwright/mcp)](https://github.com/microsoft/playwright-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-playwright&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-playwright%3A0.0.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Browser automation for LLMs using structured accessibility snapshots.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @playwright/mcp original [sources](https://github.com/microsoft/playwright-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-playwright/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/charts/mcp-server-playwright/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @playwright/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Gardrails

### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

## Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/charts/mcp-server-playwright#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-playwright scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-playwright&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-playwright%3A0.0.25%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-playwright": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "docker.io/acuvity/mcp-server-playwright:0.0.25"
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
    "acuvity-mcp-server-playwright": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-playwright:0.0.25"
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
    "acuvity-mcp-server-playwright": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-playwright:0.0.25"
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
    "acuvity-mcp-server-playwright": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-playwright:0.0.25"
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
    "acuvity-mcp-server-playwright": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-playwright:0.0.25"
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
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","docker.io/acuvity/mcp-server-playwright:0.0.25"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-playwright:0.0.25`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-playwright:0.0.25
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-playwright": {
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
    "acuvity-mcp-server-playwright": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Minibridge offers a host of additional features. For step-by-step guidance, please visit the wiki. And if anything’s unclear, don’t hesitate to reach out!

</details>

## 🛡️ Runtime security

**Guardrails:**

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.

**Basic Authentication:**

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

Then you can connect through `http/sse` as usual given that you pass an `Authorization: Bearer supersecret` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-playwright --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-playwright --version 1.0.0
````

Install with helm

```console
helm install mcp-server-playwright oci://docker.io/acuvity/mcp-server-playwright --version 1.0.0
```

From there your MCP server mcp-server-playwright will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-playwright` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/charts/mcp-server-playwright/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (25)
<details>
<summary>browser_close</summary>

**Description**:

```
Close the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_resize</summary>

**Description**:

```
Resize the browser window
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | Height of the browser window | Yes
| width | number | Width of the browser window | Yes
</details>
<details>
<summary>browser_console_messages</summary>

**Description**:

```
Returns all console messages
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_handle_dialog</summary>

**Description**:

```
Handle a dialog
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| accept | boolean | Whether to accept the dialog. | Yes
| promptText | string | The text of the prompt in case of a prompt dialog. | No
</details>
<details>
<summary>browser_file_upload</summary>

**Description**:

```
Upload one or multiple files
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| paths | array | The absolute paths to the files to upload. Can be a single file or multiple files. | Yes
</details>
<details>
<summary>browser_install</summary>

**Description**:

```
Install the browser specified in the config. Call this if you get an error about the browser not being installed.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_press_key</summary>

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
<summary>browser_navigate</summary>

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
<summary>browser_navigate_back</summary>

**Description**:

```
Go back to the previous page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_navigate_forward</summary>

**Description**:

```
Go forward to the next page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_network_requests</summary>

**Description**:

```
Returns all network requests since loading the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_pdf_save</summary>

**Description**:

```
Save page as PDF
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filename | string | File name to save the pdf to. Defaults to `page-{timestamp}.pdf` if not specified. | No
</details>
<details>
<summary>browser_take_screenshot</summary>

**Description**:

```
Take a screenshot of the current page. You can't perform actions based on the screenshot, use browser_snapshot for actions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description used to obtain permission to screenshot the element. If not provided, the screenshot will be taken of viewport. If element is provided, ref must be provided too. | No
| filename | string | File name to save the screenshot to. Defaults to `page-{timestamp}.{png|jpeg}` if not specified. | No
| raw | boolean | Whether to return without compression (in PNG format). Default is false, which returns a JPEG image. | No
| ref | string | Exact target element reference from the page snapshot. If not provided, the screenshot will be taken of viewport. If ref is provided, element must be provided too. | No
</details>
<details>
<summary>browser_snapshot</summary>

**Description**:

```
Capture accessibility snapshot of the current page, this is better than screenshot
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_click</summary>

**Description**:

```
Perform click on a web page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description used to obtain permission to interact with the element | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
</details>
<details>
<summary>browser_drag</summary>

**Description**:

```
Perform drag and drop between two elements
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| endElement | string | Human-readable target element description used to obtain the permission to interact with the element | Yes
| endRef | string | Exact target element reference from the page snapshot | Yes
| startElement | string | Human-readable source element description used to obtain the permission to interact with the element | Yes
| startRef | string | Exact source element reference from the page snapshot | Yes
</details>
<details>
<summary>browser_hover</summary>

**Description**:

```
Hover over element on page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description used to obtain permission to interact with the element | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
</details>
<details>
<summary>browser_type</summary>

**Description**:

```
Type text into editable element
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description used to obtain permission to interact with the element | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
| slowly | boolean | Whether to type one character at a time. Useful for triggering key handlers in the page. By default entire text is filled in at once. | No
| submit | boolean | Whether to submit entered text (press Enter after) | No
| text | string | Text to type into the element | Yes
</details>
<details>
<summary>browser_select_option</summary>

**Description**:

```
Select an option in a dropdown
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description used to obtain permission to interact with the element | Yes
| ref | string | Exact target element reference from the page snapshot | Yes
| values | array | Array of values to select in the dropdown. This can be a single value or multiple values. | Yes
</details>
<details>
<summary>browser_tab_list</summary>

**Description**:

```
List browser tabs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browser_tab_new</summary>

**Description**:

```
Open a new tab
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | The URL to navigate to in the new tab. If not provided, the new tab will be blank. | No
</details>
<details>
<summary>browser_tab_select</summary>

**Description**:

```
Select a tab by index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | The index of the tab to select | Yes
</details>
<details>
<summary>browser_tab_close</summary>

**Description**:

```
Close a tab
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | The index of the tab to close. Closes current tab if not provided. | No
</details>
<details>
<summary>browser_generate_playwright_test</summary>

**Description**:

```
Generate a Playwright test for given scenario
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | The description of the test | Yes
| name | string | The name of the test | Yes
| steps | array | The steps of the test | Yes
</details>
<details>
<summary>browser_wait_for</summary>

**Description**:

```
Wait for text to appear or disappear or a specified time to pass
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| text | string | The text to wait for | No
| textGone | string | The text to wait for to disappear | No
| time | number | The time to wait in seconds | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
