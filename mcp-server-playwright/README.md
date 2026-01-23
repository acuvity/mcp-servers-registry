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


# What is mcp-server-playwright?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-playwright/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-playwright/0.0.56?logo=docker&logoColor=fff&label=0.0.56)](https://hub.docker.com/r/acuvity/mcp-server-playwright)
[![PyPI](https://img.shields.io/badge/0.0.56-3775A9?logo=pypi&logoColor=fff&label=@playwright/mcp)](https://github.com/microsoft/playwright-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-playwright/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-playwright&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-playwright%3A0.0.56%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-playwright/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-playwright scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

For more information and extra configuration you can consult the [package](https://github.com/microsoft/playwright-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-playwright&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-playwright%3A0.0.56%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-playwright:0.0.56"
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
        "docker.io/acuvity/mcp-server-playwright:0.0.56"
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
        "docker.io/acuvity/mcp-server-playwright:0.0.56"
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
        "docker.io/acuvity/mcp-server-playwright:0.0.56"
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
        "docker.io/acuvity/mcp-server-playwright:0.0.56"
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
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","docker.io/acuvity/mcp-server-playwright:0.0.56"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-playwright:0.0.56`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-playwright:0.0.56
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

## 🧰 Tools (22)
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
| level | string | Level of the console messages to return. Each level includes the messages of more severe levels. Defaults to "info". | No
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
<summary>browser_evaluate</summary>

**Description**:

```
Evaluate JavaScript expression on page or element
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | Human-readable element description used to obtain permission to interact with the element | No
| function | string | () => { /* code */ } or (element) => { /* code */ } when element is provided | Yes
| ref | string | Exact target element reference from the page snapshot | No
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
| paths | array | The absolute paths to the files to upload. Can be single file or multiple files. If omitted, file chooser is cancelled. | No
</details>
<details>
<summary>browser_fill_form</summary>

**Description**:

```
Fill multiple form fields
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fields | array | Fields to fill in | Yes
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
<summary>browser_network_requests</summary>

**Description**:

```
Returns all network requests since loading the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeStatic | boolean | Whether to include successful static resources like images, fonts, scripts, etc. Defaults to false. | No
</details>
<details>
<summary>browser_run_code</summary>

**Description**:

```
Run Playwright code snippet
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| code | string | A JavaScript function containing Playwright code to execute. It will be invoked with a single argument, page, which you can use for any page interaction. For example: `async (page) => { await page.getByRole('button', { name: 'Submit' }).click(); return await page.title(); }` | Yes
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
| filename | string | File name to save the screenshot to. Defaults to `page-{timestamp}.{png|jpeg}` if not specified. Prefer relative file names to stay within the output directory. | No
| fullPage | boolean | When true, takes a screenshot of the full scrollable page, instead of the currently visible viewport. Cannot be used with element screenshots. | No
| ref | string | Exact target element reference from the page snapshot. If not provided, the screenshot will be taken of viewport. If ref is provided, element must be provided too. | No
| type | string | Image format for the screenshot. Default is png. | No
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
| filename | string | Save snapshot to markdown file instead of returning it in the response. | No
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
| button | string | Button to click, defaults to left | No
| doubleClick | boolean | Whether to perform a double click instead of a single click | No
| element | string | Human-readable element description used to obtain permission to interact with the element | Yes
| modifiers | array | Modifier keys to press | No
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
<summary>browser_tabs</summary>

**Description**:

```
List, create, close, or select a browser tab.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | Operation to perform | Yes
| index | number | Tab index, used for close/select. If omitted for close, current tab is closed. | No
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
| tools | browser_click | description | 5bc7302b94469359a1d759df8be7523c927ea63e200d90a2a9360da1612e9d29 |
| tools | browser_click | button | bcf7191949cb3d5e11f688a4824c826803f134f511ba1af21fde521e72e058d9 |
| tools | browser_click | doubleClick | c0e8001956075bada49bf20b77cc162d67a74fef05dffcc41860060baeec2dc1 |
| tools | browser_click | element | 8f7a4a92e8b1e44bcafaa5788842d15a674aef367878aa1707f321875208d02a |
| tools | browser_click | modifiers | 5b22a3b71f204a1ce340e8d3643e041fc1cb1d3a6d881aa6b2efb7c62110b548 |
| tools | browser_click | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browser_close | description | c483523dc3bb5b05eb23920e124b65ee9dcba6d8e75d2052f785c3010c4cb960 |
| tools | browser_console_messages | description | 2ce06ce1312ba7c5fe48cadccb19236fcf7b97a9998ef2454c8f67f3df8ecfb8 |
| tools | browser_console_messages | level | 824de0e31c97e7a78453d5fb291950ab3a401e9a66b5d422691a3f2daa22d40d |
| tools | browser_drag | description | 684f8531f973ebdaed04f74c1f8840f3c5dedbfacab923ce4d63a6960bce306d |
| tools | browser_drag | endElement | 8316bc24736a8b1b3d499b84691448227959ff9dd2741b4d4f886300e2862c15 |
| tools | browser_drag | endRef | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browser_drag | startElement | ccb99ea06f1f4cfe6348216abc31d647899e1100f3a1a353af89afa578f2a2b4 |
| tools | browser_drag | startRef | a2a0c2d0f7b7d8056a3aaaa53c71eba4f2bfeb35a02c5c6d860b52a9cccb9088 |
| tools | browser_evaluate | description | 22e0b74e1d420965fe259f0935a50d24f165977e841fec930760361368c8ef2f |
| tools | browser_evaluate | element | 8f7a4a92e8b1e44bcafaa5788842d15a674aef367878aa1707f321875208d02a |
| tools | browser_evaluate | function | 8bf24a3b442a02ea43fa3618d302da4155bb6d0d5e6e91bf447e576438e83aca |
| tools | browser_evaluate | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browser_file_upload | description | d272f8f519d6502ebcbb90472ec6c6b23827101fc85aa46f63224bbe27b9c5e7 |
| tools | browser_file_upload | paths | 0210de90718589f56f3d795add6ea2c0a6e9a099237d43ce8224dc1c9357e35f |
| tools | browser_fill_form | description | fbba903ace94805c1935afa1dbfc2ece6b14c187906b3b75f6cabf06bb4e1d09 |
| tools | browser_fill_form | fields | 95c53900d8deb08d6a0256df5265b0ea8500e1079a798178e942f8fe01a505b8 |
| tools | browser_handle_dialog | description | 34a2837f16e0b3e9aff154f1df1db28a393f6715f106da3c4a1e7e54e2253d83 |
| tools | browser_handle_dialog | accept | 0a86f27cbc233d22e1033a3257e24e2185897c0ab40c4b8452b40772af5e91f7 |
| tools | browser_handle_dialog | promptText | 2e7f193e01947d6e2549c0043cb64cce077c32b98d8b799d3c9b3f861669f333 |
| tools | browser_hover | description | 8513e4975a84cba22d8ffce77bca05b555ddb72cb31a6271907b345bb834fe45 |
| tools | browser_hover | element | 8f7a4a92e8b1e44bcafaa5788842d15a674aef367878aa1707f321875208d02a |
| tools | browser_hover | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browser_install | description | f260f51a276fc052742927c5457dea08462324d6dc955a35b8ba622189916ec2 |
| tools | browser_navigate | description | 5e517ac29796df4781d6e8f8b3be061cc694f0c8e027f40e42ce0739e887b1d5 |
| tools | browser_navigate | url | 63d749360d127f3c1d0d108336745c687aaa08760a306f0dadbbef4e9fadf27f |
| tools | browser_navigate_back | description | 1070d603d3951f9282bc8e5111b7a6993fa05215c23ba5099429b567a9bdb467 |
| tools | browser_network_requests | description | 62964542d2e6023a8136a0d8e72d15c1ddb70dd61a7885efe1244faffb99be11 |
| tools | browser_network_requests | includeStatic | 4840d358d3d36cacab9db67a1f7d9d97a4731c6d8da5e2060f5b7d1db9262667 |
| tools | browser_press_key | description | aad8c3412d76c93e83c00bbe260068e5e2b988fb41080d148f31d49b5e7d2532 |
| tools | browser_press_key | key | 99b4b6f2c8718d62ab46cca9b057177560c7ba358835bde04cebfdb9380036a2 |
| tools | browser_resize | description | 562c4779388a2d66374bf8197abfc94572bd0ae1d09e9990f3c16a99111e7899 |
| tools | browser_resize | height | 744a788ef6d6749b0fcfeda5184af52314f2bc859b082296cde9ef62ac933a59 |
| tools | browser_resize | width | 98392dfba8217b86ac97bae43deb861684eb3b1e771bc8524c8a901d2f3f6d49 |
| tools | browser_run_code | description | dc358ed85e9fa884356d449a58f7ca0f8cccf2bb19bf6a72afefa1ccbdd433cf |
| tools | browser_run_code | code | 62cbb639162041f7d754efd1a4c57da993c07f162620636cad2cbabe8231bb71 |
| tools | browser_select_option | description | a085193341d59ac28092de80bbabb95a51012a6a85c011db3e1211fa2b80930a |
| tools | browser_select_option | element | 8f7a4a92e8b1e44bcafaa5788842d15a674aef367878aa1707f321875208d02a |
| tools | browser_select_option | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browser_select_option | values | 043660ef1e2bf819c47fee4ecba90c983b6598c8a881dd856100e336f001c748 |
| tools | browser_snapshot | description | a3f68829ce29df3dbfa0e4e91dbf4564977b4f57a4b15ac977d894429e0ed08a |
| tools | browser_snapshot | filename | 3295eef1b00103e71a590c4b05d303364e051c47e1334fadaad04d8c59404409 |
| tools | browser_tabs | description | e1663538ca64d92f7bb7f0f4a8eadaeab827a7a3380418bf791ce82b65e70c2c |
| tools | browser_tabs | action | 43b37e55227f1fb3ac29433eea0546479637b3054a88b4bdeea53b4b77eed728 |
| tools | browser_tabs | index | 929abc7a3fe9feecc39c3ce49cc78a72e1b27bdd2003bb213f381da44c0f2ff8 |
| tools | browser_take_screenshot | description | 14f147272c20299ea428abd9a08b576144fc06fe44968949e477b0ec490fc661 |
| tools | browser_take_screenshot | element | 0a584a11c45269e0b00e83541abffa5294b5cbfd951d73916de962a7e8565184 |
| tools | browser_take_screenshot | filename | 0a3b03201cbed53f5c1607859dfb8864918c1bfce69764f11ec0ee5348c7be0b |
| tools | browser_take_screenshot | fullPage | 55fafe4e80fdd224141e6d863176640841168e4108586533300a9bf4c830e483 |
| tools | browser_take_screenshot | ref | 6b63c0b921d6d1d6c6c5221e95f36488876b4d2d0c53e5a4eef0d8dd4d7e088f |
| tools | browser_take_screenshot | type | 2ff2bd010287dcf0d287eebcc274250f78c6c78a7e1f49e9701f6a7c8bab3fbf |
| tools | browser_type | description | 390727daa0fdd31a5d9417f51fd818b1b6d6b934eb9b5b15be57dd9e7e0da2a9 |
| tools | browser_type | element | 8f7a4a92e8b1e44bcafaa5788842d15a674aef367878aa1707f321875208d02a |
| tools | browser_type | ref | e39a6f5e4db7b686d2128626a5d61f81db06008308d63767bffc7d16ca432c3b |
| tools | browser_type | slowly | fbaa1f504a8fc996ebf95c85fe33b2d70f8291663b28707ca388673db5489dbd |
| tools | browser_type | submit | 2878d7dee713522a404fd189b76b7ce01b439e50b164a1e5c992b6ba2f577106 |
| tools | browser_type | text | 42bc9d6777b527b20636d608e53bc2cb9dc43f74c263b701827645bcc369d438 |
| tools | browser_wait_for | description | 5b754f8f4ac481dae127cb350272c1e5b484b4a3cb819cc426b1bfac9747a372 |
| tools | browser_wait_for | text | 4eb9b99a23f0994f4aa3a51152537abd4534da072acffe75fbee9c5cb93963cd |
| tools | browser_wait_for | textGone | b3a67c647eb43e55e93a542d28475c534063b1277abbadf885839632f244c4ef |
| tools | browser_wait_for | time | 0ed8e3c1f110ea73b266829774a105a70725d2360fb3464757d342a893e8f71d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
