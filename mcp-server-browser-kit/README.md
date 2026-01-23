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


# What is mcp-server-browser-kit?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browser-kit/6.0.0?logo=docker&logoColor=fff&label=6.0.0)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit)
[![PyPI](https://img.shields.io/badge/6.0.0-3775A9?logo=pypi&logoColor=fff&label=@mcp-browser-kit/server)](https://github.com/ndthanhdev/mcp-browser-kit)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browser-kit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-browser-kit%3A6.0.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** An MCP Server for interacting with manifest v2 compatible browsers.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @mcp-browser-kit/server original [sources](https://github.com/ndthanhdev/mcp-browser-kit).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-browser-kit/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/charts/mcp-server-browser-kit/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @mcp-browser-kit/server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-browser-kit scope of operation the intended usage is to run natively on the targeted machine to access local resources.

For more information and extra configuration you can consult the [package](https://github.com/ndthanhdev/mcp-browser-kit) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browser-kit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-browser-kit%3A6.0.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-browser-kit": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-browser-kit:6.0.0"
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
    "acuvity-mcp-server-browser-kit": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-browser-kit:6.0.0"
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
    "acuvity-mcp-server-browser-kit": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-browser-kit:6.0.0"
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
    "acuvity-mcp-server-browser-kit": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-browser-kit:6.0.0"
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
    "acuvity-mcp-server-browser-kit": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-browser-kit:6.0.0"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-browser-kit:6.0.0"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-browser-kit:6.0.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-browser-kit:6.0.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browser-kit": {
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
    "acuvity-mcp-server-browser-kit": {
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
helm show readme oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
````

Install with helm

```console
helm install mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
```

From there your MCP server mcp-server-browser-kit will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-browser-kit` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/charts/mcp-server-browser-kit/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>getBasicBrowserContext</summary>

**Description**:

```
🌐 GET BROWSER CONTEXT - CRITICAL FIRST STEP BEFORE USING ANY OTHER TOOLS!
* This tool MUST be called first to initialize browser automation and get essential data.
* Returns data structure with:
  - tabs: Array of browser tabs with properties like id, url, title, and active status
  - manifestVersion: Version of extension manifest format supported by the browser
* Each tab includes a unique tabKey required for all other tool operations
* The active tab (marked with 'active: true') is typically your target for automation
* The manifestVersion determines which browser features and extension capabilities are available
* Different browsers support different manifest versions, affecting available tools and API access
* Standard workflow:
  1) getBasicBrowserContext → get browser state and tabKey
  2) Analyze page content based on your goal and manifest version:
     - If interaction is required (clicking, filling forms, etc.):
       · For Manifest Version 2: Use captureTab for visual context or getReadableElements for element identification
       · For other Manifest Versions: Use only getReadableElements for element identification
     - If no interaction is required (just reading page content):
       · Use getReadableText to extract all visible text from the page
  3) Interact using click/fill/enter tools with the obtained tabKey
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>captureTab</summary>

**Description**:

```
📷 Captures a screenshot of a browser tab
* Use this tool after calling getBasicBrowserContext to obtain visual context of the page
* The screenshot helps you see what the browser is displaying to the user
* Requires tabKey from getBasicBrowserContext
* Returns an image with width, height, and data in base64 format
* Workflow: 1) getBasicBrowserContext → 2) captureTab → 3) interact with elements
* Parameters: tabKey
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>invokeJsFn</summary>

**Description**:

```
⚙️ Executes custom JavaScript code in the context of the web page
* Use this for advanced operations not covered by other tools
* Requires tabKey from getBasicBrowserContext and JavaScript code to execute
* The code should be the body of a function that returns a value
* Example: 'return document.title;' to get the page title
* Gives you full flexibility for custom browser automation
* Parameters: tabKey, fnBodyCode (JavaScript code as string)
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fnBodyCode | string | Function body code to execute in page context | Yes
| tabKey | string | Tab key to run JavaScript in | Yes
</details>
<details>
<summary>openTab</summary>

**Description**:

```
🌐 Opens a new browser tab with the specified URL
* Use this to navigate to a new page in a new tab
* Requires windowKey from getBasicBrowserContext and the URL to open
* Returns the tabKey of the newly created tab which you can use for further operations
* The new tab will be created in the specified browser window
* After opening, you may need to wait a moment for the page to load
* Parameters: windowKey, url
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | URL to open in the new tab | Yes
| windowKey | string | Window key where the new tab should open | Yes
</details>
<details>
<summary>closeTab</summary>

**Description**:

```
🗑️ Closes a specific browser tab
* Use this to close a tab when you're done with it or need to clean up
* Requires tabKey from getBasicBrowserContext
* The tab will be permanently closed and cannot be recovered
* Be careful not to close the tab you're currently working with
* Parameters: tabKey
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>getSelection</summary>

**Description**:

```
📋 Gets the current text selection in the browser tab
* Use this to retrieve text that the user has selected on the page
* Requires tabKey from getBasicBrowserContext
* Returns information about the selected text including the text content itself
* Useful for capturing user selections or verifying what text is highlighted
* Returns empty selection if nothing is currently selected
* Parameters: tabKey
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>getReadableText</summary>

**Description**:

```
📝 Extracts all text content from the current web page
* Retrieves all visible text from the active tab
* Requires the tabKey obtained from getBasicBrowserContext
* Use this to analyze the page content without visual elements
* Returns a string containing all the text on the page
* Useful for getting a quick overview of page content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>getReadableElements</summary>

**Description**:

```
🔍 Lists all interactive elements on the page with their text
* Returns a list of elements with their path, role, and text content
* Requires the tabKey obtained from getBasicBrowserContext
* Each element is returned as [path, accessibleRole, accessibleText]
* Use the path as readablePath to interact with elements through click or fill operations
* Helps you identify which elements can be interacted with by their text
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>clickOnViewableElement</summary>

**Description**:

```
👆 Clicks on an element at specific X,Y coordinates
* Use this to click on elements by their position on the screen
* Requires tabKey from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureTab screenshot dimensions
* Useful when you know the visual position of an element
* Parameters: tabKey, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key of the active tab | Yes
| x | number | X coordinate (pixels) | Yes
| y | number | Y coordinate (pixels) | Yes
</details>
<details>
<summary>fillTextToViewableElement</summary>

**Description**:

```
⌨️ Types text into an input field at specific X,Y coordinates
* Use this to enter text into form fields by their position
* Requires tabKey from getBasicBrowserContext, x,y coordinates, and the text to enter
* Coordinates are based on the captureTab screenshot dimensions
* First clicks at the specified position, then types the provided text
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnViewableElement with that button
* If no submit button is visible, use hitEnterOnViewableElement instead
* Parameters: tabKey, x, y, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key of the active tab | Yes
| value | string | Text to enter into the input field | Yes
| x | number | X coordinate (pixels) | Yes
| y | number | Y coordinate (pixels) | Yes
</details>
<details>
<summary>hitEnterOnViewableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element at specific X,Y coordinates
* Use this to trigger actions like form submission or button clicks
* Requires tabKey from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureTab screenshot dimensions
* Parameters: tabKey, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key of the active tab | Yes
| x | number | X coordinate (pixels) | Yes
| y | number | Y coordinate (pixels) | Yes
</details>
<details>
<summary>clickOnReadableElement</summary>

**Description**:

```
🔘 Clicks on an element identified by its readablePath from getReadableElements
* Use this to click on elements after identifying them by their text
* Requires tabKey from getBasicBrowserContext and readablePath from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the readablePath, then use this tool
* Parameters: tabKey, readablePath
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readablePath | string | Readable path from getReadableElements | Yes
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>fillTextToReadableElement</summary>

**Description**:

```
✏️ Types text into an input field identified by its readablePath from getReadableElements
* Use this to enter text into form fields identified by their text
* Requires tabKey from getBasicBrowserContext, readablePath from getReadableElements, and text to enter
* Works with text inputs, textareas, and other editable elements
* First call getReadableElements to get the readablePath, then use this tool
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnReadableElement with that button
* If no submit button is visible, use hitEnterOnReadableElement instead
* Parameters: tabKey, readablePath, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readablePath | string | Readable path from getReadableElements | Yes
| tabKey | string | Tab key to target | Yes
| value | string | Text to enter into the input field | Yes
</details>
<details>
<summary>hitEnterOnReadableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element identified by its readablePath from getReadableElements
* Use this to trigger actions like form submission or button clicks
* Requires tabKey from getBasicBrowserContext and readablePath from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the readablePath, then use this tool
* Parameters: tabKey, readablePath
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readablePath | string | Readable path from getReadableElements | Yes
| tabKey | string | Tab key to target | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | captureTab | description | 152fb60c5e1ca8d698be64696826fadfd3011e3d6506bf10ae25eb54849f25f8 |
| tools | captureTab | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | clickOnReadableElement | description | 74103a94e481633340bf37de9227c79583b672b71474b3002c17c71be6428304 |
| tools | clickOnReadableElement | readablePath | a821ee6279e49d0e8612bd5b956e9d9d068310896baa044a2360a013e05ba670 |
| tools | clickOnReadableElement | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | clickOnViewableElement | description | d299973fae685829743762c47e7dc7e834c91cc118a8144677ea0a5843c97d39 |
| tools | clickOnViewableElement | tabKey | 1905d1d81df0a9cc7ad121903f7ce900212d89c7a0a61302e3024eb7fdc818cc |
| tools | clickOnViewableElement | x | 99e485969ccfcf64b1a19ba66225ab59a10fd001381f06eb985c786f11aa5dc7 |
| tools | clickOnViewableElement | y | 352255b47c2dd55fc1ba4cc33ee8e6ee31ac9bea2904356cf45a843cea4eb010 |
| tools | closeTab | description | 7688fa4da5c6e071bc02f9de5ea358ba1f154f88c74b92a3c03c698766b10fb9 |
| tools | closeTab | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | fillTextToReadableElement | description | d4a19ba1806b2bf8c0d22fef01a727c9f20fd89550ad15d3880d69eceaac3a8e |
| tools | fillTextToReadableElement | readablePath | a821ee6279e49d0e8612bd5b956e9d9d068310896baa044a2360a013e05ba670 |
| tools | fillTextToReadableElement | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | fillTextToReadableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | description | 0faa5e473ac318b0523b870006ae95c2fd188218cc397fd5653d30c7c5c1bfc9 |
| tools | fillTextToViewableElement | tabKey | 1905d1d81df0a9cc7ad121903f7ce900212d89c7a0a61302e3024eb7fdc818cc |
| tools | fillTextToViewableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | x | 99e485969ccfcf64b1a19ba66225ab59a10fd001381f06eb985c786f11aa5dc7 |
| tools | fillTextToViewableElement | y | 352255b47c2dd55fc1ba4cc33ee8e6ee31ac9bea2904356cf45a843cea4eb010 |
| tools | getBasicBrowserContext | description | 0efa36a8e491b8af1859fc7d3043445c97f044800c76d53244571bb51ff660b7 |
| tools | getReadableElements | description | 83421405f70f23e7e0d6360813246c2affa9b147946490d9e912e6c58c318e3d |
| tools | getReadableElements | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | getReadableText | description | 953ad929cd5f3bd90e24269390db34df662f1c6ca596b6c7982cb5a9986c16e6 |
| tools | getReadableText | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | getSelection | description | 003adda1508fb36bca5fd64a1615e2b6e6be59121f9127905bd359674dbda16b |
| tools | getSelection | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | hitEnterOnReadableElement | description | 72f368e61a6bebbb9c449c5acb16847750b21034df5666c0b95c5d42276a95cc |
| tools | hitEnterOnReadableElement | readablePath | a821ee6279e49d0e8612bd5b956e9d9d068310896baa044a2360a013e05ba670 |
| tools | hitEnterOnReadableElement | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | hitEnterOnViewableElement | description | 9497ea9d06fc3c06782c3ebcf659c262b5e73d48b42024f8542be786cef91b9a |
| tools | hitEnterOnViewableElement | tabKey | 1905d1d81df0a9cc7ad121903f7ce900212d89c7a0a61302e3024eb7fdc818cc |
| tools | hitEnterOnViewableElement | x | 99e485969ccfcf64b1a19ba66225ab59a10fd001381f06eb985c786f11aa5dc7 |
| tools | hitEnterOnViewableElement | y | 352255b47c2dd55fc1ba4cc33ee8e6ee31ac9bea2904356cf45a843cea4eb010 |
| tools | invokeJsFn | description | 346a3964a9981ab3a17b524d04e6a37546211aa6877326ee1cc4c513d383e737 |
| tools | invokeJsFn | fnBodyCode | 94e3e04f3d9fb5007d21cc65151c5c06fd599343b91a4a9ddc0825c698d3e5d0 |
| tools | invokeJsFn | tabKey | 38d6163316bb484cc05e0fabdef1292b391cb04ac7450fc0c56082586c28afdc |
| tools | openTab | description | 48fd5fe3b54a97ffa89790256789639d05029426ddad4955d5ba8a778df4569f |
| tools | openTab | url | c5c97556e9cbd94912bf77a26557f0783744994e813a89ef4d4b6c049087ff69 |
| tools | openTab | windowKey | 860d4f0888ac2e7d876f8a178933dcb83417b2a8cbc46a3fb973886ca31b0a13 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
