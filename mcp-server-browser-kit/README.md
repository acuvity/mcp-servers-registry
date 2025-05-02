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
</p>


# What is mcp-server-browser-kit?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browser-kit/5.0.1?logo=docker&logoColor=fff&label=5.0.1)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit)
[![PyPI](https://img.shields.io/badge/5.0.1-3775A9?logo=pypi&logoColor=fff&label=@mcp-browser-kit/server)](https://github.com/ndthanhdev/mcp-browser-kit)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browser-kit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-browser-kit%3A5.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** <no value>

> [!NOTE]
> `@mcp-browser-kit/server` has been repackaged by Acuvity from Author original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @mcp-browser-kit/server run reliably and safely.

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
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails that protect MCP server integrity and detect suspicious behaviors in real-time.:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions - or call arguments - reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognised tokens formats with `[REDACTED]` in outbound content.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# 📦 How to Use


> [!NOTE]
> Given mcp-server-browser-kit scope of operation the intended usage is to run natively on the targeted machine to access local resources.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browser-kit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-browser-kit%3A5.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-browser-kit:5.0.1"
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
        "docker.io/acuvity/mcp-server-browser-kit:5.0.1"
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
        "docker.io/acuvity/mcp-server-browser-kit:5.0.1"
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
        "docker.io/acuvity/mcp-server-browser-kit:5.0.1"
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
        "docker.io/acuvity/mcp-server-browser-kit:5.0.1"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-browser-kit:5.0.1"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-browser-kit:5.0.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-browser-kit:5.0.1
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browser-kit": {
      "url": "http://localhost:<localport>/sse",
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

Of course there are plenty of other options that minibridge can provide.

Don't be shy to ask question either.

</details>

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0-
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

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/charts/mcp-server-browser-kit/README.md) for more details about settings.

</details>
# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>getBasicBrowserContext</summary>

**Description**:

```
🌐 GET BROWSER CONTEXT - CRITICAL FIRST STEP BEFORE USING ANY OTHER TOOLS!
* This tool MUST be called first to initialize browser automation and get essential data.
* Returns data structure with:
  - tabs: Array of browser tabs with properties like id, url, title, and active status
  - manifestVersion: Version of extension manifest format supported by the browser
* Each tab includes a unique tabId required for all other tool operations
* The active tab (marked with 'active: true') is typically your target for automation
* The manifestVersion determines which browser features and extension capabilities are available
* Different browsers support different manifest versions, affecting available tools and API access
* Standard workflow:
  1) getBasicBrowserContext → get browser state and tabId
  2) Analyze page content based on your goal and manifest version:
     - If interaction is required (clicking, filling forms, etc.):
       · For Manifest Version 2: Use captureActiveTab for visual context or getReadableElements for element identification
       · For other Manifest Versions: Use only getReadableElements for element identification
     - If no interaction is required (just reading page content):
       · Use getInnerText to extract all visible text from the page
  3) Interact using click/fill/enter tools with the obtained tabId
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>captureActiveTab</summary>

**Description**:

```

📷 Captures a screenshot of the active browser tab
* Use this tool after calling getBasicBrowserContext to obtain visual context of the current page
* The screenshot helps you see what the browser is displaying to the user
* No parameters are needed as it automatically captures the active tab
* Returns an image with width, height, and data in base64 format
* Workflow: 1) getBasicBrowserContext → 2) captureActiveTab → 3) interact with elements
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>getInnerText</summary>

**Description**:

```
📝 Extracts all text content from the current web page
* Retrieves all visible text from the active tab
* Requires the tabId obtained from getBasicBrowserContext
* Use this to analyze the page content without visual elements
* Returns a string containing all the text on the page
* Useful for getting a quick overview of page content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID to extract text from | Yes
</details>
<details>
<summary>getReadableElements</summary>

**Description**:

```
🔍 Lists all interactive elements on the page with their text
* Returns a list of elements with their index, HTML tag, and text content
* Requires the tabId obtained from getBasicBrowserContext
* Each element is returned as [index, tag, text]
* Use the index to interact with elements through click or fill operations
* Helps you identify which elements can be interacted with by their text
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID to extract elements from | Yes
</details>
<details>
<summary>clickOnViewableElement</summary>

**Description**:

```
👆 Clicks on an element at specific X,Y coordinates
* Use this to click on elements by their position on the screen
* Requires tabId from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureActiveTab screenshot dimensions
* Useful when you know the visual position of an element
* Parameters: tabId, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID of the active tab | Yes
| x | number | X coordinate (pixels) of the element to click | Yes
| y | number | Y coordinate (pixels) of the element to click | Yes
</details>
<details>
<summary>fillTextToViewableElement</summary>

**Description**:

```
⌨️ Types text into an input field at specific X,Y coordinates
* Use this to enter text into form fields by their position
* Requires tabId from getBasicBrowserContext, x,y coordinates, and the text to enter
* Coordinates are based on the captureActiveTab screenshot dimensions
* First clicks at the specified position, then types the provided text
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnViewableElement with that button
* If no submit button is visible, use hitEnterOnViewableElement instead
* Parameters: tabId, x, y, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID of the active tab | Yes
| value | string | Text to enter into the input field | Yes
| x | number | X coordinate (pixels) of the input element | Yes
| y | number | Y coordinate (pixels) of the input element | Yes
</details>
<details>
<summary>hitEnterOnViewableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element at specific X,Y coordinates
* Use this to trigger actions like form submission or button clicks
* Requires tabId from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureActiveTab screenshot dimensions
* Parameters: tabId, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID of the active tab | Yes
| x | number | X coordinate (pixels) of the input element | Yes
| y | number | Y coordinate (pixels) of the input element | Yes
</details>
<details>
<summary>clickOnReadableElement</summary>

**Description**:

```
🔘 Clicks on an element identified by its index from getReadableElements
* Use this to click on elements after identifying them by their text
* Requires tabId from getBasicBrowserContext and index from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the index, then use this tool
* Parameters: tabId, index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Element index from getReadableElements | Yes
| tabId | string | Tab ID to target | Yes
</details>
<details>
<summary>fillTextToReadableElement</summary>

**Description**:

```
✏️ Types text into an input field identified by its index from getReadableElements
* Use this to enter text into form fields identified by their text
* Requires tabId from getBasicBrowserContext, index from getReadableElements, and text to enter
* Works with text inputs, textareas, and other editable elements
* First call getReadableElements to get the index, then use this tool
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnReadableElement with that button
* If no submit button is visible, use hitEnterOnReadableElement instead
* Parameters: tabId, index, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Element index from getReadableElements | Yes
| tabId | string | Tab ID to target | Yes
| value | string | Text to enter into the input field | Yes
</details>
<details>
<summary>hitEnterOnReadableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element identified by its index from getReadableElements
* Use this to trigger actions like form submission or button clicks
* Requires tabId from getBasicBrowserContext and index from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the index, then use this tool
* Parameters: tabId, index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Element index from getReadableElements | Yes
| tabId | string | Tab ID to target | Yes
</details>
<details>
<summary>invokeJsFn</summary>

**Description**:

```
⚙️ Executes custom JavaScript code in the context of the web page
* Use this for advanced operations not covered by other tools
* Requires tabId from getBasicBrowserContext and JavaScript code to execute
* The code should be the body of a function that returns a value
* Example: 'return document.title;' to get the page title
* Gives you full flexibility for custom browser automation
* Parameters: tabId, fnBodyCode (JavaScript code as string)
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fnBodyCode | string | JavaScript function body to execute in page context | Yes
| tabId | string | Tab ID to run JavaScript in | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | captureActiveTab | description | af2fce241e21a76efa4e308a4e0063945e0b1752cb63e107a28e2a5031313851 |
| tools | clickOnReadableElement | description | 0438df73af4298fd9ec61c2247a0194f476bb8897d5ed905c174e4aad43176c2 |
| tools | clickOnReadableElement | index | 00ce0f742d8f01096ec9c784fdc8602c4c23d2c6892a28f66da5be7b339602b4 |
| tools | clickOnReadableElement | tabId | ab47f3937da53de3304fcdc69fc699789b345e543a90bff7f350152c4cbec94e |
| tools | clickOnViewableElement | description | 7aa07ce61e8fb1ea991061d521b95bb4dc12b3d883e02a5de0c01a55a5156976 |
| tools | clickOnViewableElement | tabId | cdbb31fdde2736d3de4f8ad98c1cfacbd2480c4d36538ef4b17087ed9a85b1dd |
| tools | clickOnViewableElement | x | 59b39337c4a10dcfead421def1e8e8c734c8359009c377b78f2b00e765e3831a |
| tools | clickOnViewableElement | y | 2c8254757572058da51b836876a7d89ff7784fe35c4d44a83da57be0cba46aa5 |
| tools | fillTextToReadableElement | description | 131ce07e5e32af2472619d8e9d496c901d5ea91f9eb509306f5f0e30a22b6fa4 |
| tools | fillTextToReadableElement | index | 00ce0f742d8f01096ec9c784fdc8602c4c23d2c6892a28f66da5be7b339602b4 |
| tools | fillTextToReadableElement | tabId | ab47f3937da53de3304fcdc69fc699789b345e543a90bff7f350152c4cbec94e |
| tools | fillTextToReadableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | description | e575ce47b46f93cdaaba248d3cc71958ab0bbd1bf744f31ccc05f0b581abd8d7 |
| tools | fillTextToViewableElement | tabId | cdbb31fdde2736d3de4f8ad98c1cfacbd2480c4d36538ef4b17087ed9a85b1dd |
| tools | fillTextToViewableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | x | 9ff70902c61f20d5928afc1078266d27bfae4e9a7f6bb0bd047907297e01d640 |
| tools | fillTextToViewableElement | y | 1e12d399a5a2b45739d01e30f9085c451692a8cfc68c3b25ae317573a6c649f4 |
| tools | getBasicBrowserContext | description | fbaacf1500b361281d9a9317b0b9d831596d4add5657fb3373efc931386e91c6 |
| tools | getInnerText | description | 533f548f87b146e20d054aa3dc6bcda97e79ddfb22a19fe4f5aee630647dc38d |
| tools | getInnerText | tabId | 46915f32fdbc787d332e2d237392bdd37e28a82bb9e132c4cc58b202bc9528fb |
| tools | getReadableElements | description | 4d48b9ab52fd816fbdd12d8b3c37236d187d4fd86fd4a91e6bcfef6b0e1215ed |
| tools | getReadableElements | tabId | 77da1d8b6cc995c38f0b0558fa9212aa7bdcd7ec325b556349dde7a53d4ec534 |
| tools | hitEnterOnReadableElement | description | d2d465c9904dee4b69dfb1504a65bfa3b42c6b01b32a8963e8ccc2331b021dc8 |
| tools | hitEnterOnReadableElement | index | 00ce0f742d8f01096ec9c784fdc8602c4c23d2c6892a28f66da5be7b339602b4 |
| tools | hitEnterOnReadableElement | tabId | ab47f3937da53de3304fcdc69fc699789b345e543a90bff7f350152c4cbec94e |
| tools | hitEnterOnViewableElement | description | 22a380bd11cb1e39f302a6a94452901bb2f5ecc0decb4d9ae038cc18997bc56a |
| tools | hitEnterOnViewableElement | tabId | cdbb31fdde2736d3de4f8ad98c1cfacbd2480c4d36538ef4b17087ed9a85b1dd |
| tools | hitEnterOnViewableElement | x | 9ff70902c61f20d5928afc1078266d27bfae4e9a7f6bb0bd047907297e01d640 |
| tools | hitEnterOnViewableElement | y | 1e12d399a5a2b45739d01e30f9085c451692a8cfc68c3b25ae317573a6c649f4 |
| tools | invokeJsFn | description | 2c31aecf416b17b6875d32778025efffd41943254f213a806892117f0d0633f3 |
| tools | invokeJsFn | fnBodyCode | 32bb4de35be8ab9939cd4881e9390f4702545ad99169cceddbe70fcb1efbc8ab |
| tools | invokeJsFn | tabId | 7cf618734c4a34ebe0999b4bea3fc172c6f7f07710d924d9e3df406aa946f1fb |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
