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


# What is mcp-server-browserbase?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browserbase/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browserbase/0.5.1?logo=docker&logoColor=fff&label=0.5.1)](https://hub.docker.com/r/acuvity/mcp-server-browserbase)
[![PyPI](https://img.shields.io/badge/0.5.1-3775A9?logo=pypi&logoColor=fff&label=@browserbasehq/mcp-browserbase)](https://github.com/browserbase/mcp-server-browserbase)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A0.5.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for browser automation using browserbase

> [!NOTE]
> `@browserbasehq/mcp-browserbase` has been repackaged by Acuvity from Anthropic, PBC original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @browserbasehq/mcp-browserbase run reliably and safely.

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
> Given mcp-server-browserbase scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A0.5.1%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-browserbase:0.5.1"
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
        "docker.io/acuvity/mcp-server-browserbase:0.5.1"
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
        "docker.io/acuvity/mcp-server-browserbase:0.5.1"
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
        "docker.io/acuvity/mcp-server-browserbase:0.5.1"
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
        "docker.io/acuvity/mcp-server-browserbase:0.5.1"
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
        "args": ["run","-i","--rm","--read-only","-e","BROWSERBASE_API_KEY","-e","BROWSERBASE_PROJECT_ID","docker.io/acuvity/mcp-server-browserbase:0.5.1"]
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
**Environment variables:**
  - `BROWSERBASE_API_KEY` required to be set
  - `BROWSERBASE_PROJECT_ID` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e BROWSERBASE_API_KEY -e BROWSERBASE_PROJECT_ID docker.io/acuvity/mcp-server-browserbase:0.5.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e BROWSERBASE_API_KEY -e BROWSERBASE_PROJECT_ID docker.io/acuvity/mcp-server-browserbase:0.5.1
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-browserbase": {
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
    "acuvity-mcp-server-browserbase": {
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

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `BROWSERBASE_API_KEY` secret to be set as secrets.BROWSERBASE_API_KEY either by `.value` or from existing with `.valueFrom`
  - `BROWSERBASE_PROJECT_ID` secret to be set as secrets.BROWSERBASE_PROJECT_ID either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0-
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

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/charts/mcp-server-browserbase/README.md) for more details about settings.

</details>
# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>browserbase_create_session</summary>

**Description**:

```
Create a new cloud browser session using Browserbase
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_close_session</summary>

**Description**:

```
Close a browser session on Browserbase
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | <no value> | Yes
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
| url | string | <no value> | Yes
</details>
<details>
<summary>browserbase_screenshot</summary>

**Description**:

```
Take a screenshot of the current page or a specific element
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | Height in pixels (default: 600) | No
| name | string | Name for the screenshot | Yes
| selector | string | CSS selector for element to screenshot | No
| width | number | Width in pixels (default: 800) | No
</details>
<details>
<summary>browserbase_click</summary>

**Description**:

```
Click an element on the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for element to click | Yes
</details>
<details>
<summary>browserbase_fill</summary>

**Description**:

```
Fill out an input field
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for input field | Yes
| value | string | Value to fill | Yes
</details>
<details>
<summary>browserbase_evaluate</summary>

**Description**:

```
Execute JavaScript in the browser console
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| script | string | JavaScript code to execute | Yes
</details>
<details>
<summary>browserbase_get_content</summary>

**Description**:

```
Extract all content from the current page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | Optional CSS selector to get content from specific elements (default: returns whole page) | No
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Browser console logs | text/plain | console://logs | <no value> |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | browserbase_click | description | 0f5e4e9a2e49b9860eacc68a7dc5312c71ab2f83be1734dcddbc8ce31fc7d82b |
| tools | browserbase_click | selector | a6922769712660b619584746585d94b11a460d199e2cb84957988b6f9f7cd3bf |
| tools | browserbase_close_session | description | be033dac5747af43f17a5e254bd24af517866cab1af756a72549b19d9292a250 |
| tools | browserbase_create_session | description | 56bdd0db0c370258b7b7ef2d4604f7602a46d68d3f7cdae47dcf8bb48305c774 |
| tools | browserbase_evaluate | description | 0d3a0f5f637a3ca339c8c9bef048bb7db6e97e99b3e930af4f90036cf0ae0eac |
| tools | browserbase_evaluate | script | 4b891a8ea8149f7f674a0058530d3027453331b59fdc8dd937f97530abe2917d |
| tools | browserbase_fill | description | 9092ab55b68d8d48b44cd4637d7c45d295489784406d1d0b2811c64eb390c12e |
| tools | browserbase_fill | selector | 9b2fd4f2a301cda1ab585f8de553e53bf5907a4b15ee68f56f075d6e57464d23 |
| tools | browserbase_fill | value | 11d5ebd4e421f3e0f32524bf28a9c06bfce4a5f82b89ad49f4636dce92377c8f |
| tools | browserbase_get_content | description | 6105d7f8013e0ad9af3aeaeb5638755ccc8337aeb2e402ea526aead14e030569 |
| tools | browserbase_get_content | selector | cf9b6a9a4d253d7e4cbb921429945fcc70861aebf48bd8c8a0e6c61201352ade |
| tools | browserbase_navigate | description | 5e517ac29796df4781d6e8f8b3be061cc694f0c8e027f40e42ce0739e887b1d5 |
| tools | browserbase_screenshot | description | 5e3558916850d55baa3a9b5dfaec0755a8c16f6bcd03be7a78aadbc65745da85 |
| tools | browserbase_screenshot | height | 0e240884937c1dc91c541aaeceb007bb3bb0994e396a1652edb748fa6198615d |
| tools | browserbase_screenshot | name | 28c1b883362fcf9a1205e2015271212cbc322322343879408bd5b191917b3379 |
| tools | browserbase_screenshot | selector | aa5efe3a86a6ab130c1c81e671113a8be57294dedf3bbde39fe0088fea2c14d5 |
| tools | browserbase_screenshot | width | d10864eef69042788f00ea5522b84a05480ff9a1479b27cc6cdfa409a2304060 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
