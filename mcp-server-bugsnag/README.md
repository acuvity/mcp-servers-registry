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


# What is mcp-server-bugsnag?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-bugsnag/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-bugsnag/1.1.0?logo=docker&logoColor=fff&label=1.1.0)](https://hub.docker.com/r/acuvity/mcp-server-bugsnag)
[![PyPI](https://img.shields.io/badge/1.1.0-3775A9?logo=pypi&logoColor=fff&label=bugsnag-mcp-server)](https://github.com/tgeselle/bugsnag-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bugsnag&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BUGSNAG_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-bugsnag%3A1.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** An MCP server for interacting with Bugsnag.

> [!NOTE]
> `bugsnag-mcp-server` has been repackaged by Acuvity from Author original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure bugsnag-mcp-server run reliably and safely.

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
> Given mcp-server-bugsnag scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bugsnag&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BUGSNAG_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-bugsnag%3A1.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-bugsnag": {
        "env": {
          "BUGSNAG_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "BUGSNAG_API_KEY",
          "docker.io/acuvity/mcp-server-bugsnag:1.1.0"
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
    "acuvity-mcp-server-bugsnag": {
      "env": {
        "BUGSNAG_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BUGSNAG_API_KEY",
        "docker.io/acuvity/mcp-server-bugsnag:1.1.0"
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
    "acuvity-mcp-server-bugsnag": {
      "env": {
        "BUGSNAG_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BUGSNAG_API_KEY",
        "docker.io/acuvity/mcp-server-bugsnag:1.1.0"
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
    "acuvity-mcp-server-bugsnag": {
      "env": {
        "BUGSNAG_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BUGSNAG_API_KEY",
        "docker.io/acuvity/mcp-server-bugsnag:1.1.0"
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
    "acuvity-mcp-server-bugsnag": {
      "env": {
        "BUGSNAG_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BUGSNAG_API_KEY",
        "docker.io/acuvity/mcp-server-bugsnag:1.1.0"
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
        "env": {"BUGSNAG_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BUGSNAG_API_KEY","docker.io/acuvity/mcp-server-bugsnag:1.1.0"]
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
  - `BUGSNAG_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e BUGSNAG_API_KEY docker.io/acuvity/mcp-server-bugsnag:1.1.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e BUGSNAG_API_KEY docker.io/acuvity/mcp-server-bugsnag:1.1.0
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-bugsnag": {
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
    "acuvity-mcp-server-bugsnag": {
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
  - `BUGSNAG_API_KEY` secret to be set as secrets.BUGSNAG_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0
````

Install with helm

```console
helm install mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0
```

From there your MCP server mcp-server-bugsnag will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-bugsnag` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bugsnag/charts/mcp-server-bugsnag/README.md) for more details about settings.

</details>

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>list_organizations</summary>

**Description**:

```
List available Bugsnag organizations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_projects</summary>

**Description**:

```
List projects in an organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organization_id | string | Bugsnag organization ID | Yes
</details>
<details>
<summary>list_errors</summary>

**Description**:

```
List errors in a project with filtering options
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of errors to return | No
| project_id | string | Bugsnag project ID | Yes
| sort | string | Sort order for errors | No
| status | string | Filter by error status | No
</details>
<details>
<summary>view_error</summary>

**Description**:

```
Get detailed information about a specific error
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| error_id | string | Bugsnag error ID | Yes
</details>
<details>
<summary>list_error_events</summary>

**Description**:

```
List events (occurrences) for a specific error
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| error_id | string | Bugsnag error ID | Yes
| limit | number | Maximum number of events to return | No
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>view_latest_event</summary>

**Description**:

```
View the latest event for an error
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| error_id | string | Bugsnag error ID | Yes
</details>
<details>
<summary>view_event</summary>

**Description**:

```
View detailed information about a specific event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>view_stacktrace</summary>

**Description**:

```
Extract and format stacktrace information from an event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| include_code | boolean | Include source code context if available | No
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>view_exception_chain</summary>

**Description**:

```
View the full chain of exceptions for an event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>search_issues</summary>

**Description**:

```
Search for issues using various criteria
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_version | string | Filter by app version | No
| error_class | string | Filter by error class | No
| project_id | string | Bugsnag project ID | Yes
| query | string | Search query | No
</details>
<details>
<summary>view_tabs</summary>

**Description**:

```
View all event data tabs including app, device, user, request, breadcrumbs, metadata, and stacktrace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| include_code | boolean | Include source code context in stacktrace if available | No
| project_id | string | Bugsnag project ID | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | list_error_events | description | 95ac8451451be25e3b7e27dac898fa642c66b1700c5cdf484468c9ddbb973ee6 |
| tools | list_error_events | error_id | 9f4225714bc44a8c55c2813c4140538451ad9f31ef7be2671a52519ba55b05bb |
| tools | list_error_events | limit | 638a93c649b59360158a5be8a53da904c181d6c7911ba09da7b827febdc1c939 |
| tools | list_error_events | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | list_errors | description | 343fde21d5ef61a6def43d08570a90cc3e320223c0702c7ace02ec6f68c6848c |
| tools | list_errors | limit | c6a4ce4be531e8abe4e8cf45c39169cafbf40248b465ca2a8f5b76d1d31592b3 |
| tools | list_errors | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | list_errors | sort | b26b0f86e0464ed8865f56f254fea435956e331f85685cb7c7ab5a7f4f35906f |
| tools | list_errors | status | bdb568d58ab98a5c2fd8342c9b0f4f14b673ffabdd64033485a42a46e2acefaa |
| tools | list_organizations | description | 8afc1eab04f56a9b4fdf6305f377aa96240e555e8e3916b5b8695b373ea713b1 |
| tools | list_projects | description | a25a925729c7debbd803810b21c2559d9ae36906eb9000e8f65d48f625ccfca2 |
| tools | list_projects | organization_id | 8f90850f7f18622ceb36614e8c069c8dd8353d2d1d5cba2a7faa2be3fc6534f2 |
| tools | search_issues | description | d6bcfe5083b67eb6fa9ed186eaffc68c733cd532fe7d062e852d4df759e565b6 |
| tools | search_issues | app_version | fc9f6edcf3a7752f37fb69ee272f675c87e5f10fe7d02bd10b548ffd383b5985 |
| tools | search_issues | error_class | 34f1e02240bd200e89ad6994eb8d45d58f7226eb43b99030c159ca938aee3f9a |
| tools | search_issues | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | search_issues | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | view_error | description | dbe777675200bd5b7f376ca368e5e6a81a5fdce885d7f9b24cbc26c2f1bf87db |
| tools | view_error | error_id | 9f4225714bc44a8c55c2813c4140538451ad9f31ef7be2671a52519ba55b05bb |
| tools | view_event | description | 9eafe212e950a93be6089d71b93bad82cd952c3a63659002bede4f533a4ac51d |
| tools | view_event | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_event | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | view_exception_chain | description | 5f53457b2818ea05716ee8d3bf8064834fa19c8834d03e0e4cfdede2dedd3b9f |
| tools | view_exception_chain | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_exception_chain | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | view_latest_event | description | 1a2b42bbe55740f8c673eb2ce2040f3879974eb35b9049362d8c37cc05a04c2f |
| tools | view_latest_event | error_id | 9f4225714bc44a8c55c2813c4140538451ad9f31ef7be2671a52519ba55b05bb |
| tools | view_stacktrace | description | 34478499b6a4bd894d494bb0169d647958ea4d7e8d001fcad3f9a0c9e462fadc |
| tools | view_stacktrace | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_stacktrace | include_code | eb3d98dc6c160ca4d6f25a2ca54a91832bf9cebfedb9520ff0fb3a0e7302e308 |
| tools | view_stacktrace | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | view_tabs | description | f7b2ea218184ab7be36e4c5064e4778fbfafd3f3e54b50ee5110ddf66e6547b9 |
| tools | view_tabs | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_tabs | include_code | 09329bf315973856f11d898f676bd20fb93bc07e9e120232af626f0bfb41fabd |
| tools | view_tabs | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
