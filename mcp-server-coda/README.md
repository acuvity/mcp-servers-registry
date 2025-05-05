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


# What is mcp-server-coda?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-coda/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-coda/1.1.2?logo=docker&logoColor=fff&label=1.1.2)](https://hub.docker.com/r/acuvity/mcp-server-coda)
[![PyPI](https://img.shields.io/badge/1.1.2-3775A9?logo=pypi&logoColor=fff&label=coda-mcp)](https://github.com/orellazri/coda-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-coda&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_KEY%22%2C%22-e%22%2C%22DOC_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-coda%3A1.1.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for Coda.

> [!NOTE]
> `coda-mcp` has been repackaged by Acuvity from Author original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure coda-mcp run reliably and safely.

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
> Given mcp-server-coda scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-coda&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_KEY%22%2C%22-e%22%2C%22DOC_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-coda%3A1.1.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-coda": {
        "env": {
          "API_KEY": "TO_BE_SET",
          "DOC_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "API_KEY",
          "-e",
          "DOC_ID",
          "docker.io/acuvity/mcp-server-coda:1.1.2"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.1.2"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.1.2"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.1.2"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.1.2"
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
        "env": {"API_KEY":"TO_BE_SET","DOC_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","API_KEY","-e","DOC_ID","docker.io/acuvity/mcp-server-coda:1.1.2"]
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
  - `API_KEY` required to be set
  - `DOC_ID` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e API_KEY -e DOC_ID docker.io/acuvity/mcp-server-coda:1.1.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e API_KEY -e DOC_ID docker.io/acuvity/mcp-server-coda:1.1.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-coda": {
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
    "acuvity-mcp-server-coda": {
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
  - `API_KEY` secret to be set as secrets.API_KEY either by `.value` or from existing with `.valueFrom`
  - `DOC_ID` secret to be set as secrets.DOC_ID either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-coda --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
````

Install with helm

```console
helm install mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
```

From there your MCP server mcp-server-coda will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-coda` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/charts/mcp-server-coda/README.md) for more details about settings.

</details>

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>list-pages</summary>

**Description**:

```
List pages in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create-page</summary>

**Description**:

```
Create a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content of the page to create - optional | No
| name | string | The name of the page to create | Yes
</details>
<details>
<summary>get-page-content</summary>

**Description**:

```
Get the content of a page as markdown
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pageIdOrName | string | The ID or name of the page to get the content of | Yes
</details>
<details>
<summary>replace-page-content</summary>

**Description**:

```
Replace the content of a page with new markdown content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content to replace the page with | Yes
| pageIdOrName | string | The ID or name of the page to replace the content of | Yes
</details>
<details>
<summary>append-page-content</summary>

**Description**:

```
Append new markdown content to the end of a page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content to append to the page | Yes
| pageIdOrName | string | The ID or name of the page to append the content to | Yes
</details>
<details>
<summary>duplicate-page</summary>

**Description**:

```
Duplicate a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| newName | string | The name of the new page | Yes
| pageIdOrName | string | The ID or name of the page to duplicate | Yes
</details>
<details>
<summary>rename-page</summary>

**Description**:

```
Rename a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| newName | string | The new name of the page | Yes
| pageIdOrName | string | The ID or name of the page to rename | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | append-page-content | description | d6eb83d5da34ae32ee47e049bfde75b03ca3a7b48c59a3195bb611f69629728c |
| tools | append-page-content | content | 5a10ac2f054a77da9b7959abb4bacdb04cb96dec1697272b5ac8dcd8fb270172 |
| tools | append-page-content | pageIdOrName | 2953a62ac23fd91570996571f459640e50db43ba7acfb27295ce332f276a9205 |
| tools | create-page | description | cc5fb25691258d75039b01e76e47c55ca99243a51ca0a1ca8316d5f9ecf4642e |
| tools | create-page | content | 22bd8cb205205d5c8826180ff748095de56dad85b69aa7d9f3e425e6d7e8f0f8 |
| tools | create-page | name | 9200c858ffe87b34c08415c39d7e1111124dc7fbbe8bf606365936cf08fabdb8 |
| tools | duplicate-page | description | 4c2496f1d91db963e00ce499c6a64ce127e3e1789f51b7674d9053fc9f11c627 |
| tools | duplicate-page | newName | 8cc9888bfa04926d724ebdfd4283bf915e056c54d7b9568b8c2c0409b00558d7 |
| tools | duplicate-page | pageIdOrName | 23b139479cb7b4beb87d1d9833534d7c323f2db9feb871a75c81fb3abdb58ff4 |
| tools | get-page-content | description | 6e954360c948036e80de20759d8e143ca665cdc6375a04d22b7fe7e79c411277 |
| tools | get-page-content | pageIdOrName | 2660e996c27d04bf1e63551dcf2f49e3414bb72b0a97bf7fce8220bd324b64bf |
| tools | list-pages | description | b70da335dd3f3b775908abe23d3fabc8d2e4c7228c8bb342fbee8c163ca48d45 |
| tools | rename-page | description | 037a2e1ce43e2a3eb82f6b3aa83f5e9dafdce96ffaa5186702482bf458a194b6 |
| tools | rename-page | newName | 47633c3d0d36d0564492d812ff19826f72d7b172b3eacad87b98f8246491662a |
| tools | rename-page | pageIdOrName | ffb5e62092ae083458b493ad20c66b6f1277f4a3bf8d35715baf351163449b8f |
| tools | replace-page-content | description | 159be8ca055b41aafbe9770117c4f1579a454f2baaba9b20f33682d5273bcc5c |
| tools | replace-page-content | content | d18f6633054b57d9534e835c3be08e87ef9588cb7127e43e4f0b51449683b75c |
| tools | replace-page-content | pageIdOrName | 54bbde434915298761a0e41ef26c250776e2129a4dc3e682586ca51f8bbc0c3b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
