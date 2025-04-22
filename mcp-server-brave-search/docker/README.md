
<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://mma.prnewswire.com/media/2544052/Acuvity__Logo.jpg" height="90" alt="Acuvity logo"/>
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://discord.gg/BkU7fBkrNk">
    <img src="https://img.shields.io/badge/Acuvity-Join-7289DA?logo=discord&logoColor=fff)](https://discord.gg/BkU7fBkrNk" alt="Join Acuvity community" /></a>
<a href="https://www.linkedin.com/company/acuvity/">
    <img src="https://img.shields.io/badge/LinkedIn-follow-0a66c2" alt="Follow us on LinkedIn" />
  </a>
</p>


# What is mcp-server-brave-search?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-brave-search?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-brave-search/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-brave-search/tags)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-brave-search)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for Brave Search API integration

> [!NOTE]
> `@modelcontextprotocol/server-brave-search` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-brave-search run reliably and safely.

## 🔐 Key Security Features

<details>
<summary>📦 Isolated Immutable Sandbox </summary>

- **Isolated Execution**: All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.
- **Non-root by Default**: Enforces least-privilege principles, minimizing the impact of potential security breaches.
- **Read-only Filesystem**: Ensures runtime immutability, preventing unauthorized modification.
- **Version Pinning**: Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.
- **CVE Scanning**: Continuously monitors for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation.
- **SBOM & Provenance**: Provides full supply chain transparency with embedded metadata and traceable build information.
</details>

<details>
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails to protect MCP server integrity and detect suspicious behavior:

- **Integrity via Hashing**: Verifies the authenticity and integrity of tool descriptors and runtime components.
- **Threat Detection**:
  - Detects hidden or covert instruction patterns.
  - Monitors for schema parameter misuse as potential exfiltration channels.
  - Flags unauthorized access to sensitive files or credentials.
  - Identifies tool shadowing and override attempts.
  - Enforces cross-origin and server-mismatch protection policies.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# Quick reference

**Maintained by**:
  - [Acuvity team](mailto:support@acuvity.ai) for packaging
  - [ Anthropic, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [The Acuvity community Discord](https://discord.gg/BkU7fBkrNk)
  - [ @modelcontextprotocol/server-brave-search ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-brave-search ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Base image**:
  - `node:23.11.0-alpine3.21`

**Dockerfile**:
  - `https://github.com/acuvity/mcp-servers-registry/mcp-server-brave-search/docker/Dockerfile`

**Current supported tag:**
  - `latest` -> `0.6.2`

> [!TIP]
> See [Docker Hub Tags](https://hub.docker.com/r/acuvity/mcp-server-brave-search/tags) section for older tags.

# 📦 How to Use


> [!NOTE]
> Given mcp-server-brave-search scope of operation it can be hosted anywhere.

## 🐳 With Docker
**Environment variables:**
  - `BRAVE_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e BRAVE_API_KEY docker.io/acuvity/mcp-server-brave-search:0.6.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e BRAVE_API_KEY docker.io/acuvity/mcp-server-brave-search:0.6.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-brave-search": {
      "url": "http://localhost:<localport>/sse",
    }
  }
}
```

You might have to use different ports for different tools.

</details>

<details>
<summary>Remotely with Websocket tunneling and MTLS </summary>

> This section assume you are familar with TLS and certificates and will require:
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
    "acuvity-mcp-server-brave-search": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Of course there is plenty of other option that minibridge can provide.

Don't be shy to ask question either.

</details>

## ☁️ On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `BRAVE_API_KEY` secret to be set as secrets.BRAVE_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-brave-search/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-brave-search --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-brave-search --version <version>
````

Install with helm

```console
helm install mcp-server-brave-search oci://docker.io/acuvity/mcp-server-brave-search --version <version>
```

From there your MCP server mcp-server-brave-search will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-brave-search` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.


</details>

# 🧰 Integrations

> [!NOTE]
> All the integrations below should work natively for all run mode.
> Only the `docker` local run is described to keep it concise.

<details>
<summary>Visual Studio Code</summary>

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-brave-search": {
        "env":
          {"BRAVE_API_KEY":"xxxxxx"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BRAVE_API_KEY","docker.io/acuvity/mcp-server-brave-search:0.6.2"]
      }
    }
  }
}
```

## Workspace scope

In your workspace createa file called `.vscode/mcp.json` and add the following section:

```json
{
  "servers": {
    "acuvity-mcp-server-brave-search": {
      "env":
        {"BRAVE_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","BRAVE_API_KEY","docker.io/acuvity/mcp-server-brave-search:0.6.2"]
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
    "acuvity-mcp-server-brave-search": {
      "env":
        {"BRAVE_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","BRAVE_API_KEY","docker.io/acuvity/mcp-server-brave-search:0.6.2"]
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
    "acuvity-mcp-server-brave-search": {
      "env":
        {"BRAVE_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","BRAVE_API_KEY","docker.io/acuvity/mcp-server-brave-search:0.6.2"]
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
    "acuvity-mcp-server-brave-search": {
      "env":
        {"BRAVE_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","BRAVE_API_KEY","docker.io/acuvity/mcp-server-brave-search:0.6.2"]
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
        "env": {"BRAVE_API_KEY":"xxxxxx"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BRAVE_API_KEY","docker.io/acuvity/mcp-server-brave-search:0.6.2"]
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

# 🧠 Server features

## 🧰 Tools (2)
<details>
<summary>brave_web_search</summary>

**Description**:

```
Performs a web search using the Brave Search API, ideal for general queries, news, articles, and online content. Use this for broad information gathering, recent events, or when you need diverse web sources. Supports pagination, content filtering, and freshness controls. Maximum 20 results per request, with offset for pagination. 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of results (1-20, default 10) | No
| offset | number | Pagination offset (max 9, default 0) | No
| query | string | Search query (max 400 chars, 50 words) | Yes
</details>
<details>
<summary>brave_local_search</summary>

**Description**:

```
Searches for local businesses and places using Brave's Local Search API. Best for queries related to physical locations, businesses, restaurants, services, etc. Returns detailed information including:
- Business names and addresses
- Ratings and review counts
- Phone numbers and opening hours
Use this when the query implies 'near me' or mentions specific locations. Automatically falls back to web search if no local results are found.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of results (1-20, default 5) | No
| query | string | Local search query (e.g. 'pizza near Central Park') | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | brave_local_search | description | 97ccad25df6ac33448532db7212f0b1d3e7a851e509e944771d08556e09657c3 |
| tools | brave_local_search | count | 74e521e182e909cddfcbda8dd5d7348b555723e1bbf4b5b941b16b27db9ef45f |
| tools | brave_local_search | query | 67466c184ee5cd1699936f4664febb33d241182ab45de7f954f45c9bb2d15655 |
| tools | brave_web_search | description | a47775f5ab8d350d58decc4839a503d8a669e81dfa2ba92c2f43b6c25ee0b3e7 |
| tools | brave_web_search | count | d99d96671d2cf62878aac47e9128a0f2cd60ea0fed87a130fb74059460a097f8 |
| tools | brave_web_search | offset | 8b090f5097253d9a2172e77da116548030d94ed60d638bffa6e9b498b81b7d1a |
| tools | brave_web_search | query | c2ba04de27eb39eb0c5d0205ae19e9d79907d8716d346a49c78a584568075ed2 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
