
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


# What is mcp-server-sanity-base?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-sanity-base?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-sanity-base/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-sanity-base/tags)
[![PyPI](https://img.shields.io/badge/2025.4.8-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-everything)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server that exercises all the features of the MCP protocol

> [!NOTE]
> `@modelcontextprotocol/server-everything` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-everything run reliably and safely.

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
  - [ @modelcontextprotocol/server-everything ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-everything ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Base image**:
  - `node:23.11.0-alpine3.21`

**Dockerfile**:
  - `https://github.com/acuvity/mcp-servers-registry/mcp-server-sanity-base/docker/Dockerfile`

**Current supported tag:**
  - `latest` -> `2025.4.8`

> [!TIP]
> See [Docker Hub Tags](https://hub.docker.com/r/acuvity/mcp-server-sanity-base/tags) section for older tags.

# 📦 How to Use


> [!NOTE]
> Given mcp-server-sanity-base scope of operation it can be hosted anywhere.
> But keep in mind that this keep a persistent state and that is not meant to be used by several client at the same time.

## 🐳 With Docker


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-sanity-base:2025.4.8`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-sanity-base:2025.4.8
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-sanity-base": {
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
    "acuvity-mcp-server-sanity-base": {
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

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-sanity-base/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-sanity-base --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-sanity-base --version <version>
````

Install with helm

```console
helm install mcp-server-sanity-base oci://docker.io/acuvity/mcp-server-sanity-base --version <version>
```

From there your MCP server mcp-server-sanity-base will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-sanity-base` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

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
      "acuvity-mcp-server-sanity-base": {
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sanity-base:2025.4.8"]
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
    "acuvity-mcp-server-sanity-base": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sanity-base:2025.4.8"]
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
    "acuvity-mcp-server-sanity-base": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sanity-base:2025.4.8"]
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
    "acuvity-mcp-server-sanity-base": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sanity-base:2025.4.8"]
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
    "acuvity-mcp-server-sanity-base": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sanity-base:2025.4.8"]
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sanity-base:2025.4.8"]
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

## 🧰 Tools (8)
<details>
<summary>echo</summary>

**Description**:

```
Echoes back the input
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | Message to echo | Yes
</details>
<details>
<summary>add</summary>

**Description**:

```
Adds two numbers
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| a | number | First number | Yes
| b | number | Second number | Yes
</details>
<details>
<summary>printEnv</summary>

**Description**:

```
Prints all environment variables, helpful for debugging MCP server configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>longRunningOperation</summary>

**Description**:

```
Demonstrates a long running operation with progress updates
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration | number | Duration of the operation in seconds | No
| steps | number | Number of steps in the operation | No
</details>
<details>
<summary>sampleLLM</summary>

**Description**:

```
Samples from an LLM using MCP's sampling feature
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxTokens | number | Maximum number of tokens to generate | No
| prompt | string | The prompt to send to the LLM | Yes
</details>
<details>
<summary>getTinyImage</summary>

**Description**:

```
Returns the MCP_TINY_IMAGE
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>annotatedMessage</summary>

**Description**:

```
Demonstrates how annotations can be used to provide metadata about content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeImage | boolean | Whether to include an example image | No
| messageType | string | Type of message to demonstrate different annotation patterns | Yes
</details>
<details>
<summary>getResourceReference</summary>

**Description**:

```
Returns a resource reference that can be used by MCP clients
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resourceId | number | ID of the resource to reference (1-100) | Yes
</details>

## 📚 Resources (100)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Resource 1 | text/plain | test://static/resource/1 | Resource 1: This is a plaintext resource |
| Resource 2 | application/octet-stream | test://static/resource/2 | UmVzb3VyY2UgMjogVGhpcyBpcyBhIGJhc2U2NCBibG9i |
| Resource 3 | text/plain | test://static/resource/3 | Resource 3: This is a plaintext resource |
| Resource 4 | application/octet-stream | test://static/resource/4 | UmVzb3VyY2UgNDogVGhpcyBpcyBhIGJhc2U2NCBibG9i |
| Resource 5 | text/plain | test://static/resource/5 | Resource 5: This is a plaintext resource |
| Resource 6 | application/octet-stream | test://static/resource/6 | UmVzb3VyY2UgNjogVGhpcyBpcyBhIGJhc2U2NCBibG9i |
| Resource 7 | text/plain | test://static/resource/7 | Resource 7: This is a plaintext resource |
| Resource 8 | application/octet-stream | test://static/resource/8 | UmVzb3VyY2UgODogVGhpcyBpcyBhIGJhc2U2NCBibG9i |
| Resource 9 | text/plain | test://static/resource/9 | Resource 9: This is a plaintext resource |
| Resource 10 | application/octet-stream | test://static/resource/10 | UmVzb3VyY2UgMTA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 11 | text/plain | test://static/resource/11 | Resource 11: This is a plaintext resource |
| Resource 12 | application/octet-stream | test://static/resource/12 | UmVzb3VyY2UgMTI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 13 | text/plain | test://static/resource/13 | Resource 13: This is a plaintext resource |
| Resource 14 | application/octet-stream | test://static/resource/14 | UmVzb3VyY2UgMTQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 15 | text/plain | test://static/resource/15 | Resource 15: This is a plaintext resource |
| Resource 16 | application/octet-stream | test://static/resource/16 | UmVzb3VyY2UgMTY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 17 | text/plain | test://static/resource/17 | Resource 17: This is a plaintext resource |
| Resource 18 | application/octet-stream | test://static/resource/18 | UmVzb3VyY2UgMTg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 19 | text/plain | test://static/resource/19 | Resource 19: This is a plaintext resource |
| Resource 20 | application/octet-stream | test://static/resource/20 | UmVzb3VyY2UgMjA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 21 | text/plain | test://static/resource/21 | Resource 21: This is a plaintext resource |
| Resource 22 | application/octet-stream | test://static/resource/22 | UmVzb3VyY2UgMjI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 23 | text/plain | test://static/resource/23 | Resource 23: This is a plaintext resource |
| Resource 24 | application/octet-stream | test://static/resource/24 | UmVzb3VyY2UgMjQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 25 | text/plain | test://static/resource/25 | Resource 25: This is a plaintext resource |
| Resource 26 | application/octet-stream | test://static/resource/26 | UmVzb3VyY2UgMjY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 27 | text/plain | test://static/resource/27 | Resource 27: This is a plaintext resource |
| Resource 28 | application/octet-stream | test://static/resource/28 | UmVzb3VyY2UgMjg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 29 | text/plain | test://static/resource/29 | Resource 29: This is a plaintext resource |
| Resource 30 | application/octet-stream | test://static/resource/30 | UmVzb3VyY2UgMzA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 31 | text/plain | test://static/resource/31 | Resource 31: This is a plaintext resource |
| Resource 32 | application/octet-stream | test://static/resource/32 | UmVzb3VyY2UgMzI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 33 | text/plain | test://static/resource/33 | Resource 33: This is a plaintext resource |
| Resource 34 | application/octet-stream | test://static/resource/34 | UmVzb3VyY2UgMzQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 35 | text/plain | test://static/resource/35 | Resource 35: This is a plaintext resource |
| Resource 36 | application/octet-stream | test://static/resource/36 | UmVzb3VyY2UgMzY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 37 | text/plain | test://static/resource/37 | Resource 37: This is a plaintext resource |
| Resource 38 | application/octet-stream | test://static/resource/38 | UmVzb3VyY2UgMzg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 39 | text/plain | test://static/resource/39 | Resource 39: This is a plaintext resource |
| Resource 40 | application/octet-stream | test://static/resource/40 | UmVzb3VyY2UgNDA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 41 | text/plain | test://static/resource/41 | Resource 41: This is a plaintext resource |
| Resource 42 | application/octet-stream | test://static/resource/42 | UmVzb3VyY2UgNDI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 43 | text/plain | test://static/resource/43 | Resource 43: This is a plaintext resource |
| Resource 44 | application/octet-stream | test://static/resource/44 | UmVzb3VyY2UgNDQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 45 | text/plain | test://static/resource/45 | Resource 45: This is a plaintext resource |
| Resource 46 | application/octet-stream | test://static/resource/46 | UmVzb3VyY2UgNDY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 47 | text/plain | test://static/resource/47 | Resource 47: This is a plaintext resource |
| Resource 48 | application/octet-stream | test://static/resource/48 | UmVzb3VyY2UgNDg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 49 | text/plain | test://static/resource/49 | Resource 49: This is a plaintext resource |
| Resource 50 | application/octet-stream | test://static/resource/50 | UmVzb3VyY2UgNTA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 51 | text/plain | test://static/resource/51 | Resource 51: This is a plaintext resource |
| Resource 52 | application/octet-stream | test://static/resource/52 | UmVzb3VyY2UgNTI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 53 | text/plain | test://static/resource/53 | Resource 53: This is a plaintext resource |
| Resource 54 | application/octet-stream | test://static/resource/54 | UmVzb3VyY2UgNTQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 55 | text/plain | test://static/resource/55 | Resource 55: This is a plaintext resource |
| Resource 56 | application/octet-stream | test://static/resource/56 | UmVzb3VyY2UgNTY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 57 | text/plain | test://static/resource/57 | Resource 57: This is a plaintext resource |
| Resource 58 | application/octet-stream | test://static/resource/58 | UmVzb3VyY2UgNTg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 59 | text/plain | test://static/resource/59 | Resource 59: This is a plaintext resource |
| Resource 60 | application/octet-stream | test://static/resource/60 | UmVzb3VyY2UgNjA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 61 | text/plain | test://static/resource/61 | Resource 61: This is a plaintext resource |
| Resource 62 | application/octet-stream | test://static/resource/62 | UmVzb3VyY2UgNjI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 63 | text/plain | test://static/resource/63 | Resource 63: This is a plaintext resource |
| Resource 64 | application/octet-stream | test://static/resource/64 | UmVzb3VyY2UgNjQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 65 | text/plain | test://static/resource/65 | Resource 65: This is a plaintext resource |
| Resource 66 | application/octet-stream | test://static/resource/66 | UmVzb3VyY2UgNjY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 67 | text/plain | test://static/resource/67 | Resource 67: This is a plaintext resource |
| Resource 68 | application/octet-stream | test://static/resource/68 | UmVzb3VyY2UgNjg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 69 | text/plain | test://static/resource/69 | Resource 69: This is a plaintext resource |
| Resource 70 | application/octet-stream | test://static/resource/70 | UmVzb3VyY2UgNzA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 71 | text/plain | test://static/resource/71 | Resource 71: This is a plaintext resource |
| Resource 72 | application/octet-stream | test://static/resource/72 | UmVzb3VyY2UgNzI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 73 | text/plain | test://static/resource/73 | Resource 73: This is a plaintext resource |
| Resource 74 | application/octet-stream | test://static/resource/74 | UmVzb3VyY2UgNzQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 75 | text/plain | test://static/resource/75 | Resource 75: This is a plaintext resource |
| Resource 76 | application/octet-stream | test://static/resource/76 | UmVzb3VyY2UgNzY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 77 | text/plain | test://static/resource/77 | Resource 77: This is a plaintext resource |
| Resource 78 | application/octet-stream | test://static/resource/78 | UmVzb3VyY2UgNzg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 79 | text/plain | test://static/resource/79 | Resource 79: This is a plaintext resource |
| Resource 80 | application/octet-stream | test://static/resource/80 | UmVzb3VyY2UgODA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 81 | text/plain | test://static/resource/81 | Resource 81: This is a plaintext resource |
| Resource 82 | application/octet-stream | test://static/resource/82 | UmVzb3VyY2UgODI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 83 | text/plain | test://static/resource/83 | Resource 83: This is a plaintext resource |
| Resource 84 | application/octet-stream | test://static/resource/84 | UmVzb3VyY2UgODQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 85 | text/plain | test://static/resource/85 | Resource 85: This is a plaintext resource |
| Resource 86 | application/octet-stream | test://static/resource/86 | UmVzb3VyY2UgODY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 87 | text/plain | test://static/resource/87 | Resource 87: This is a plaintext resource |
| Resource 88 | application/octet-stream | test://static/resource/88 | UmVzb3VyY2UgODg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 89 | text/plain | test://static/resource/89 | Resource 89: This is a plaintext resource |
| Resource 90 | application/octet-stream | test://static/resource/90 | UmVzb3VyY2UgOTA6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 91 | text/plain | test://static/resource/91 | Resource 91: This is a plaintext resource |
| Resource 92 | application/octet-stream | test://static/resource/92 | UmVzb3VyY2UgOTI6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 93 | text/plain | test://static/resource/93 | Resource 93: This is a plaintext resource |
| Resource 94 | application/octet-stream | test://static/resource/94 | UmVzb3VyY2UgOTQ6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 95 | text/plain | test://static/resource/95 | Resource 95: This is a plaintext resource |
| Resource 96 | application/octet-stream | test://static/resource/96 | UmVzb3VyY2UgOTY6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 97 | text/plain | test://static/resource/97 | Resource 97: This is a plaintext resource |
| Resource 98 | application/octet-stream | test://static/resource/98 | UmVzb3VyY2UgOTg6IFRoaXMgaXMgYSBiYXNlNjQgYmxvYg== |
| Resource 99 | text/plain | test://static/resource/99 | Resource 99: This is a plaintext resource |
| Resource 100 | application/octet-stream | test://static/resource/100 | UmVzb3VyY2UgMTAwOiBUaGlzIGlzIGEgYmFzZTY0IGJsb2I= |

</details>

## 📝 Prompts (3)
<details>
<summary>simple_prompt</summary>

**Description**:

```
A prompt without arguments
```
<details>
<summary>complex_prompt</summary>

**Description**:

```
A prompt with arguments
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| temperature | Temperature setting | true |
| style | Output style | <no value> |
<details>
<summary>resource_prompt</summary>

**Description**:

```
A prompt that includes an embedded resource reference
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| resourceId | Resource ID to include (1-100) | true |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | complex_prompt | description | 09b401289593b83e9904a308f5f25490bdf350b411a5c0704c2b809d0e1617ca |
| prompts | complex_prompt | style | f2e0e00a539e768a78c725148346c3b6c05beaa30157b103ce978e263381c4ba |
| prompts | complex_prompt | temperature | 15a255689d20cdae7535538cd0e874bba74ae5a398cda49bcd47b9301abf7b25 |
| prompts | resource_prompt | description | 485a9a963ffe2b74994e89a2ac741dc26ef7656974ba85d6e1a8fba8472adaca |
| prompts | resource_prompt | resourceId | 1c5b7ee8d6755c3d34e32b2f8ef08d51cf7270d762759795aa86e158a488a824 |
| prompts | simple_prompt | description | 388feeee3ff98cdb53b9fa774fe7e58b502a74241ccb5f4635160acf777ea5fb |
| tools | add | description | 1efcb1f3567517e507fe44f6853681a389c3ac9ec493ea45f8e0da09b2d6aaf8 |
| tools | add | a | 4d238256ad692183f3c2e945213eac5ae9e86bce06e6989360af210cae8751f4 |
| tools | add | b | c079e9787b04a05e7e4dd561a044bce326711ebc3f0c90160f33823530da93d3 |
| tools | annotatedMessage | description | c64e27024ec7adde221d1172fc30350a16cc89e948dee762bda74904f5bc9358 |
| tools | annotatedMessage | includeImage | 3f577041e74ad35132f1242ae17815ed70e39bad9533b717021987963f8abb27 |
| tools | annotatedMessage | messageType | 48ca223484fb0957dc6efa4920a79cc385ab419c7c3af0309e8acb4784c58d0d |
| tools | echo | description | befddbd2f7f4e08645d4777c5722d61db17d56a0115f5c9bdb19577e865a299b |
| tools | echo | message | 2aa7ac486933d92f1de28d4b527088a577a0fe0ad5d33c0c36c1d122fc8477ba |
| tools | getResourceReference | description | f65488ea8977f68a7680a0ba04efa98d742a3007664649c9e00899f43f1d89de |
| tools | getResourceReference | resourceId | babe671d40822849f662adcd0a04271ed201dc3849256f46bd5e721e0c752a69 |
| tools | getTinyImage | description | e05d66ca9c64728b0a6bb482363447a84c28caffab8df5c51e604876fd30b6fb |
| tools | longRunningOperation | description | 56b51dc5e58071626c7d2658ccc5f1e252cbc9cae02a03d228fbb82ca57d5562 |
| tools | longRunningOperation | duration | 611a5d1b6734296bafe76d21bca6f9c984b30ae9cf9921554c4440d26b7ea431 |
| tools | longRunningOperation | steps | 70c271e49e3c4217d398f502fda4be342f73aa5875a69b7f59fc749564181707 |
| tools | printEnv | description | 20b7f527310a05a74c119c317a418b8bb4d388fe182e2e4574758be98f06d06f |
| tools | sampleLLM | description | 585d6f5a9315c93685cfc6daa069743de7a0b05e1a055e593cb413d2dd466363 |
| tools | sampleLLM | maxTokens | 877bc91aff3481950f61058439e2f8d8e4a15e3cfa9d1f031c94e945ba2d516e |
| tools | sampleLLM | prompt | 472f849bc61d2fc5c70dac589c4cab3ee7ed1800fbc61dc1c78ba30546c40e95 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
