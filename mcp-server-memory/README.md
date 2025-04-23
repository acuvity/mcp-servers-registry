
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


# What is mcp-server-memory?

[![Helm](https://img.shields.io/badge/v1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-memory/0.6.2?logo=docker&logoColor=fff&label=0.6.2)](https://hub.docker.com/r/acuvity/mcp-server-memory/tags/0.6.2)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-memory)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for enabling memory for Claude through a knowledge graph

> [!NOTE]
> `@modelcontextprotocol/server-memory` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-memory run reliably and safely.

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


# 📦 How to Use


> [!NOTE]
> Given mcp-server-memory scope of operation it can be hosted anywhere.
> But keep in mind that this keep a persistent state and that is not meant to be used by several client at the same time.

## 🐳 With Docker
**Environment variables:**
  - `MEMORY_FILE_PATH` optional (/data/default.json)
**Required volumes or mountPaths:**
  - data to be mounted on `/data`


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -v memory:/data docker.io/acuvity/mcp-server-memory:0.6.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -v memory:/data docker.io/acuvity/mcp-server-memory:0.6.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-memory": {
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
    "acuvity-mcp-server-memory": {
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

### Chart storage requirement

This chart will be deployed as a `StatefulSet` as the server requires access to persistent storage.

You will have to configure the storage settings for:
  - `storage.memory.class` with a proper storage class
  - `storage.memory.size` with a proper storage size

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Optional Environment variables**:
  - `MEMORY_FILE_PATH="/data/default.json"` environment variable can be changed with env.MEMORY_FILE_PATH="/data/default.json"

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-memory/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-memory --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-memory --version <version>
````

Install with helm

```console
helm install mcp-server-memory oci://docker.io/acuvity/mcp-server-memory --version <version>
```

From there your MCP server mcp-server-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-memory` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-memory/charts/mcp-server-memory/README.md) for more details about settings.

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
      "acuvity-mcp-server-memory": {
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:0.6.2"]
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:0.6.2"]
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:0.6.2"]
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:0.6.2"]
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:0.6.2"]
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
        "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:0.6.2"]
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

## 🧰 Tools (9)
<details>
<summary>create_entities</summary>

**Description**:

```
Create multiple new entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entities | array | <no value> | Yes
</details>
<details>
<summary>create_relations</summary>

**Description**:

```
Create multiple new relations between entities in the knowledge graph. Relations should be in active voice
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | <no value> | Yes
</details>
<details>
<summary>add_observations</summary>

**Description**:

```
Add new observations to existing entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| observations | array | <no value> | Yes
</details>
<details>
<summary>delete_entities</summary>

**Description**:

```
Delete multiple entities and their associated relations from the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entityNames | array | An array of entity names to delete | Yes
</details>
<details>
<summary>delete_observations</summary>

**Description**:

```
Delete specific observations from entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| deletions | array | <no value> | Yes
</details>
<details>
<summary>delete_relations</summary>

**Description**:

```
Delete multiple relations from the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | An array of relations to delete | Yes
</details>
<details>
<summary>read_graph</summary>

**Description**:

```
Read the entire knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>search_nodes</summary>

**Description**:

```
Search for nodes in the knowledge graph based on a query
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The search query to match against entity names, types, and observation content | Yes
</details>
<details>
<summary>open_nodes</summary>

**Description**:

```
Open specific nodes in the knowledge graph by their names
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| names | array | An array of entity names to retrieve | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_observations | description | f66d1982a935c25deae16641b447a894687858da5f4e56a4ffd5eded9f15287b |
| tools | create_entities | description | 5d2cd1d3e5d4ea6fd952e9568d41dd54e18c1c5a611daffe1c0399ebc57444e1 |
| tools | create_relations | description | eeb160c5595ea67cee737ea4d34dcf3d22b3d316e107d1edcf02d1dc71727f37 |
| tools | delete_entities | description | 4e8ad2271cd9cfd21a213070f051534e2fb5c6723d7f5d2eed86c9a2f41b05c2 |
| tools | delete_entities | entityNames | a927153ab95010896fc74cf8f26a9c7bc3e840e7aaf9fc7f15866c3525873ab2 |
| tools | delete_observations | description | bae5684867bc99aa4c62c3cb29dccb386983e7575a910a8be7d13ea023aafd80 |
| tools | delete_relations | description | 1b07436348ac9732db58c69ed4db4dbebed012fd263851e1ee4e35e86fe0968e |
| tools | delete_relations | relations | 16642cf152c4f981edf60e0064e4fa10410158457a438a63b60c21c1c4beb5c9 |
| tools | open_nodes | description | 0a799b2e13cab0744fe6b8dd3dbacf7e04753376fdf0adb9d9b6821ad853eded |
| tools | open_nodes | names | 7275b2ac1cb2f632b23e78c872c589a8489cda3a5306f3b399dce23ca813e3ca |
| tools | read_graph | description | 1dfb0bb4dcfe39f92a8a0464153263a3d836524a3c8fd9ff3f73be5ecb2a098c |
| tools | search_nodes | description | cdd54c52fcef34587fc903df13b58b02371a9fb2390cab93d0eeabd229c479f3 |
| tools | search_nodes | query | 2be985b738ac91d8f1e6039cc46c99b96b49b912c19eefccf337c0fc89173cff |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
