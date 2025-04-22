
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


# What is mcp-server-aws-kb-retrieval?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-aws-kb-retrieval?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-kb-retrieval/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-aws-kb-retrieval/tags)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-aws-kb-retrieval)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for AWS Knowledge Base retrieval using Bedrock Agent Runtime

> [!NOTE]
> `@modelcontextprotocol/server-aws-kb-retrieval` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-aws-kb-retrieval run reliably and safely.

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
  - [ @modelcontextprotocol/server-aws-kb-retrieval ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-aws-kb-retrieval ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Base image**:
  - `node:23.11.0-alpine3.21`

**Dockerfile**:
  - `https://github.com/acuvity/mcp-servers-registry/mcp-server-aws-kb-retrieval/docker/Dockerfile`

**Current supported tag:**
  - `latest` -> `0.6.2`

> [!TIP]
> See [Docker Hub Tags](https://hub.docker.com/r/acuvity/mcp-server-aws-kb-retrieval/tags) section for older tags.

# 📦 How to Use


> [!NOTE]
> Given mcp-server-aws-kb-retrieval scope of operation it can be hosted anywhere.

## 🐳 With Docker
**Environment variables:**
  - `AWS_ACCESS_KEY_ID` required to be set
  - `AWS_REGION` required to be set
  - `AWS_SECRET_ACCESS_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e AWS_ACCESS_KEY_ID -e AWS_REGION -e AWS_SECRET_ACCESS_KEY docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e AWS_ACCESS_KEY_ID -e AWS_REGION -e AWS_SECRET_ACCESS_KEY docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-kb-retrieval": {
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
    "acuvity-mcp-server-aws-kb-retrieval": {
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
  - `AWS_ACCESS_KEY_ID` secret to be set as secrets.AWS_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `AWS_SECRET_ACCESS_KEY` secret to be set as secrets.AWS_SECRET_ACCESS_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `AWS_REGION` environment variable to be set by env.AWS_REGION

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-aws-kb-retrieval/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-kb-retrieval --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-kb-retrieval --version <version>
````

Install with helm

```console
helm install mcp-server-aws-kb-retrieval oci://docker.io/acuvity/mcp-server-aws-kb-retrieval --version <version>
```

From there your MCP server mcp-server-aws-kb-retrieval will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-kb-retrieval` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

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
      "acuvity-mcp-server-aws-kb-retrieval": {
        "env":
          {"AWS_ACCESS_KEY_ID":"xxxxxx","AWS_REGION":"xxxxxx","AWS_SECRET_ACCESS_KEY":"xxxxxx"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","AWS_ACCESS_KEY_ID","-e","AWS_REGION","-e","AWS_SECRET_ACCESS_KEY","docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2"]
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
    "acuvity-mcp-server-aws-kb-retrieval": {
      "env":
        {"AWS_ACCESS_KEY_ID":"xxxxxx","AWS_REGION":"xxxxxx","AWS_SECRET_ACCESS_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","AWS_ACCESS_KEY_ID","-e","AWS_REGION","-e","AWS_SECRET_ACCESS_KEY","docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2"]
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
    "acuvity-mcp-server-aws-kb-retrieval": {
      "env":
        {"AWS_ACCESS_KEY_ID":"xxxxxx","AWS_REGION":"xxxxxx","AWS_SECRET_ACCESS_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","AWS_ACCESS_KEY_ID","-e","AWS_REGION","-e","AWS_SECRET_ACCESS_KEY","docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2"]
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
    "acuvity-mcp-server-aws-kb-retrieval": {
      "env":
        {"AWS_ACCESS_KEY_ID":"xxxxxx","AWS_REGION":"xxxxxx","AWS_SECRET_ACCESS_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","AWS_ACCESS_KEY_ID","-e","AWS_REGION","-e","AWS_SECRET_ACCESS_KEY","docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2"]
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
    "acuvity-mcp-server-aws-kb-retrieval": {
      "env":
        {"AWS_ACCESS_KEY_ID":"xxxxxx","AWS_REGION":"xxxxxx","AWS_SECRET_ACCESS_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","AWS_ACCESS_KEY_ID","-e","AWS_REGION","-e","AWS_SECRET_ACCESS_KEY","docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2"]
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
        "env": {"AWS_ACCESS_KEY_ID":"xxxxxx","AWS_REGION":"xxxxxx","AWS_SECRET_ACCESS_KEY":"xxxxxx"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","AWS_ACCESS_KEY_ID","-e","AWS_REGION","-e","AWS_SECRET_ACCESS_KEY","docker.io/acuvity/mcp-server-aws-kb-retrieval:0.6.2"]
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

## 🧰 Tools (1)
<details>
<summary>retrieve_from_aws_kb</summary>

**Description**:

```
Performs retrieval from the AWS Knowledge Base using the provided query and Knowledge Base ID.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| knowledgeBaseId | string | The ID of the AWS Knowledge Base | Yes
| n | number | Number of results to retrieve | No
| query | string | The query to perform retrieval on | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | retrieve_from_aws_kb | description | 88ffc5560bf074b0c33c0c643665d0ea26bf1c25713f7b60cdac42c74710587a |
| tools | retrieve_from_aws_kb | knowledgeBaseId | d6726a4de44a9f1de6f457c221f141e48b50f1b81bf80d193824d3b0b0ed8232 |
| tools | retrieve_from_aws_kb | n | 09f1972c1a99112a69bce71d462cd0665e51316c57c9f56cf6574124ffe16f87 |
| tools | retrieve_from_aws_kb | query | bfd6dedc73a4801e231ca5f4c7f0ec411bbe9a4682fe7408e7bb4acc6ae7ada7 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
