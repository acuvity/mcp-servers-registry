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
  </a>
</p>


# What is mcp-server-alibabacloud-opensearch-vector-search?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-opensearch-vector-search/545d264?logo=docker&logoColor=fff&label=545d264)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search)
[![GitHUB](https://img.shields.io/badge/545d264-3775A9?logo=github&logoColor=fff&label=aliyun/alibabacloud-opensearch-mcp-server)](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-opensearch-vector-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_USERNAME%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_PASSWORD%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_INSTANCE_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-opensearch-vector-search%3A545d264%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Universal interface between AI Agents and OpenSearch Vector.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from aliyun/alibabacloud-opensearch-mcp-server original [sources](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-opensearch-vector-search/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure aliyun/alibabacloud-opensearch-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `resource integrity`             | Embeds a hash of all exposed resources to ensure their authenticity and prevent unauthorized modifications, guarding against supply chain attacks and dynamic alterations of tool metadata. |
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |
| `basic authentication`           | Enables the configuration of a shared secret to restrict unauthorized access to the MCP server and ensure only approved clients can connect. |

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

> [!NOTE]
> By default, all guardrails except `resource integrity` are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [Acuvity team](mailto:support@acuvity.ai) for packaging
  - [ aliyun ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server) for original source application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [The Acuvity community Discord](https://discord.gg/BkU7fBkrNk)
  - [ aliyun/alibabacloud-opensearch-mcp-server ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ aliyun/alibabacloud-opensearch-mcp-server ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Base image**:
  - `ghcr.io/astral-sh/uv:python3.12-alpine`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/Dockerfile)

**Latest tags:**
  - `latest` -> `1.0.0-545d264` -> `545d264`
  - [older tags](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/tags)

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:latest`
  - `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264`
  - `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:1.0.0-545d264`

# 📦 How to Install


> [!TIP]
> Given mcp-server-alibabacloud-opensearch-vector-search scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `OPENSEARCH_VECTOR_USERNAME` required to be set
  - `OPENSEARCH_VECTOR_PASSWORD` required to be set
  - `OPENSEARCH_VECTOR_INSTANCE_ID` required to be set
  - `OPENSEARCH_VECTOR_INDEX_NAME` optional (not set)
  - `AISEARCH_API_KEY` optional (not set)
  - `AISEARCH_ENDPOINT` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-opensearch-vector-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_USERNAME%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_PASSWORD%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_INSTANCE_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-opensearch-vector-search%3A545d264%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
        "env": {
          "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
          "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
          "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "OPENSEARCH_VECTOR_USERNAME",
          "-e",
          "OPENSEARCH_VECTOR_PASSWORD",
          "-e",
          "OPENSEARCH_VECTOR_INSTANCE_ID",
          "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
        "env": {"OPENSEARCH_VECTOR_INSTANCE_ID":"TO_BE_SET","OPENSEARCH_VECTOR_PASSWORD":"TO_BE_SET","OPENSEARCH_VECTOR_USERNAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","OPENSEARCH_VECTOR_USERNAME","-e","OPENSEARCH_VECTOR_PASSWORD","-e","OPENSEARCH_VECTOR_INSTANCE_ID","docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"]
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
- arguments: `run -i --rm --read-only -e OPENSEARCH_VECTOR_USERNAME -e OPENSEARCH_VECTOR_PASSWORD -e OPENSEARCH_VECTOR_INSTANCE_ID docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e OPENSEARCH_VECTOR_USERNAME -e OPENSEARCH_VECTOR_PASSWORD -e OPENSEARCH_VECTOR_INSTANCE_ID docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
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

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `OPENSEARCH_VECTOR_PASSWORD` secret to be set as secrets.OPENSEARCH_VECTOR_PASSWORD either by `.value` or from existing with `.valueFrom`

**Optional Secrets**:
  - `AISEARCH_API_KEY` secret to be set as secrets.AISEARCH_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `OPENSEARCH_VECTOR_USERNAME` environment variable to be set by env.OPENSEARCH_VECTOR_USERNAME
  - `OPENSEARCH_VECTOR_INSTANCE_ID` environment variable to be set by env.OPENSEARCH_VECTOR_INSTANCE_ID

**Optional Environment variables**:
  - `OPENSEARCH_VECTOR_INDEX_NAME=""` environment variable can be changed with env.OPENSEARCH_VECTOR_INDEX_NAME=""
  - `AISEARCH_ENDPOINT=""` environment variable can be changed with env.AISEARCH_ENDPOINT=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
````

Install with helm

```console
helm install mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
```

From there your MCP server mcp-server-alibabacloud-opensearch-vector-search will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-opensearch-vector-search` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

For detailed list of all features, tools, arguments and SBOM hashes provided by this server please consult the [readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search)

## 🧰 Tools (6)


💬 Questions? Open an issue or contact us [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
