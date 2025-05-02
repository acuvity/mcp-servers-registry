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


# What is mcp-server-base?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-base/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-base/1.0.13?logo=docker&logoColor=fff&label=1.0.13)](https://hub.docker.com/r/acuvity/mcp-server-base)
[![PyPI](https://img.shields.io/badge/1.0.13-3775A9?logo=pypi&logoColor=fff&label=base-mcp)](https://github.com/base/base-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-base&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALCHEMY_API_KEY%22%2C%22-e%22%2C%22COINBASE_API_KEY_NAME%22%2C%22-e%22%2C%22COINBASE_API_PRIVATE_KEY%22%2C%22-e%22%2C%22COINBASE_PROJECT_ID%22%2C%22-e%22%2C%22OPENROUTER_API_KEY%22%2C%22-e%22%2C%22PINATA_JWT%22%2C%22-e%22%2C%22SEED_PHRASE%22%2C%22docker.io%2Facuvity%2Fmcp-server-base%3A1.0.13%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Base Network integration for onchain tools, allowing interaction with Base Network and Coinbase API for wallet management, fund transfers, smart contracts, and DeFi operations.

> [!NOTE]
> `base-mcp` has been repackaged by Acuvity from Dan Schlabach, Tina He original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure base-mcp run reliably and safely.

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
> Given mcp-server-base scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-base&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALCHEMY_API_KEY%22%2C%22-e%22%2C%22COINBASE_API_KEY_NAME%22%2C%22-e%22%2C%22COINBASE_API_PRIVATE_KEY%22%2C%22-e%22%2C%22COINBASE_PROJECT_ID%22%2C%22-e%22%2C%22OPENROUTER_API_KEY%22%2C%22-e%22%2C%22PINATA_JWT%22%2C%22-e%22%2C%22SEED_PHRASE%22%2C%22docker.io%2Facuvity%2Fmcp-server-base%3A1.0.13%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-base": {
        "env": {
          "ALCHEMY_API_KEY": "TO_BE_SET",
          "COINBASE_API_KEY_NAME": "TO_BE_SET",
          "COINBASE_API_PRIVATE_KEY": "TO_BE_SET",
          "COINBASE_PROJECT_ID": "TO_BE_SET",
          "OPENROUTER_API_KEY": "TO_BE_SET",
          "PINATA_JWT": "TO_BE_SET",
          "SEED_PHRASE": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "ALCHEMY_API_KEY",
          "-e",
          "COINBASE_API_KEY_NAME",
          "-e",
          "COINBASE_API_PRIVATE_KEY",
          "-e",
          "COINBASE_PROJECT_ID",
          "-e",
          "OPENROUTER_API_KEY",
          "-e",
          "PINATA_JWT",
          "-e",
          "SEED_PHRASE",
          "docker.io/acuvity/mcp-server-base:1.0.13"
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
    "acuvity-mcp-server-base": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET",
        "COINBASE_API_KEY_NAME": "TO_BE_SET",
        "COINBASE_API_PRIVATE_KEY": "TO_BE_SET",
        "COINBASE_PROJECT_ID": "TO_BE_SET",
        "OPENROUTER_API_KEY": "TO_BE_SET",
        "PINATA_JWT": "TO_BE_SET",
        "SEED_PHRASE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "-e",
        "COINBASE_API_KEY_NAME",
        "-e",
        "COINBASE_API_PRIVATE_KEY",
        "-e",
        "COINBASE_PROJECT_ID",
        "-e",
        "OPENROUTER_API_KEY",
        "-e",
        "PINATA_JWT",
        "-e",
        "SEED_PHRASE",
        "docker.io/acuvity/mcp-server-base:1.0.13"
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
    "acuvity-mcp-server-base": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET",
        "COINBASE_API_KEY_NAME": "TO_BE_SET",
        "COINBASE_API_PRIVATE_KEY": "TO_BE_SET",
        "COINBASE_PROJECT_ID": "TO_BE_SET",
        "OPENROUTER_API_KEY": "TO_BE_SET",
        "PINATA_JWT": "TO_BE_SET",
        "SEED_PHRASE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "-e",
        "COINBASE_API_KEY_NAME",
        "-e",
        "COINBASE_API_PRIVATE_KEY",
        "-e",
        "COINBASE_PROJECT_ID",
        "-e",
        "OPENROUTER_API_KEY",
        "-e",
        "PINATA_JWT",
        "-e",
        "SEED_PHRASE",
        "docker.io/acuvity/mcp-server-base:1.0.13"
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
    "acuvity-mcp-server-base": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET",
        "COINBASE_API_KEY_NAME": "TO_BE_SET",
        "COINBASE_API_PRIVATE_KEY": "TO_BE_SET",
        "COINBASE_PROJECT_ID": "TO_BE_SET",
        "OPENROUTER_API_KEY": "TO_BE_SET",
        "PINATA_JWT": "TO_BE_SET",
        "SEED_PHRASE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "-e",
        "COINBASE_API_KEY_NAME",
        "-e",
        "COINBASE_API_PRIVATE_KEY",
        "-e",
        "COINBASE_PROJECT_ID",
        "-e",
        "OPENROUTER_API_KEY",
        "-e",
        "PINATA_JWT",
        "-e",
        "SEED_PHRASE",
        "docker.io/acuvity/mcp-server-base:1.0.13"
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
    "acuvity-mcp-server-base": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET",
        "COINBASE_API_KEY_NAME": "TO_BE_SET",
        "COINBASE_API_PRIVATE_KEY": "TO_BE_SET",
        "COINBASE_PROJECT_ID": "TO_BE_SET",
        "OPENROUTER_API_KEY": "TO_BE_SET",
        "PINATA_JWT": "TO_BE_SET",
        "SEED_PHRASE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "-e",
        "COINBASE_API_KEY_NAME",
        "-e",
        "COINBASE_API_PRIVATE_KEY",
        "-e",
        "COINBASE_PROJECT_ID",
        "-e",
        "OPENROUTER_API_KEY",
        "-e",
        "PINATA_JWT",
        "-e",
        "SEED_PHRASE",
        "docker.io/acuvity/mcp-server-base:1.0.13"
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
        "env": {"ALCHEMY_API_KEY":"TO_BE_SET","COINBASE_API_KEY_NAME":"TO_BE_SET","COINBASE_API_PRIVATE_KEY":"TO_BE_SET","COINBASE_PROJECT_ID":"TO_BE_SET","OPENROUTER_API_KEY":"TO_BE_SET","PINATA_JWT":"TO_BE_SET","SEED_PHRASE":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","ALCHEMY_API_KEY","-e","COINBASE_API_KEY_NAME","-e","COINBASE_API_PRIVATE_KEY","-e","COINBASE_PROJECT_ID","-e","OPENROUTER_API_KEY","-e","PINATA_JWT","-e","SEED_PHRASE","docker.io/acuvity/mcp-server-base:1.0.13"]
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
  - `ALCHEMY_API_KEY` required to be set
  - `CHAIN_ID` optional (not set)
  - `COINBASE_API_KEY_NAME` required to be set
  - `COINBASE_API_PRIVATE_KEY` required to be set
  - `COINBASE_PROJECT_ID` required to be set
  - `OPENROUTER_API_KEY` required to be set
  - `PINATA_JWT` required to be set
  - `SEED_PHRASE` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e ALCHEMY_API_KEY -e COINBASE_API_KEY_NAME -e COINBASE_API_PRIVATE_KEY -e COINBASE_PROJECT_ID -e OPENROUTER_API_KEY -e PINATA_JWT -e SEED_PHRASE docker.io/acuvity/mcp-server-base:1.0.13`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e ALCHEMY_API_KEY -e COINBASE_API_KEY_NAME -e COINBASE_API_PRIVATE_KEY -e COINBASE_PROJECT_ID -e OPENROUTER_API_KEY -e PINATA_JWT -e SEED_PHRASE docker.io/acuvity/mcp-server-base:1.0.13
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-base": {
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
    "acuvity-mcp-server-base": {
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
  - `ALCHEMY_API_KEY` secret to be set as secrets.ALCHEMY_API_KEY either by `.value` or from existing with `.valueFrom`
  - `COINBASE_API_KEY_NAME` secret to be set as secrets.COINBASE_API_KEY_NAME either by `.value` or from existing with `.valueFrom`
  - `COINBASE_API_PRIVATE_KEY` secret to be set as secrets.COINBASE_API_PRIVATE_KEY either by `.value` or from existing with `.valueFrom`
  - `COINBASE_PROJECT_ID` secret to be set as secrets.COINBASE_PROJECT_ID either by `.value` or from existing with `.valueFrom`
  - `OPENROUTER_API_KEY` secret to be set as secrets.OPENROUTER_API_KEY either by `.value` or from existing with `.valueFrom`
  - `PINATA_JWT` secret to be set as secrets.PINATA_JWT either by `.value` or from existing with `.valueFrom`
  - `SEED_PHRASE` secret to be set as secrets.SEED_PHRASE either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `CHAIN_ID=""` environment variable can be changed with env.CHAIN_ID=""

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-base --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-base --version 1.0.0
````

Install with helm

```console
helm install mcp-server-base oci://docker.io/acuvity/mcp-server-base --version 1.0.0
```

From there your MCP server mcp-server-base will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-base` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-base/charts/mcp-server-base/README.md) for more details about settings.

</details>

💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
