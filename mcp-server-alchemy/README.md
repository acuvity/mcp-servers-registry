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


# What is mcp-server-alchemy?
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alchemy/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alchemy/0.1.5?logo=docker&logoColor=fff&label=0.1.5)](https://hub.docker.com/r/acuvity/mcp-server-alchemy)
[![PyPI](https://img.shields.io/badge/0.1.5-3775A9?logo=pypi&logoColor=fff&label=@alchemy/mcp-server)](https://github.com/alchemyplatform/alchemy-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alchemy/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alchemy&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALCHEMY_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-alchemy%3A0.1.5%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Allow AI agents to interact with Alchemy's blockchain APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @alchemy/mcp-server original [sources](https://github.com/alchemyplatform/alchemy-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alchemy/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alchemy/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alchemy/charts/mcp-server-alchemy/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @alchemy/mcp-server run reliably and safely.

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
<summary>🛡️ Runtime Security and Guardrails</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alchemy/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Guardrails

#### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

#### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

#### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

#### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

#### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

#### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

### Enable guardrails

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need.

| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |

Example: add `-e GUARDRAILS="secrets-redaction sensitive-pattern-detection"` to enable those guardrails.

## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, define `BASIC_AUTH_SECRET` environment variable with a shared secret.

Example: add `-e BASIC_AUTH_SECRET="supersecret"` to enable the basic authentication.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-alchemy scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `ALCHEMY_API_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/alchemyplatform/alchemy-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alchemy&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALCHEMY_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-alchemy%3A0.1.5%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-alchemy": {
        "env": {
          "ALCHEMY_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "ALCHEMY_API_KEY",
          "docker.io/acuvity/mcp-server-alchemy:0.1.5"
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
    "acuvity-mcp-server-alchemy": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "docker.io/acuvity/mcp-server-alchemy:0.1.5"
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
    "acuvity-mcp-server-alchemy": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "docker.io/acuvity/mcp-server-alchemy:0.1.5"
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
    "acuvity-mcp-server-alchemy": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "docker.io/acuvity/mcp-server-alchemy:0.1.5"
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
    "acuvity-mcp-server-alchemy": {
      "env": {
        "ALCHEMY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALCHEMY_API_KEY",
        "docker.io/acuvity/mcp-server-alchemy:0.1.5"
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
        "env": {"ALCHEMY_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","ALCHEMY_API_KEY","docker.io/acuvity/mcp-server-alchemy:0.1.5"]
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
- arguments: `run -i --rm --read-only -e ALCHEMY_API_KEY docker.io/acuvity/mcp-server-alchemy:0.1.5`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e ALCHEMY_API_KEY docker.io/acuvity/mcp-server-alchemy:0.1.5
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-alchemy": {
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
    "acuvity-mcp-server-alchemy": {
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
  - `ALCHEMY_API_KEY` secret to be set as secrets.ALCHEMY_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-alchemy --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alchemy --version 1.0.0
````

Install with helm

```console
helm install mcp-server-alchemy oci://docker.io/acuvity/mcp-server-alchemy --version 1.0.0
```

From there your MCP server mcp-server-alchemy will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alchemy` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alchemy/charts/mcp-server-alchemy/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>fetchTokenPriceBySymbol</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| symbols | array | A list of blockchaintoken symbols to query. e.g. ["BTC", "ETH"] | Yes
</details>
<details>
<summary>fetchTokenPriceByAddress</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | A list of token contract address and network pairs | Yes
</details>
<details>
<summary>fetchTokenPriceHistoryBySymbol</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| endTime | string | The end time date to query. e.g. "2021-01-01" | Yes
| interval | string | The interval to query. e.g. "1d" or "1h" | Yes
| startTime | string | The start time date to query. e.g. "2021-01-01" | Yes
| symbol | string | The token symbol to query. e.g. "BTC" or "ETH" | Yes
</details>
<details>
<summary>fetchTokenPriceHistoryByTimeFrame</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| interval | string | The interval to query. e.g. "1d" or "1h" | No
| symbol | string | The token symbol to query. e.g. "BTC" or "ETH" | Yes
| timeFrame | string | Time frame like "last-week", "past-7d", "ytd", "last-month", etc. or use natural language like "last week" | Yes
| useNaturalLanguageProcessing | boolean | If true, will interpret timeFrame as natural language | No
</details>
<details>
<summary>fetchTokensOwnedByMultichainAddresses</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | A list of wallet address and network pairs | Yes
</details>
<details>
<summary>fetchAddressTransactionHistory</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | A list of wallet address and network pairs | Yes
| after | string | The cursor that points to the next set of results. Use this to paginate through the results. | No
| before | string | The cursor that points to the previous set of results. Use this to paginate through the results. | No
| limit | number | The number of results to return. Default is 25. Max is 100 | No
</details>
<details>
<summary>fetchTransfers</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category | array | The category of transfers to query. e.g. "external" or "internal" | No
| contractAddresses | array | The contract addresses to query. e.g. ["0x1234567890123456789012345678901234567890"] | No
| excludeZeroValue | boolean | Whether to exclude zero value transfers. | No
| fromAddress | string | The wallet address to query the transfer was sent from. | No
| fromBlock | string | The block number to start the search from. e.g. "1234567890". Inclusive from block (hex string, int, latest, or indexed). | No
| maxCount | string | The maximum number of results to return. e.g. "0x3E8". | No
| network | string | The blockchain network to query. e.g. "eth-mainnet" or "base-mainnet"). | No
| order | string | The order of the results. e.g. "asc" or "desc". | No
| pageKey | string | The cursor to start the search from. Use this to paginate through the results. | No
| toAddress | string | The wallet address to query the transfer was sent to. | No
| toBlock | string | The block number to end the search at. e.g. "1234567890". Inclusive to block (hex string, int, latest, or indexed). | No
| withMetadata | boolean | Whether to include metadata in the results. | No
</details>
<details>
<summary>fetchNftsOwnedByMultichainAddresses</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | A list of wallet address and network pairs | Yes
| pageKey | string | The cursor to start the search from. Use this to paginate through the results. | No
| pageSize | number | The number of results to return. Default is 100. Max is 100 | No
| withMetadata | boolean | Whether to include metadata in the results. | No
</details>
<details>
<summary>fetchNftContractDataByMultichainAddress</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | A list of wallet address and network pairs | Yes
| withMetadata | boolean | Whether to include metadata in the results. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | fetchAddressTransactionHistory | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchAddressTransactionHistory | addresses | ffb1468960a5dc4e5e179e77288966e4090bccf5070bf10bf00dac33f2279470 |
| tools | fetchAddressTransactionHistory | after | 332fb2a08aab21ea70084f57a0d1dfd49e2909badb31ce9c63c86b3a6dede3b7 |
| tools | fetchAddressTransactionHistory | before | 7d975e5bd496dd9d104c737c11557334d5c682bb978bc11ed83af9321f19f6d4 |
| tools | fetchAddressTransactionHistory | limit | 2a8dba3b21367d1cebfaf2d5a8e7d3f4e074231968409a0fb64d1a0fdee3708a |
| tools | fetchNftContractDataByMultichainAddress | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchNftContractDataByMultichainAddress | addresses | ffb1468960a5dc4e5e179e77288966e4090bccf5070bf10bf00dac33f2279470 |
| tools | fetchNftContractDataByMultichainAddress | withMetadata | b005bb2155f81ff5cb94586554413e02ec9a5242e5e59955f94e71336db8c5bf |
| tools | fetchNftsOwnedByMultichainAddresses | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchNftsOwnedByMultichainAddresses | addresses | ffb1468960a5dc4e5e179e77288966e4090bccf5070bf10bf00dac33f2279470 |
| tools | fetchNftsOwnedByMultichainAddresses | pageKey | 99eb158dfedabe6d368c59e1fa276740ed05bb4cb326adc0f58de26afacff835 |
| tools | fetchNftsOwnedByMultichainAddresses | pageSize | e1e67f699b4229489229b57cd8151687d97ef9bdd94e95c08b0e10eb65f27a4b |
| tools | fetchNftsOwnedByMultichainAddresses | withMetadata | b005bb2155f81ff5cb94586554413e02ec9a5242e5e59955f94e71336db8c5bf |
| tools | fetchTokenPriceByAddress | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchTokenPriceByAddress | addresses | bc83961898ddc3af6dd87e2560d542e18ed07a18fa787019e364430e14348522 |
| tools | fetchTokenPriceBySymbol | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchTokenPriceBySymbol | symbols | defb27c7dced62fb5cbc152cb032282bc64f7662279ac50b8eef0824f6e61c50 |
| tools | fetchTokenPriceHistoryBySymbol | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchTokenPriceHistoryBySymbol | endTime | 15b20314c7558f855f90f5092d9d38865a9d0776171f2b60b9d913e652f07466 |
| tools | fetchTokenPriceHistoryBySymbol | interval | 018622c498bd4a52f0b56608e0af5cbced71a31a489623a6825546114609d715 |
| tools | fetchTokenPriceHistoryBySymbol | startTime | 94efa83a7b669611814e18ffb7d048350fa474c1ad986e821f9b210cc488068e |
| tools | fetchTokenPriceHistoryBySymbol | symbol | 0a9dd337d589f4491b42460704b4d9bf48fc8524132ddb42f5d0b43d55f2cada |
| tools | fetchTokenPriceHistoryByTimeFrame | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchTokenPriceHistoryByTimeFrame | interval | 018622c498bd4a52f0b56608e0af5cbced71a31a489623a6825546114609d715 |
| tools | fetchTokenPriceHistoryByTimeFrame | symbol | 0a9dd337d589f4491b42460704b4d9bf48fc8524132ddb42f5d0b43d55f2cada |
| tools | fetchTokenPriceHistoryByTimeFrame | timeFrame | 83c2fd11cf4829f292af53322ff9c106aaef9fe388bf39d8afbb11a96615c2cf |
| tools | fetchTokenPriceHistoryByTimeFrame | useNaturalLanguageProcessing | 7899970690c2fd724b551bf07cf0f4820d7dfb1141dc16721753eda1bee3121c |
| tools | fetchTokensOwnedByMultichainAddresses | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchTokensOwnedByMultichainAddresses | addresses | ffb1468960a5dc4e5e179e77288966e4090bccf5070bf10bf00dac33f2279470 |
| tools | fetchTransfers | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | fetchTransfers | category | 6392365e8eb006e512cfe91ee18e6a02ef06c9e19e49f420fae89eb4119162d4 |
| tools | fetchTransfers | contractAddresses | 26aa6eb5810220ae088cf358927089424a2f3ad79afe205d484e3924fd45a003 |
| tools | fetchTransfers | excludeZeroValue | 9f3f3af005fea41940a7652153cb239582b5b2e96333158cf77325205e3fac72 |
| tools | fetchTransfers | fromAddress | f3efec745b105dd3d2d0604a2fbfd44c3c08de692ac18881ee31057a826050aa |
| tools | fetchTransfers | fromBlock | 0171503765cdc1a2f902df7eb866e3ce5beccb60dbfac8de34e393cf2786e9dd |
| tools | fetchTransfers | maxCount | 1c8e5b0dc0117df6cf2f0a1509b3158359ee9b076d7e682dc0ac26cc6cd3307c |
| tools | fetchTransfers | network | d5e822cf1e35214144754a47848071154c9b793d9b9e3d8cbb6140561146e614 |
| tools | fetchTransfers | order | 288fcdfe8607472d14c280cd0ee063e6d0c5001772a284475c798b0b37ab72d5 |
| tools | fetchTransfers | pageKey | 99eb158dfedabe6d368c59e1fa276740ed05bb4cb326adc0f58de26afacff835 |
| tools | fetchTransfers | toAddress | 672b017d0fdbb0d4c966d5db0b458dc94b0ed7c89508340390fb87bcac52c82d |
| tools | fetchTransfers | toBlock | 7a9f3e18c913dd037adcb7fb8335834af846d975a51a895434247f25a269bb71 |
| tools | fetchTransfers | withMetadata | b005bb2155f81ff5cb94586554413e02ec9a5242e5e59955f94e71336db8c5bf |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
