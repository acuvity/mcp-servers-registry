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


# What is mcp-server-codex?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-codex/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-codex/0.1.3?logo=docker&logoColor=fff&label=0.1.3)](https://hub.docker.com/r/acuvity/mcp-server-codex)
[![PyPI](https://img.shields.io/badge/0.1.3-3775A9?logo=pypi&logoColor=fff&label=@codex-data/codex-mcp)](https://github.com/Codex-Data/codex-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-codex&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CODEX_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-codex%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Codex API integration for real-time enriched blockchain and market data on 60+ networks.

> [!NOTE]
> `@codex-data/codex-mcp` has been repackaged by Acuvity from Codex original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @codex-data/codex-mcp run reliably and safely.

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
> Given mcp-server-codex scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-codex&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CODEX_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-codex%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-codex": {
        "env": {
          "CODEX_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "CODEX_API_KEY",
          "docker.io/acuvity/mcp-server-codex:0.1.3"
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
    "acuvity-mcp-server-codex": {
      "env": {
        "CODEX_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CODEX_API_KEY",
        "docker.io/acuvity/mcp-server-codex:0.1.3"
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
    "acuvity-mcp-server-codex": {
      "env": {
        "CODEX_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CODEX_API_KEY",
        "docker.io/acuvity/mcp-server-codex:0.1.3"
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
    "acuvity-mcp-server-codex": {
      "env": {
        "CODEX_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CODEX_API_KEY",
        "docker.io/acuvity/mcp-server-codex:0.1.3"
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
    "acuvity-mcp-server-codex": {
      "env": {
        "CODEX_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CODEX_API_KEY",
        "docker.io/acuvity/mcp-server-codex:0.1.3"
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
        "env": {"CODEX_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","CODEX_API_KEY","docker.io/acuvity/mcp-server-codex:0.1.3"]
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
  - `CODEX_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e CODEX_API_KEY docker.io/acuvity/mcp-server-codex:0.1.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e CODEX_API_KEY docker.io/acuvity/mcp-server-codex:0.1.3
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-codex": {
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
    "acuvity-mcp-server-codex": {
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
  - `CODEX_API_KEY` secret to be set as secrets.CODEX_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-codex --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-codex --version 1.0.0
````

Install with helm

```console
helm install mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0
```

From there your MCP server mcp-server-codex will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-codex` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/charts/mcp-server-codex/README.md) for more details about settings.

</details>
# 🧠 Server features

## 🧰 Tools (25)
<details>
<summary>get_networks</summary>

**Description**:

```
Get a list of all blockchain networks supported by Codex
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_network_status</summary>

**Description**:

```
Get the status of a specific blockchain network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| networkId | number | The network ID to get status for | Yes
</details>
<details>
<summary>get_network_stats</summary>

**Description**:

```
Get metadata and statistics for a given network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| networkId | number | The network ID to get stats for | Yes
</details>
<details>
<summary>get_token_info</summary>

**Description**:

```
Get detailed information about a specific token
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_tokens</summary>

**Description**:

```
Get detailed information about multiple tokens
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ids | array | not set | Yes
</details>
<details>
<summary>get_token_prices</summary>

**Description**:

```
Get real-time or historical prices for a list of tokens
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| inputs | array | not set | Yes
</details>
<details>
<summary>filter_tokens</summary>

**Description**:

```
Filter tokens by various criteria
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| excludeTokens | array | A list of token IDs to exclude from results (address:networkId) | No
| filters | object | A set of filters to apply | No
| limit | number | Maximum number of items to return | No
| offset | number | Number of items to skip | No
| phrase | string | A phrase to search for. Can match a token contract address or partially match a token's name or symbol | No
| rankings | array | A list of ranking attributes to apply | No
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
| tokens | any | A list of token IDs (address:networkId) or addresses. Can be left blank to discover new tokens | No
</details>
<details>
<summary>get_token_holders</summary>

**Description**:

```
Returns list of wallets that hold a given token, ordered by holdings descending. Also has the unique count of holders for that token. (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| cursor | string | Cursor for pagination | No
| networkId | number | The network ID the token is on | Yes
| sort | object | Sort options for the holders list | No
</details>
<details>
<summary>get_token_balances</summary>

**Description**:

```
Get token balances for a wallet (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Cursor for pagination | No
| filterToken | string | Optional token to filter balances for | No
| includeNative | boolean | Include native token balances | No
| networkId | number | The network ID the wallet is on | Yes
| walletAddress | string | The wallet address to get balances for | Yes
</details>
<details>
<summary>get_top_10_holders_percent</summary>

**Description**:

```
Get the percentage of tokens held by top 10 holders
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_token_chart_data</summary>

**Description**:

```
Returns bar chart data to track token price changes over time. Can be queried using either a pair address or token address.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair address or token address to get chart data for. If a token address is provided, the token's top pair will be used. | Yes
| countback | number | not set | No
| currencyCode | string | not set | No
| from | number | Unix timestamp | Yes
| networkId | number | The network ID the pair or token is on | Yes
| quoteToken | string | The token of interest (token0 or token1) | No
| removeEmptyBars | boolean | not set | No
| removeLeadingNullValues | any | not set | No
| resolution | string | The time frame for each candle. Available options are 1, 5, 15, 30, 60, 240, 720, 1D, 7D | Yes
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
| symbolType | string | not set | No
| to | any | not set | Yes
</details>
<details>
<summary>get_token_chart_urls</summary>

**Description**:

```
Chart images for token pairs (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| networkId | number | The network ID the pair is on | Yes
| pairAddress | string | The pair contract address | Yes
| quoteToken | string | The token of interest (token0 or token1) | No
</details>
<details>
<summary>get_latest_tokens</summary>

**Description**:

```
Get a list of the latests token contracts deployed (Codex Growth and Enterprise Plans only). Note: This endpoint is only available on Ethereum, Optimum, Base, and Arbitrum networks (network IDs 1, 10, 8453, and 42161).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of items to return | No
| networkFilter | array | not set | Yes
| offset | number | Number of items to skip | No
</details>
<details>
<summary>get_token_sparklines</summary>

**Description**:

```
Get a list of token simple chart data (sparklines) for the given tokens
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | Array of token contract addresses | Yes
| networkId | number | The network ID the tokens are on | Yes
</details>
<details>
<summary>get_token_events</summary>

**Description**:

```
Get transactions for a token pair
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | A cursor for use in pagination | No
| direction | string | The direction to sort the events by | No
| limit | number | The maximum number of events to return | No
| query | object | Query parameters for filtering token events | Yes
</details>
<details>
<summary>get_token_events_for_maker</summary>

**Description**:

```
Get a list of token events for a given wallet address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | A cursor for use in pagination | No
| direction | string | The direction to sort the events by | No
| limit | number | The maximum number of events to return | No
| query | object | Query parameters for filtering token events | Yes
</details>
<details>
<summary>get_detailed_pair_stats</summary>

**Description**:

```
Get bucketed stats for a given token within a pair
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| bucketCount | number | The number of aggregated values to receive. Note: Each duration has predetermined bucket sizes. The first n-1 buckets are historical. The last bucket is a snapshot of current data. | No
| duration | string | The duration for stats | Yes
| networkId | number | The network ID the pair is on | Yes
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
| timestamp | number | not set | No
| tokenOfInterest | string | not set | No
</details>
<details>
<summary>get_detailed_pairs_stats</summary>

**Description**:

```
Get bucketed stats for a given token within a list of pairs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| bucketCount | number | The number of aggregated values to receive. Note: Each duration has predetermined bucket sizes. The first n-1 buckets are historical. The last bucket is a snapshot of current data. | No
| duration | string | The duration for stats | Yes
| networkId | number | The network ID the pairs are on | Yes
| pairAddresses | array | Array of pair contract addresses | Yes
</details>
<details>
<summary>filter_pairs</summary>

**Description**:

```
Get a list of pairs based on various filters like volume, price, liquidity, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | not set | No
| limit | number | Maximum number of items to return | No
| offset | number | Number of items to skip | No
| pairs | any | not set | No
| phrase | string | not set | No
| rankings | any | not set | No
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
</details>
<details>
<summary>get_pair_metadata</summary>

**Description**:

```
Get metadata for a pair of tokens, including price, volume, and liquidity stats over various timeframes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| networkId | number | The network ID the pair is on | Yes
| quoteToken | string | The token of interest (token0 or token1) | No
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
</details>
<details>
<summary>get_token_pairs</summary>

**Description**:

```
Get a list of pairs for a token
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| limit | number | Maximum number of pairs to return (default: 10) | No
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_token_pairs_with_metadata</summary>

**Description**:

```
Get pairs with metadata for a specific token
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| limit | number | Maximum number of pairs to return (default: 10) | No
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_liquidity_metadata</summary>

**Description**:

```
Get liquidity metadata for a pair, including both unlocked and locked liquidity data
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| networkId | number | The network ID the pair is on | Yes
</details>
<details>
<summary>get_liquidity_locks</summary>

**Description**:

```
Get liquidity locks for a pair, including details about locked amounts, lock duration, and owner information (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| cursor | string | Cursor for pagination | No
| networkId | number | The network ID the pair is on | Yes
</details>
<details>
<summary>filter_exchanges</summary>

**Description**:

```
Get a list of exchanges based on various filters like volume, transactions, active users, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | not set | No
| limit | number | Maximum number of items to return | No
| offset | number | Number of items to skip | No
| phrase | string | A phrase to search for. Can match an exchange address or ID (address:networkId), or partially match an exchange name | No
| rankings | array | A list of ranking attributes to apply | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | filter_exchanges | description | 8630c1b6c5eebcc85ba3291a22119ec0c08d81cfd442d6a98e5984a36a43fa7e |
| tools | filter_exchanges | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | filter_exchanges | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | filter_exchanges | phrase | 53f29b67c8d12d5eba8d98ce93c733c3da39a26b8615c11d42a8d14dbd6ecc64 |
| tools | filter_exchanges | rankings | 7ffc7462315f7dc4a4d4d466ae87caba4c8a82ac3434dd69690de0bd6447aa5c |
| tools | filter_pairs | description | 21860fffc620dc64fb8a8950458c0ca1c2d246f10a43132bb0eff087687afc54 |
| tools | filter_pairs | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | filter_pairs | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | filter_pairs | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | filter_tokens | description | 7f42285dfb6edeb092932d1d5150790d852fa4088d9843b76fb0146e3c7092f1 |
| tools | filter_tokens | excludeTokens | 2a18cae57bbaa74042dac148d0785f623868ca19c323c6b14009aebf5545819b |
| tools | filter_tokens | filters | 5e2d490530e30f2a5c970a251f1982736aac2e3d6245f6146115ce846563d092 |
| tools | filter_tokens | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | filter_tokens | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | filter_tokens | phrase | 3a4cd287a899ea850962f034b94b6d9304978abc39f0e5b12e19295dcec4002a |
| tools | filter_tokens | rankings | 7ffc7462315f7dc4a4d4d466ae87caba4c8a82ac3434dd69690de0bd6447aa5c |
| tools | filter_tokens | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | filter_tokens | tokens | 620a1127deffb97aeddc2ddef7bfb5d4cfd3160011685d6f16602a2a5d09ffd0 |
| tools | get_detailed_pair_stats | description | 9fc39174e9aa193c8ad1c90bb004d9a522d3596cddca3d9de827a1c8a6cc4ee1 |
| tools | get_detailed_pair_stats | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_detailed_pair_stats | bucketCount | a8115d5bc9d7211a3ba644593d51d8abce2209688f49bbd22071802730a50bbf |
| tools | get_detailed_pair_stats | duration | eca43c06d8b35b718ce4c6f1b1fa2edee25e80de7ff735e5f627e73a4d7b8462 |
| tools | get_detailed_pair_stats | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_detailed_pair_stats | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | get_detailed_pairs_stats | description | 470cb8d70ab7a48d4eaae053c2ac0d6e72bdc8093c1b73d6ce69baa47f3a7cbc |
| tools | get_detailed_pairs_stats | bucketCount | a8115d5bc9d7211a3ba644593d51d8abce2209688f49bbd22071802730a50bbf |
| tools | get_detailed_pairs_stats | duration | eca43c06d8b35b718ce4c6f1b1fa2edee25e80de7ff735e5f627e73a4d7b8462 |
| tools | get_detailed_pairs_stats | networkId | 769e842b67f6ecd7e0b62c7ded4ac995cd898d2d4c08490ec62a6d96b0cb67a2 |
| tools | get_detailed_pairs_stats | pairAddresses | bb118d83f2028e02dce29ed7b4f033e1c10535002722036d1d9e9d1884ed0b52 |
| tools | get_latest_tokens | description | 6c1f9cf9296841e1ce565d3e5dafd616c18bddf8a0ff3071c523bb919c97b195 |
| tools | get_latest_tokens | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | get_latest_tokens | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | get_liquidity_locks | description | 46313e0acd7757c54bf60a9c30b5ff96cf35b055e12bc116ef775a424b80a3a0 |
| tools | get_liquidity_locks | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_liquidity_locks | cursor | 81a3aa63db02772fff8daadbfc1304469ac0c2bee674363902041e3474bd5d14 |
| tools | get_liquidity_locks | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_liquidity_metadata | description | 9fffc813b44d940c80c42534a9f958e068700e0988c2be7bd759e6cf66b308b6 |
| tools | get_liquidity_metadata | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_liquidity_metadata | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_network_stats | description | ffcfa8385b76a2fd430b1d9b87e46efe9a5897cc31fa9c7fce6e6ef6086cabbf |
| tools | get_network_stats | networkId | 51f97a45d980cadc59936925b9f4ba1d832f3025192094619863ddf3bace4f13 |
| tools | get_network_status | description | d00d1303c24cf762215e9237abfceffa4495737886ed702fca5b4ecf014eab1e |
| tools | get_network_status | networkId | ec0489f5be47d47fc4000d7ffa78fe9b986e3845433b8187fcbb61917f137ba8 |
| tools | get_networks | description | d3f5cff9649dd3b2dbfbf114fef1de8109c97ffcc942d2d0c39f5fd9adb0b4be |
| tools | get_pair_metadata | description | 9e96de2e28ddcf03d626555cdd2a0f2122b6da251ffae11d1eba0eb006f94dab |
| tools | get_pair_metadata | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_pair_metadata | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_pair_metadata | quoteToken | 08bbd99302b6a571a05e72dcaccd7e2be846a5ebd5b6671fc79059888022545b |
| tools | get_pair_metadata | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | get_token_balances | description | 092b99a455a510605e2c11239bd4e660cc9d59590f5a63881f809ea0ae6e4829 |
| tools | get_token_balances | cursor | 81a3aa63db02772fff8daadbfc1304469ac0c2bee674363902041e3474bd5d14 |
| tools | get_token_balances | filterToken | 856147bf47963c5fa3b398000b8254dc8c9183d4fdc0f19f5b0a53ce6b92e1f9 |
| tools | get_token_balances | includeNative | 1fa43d78f4ac0bf01712926d814025c68c12f802f698c513aec50c724d753ce0 |
| tools | get_token_balances | networkId | 842075da3361b80fb82e59882ca0aeca463b0dfae3a88cafc1d93300c6435f94 |
| tools | get_token_balances | walletAddress | 16994c44e621216227e163edaaa50a589cc00005411bbe22ae036e8761e3438c |
| tools | get_token_chart_data | description | a19d5851b5e4388b73126f470c87ff7cd2b53bcbedc615ba3123c54a335e193e |
| tools | get_token_chart_data | address | b5f3cdb268f4472b253f29af47672b6790fb7a33594a31e128772ebf02743426 |
| tools | get_token_chart_data | from | 57c536372fb30c9882041213d54caf3b1c24a0339c1fda6980dd7b07eefa862a |
| tools | get_token_chart_data | networkId | afb0b46b6fb98b529d11e9570a99683ed44f3ead5b731c042a7def871d6cdf9e |
| tools | get_token_chart_data | quoteToken | 08bbd99302b6a571a05e72dcaccd7e2be846a5ebd5b6671fc79059888022545b |
| tools | get_token_chart_data | resolution | 9411ec331a694f15f2a44c23b97541bd2ef8b3283fcdc08128b4e5d075465e70 |
| tools | get_token_chart_data | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | get_token_chart_urls | description | d13d3a29be9f78df3f02f44a7efdaf8989d6859601cbaa88c3ab3d97fe1426db |
| tools | get_token_chart_urls | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_token_chart_urls | pairAddress | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_token_chart_urls | quoteToken | 08bbd99302b6a571a05e72dcaccd7e2be846a5ebd5b6671fc79059888022545b |
| tools | get_token_events | description | 6d57b89054e980fcfd78227c5a2d6e5227b12c522d3456a8e9f139d3036374e0 |
| tools | get_token_events | cursor | bdb32017fa9c6d99d3a448b4b82f877ab67b967dafb13768023bede720ce5e36 |
| tools | get_token_events | direction | ae424249e49728aa72ea501db533ddb30f70cc1a41725e4acefd5ff942d6ca28 |
| tools | get_token_events | limit | 58aeef310c17e3ae9fbad20ae949bfd619e1aa233457b5ec4e319134febc3119 |
| tools | get_token_events | query | ad287d740db02910935323d0212f11fa32701a3197672cf6a56241a0cd885d6f |
| tools | get_token_events_for_maker | description | 30d3fca07600242d64807ed0b273c5eb198511dfc0966604d97e185e5702e039 |
| tools | get_token_events_for_maker | cursor | bdb32017fa9c6d99d3a448b4b82f877ab67b967dafb13768023bede720ce5e36 |
| tools | get_token_events_for_maker | direction | ae424249e49728aa72ea501db533ddb30f70cc1a41725e4acefd5ff942d6ca28 |
| tools | get_token_events_for_maker | limit | 58aeef310c17e3ae9fbad20ae949bfd619e1aa233457b5ec4e319134febc3119 |
| tools | get_token_events_for_maker | query | ad287d740db02910935323d0212f11fa32701a3197672cf6a56241a0cd885d6f |
| tools | get_token_holders | description | fc449faf373608ebe12f069e17fd58357247fb08b0beeff0c287e9bbf03cc196 |
| tools | get_token_holders | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_holders | cursor | 81a3aa63db02772fff8daadbfc1304469ac0c2bee674363902041e3474bd5d14 |
| tools | get_token_holders | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_holders | sort | 4a0bb4740faf12bf6d6e89b2ac9d91a4079ee16aa499ff91e757e0fe175232f8 |
| tools | get_token_info | description | 73948792b8dee5194fa86152b0b138facda5af769ddf019e7521aedcfb8daf46 |
| tools | get_token_info | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_info | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_pairs | description | 4892a5976e03b2131377a544ca747d1430ee2d1a26a49bb49be268daa32faddc |
| tools | get_token_pairs | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_pairs | limit | 41d99529a15a9452e284d987dcd32299180074a66358962c9047d6c8e8c24ebc |
| tools | get_token_pairs | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_pairs_with_metadata | description | 64fe25d2e3dffafedf1e38ad2430f9138a88d669685d55acf62af61a08bff029 |
| tools | get_token_pairs_with_metadata | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_pairs_with_metadata | limit | 41d99529a15a9452e284d987dcd32299180074a66358962c9047d6c8e8c24ebc |
| tools | get_token_pairs_with_metadata | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_prices | description | ae01f6a57c459aa1829b25acde1a313b6bafe76d56239d96047762000cee346d |
| tools | get_token_sparklines | description | c8f00c6033b79ff5b4e5a956356df5aea4fcd5bf182c8122cb58285a8f286a26 |
| tools | get_token_sparklines | addresses | e27c4e3ea68338285c4c8a4aa13227ea5d3508adeb94adc4111585c82509e2b8 |
| tools | get_token_sparklines | networkId | ee19b925f1ac5a57dbd766748d5b17eec77f951b90ea9289b93d29939944e1de |
| tools | get_tokens | description | 5d94664ccc45387dcd5cada3ba00d9458c198d715358e4853e08f513112bc478 |
| tools | get_top_10_holders_percent | description | a51fc3400cb76ea941fec38a581728c9c0df1985b8c3d0dc83088e9f8a0f0114 |
| tools | get_top_10_holders_percent | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_top_10_holders_percent | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
