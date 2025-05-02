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


# What is mcp-server-bankless-onchain?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-bankless-onchain/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-bankless-onchain/1.0.6?logo=docker&logoColor=fff&label=1.0.6)](https://hub.docker.com/r/acuvity/mcp-server-bankless-onchain)
[![PyPI](https://img.shields.io/badge/1.0.6-3775A9?logo=pypi&logoColor=fff&label=@bankless/onchain-mcp)](https://bankless.com)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bankless-onchain&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BANKLESS_API_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-bankless-onchain%3A1.0.6%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for using Bankless Onchain

> [!NOTE]
> `@bankless/onchain-mcp` has been repackaged by Acuvity from Bankless Engineering original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @bankless/onchain-mcp run reliably and safely.

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
> Given mcp-server-bankless-onchain scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bankless-onchain&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BANKLESS_API_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-bankless-onchain%3A1.0.6%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-bankless-onchain": {
        "env": {
          "BANKLESS_API_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "BANKLESS_API_TOKEN",
          "docker.io/acuvity/mcp-server-bankless-onchain:1.0.6"
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
    "acuvity-mcp-server-bankless-onchain": {
      "env": {
        "BANKLESS_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BANKLESS_API_TOKEN",
        "docker.io/acuvity/mcp-server-bankless-onchain:1.0.6"
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
    "acuvity-mcp-server-bankless-onchain": {
      "env": {
        "BANKLESS_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BANKLESS_API_TOKEN",
        "docker.io/acuvity/mcp-server-bankless-onchain:1.0.6"
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
    "acuvity-mcp-server-bankless-onchain": {
      "env": {
        "BANKLESS_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BANKLESS_API_TOKEN",
        "docker.io/acuvity/mcp-server-bankless-onchain:1.0.6"
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
    "acuvity-mcp-server-bankless-onchain": {
      "env": {
        "BANKLESS_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BANKLESS_API_TOKEN",
        "docker.io/acuvity/mcp-server-bankless-onchain:1.0.6"
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
        "env": {"BANKLESS_API_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BANKLESS_API_TOKEN","docker.io/acuvity/mcp-server-bankless-onchain:1.0.6"]
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
  - `BANKLESS_API_TOKEN` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e BANKLESS_API_TOKEN docker.io/acuvity/mcp-server-bankless-onchain:1.0.6`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e BANKLESS_API_TOKEN docker.io/acuvity/mcp-server-bankless-onchain:1.0.6
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-bankless-onchain": {
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
    "acuvity-mcp-server-bankless-onchain": {
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
  - `BANKLESS_API_TOKEN` secret to be set as secrets.BANKLESS_API_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0
````

Install with helm

```console
helm install mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0
```

From there your MCP server mcp-server-bankless-onchain will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-bankless-onchain` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bankless-onchain/charts/mcp-server-bankless-onchain/README.md) for more details about settings.

</details>
# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>read_contract</summary>

**Description**:

```
Read contract state from a blockchain. important:  
                
                In case of a tuple, don't use type tuple, but specify the inner types (found in the source) in order. For nested structs, include the substructs types.
    
    Example: 
    struct DataTypeA {
    DataTypeB b;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    }
    
    struct DataTypeB {
    address token;
    }
    
    results in outputs for function with return type DataTypeA (tuple in abi): outputs: [{"type": "address"}, {"type": "uint128"}]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address | Yes
| inputs | array | Input parameters for the method call | Yes
| method | string | The contract method to call | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
| outputs | array | Expected output types for the method call. 
    In case of a tuple, don't use type tuple, but specify the inner types (found in the source) in order. For nested structs, include the substructs types.
    
    Example: 
    struct DataTypeA {
    DataTypeB b;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    }
    
    struct DataTypeB {
    address token;
    }
    
    results in outputs for function with return type DataTypeA (tuple in abi): outputs: [{"type": "address"}, {"type": "uint128"}]
   | Yes
</details>
<details>
<summary>get_proxy</summary>

**Description**:

```
Gets the proxy address for a given network and contract
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address to request the proxy implementation contract for | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_abi</summary>

**Description**:

```
Gets the ABI for a given contract on a specific network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_source</summary>

**Description**:

```
Gets the source code for a given contract on a specific network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_events</summary>

**Description**:

```
Fetches event logs for a given network and filter criteria
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | List of contract addresses to filter events | Yes
| fromBlock | number | Block number to start fetching logs from | No
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
| optionalTopics | array | Optional additional topics | No
| toBlock | number | Block number to stop fetching logs at | No
| topic | string | Primary topic to filter events | Yes
</details>
<details>
<summary>build_event_topic</summary>

**Description**:

```
Builds an event topic signature based on event name and arguments
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| arguments | array | Event arguments types | Yes
| name | string | Event name (e.g., "Transfer(address,address,uint256)") | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_transaction_history_for_user</summary>

**Description**:

```
Gets transaction history for a user and optional contract
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | [string null] | The contract address (optional) | No
| includeData | boolean | Whether to include transaction data | No
| methodId | [string null] | The method ID to filter by (optional) | No
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
| startBlock | [string null] | The starting block number (optional) | No
| user | string | The user address | Yes
</details>
<details>
<summary>get_transaction_info</summary>

**Description**:

```
Gets detailed information about a specific transaction
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | The blockchain network (e.g., "ethereum", "polygon") | Yes
| txHash | string | The transaction hash to fetch details for | Yes
</details>
<details>
<summary>get_token_balances_on_network</summary>

**Description**:

```
Gets all token balances for a given address on a specific network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The address to check token balances for | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_block_info</summary>

**Description**:

```
Gets detailed information about a specific block by number or hash
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| blockId | string | The block number or block hash to fetch information for | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | build_event_topic | description | 262f27f4028228da097205a7c410f06fa7a823b2040556a721746d1e4cf50bd0 |
| tools | build_event_topic | arguments | 67282223b6da520d3f37a9a8146cfc02993e311b1b1ec2c71473500e73e4784d |
| tools | build_event_topic | name | 6ed8951c00312e24c4e0ca6dec06cdfea75fbf486288154b923151ec5254a2d0 |
| tools | build_event_topic | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_abi | description | 49edadd258a74f8d62a9b06c2356fc8ddcebcebeade9a3fc236e46f47568f966 |
| tools | get_abi | contract | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | get_abi | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_block_info | description | cdd6ae064cb18ddd093b64ad864cf0af9ad5b6f99297510466afce477ee0c8b2 |
| tools | get_block_info | blockId | 77ebd2d66c92208bc200c76cd91ccb3fce561d3b4592fb3b7c877691840eb705 |
| tools | get_block_info | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_events | description | 11e496bebf052d4a45c1d427323e47fc0e00617e34751b195e3c38e6da7b5a84 |
| tools | get_events | addresses | f3433afc56ec432d7da942237b9838973548370a4abed0a8b52f70d8a7ff8c7f |
| tools | get_events | fromBlock | bb3f18b71d6e1a36d93340e52b54b32fab0f24676dfd3e7dc0a044f36fcec82a |
| tools | get_events | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_events | optionalTopics | df86f24833db44832dac5eff638f0df4821f303020cb9dcb7d29400c931b0cb1 |
| tools | get_events | toBlock | 8ff070ee8eb0d4a64c9f490771fcb0516ed7091ba119e91bff1088f94e0027c8 |
| tools | get_events | topic | 095440b149b2fc5b6b258519a8f32231f525a90740d929968153872ea9c608ec |
| tools | get_proxy | description | 436a19a7bf59229497f6b870fa2cf42c0bd2578592069370131071e407a112c8 |
| tools | get_proxy | contract | 3bbd104044dbad8cd8d2723283008b627f3e02c6f517e5c5d252f40f86b80980 |
| tools | get_proxy | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_source | description | 232c3246004c70ef08d9e17e72dc490270c132ab9a637c051327ca8975a1017c |
| tools | get_source | contract | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | get_source | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_token_balances_on_network | description | 28baa9b9ac94405d2bc35b0860f7d13635c73067a2f147ada97a2d170c4f430f |
| tools | get_token_balances_on_network | address | 405710c18f1099e1fbe199741ff78a9ade223cf5bde63fd6dad6f57b0ae5e684 |
| tools | get_token_balances_on_network | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_transaction_history_for_user | description | 97d03e583c1db4a6b71ed2feded2de7fc39007f3e2732298262bce1f368188b0 |
| tools | get_transaction_history_for_user | contract | db0fa3adc605fb68ab41f05976668758d6fbb9e1995f68ec49f7cd1960be22ca |
| tools | get_transaction_history_for_user | includeData | 3ccf882c87a83cdb846aebc669f3771512dbc5efccad0761e4441b20a2d709e0 |
| tools | get_transaction_history_for_user | methodId | 32660cb5cb9250dcbeb97a6c16be7878da4d98aa04e9fd78bdd6abc4c4d007f6 |
| tools | get_transaction_history_for_user | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_transaction_history_for_user | startBlock | c9feb1fbcecaf65a2cd51919a5adaa2272ef1b05051811d280bd454b11ed13a3 |
| tools | get_transaction_history_for_user | user | 5c7282f0c6e567a96b80b014ca83778432010c18ac6f90cd1dc8879113b3032b |
| tools | get_transaction_info | description | 3cb6ea3fc5e3c082d042ab9e3bad43752ee3049017b95b76c1862daf208374f4 |
| tools | get_transaction_info | network | 27df8fb99fdf67ada2c14cfe2ba1a6e684d6fc1affb76f4ddf6adbe297b82763 |
| tools | get_transaction_info | txHash | 108c12c4ccab2dc50c541fae3e1cad3200fa099de05555fe87b5691ac93ac9b8 |
| tools | read_contract | description | a39ce1e9dea8ace0aa384880e028dbe10062cac5975198e3d646c804ef67ff77 |
| tools | read_contract | contract | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | read_contract | inputs | 68674e5ff81fbba2b59057b879623f4d3b3651732f1fa0786780354da49863f8 |
| tools | read_contract | method | 9f86a9f0e03eceff52a4ff49aa79c0a85988d9357a4ac066b19dd6d91b0e2f2f |
| tools | read_contract | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | read_contract | outputs | 1048bd1cff242e3d62763291c1b1140f5cbe8b06e984314cbe2decc5abb189a2 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
