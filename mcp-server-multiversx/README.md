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


# What is mcp-server-multiversx?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-multiversx/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-multiversx/1.0.3?logo=docker&logoColor=fff&label=1.0.3)](https://hub.docker.com/r/acuvity/mcp-server-multiversx)
[![PyPI](https://img.shields.io/badge/1.0.3-3775A9?logo=pypi&logoColor=fff&label=@multiversx/mcp)](https://github.com/multiversx/mx-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-multiversx/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-multiversx&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22MVX_NETWORK%22%2C%22-e%22%2C%22MVX_WALLET%22%2C%22docker.io%2Facuvity%2Fmcp-server-multiversx%3A1.0.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Manage MultiversX blockchain wallets and perform token transactions.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @multiversx/mcp original [sources](https://github.com/multiversx/mx-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-multiversx/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-multiversx/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-multiversx/charts/mcp-server-multiversx/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @multiversx/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-multiversx/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-multiversx scope of operation the intended usage is to run natively on the targeted machine to access local resources.

**Environment variables and secrets:**
  - `MVX_NETWORK` required to be set
  - `MVX_WALLET` required to be set

For more information and extra configuration you can consult the [package](https://github.com/multiversx/mx-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-multiversx&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22MVX_NETWORK%22%2C%22-e%22%2C%22MVX_WALLET%22%2C%22docker.io%2Facuvity%2Fmcp-server-multiversx%3A1.0.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-multiversx": {
        "env": {
          "MVX_NETWORK": "TO_BE_SET",
          "MVX_WALLET": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "MVX_NETWORK",
          "-e",
          "MVX_WALLET",
          "docker.io/acuvity/mcp-server-multiversx:1.0.3"
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
    "acuvity-mcp-server-multiversx": {
      "env": {
        "MVX_NETWORK": "TO_BE_SET",
        "MVX_WALLET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MVX_NETWORK",
        "-e",
        "MVX_WALLET",
        "docker.io/acuvity/mcp-server-multiversx:1.0.3"
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
    "acuvity-mcp-server-multiversx": {
      "env": {
        "MVX_NETWORK": "TO_BE_SET",
        "MVX_WALLET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MVX_NETWORK",
        "-e",
        "MVX_WALLET",
        "docker.io/acuvity/mcp-server-multiversx:1.0.3"
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
    "acuvity-mcp-server-multiversx": {
      "env": {
        "MVX_NETWORK": "TO_BE_SET",
        "MVX_WALLET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MVX_NETWORK",
        "-e",
        "MVX_WALLET",
        "docker.io/acuvity/mcp-server-multiversx:1.0.3"
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
    "acuvity-mcp-server-multiversx": {
      "env": {
        "MVX_NETWORK": "TO_BE_SET",
        "MVX_WALLET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MVX_NETWORK",
        "-e",
        "MVX_WALLET",
        "docker.io/acuvity/mcp-server-multiversx:1.0.3"
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
        "env": {"MVX_NETWORK":"TO_BE_SET","MVX_WALLET":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","MVX_NETWORK","-e","MVX_WALLET","docker.io/acuvity/mcp-server-multiversx:1.0.3"]
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
- arguments: `run -i --rm --read-only -e MVX_NETWORK -e MVX_WALLET docker.io/acuvity/mcp-server-multiversx:1.0.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e MVX_NETWORK -e MVX_WALLET docker.io/acuvity/mcp-server-multiversx:1.0.3
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-multiversx": {
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
    "acuvity-mcp-server-multiversx": {
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

**Mandatory Environment variables**:
  - `MVX_NETWORK` environment variable to be set by env.MVX_NETWORK
  - `MVX_WALLET` environment variable to be set by env.MVX_WALLET

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-multiversx --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-multiversx --version 1.0.0
````

Install with helm

```console
helm install mcp-server-multiversx oci://docker.io/acuvity/mcp-server-multiversx --version 1.0.0
```

From there your MCP server mcp-server-multiversx will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-multiversx` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-multiversx/charts/mcp-server-multiversx/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>get-balance-of-address</summary>

**Description**:

```
Get the balance for a MultiversX address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The bech32 representation of the address | Yes
</details>
<details>
<summary>get-wallet-address</summary>

**Description**:

```
Get the bech32 address of the wallet set in the environment config
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create-wallet</summary>

**Description**:

```
Create a new wallet and save it as a PEM file. PEM file ARE NOT SECURE. If a wallet already exists, will abort operation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>send-egld</summary>

**Description**:

```
Create a move balance transaction and send it. Will send EGLD using the wallet set in the env to the specified receiver.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The amount of EGLD to send. This amount will then be denominated (1 EGLD=1000000000000000000) | Yes
| receiver | string | The bech32 address of the receiver (erd1...) | Yes
</details>
<details>
<summary>send-fungible-tokens</summary>

**Description**:

```
Create a fungible token transfer transaction and send it. Will send the specified token using the wallet set in the env to the specified receiver.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The amount to send. This amount will then be denominated. | Yes
| receiver | string | The bech32 address of the receiver (erd1...) | Yes
| token | string | The identifier of the token to send. | Yes
</details>
<details>
<summary>send-sft-nft-meta-tokens</summary>

**Description**:

```
Create a nft, sft or meta esdt transfer transaction and send it. Will send the specified token using the wallet set in the env to the specified receiver.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The amount of tokens to send. ONLY needed for SFT or Meta-ESDT. | No
| receiver | string | The bech32 address of the receiver (erd1...) | Yes
| token | string | The extended identifier of the token to send (e.g. NFTEST-123456-0a). | Yes
</details>
<details>
<summary>issue-fungible-token</summary>

**Description**:

```
Create a transaction to issue a fungible token and send it. Will issue the token with the specified arguments. All the properties will be set to true.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| initialSupply | string | The initial supply that will be minted. | Yes
| numDecimals | string | The number of decimals the token will have. | Yes
| tokenName | string | The token name. | Yes
| tokenTicker | string | The token ticker. | Yes
</details>
<details>
<summary>issue-semi-fungible-collection</summary>

**Description**:

```
Create a transaction to issue a semi-fungible collection (SFT) and send it. Will issue the collection with the specified arguments. All the properties will be set to true.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tokenName | string | The token name. | Yes
| tokenTicker | string | The token ticker. | Yes
</details>
<details>
<summary>issue-nft-collection</summary>

**Description**:

```
Create a transaction to issue a non-fungible token collection (NFT) and send it. Will issue the collection with the specified arguments. All the properties will be set to true.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tokenName | string | The token name. | Yes
| tokenTicker | string | The token ticker. | Yes
</details>
<details>
<summary>issue-meta-esdt-collection</summary>

**Description**:

```
Create a transaction to issue a MetaESDT token collection (MESDT) and send it. Will issue the collection with the specified arguments. All the properties will be set to true.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| numDecimals | string | The number of decimals. | Yes
| tokenName | string | The token name. | Yes
| tokenTicker | string | The token ticker. | Yes
</details>
<details>
<summary>create-sft-nft-mesdt-tokens</summary>

**Description**:

```
Create a transaction to issue a semi-fungible token (SFT), or a non-fungible token (NFT), or a MetaESDT token for a collection and send it.
Please also specify the initial quantity and the royalties.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| initialQuantity | string | The initial quantity(number of tokens) that will be minted. If not provided, defaults to 1. | Yes
| name | string | The name of the token. | Yes
| royalties | string | The royalties you'll receive. | No
| tokenIdentifier | string | The identifier of the collection. | Yes
</details>
<details>
<summary>get-tokens-of-address</summary>

**Description**:

```
Get the tokens of an address. Returns the first 25 fungible tokens and the first 25 NFTs, SFTs and MetaESDT. To get more tokens, specify the number of tokens you want to get. Will return the specified number of fungible tokens and the same number of non-fungible. The returned list will contain twice the number of tokens specified, if tokens are available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The bech32 address of the account (erd1...) | Yes
| size | number | The number of each token type to be returned. By default, the number is 25. | No
</details>
<details>
<summary>send-egld-to-multiple-receivers</summary>

**Description**:

```
Create move balance transactions and send them. Will send EGLD using the wallet set in the env to each specified receiver.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The amount of EGLD to send. This amount will then be denominated (1 EGLD=1000000000000000000) | Yes
| receivers | array | An array of bech32 addresses of the receivers (erd1...) | Yes
</details>
<details>
<summary>get-network</summary>

**Description**:

```
Get the network set in the environment config
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create-sft-nft-mesdt-tokens | description | 41241a9154a5b42677f125605b4402bc6008a1243bfe47c882436bd30e104e6a |
| tools | create-sft-nft-mesdt-tokens | initialQuantity | b7867d762b70b6e5090d17102433ccd55cc6eb38d363295a11202d22f6f8805d |
| tools | create-sft-nft-mesdt-tokens | name | 3f1a788d734c6204ba8ec1f6c426a2abc853c6219124bf9bc332fc26b593cb09 |
| tools | create-sft-nft-mesdt-tokens | royalties | c43fd3b18d729908c3d345d9479bdae2e15ffdab2334c32e6ae8fd673022808f |
| tools | create-sft-nft-mesdt-tokens | tokenIdentifier | e4b376a4d9a2237d893bb5ea16d81f6a2839af96f5101d3c897b984a82a056c4 |
| tools | create-wallet | description | a18a7336ed81d8b6c8a1b3263a842b7c3de1f262e3209cbfd299a980ee057dea |
| tools | get-balance-of-address | description | 49a000f1ab084999c494f0040f9fa742ce1f9d6b5d2e7dd20327a7114edf4f31 |
| tools | get-balance-of-address | address | 40f22b2a85ff1c838635ea8c62210e354c7e811d8a32e9838e423c7b1b327f26 |
| tools | get-network | description | d1c38c77747f78bd8aa27088f0d025f3e5ef128e0921cf6f0464b269f5587a72 |
| tools | get-tokens-of-address | description | c7d82d4bc5b4fd56e05f376d83db698b71dcfa898b593d1e2c13c364dcbe9166 |
| tools | get-tokens-of-address | address | 6db278e039eef9baa29cef43dde4c312be4bf7382df1043de2db43815ea0bdae |
| tools | get-tokens-of-address | size | d25bcfdda3f70640a78f0728ab8655d5f9d4cc2aabef02ff249a4c1619c51118 |
| tools | get-wallet-address | description | 6acc57730a7cd271f8f4f7fd59d69d4cfa26083421d4405f79b57af119a038b9 |
| tools | issue-fungible-token | description | 83dd1288fffd93d0ab09c6e912e6799ee6751bee3dc4be2dd8074599926f36e1 |
| tools | issue-fungible-token | initialSupply | 1d45951e94b0e5a8f45343ea1c6a756255046ba0f36a26476e2c9df79f515eb0 |
| tools | issue-fungible-token | numDecimals | 41fec9f80ddb3f8d2372a69a90724f39286908e0b8ea6a7a447d077b8bf803f9 |
| tools | issue-fungible-token | tokenName | d1ad0a25564e75a210f396a96c3de0b7dc86b5b2fe75fc72287290bf331619a9 |
| tools | issue-fungible-token | tokenTicker | 9a4326e7626bc0a005a965f384a99949e4e5d250f7902d556d702528c7d645d2 |
| tools | issue-meta-esdt-collection | description | 24df50a71355aee148bac559582d1a2147a61d755e07b80737f5ec91d1fd67ec |
| tools | issue-meta-esdt-collection | numDecimals | 1b9b512136bfd6cb31f14580f9f2ef362005c8c98582e66475ae2ba849138c5a |
| tools | issue-meta-esdt-collection | tokenName | d1ad0a25564e75a210f396a96c3de0b7dc86b5b2fe75fc72287290bf331619a9 |
| tools | issue-meta-esdt-collection | tokenTicker | 9a4326e7626bc0a005a965f384a99949e4e5d250f7902d556d702528c7d645d2 |
| tools | issue-nft-collection | description | d47e27058eecfde8f3f1a2eb76f6b8ceab18547903a586b7bf8f6b68dbc29bfb |
| tools | issue-nft-collection | tokenName | d1ad0a25564e75a210f396a96c3de0b7dc86b5b2fe75fc72287290bf331619a9 |
| tools | issue-nft-collection | tokenTicker | 9a4326e7626bc0a005a965f384a99949e4e5d250f7902d556d702528c7d645d2 |
| tools | issue-semi-fungible-collection | description | a6703990de0da69fb09ede933de1ff7948e052553b611fc6aa1192de9be80099 |
| tools | issue-semi-fungible-collection | tokenName | d1ad0a25564e75a210f396a96c3de0b7dc86b5b2fe75fc72287290bf331619a9 |
| tools | issue-semi-fungible-collection | tokenTicker | 9a4326e7626bc0a005a965f384a99949e4e5d250f7902d556d702528c7d645d2 |
| tools | send-egld | description | 6f9aa181a2d8a266aadfb01574856b816425c532c17c9bf511ee49631be43ef3 |
| tools | send-egld | amount | 32b6c4903e37048deb667907395ba2f68aeceaf76cf4246e8288ee98390134bb |
| tools | send-egld | receiver | 16cd2c0e8cd1bd5503e782f6280a755a6f8c87eb9a7b654250654409819ed127 |
| tools | send-egld-to-multiple-receivers | description | 71ffd685ba5968d134b355b7bac4ff66643aed698c80272c8f2c599a001a577b |
| tools | send-egld-to-multiple-receivers | amount | 32b6c4903e37048deb667907395ba2f68aeceaf76cf4246e8288ee98390134bb |
| tools | send-egld-to-multiple-receivers | receivers | 5c3b3fe7914a6e4595819d0a139c80f6c8ab2f7fe9c3c644a8e9e6d591b6a767 |
| tools | send-fungible-tokens | description | 2da7410c06af60f8d40b001307a34fd52f359d6b44077e17ae825ee5532253ad |
| tools | send-fungible-tokens | amount | d311e10bc69452c730e1831b8a1ecc0b962d23af1cf107612abed3ad83498e17 |
| tools | send-fungible-tokens | receiver | 16cd2c0e8cd1bd5503e782f6280a755a6f8c87eb9a7b654250654409819ed127 |
| tools | send-fungible-tokens | token | 18b79649ab3f40d9e998cafd96198fd5ac04fcc35944464ffbccff1e65aac01b |
| tools | send-sft-nft-meta-tokens | description | f2125bab14d636100b780ac1f52197e6a8ef91e7ca5feec9e7b79663d9efe317 |
| tools | send-sft-nft-meta-tokens | amount | ae32291808ecd9785438d3e517e7d96702982602db2ad60c5123d3f6b2a0bc39 |
| tools | send-sft-nft-meta-tokens | receiver | 16cd2c0e8cd1bd5503e782f6280a755a6f8c87eb9a7b654250654409819ed127 |
| tools | send-sft-nft-meta-tokens | token | e7997734313ec176cbf44c186ab6c6319ffac39b70b79c2b4b63f4db86d901f8 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
