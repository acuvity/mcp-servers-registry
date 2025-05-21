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


# What is mcp-server-bitrefill?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-bitrefill/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-bitrefill/0.3.0?logo=docker&logoColor=fff&label=0.3.0)](https://hub.docker.com/r/acuvity/mcp-server-bitrefill)
[![PyPI](https://img.shields.io/badge/0.3.0-3775A9?logo=pypi&logoColor=fff&label=bitrefill-mcp-server)](https://github.com/bitrefill/bitrefill-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-bitrefill/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bitrefill&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BITREFILL_API_ID%22%2C%22-e%22%2C%22BITREFILL_API_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-bitrefill%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides Bitrefill services for AI assistants via the Model Context Protocol.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from bitrefill-mcp-server original [sources](https://github.com/bitrefill/bitrefill-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-bitrefill/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrefill/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrefill/charts/mcp-server-bitrefill/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure bitrefill-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrefill/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-bitrefill scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `BITREFILL_API_ID` required to be set
  - `BITREFILL_API_SECRET` required to be set

For more information and extra configuration you can consult the [package](https://github.com/bitrefill/bitrefill-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bitrefill&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BITREFILL_API_ID%22%2C%22-e%22%2C%22BITREFILL_API_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-bitrefill%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-bitrefill": {
        "env": {
          "BITREFILL_API_ID": "TO_BE_SET",
          "BITREFILL_API_SECRET": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "BITREFILL_API_ID",
          "-e",
          "BITREFILL_API_SECRET",
          "docker.io/acuvity/mcp-server-bitrefill:0.3.0"
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
    "acuvity-mcp-server-bitrefill": {
      "env": {
        "BITREFILL_API_ID": "TO_BE_SET",
        "BITREFILL_API_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BITREFILL_API_ID",
        "-e",
        "BITREFILL_API_SECRET",
        "docker.io/acuvity/mcp-server-bitrefill:0.3.0"
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
    "acuvity-mcp-server-bitrefill": {
      "env": {
        "BITREFILL_API_ID": "TO_BE_SET",
        "BITREFILL_API_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BITREFILL_API_ID",
        "-e",
        "BITREFILL_API_SECRET",
        "docker.io/acuvity/mcp-server-bitrefill:0.3.0"
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
    "acuvity-mcp-server-bitrefill": {
      "env": {
        "BITREFILL_API_ID": "TO_BE_SET",
        "BITREFILL_API_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BITREFILL_API_ID",
        "-e",
        "BITREFILL_API_SECRET",
        "docker.io/acuvity/mcp-server-bitrefill:0.3.0"
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
    "acuvity-mcp-server-bitrefill": {
      "env": {
        "BITREFILL_API_ID": "TO_BE_SET",
        "BITREFILL_API_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "BITREFILL_API_ID",
        "-e",
        "BITREFILL_API_SECRET",
        "docker.io/acuvity/mcp-server-bitrefill:0.3.0"
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
        "env": {"BITREFILL_API_ID":"TO_BE_SET","BITREFILL_API_SECRET":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","BITREFILL_API_ID","-e","BITREFILL_API_SECRET","docker.io/acuvity/mcp-server-bitrefill:0.3.0"]
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
- arguments: `run -i --rm --read-only -e BITREFILL_API_ID -e BITREFILL_API_SECRET docker.io/acuvity/mcp-server-bitrefill:0.3.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e BITREFILL_API_ID -e BITREFILL_API_SECRET docker.io/acuvity/mcp-server-bitrefill:0.3.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-bitrefill": {
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
    "acuvity-mcp-server-bitrefill": {
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
  - `BITREFILL_API_ID` secret to be set as secrets.BITREFILL_API_ID either by `.value` or from existing with `.valueFrom`
  - `BITREFILL_API_SECRET` secret to be set as secrets.BITREFILL_API_SECRET either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-bitrefill --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-bitrefill --version 1.0.0
````

Install with helm

```console
helm install mcp-server-bitrefill oci://docker.io/acuvity/mcp-server-bitrefill --version 1.0.0
```

From there your MCP server mcp-server-bitrefill will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-bitrefill` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrefill/charts/mcp-server-bitrefill/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>search</summary>

**Description**:

```
Search for gift cards, esims, mobile topups and more. It's suggested to use the `categories` tool before searching for products, to have a better understanding of what's available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| beta_flags | string | Beta feature flags | No
| cart | string | Cart identifier | No
| category | string | Filter by category (e.g., 'gaming', 'entertainment') | No
| col | number | Column layout parameter | No
| country | string | Country code (e.g., 'US', 'IT', 'GB') | No
| do_recommend | number | Enable recommendations | No
| language | string | Language code for results (e.g., 'en') | No
| limit | number | Maximum number of results to return | No
| prefcc | number | Preferred country code parameter | No
| query | string | Search query (e.g., 'Amazon', 'Netflix', 'AT&T' or '*' for all the available products) | Yes
| rec | number | Recommendation parameter | No
| sec | number | Security parameter | No
| skip | number | Number of results to skip (for pagination) | No
| src | string | Source of the request | No
</details>
<details>
<summary>detail</summary>

**Description**:

```
Get detailed information about a product
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Unique identifier of the product | Yes
</details>
<details>
<summary>categories</summary>

**Description**:

```
Get the full product type/categories map. It's suggested to use this tool to get the categories and then use the `search` tool to search for products in a specific category.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_invoice</summary>

**Description**:

```
Create a new invoice for purchasing products with various payment methods
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_pay | boolean | Optional: Automatically pay with balance | No
| payment_method | string | Required payment method. Available methods: balance, lightning, bitcoin, eth_base, usdc_base | Yes
| products | array | Array of products to include in the invoice | Yes
| webhook_url | string | Optional: URL for webhook notifications | No
</details>
<details>
<summary>get_invoices</summary>

**Description**:

```
Retrieve a list of invoices with optional filtering
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | Start date for limiting results (Inclusive). Format: YYYY-MM-DD HH:MM:SS | No
| before | string | End date for limiting results (Non-Inclusive). Format: YYYY-MM-DD HH:MM:SS | No
| limit | integer | Maximum number of records. Maximum/Default: 50 | No
| start | integer | Start index. Default: 0 | No
</details>
<details>
<summary>get_invoice</summary>

**Description**:

```
Retrieve details for a specific invoice by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Unique invoice identifier | Yes
</details>
<details>
<summary>pay_invoice</summary>

**Description**:

```
Pay an unpaid invoice (only works with 'balance' payment method)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Unique invoice identifier | Yes
</details>
<details>
<summary>get_orders</summary>

**Description**:

```
Retrieve a list of orders with optional filtering
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | Start date for limiting results (Inclusive). Format: YYYY-MM-DD HH:MM:SS | No
| before | string | End date for limiting results (Non-Inclusive). Format: YYYY-MM-DD HH:MM:SS | No
| limit | integer | Maximum number of records. Maximum/Default: 50 | No
| start | integer | Start index. Default: 0 | No
</details>
<details>
<summary>get_order</summary>

**Description**:

```
Retrieve details for a specific order by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Unique order identifier | Yes
</details>
<details>
<summary>unseal_order</summary>

**Description**:

```
Reveal codes and PINs for a specific order by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Unique order identifier | Yes
</details>
<details>
<summary>get_account_balance</summary>

**Description**:

```
Retrieve your account balance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>ping</summary>

**Description**:

```
Check if the Bitrefill API is available
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>

## 📚 Resources (7)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| payment-methods | <no value> | bitrefill://payment-methods | - |
| product-types | <no value> | bitrefill://product-types | - |
| giftcards | <no value> | bitrefill://product-types/giftcards | - |
| refills | <no value> | bitrefill://product-types/refills | - |
| bills | <no value> | bitrefill://product-types/bills | - |
| esims | <no value> | bitrefill://product-types/esims | - |
| crypto-utils | <no value> | bitrefill://product-types/crypto-utils | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | categories | description | 35f9a019a9b11575a7e3eee76077ead49dd715d4ec8f809f183ab9cbcccc4e01 |
| tools | create_invoice | description | 3d42e993c49ba735c5d6e0c9d63f50123f1b31f3eb1d48f44cd26ec520389cd7 |
| tools | create_invoice | auto_pay | ca747c87c9cd5d58eab86bce067a7c5159801b6955aa867063048584d9c933bb |
| tools | create_invoice | payment_method | 161c42cff3de3b31488fe78b93ef887106bff184bd8ebed23f7bdd099fb65e1e |
| tools | create_invoice | products | 26c297a5cdcc08421d501fde8ae2e379933347fcd8cfb35819ade22c5ca6b6cb |
| tools | create_invoice | webhook_url | 3617456ac56c265c448adb8549f5c40a07808b2c0d27a2cf2169b915271b1ea7 |
| tools | detail | description | e59f84ee5ad331ff1ad7975e6d9702af918442a3dab883490ad932a56c2a438f |
| tools | detail | id | 9eb19521e2044f7d8e84838a9747a8f5921fed2d1de5ee08b6f32c8cd6244718 |
| tools | get_account_balance | description | 7bae02ed305520bf876f16976c07cf051092e78140ea9b395ce8db74adfabdc2 |
| tools | get_invoice | description | 9625744ba65e15145694c64a0c0c23956eff00e40f77586aed853f71520f1725 |
| tools | get_invoice | id | e650d8abe39dae63313e2ce510e41a533b74e5b7335c0131290dd17be79ed345 |
| tools | get_invoices | description | 7e0aaf77f5e5f899eaeb6ffc43048267fbbd1ebe92c323a022f098f1c2da18b2 |
| tools | get_invoices | after | c34e7dcf65d0439becb55c557a33d319740d21227857c1c3a36e950d03d4a7c9 |
| tools | get_invoices | before | f17302de35cabf73d96df7eb50adccd294867ca6afdaee9db4e6507af0c6fcb6 |
| tools | get_invoices | limit | 4b335efa0a3151e9d25a6661287b9283396299477f440a09c67566105aa0b929 |
| tools | get_invoices | start | 26b6f6b10330ebc338645950585d700fc63ecd99692126fa9417c327fb2edf65 |
| tools | get_order | description | 786a457b3cb4ff47c12f6d5336bacd89f7a084fa799f66f85ef139e0869da4ed |
| tools | get_order | id | e66fc76d2d0586ff442141d8d63732cba2a012a9d1ed10a4b442bcdea745f281 |
| tools | get_orders | description | 7fba44c003771e908458e5af00070f6927ccbc6a5bf4b9a823df5a13aae43566 |
| tools | get_orders | after | c34e7dcf65d0439becb55c557a33d319740d21227857c1c3a36e950d03d4a7c9 |
| tools | get_orders | before | f17302de35cabf73d96df7eb50adccd294867ca6afdaee9db4e6507af0c6fcb6 |
| tools | get_orders | limit | 4b335efa0a3151e9d25a6661287b9283396299477f440a09c67566105aa0b929 |
| tools | get_orders | start | 26b6f6b10330ebc338645950585d700fc63ecd99692126fa9417c327fb2edf65 |
| tools | pay_invoice | description | c59e1725728024b42b90ef76d36adc1bf926f2e31489d605f4fd268d936f4429 |
| tools | pay_invoice | id | e650d8abe39dae63313e2ce510e41a533b74e5b7335c0131290dd17be79ed345 |
| tools | ping | description | 67662099e9b82f89e35a83f2d2d71b66a394d2d30fd765d7654aa57a861b24dc |
| tools | search | description | 34e293fb5b41a57a2866e83bb66dd19925e4f032b3eccc78434ef3de8a7a927d |
| tools | search | beta_flags | a6e6f1c39402c68dcd4e2b0728e8c96adfa4ecb32651f4546a7af3524bfc6896 |
| tools | search | cart | cc16f0966b182d1391d3912386ae70620d6acd25c4b64ebf6ac5c495a3092a9c |
| tools | search | category | 9ee90bb724141fe9d897f59feb21965609cbbe6578f796eb12ab43fec1a14bb2 |
| tools | search | col | 56f3ffdf61b41f318a6f550afa04a56387524a4af03bd2740cd07fb4451e7496 |
| tools | search | country | 914fd7e5d47f236c0a78ec2b0fc3c6e4074ae84a6f8bed53867e8f09445d0a74 |
| tools | search | do_recommend | a7aafb08968960fcb5e1e21e1061c5134871a649da971a708cc6857c8189ea2f |
| tools | search | language | 2e649bfa271e3ee43d563a0a17a2a14877968f5909e1732e4e2e35f0235915da |
| tools | search | limit | b04468046d2f2a5692b75e7d703a30fd2787b8f80972a3b07b618e4ca4b3fa70 |
| tools | search | prefcc | b18bb9b9246041f55afcce561db5903f3f7b1de477d04b543009a3b170e4f4c5 |
| tools | search | query | 047b784c06acea87ecd0267f11aa8185f98cee671d7b21ef607319b26aaa049b |
| tools | search | rec | 2ce087cb67108fb85fd430d7de59c968dec7107ebaab7cf6849802dbb06bf565 |
| tools | search | sec | eba8b8d9cc1032b17f43c4a414829bf69b9197d4e641de2d12004deb37173a1b |
| tools | search | skip | 56cf224e81d41d59cc76f600af712aacd613e67f9cf7489c15d711f860b25c0b |
| tools | search | src | dd45303f19eb9ab9fbd7f20dc6fb5497108b038e2718dd1a56d7834f9e30edaa |
| tools | unseal_order | description | c6970927a67fd6eab6840f1a171592eb932d7c967f5bfd8030a01cab7d0307c0 |
| tools | unseal_order | id | e66fc76d2d0586ff442141d8d63732cba2a012a9d1ed10a4b442bcdea745f281 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
