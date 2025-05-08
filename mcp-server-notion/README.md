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


# What is mcp-server-notion?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-notion/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-notion/1.2.3?logo=docker&logoColor=fff&label=1.2.3)](https://hub.docker.com/r/acuvity/mcp-server-notion)
[![PyPI](https://img.shields.io/badge/1.2.3-3775A9?logo=pypi&logoColor=fff&label=@suekou/mcp-notion-server)](https://github.com/suekou/mcp-notion-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-notion&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NOTION_API_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-notion%3A1.2.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Interacting with Notion API.

> [!NOTE]
> `mcp-server-notion` has been packaged by Acuvity from @suekou/mcp-notion-server original [sources](https://github.com/suekou/mcp-notion-server).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @suekou/mcp-notion-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a built-in Rego policy that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Gardrails

### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

## Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

</details>

> [!NOTE]
> All guardrails start disabled. You can switch each one on or off individually, so you only activate the protections your environment requires.


# 📦 How to Use


> [!NOTE]
> Given mcp-server-notion scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-notion&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NOTION_API_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-notion%3A1.2.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-notion": {
        "env": {
          "NOTION_API_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "NOTION_API_TOKEN",
          "docker.io/acuvity/mcp-server-notion:1.2.3"
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
    "acuvity-mcp-server-notion": {
      "env": {
        "NOTION_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NOTION_API_TOKEN",
        "docker.io/acuvity/mcp-server-notion:1.2.3"
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
    "acuvity-mcp-server-notion": {
      "env": {
        "NOTION_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NOTION_API_TOKEN",
        "docker.io/acuvity/mcp-server-notion:1.2.3"
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
    "acuvity-mcp-server-notion": {
      "env": {
        "NOTION_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NOTION_API_TOKEN",
        "docker.io/acuvity/mcp-server-notion:1.2.3"
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
    "acuvity-mcp-server-notion": {
      "env": {
        "NOTION_API_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NOTION_API_TOKEN",
        "docker.io/acuvity/mcp-server-notion:1.2.3"
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
        "env": {"NOTION_API_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","NOTION_API_TOKEN","docker.io/acuvity/mcp-server-notion:1.2.3"]
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

**Environment variables and secrets:**
  - `NOTION_API_TOKEN` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e NOTION_API_TOKEN docker.io/acuvity/mcp-server-notion:1.2.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e NOTION_API_TOKEN docker.io/acuvity/mcp-server-notion:1.2.3
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-notion": {
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
    "acuvity-mcp-server-notion": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Minibridge offers a host of additional features. For step-by-step guidance, please visit the wiki. And if anything’s unclear, don’t hesitate to reach out!

</details>

## 🛡️ Runtime security

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

for example, `-e GUARDRAILS="secrets-redaction covert-instruction-detection"` will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


To turn on Basic Authentication, set BASIC_AUTH_SECRET like `- e BASIC_AUTH_SECRET="supersecret`

Then you can connect through `http/sse` as usual given that you pass an `Authorization: Bearer supersecret` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `NOTION_API_TOKEN` secret to be set as secrets.NOTION_API_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
````

Install with helm

```console
helm install mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
```

From there your MCP server mcp-server-notion will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-notion` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/charts/mcp-server-notion/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (18)
<details>
<summary>notion_append_block_children</summary>

**Description**:

```
Append new children blocks to a specified parent block in Notion. Requires insert content capabilities. You can optionally specify the 'after' parameter to append after a certain block.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | The ID of the existing block that the new block should be appended after.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | No
| block_id | string | The ID of the parent block.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| children | array | Array of block objects to append. Each block must follow the Notion block schema. | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
</details>
<details>
<summary>notion_retrieve_block</summary>

**Description**:

```
Retrieve a block from Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | The ID of the block to retrieve.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
</details>
<details>
<summary>notion_retrieve_block_children</summary>

**Description**:

```
Retrieve the children of a block
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | The ID of the block.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_size | number | Number of results per page (max 100) | No
| start_cursor | string | Pagination cursor for next page of results | No
</details>
<details>
<summary>notion_delete_block</summary>

**Description**:

```
Delete a block in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | The ID of the block to delete.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
</details>
<details>
<summary>notion_update_block</summary>

**Description**:

```
Update the content of a block in Notion based on its type. The update replaces the entire value for a given field.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block | object | The updated content for the block. Must match the block's type schema. | Yes
| block_id | string | The ID of the block to update.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
</details>
<details>
<summary>notion_retrieve_page</summary>

**Description**:

```
Retrieve a page from Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_id | string | The ID of the page to retrieve.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
</details>
<details>
<summary>notion_update_page_properties</summary>

**Description**:

```
Update properties of a page or an item in a Notion database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_id | string | The ID of the page or database item to update.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| properties | object | Properties to update. These correspond to the columns or fields in the database. | Yes
</details>
<details>
<summary>notion_list_all_users</summary>

**Description**:

```
List all users in the Notion workspace. **Note:** This function requires upgrading to the Notion Enterprise plan and using an Organization API key to avoid permission errors.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_size | number | Number of users to retrieve (max 100) | No
| start_cursor | string | Pagination start cursor for listing users | No
</details>
<details>
<summary>notion_retrieve_user</summary>

**Description**:

```
Retrieve a specific user by user_id in Notion. **Note:** This function requires upgrading to the Notion Enterprise plan and using an Organization API key to avoid permission errors.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| user_id | string | The ID of the user to retrieve.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
</details>
<details>
<summary>notion_retrieve_bot_user</summary>

**Description**:

```
Retrieve the bot user associated with the current token in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| random_string | string | Dummy parameter for no-parameter tools | Yes
</details>
<details>
<summary>notion_create_database</summary>

**Description**:

```
Create a database in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| parent | object | Parent object of the database | Yes
| properties | object | Property schema of database. The keys are the names of properties as they appear in Notion and the values are property schema objects. | Yes
| title | array | Title of database as it appears in Notion. An array of rich text objects. | No
</details>
<details>
<summary>notion_query_database</summary>

**Description**:

```
Query a database in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_id | string | The ID of the database to query.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| filter | object | Filter conditions | No
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_size | number | Number of results per page (max 100) | No
| sorts | array | Sort conditions | No
| start_cursor | string | Pagination cursor for next page of results | No
</details>
<details>
<summary>notion_retrieve_database</summary>

**Description**:

```
Retrieve a database in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_id | string | The ID of the database to retrieve.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
</details>
<details>
<summary>notion_update_database</summary>

**Description**:

```
Update a database in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_id | string | The ID of the database to update.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| description | array | An array of rich text objects that represents the description of the database that is displayed in the Notion UI. | No
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| properties | object | The properties of a database to be changed in the request, in the form of a JSON object. | No
| title | array | An array of rich text objects that represents the title of the database that is displayed in the Notion UI. | No
</details>
<details>
<summary>notion_create_database_item</summary>

**Description**:

```
Create a new item (page) in a Notion database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_id | string | The ID of the database to add the item to.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| properties | object | Properties of the new database item. These should match the database schema. | Yes
</details>
<details>
<summary>notion_create_comment</summary>

**Description**:

```
Create a comment in Notion. This requires the integration to have 'insert comment' capabilities. You can either specify a page parent or a discussion_id, but not both.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| discussion_id | string | The ID of an existing discussion thread to add a comment to.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | No
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| parent | object | Parent object that specifies the page to comment on. Must include a page_id if used. | No
| rich_text | array | Array of rich text objects representing the comment content. | Yes
</details>
<details>
<summary>notion_retrieve_comments</summary>

**Description**:

```
Retrieve a list of unresolved comments from a Notion page or block. Requires the integration to have 'read comment' capabilities.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | The ID of the block or page whose comments you want to retrieve.It should be a 32-character string (excluding hyphens) formatted as 8-4-4-4-12 with hyphens (-). | Yes
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_size | number | Number of comments to retrieve (max 100). | No
| start_cursor | string | If supplied, returns a page of results starting after the cursor. | No
</details>
<details>
<summary>notion_search</summary>

**Description**:

```
Search pages or databases by title in Notion
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter | object | Filter results by object type (page or database) | No
| format | string | Specify the response format. 'json' returns the original data structure, 'markdown' returns a more readable format. Use 'markdown' when the user only needs to read the page and isn't planning to write or modify it. Use 'json' when the user needs to read the page with the intention of writing to or modifying it. | No
| page_size | number | Number of results to return (max 100).  | No
| query | string | Text to search for in page or database titles | No
| sort | object | Sort order of results | No
| start_cursor | string | Pagination start cursor | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | notion_append_block_children | description | 12321e958ea635cd5b18aa55541adfa74923ec6b9b8fa7445f71ae38ec8c94ad |
| tools | notion_append_block_children | after | 906f6f3316057fe492966d7b3d1f8bd3d8faeedb5a20b417de20ffe0a9042090 |
| tools | notion_append_block_children | block_id | 7bed4ad4bf9c3ba038de32f2c5586f8ddec1924f5f8a1a02addd12b5d2296b9e |
| tools | notion_append_block_children | children | fe52bb3553357b05c787a49d600457ab983a55aba8a2023293bc2789ca9a25aa |
| tools | notion_append_block_children | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_create_comment | description | bdca981386debfe6444c598907ada9d63e8acb12541370fa9a0e856e487e0377 |
| tools | notion_create_comment | discussion_id | 001d8a0550e16c385fc97ff2758676e22290815578df98e974fb58a1c46737fd |
| tools | notion_create_comment | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_create_comment | parent | 98d7a1607cf3c923ad73884d28fa9c23d5d236f498afee6e2ee8f8c470bdd9d5 |
| tools | notion_create_comment | rich_text | f29bd88e7553fcee7e106363e02afef29e0f64f3c48761fe8b63c6118af6f717 |
| tools | notion_create_database | description | 22c97e2d1e533b2a8cfdf2a4a86c589164c338281fc9fd768a785f342d830456 |
| tools | notion_create_database | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_create_database | parent | 3ade884bc68930b24ba889a3970dea49e30fe22260bad38158d3aaa4ca29c4f4 |
| tools | notion_create_database | properties | 4c6e8bbe47ff2bb9f12c2660a165a06c025521d0c408f16f6803fd8da628bb1f |
| tools | notion_create_database | title | 5fc90f86ecf25deb1adf9402a5cd1052f90f01f7bdc3c999886300ca148b297e |
| tools | notion_create_database_item | description | 14ef3abb68041b0ef420bae5b9fd5865944dada379089cc837a794c0a4e61bb4 |
| tools | notion_create_database_item | database_id | a62d1aff88b3ca3155a84e6f2e06af8b5b4344c2c58e6a02d1054910763c9870 |
| tools | notion_create_database_item | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_create_database_item | properties | 658fe42241762c24167929c66f7c5bdb52b7d3b51f11f78a63d6fef0772b60df |
| tools | notion_delete_block | description | d8e6ae63e7c6ec7a3c4763bc83cdaf61103ce52ab6acaac9d31f5f2aef499f30 |
| tools | notion_delete_block | block_id | 6a10908b39462662fe33dec1c4408f5009716692685ff2da9770cad12fcb15b1 |
| tools | notion_delete_block | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_list_all_users | description | e6d9f69de7d52ad82cfee8270cefcaaf465e7995bd0316ef8ca2a156f7a0ca10 |
| tools | notion_list_all_users | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_list_all_users | page_size | f22f56658ae22fd3a776523328580be6a4be69eb1eac0f78a3580f4cff0cbd45 |
| tools | notion_list_all_users | start_cursor | bdc70c59fb190ece7f7be773a4facef934df083939c54cf9f23e32faa37846ee |
| tools | notion_query_database | description | 97cedfc473bea5729b0ea165f19ab7db0fec6b0c847f8f627ef612f6ebe97eda |
| tools | notion_query_database | database_id | d2b73aee8962d69b2f311cfd3bdc8a7776fe6c8790ce58ea01a2e5fc5a34a5fd |
| tools | notion_query_database | filter | b4060a70d15041044d885205c53ad809cbbb885c89d03fe9aff62b7766be185b |
| tools | notion_query_database | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_query_database | page_size | 462903a69ac0e31e27ded9aa8a40dc2092720b36aa094a21a124a47aadbd1901 |
| tools | notion_query_database | sorts | 7295aa2b6c9eb082c7b49b8b12bbb4eb074f3a785c8f9a08169c94ea1d786e80 |
| tools | notion_query_database | start_cursor | af663f140c35780ea36be96fa602b310c84c5373bd95d8f7e98e2fdb474d5061 |
| tools | notion_retrieve_block | description | 4399eb090a229fcc211c82842281b1368a483e349074733c48757822aae06b85 |
| tools | notion_retrieve_block | block_id | b8aa6a3e62824694f976523f6498ec8f046d586f86d6bf586432f28c69fcfb4d |
| tools | notion_retrieve_block | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_block_children | description | 74ff5388c92733c41a636cc773d86df45eda6a5f8243d0c3c0246d088e70a425 |
| tools | notion_retrieve_block_children | block_id | cb56bb172b9fecc86a15858dbd0e4f0c2c80acb5e1e86402d3fcbde0bfbfca00 |
| tools | notion_retrieve_block_children | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_block_children | page_size | 462903a69ac0e31e27ded9aa8a40dc2092720b36aa094a21a124a47aadbd1901 |
| tools | notion_retrieve_block_children | start_cursor | af663f140c35780ea36be96fa602b310c84c5373bd95d8f7e98e2fdb474d5061 |
| tools | notion_retrieve_bot_user | description | 7434b611dd5e6dea1ab4af7ab2505dd030681ca3024ee943c2e5038644b758ed |
| tools | notion_retrieve_bot_user | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_bot_user | random_string | ad4e9f571a00a7ee3fc8a4d23732082c760747cb9c3006c24d8fbea85bb1c704 |
| tools | notion_retrieve_comments | description | f2eab490252c0a5176b7d0113b6aca7f2ac655f7a63b99b10438c7e5b81caaae |
| tools | notion_retrieve_comments | block_id | 85a9544b20528c7101672082074817e0531e5ee21a7b5559be5ec69015ad8004 |
| tools | notion_retrieve_comments | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_comments | page_size | fed7a9cd82db1d3fe95b6b930cc37f0cd28fad78f99dc2b140ee13266287092c |
| tools | notion_retrieve_comments | start_cursor | a8ff75992d55f4e0956503e21baf504ba8b053fc79b7ecf3dd0a947ea27e5dcf |
| tools | notion_retrieve_database | description | 8f1ebf8d275a8bd57bd835dc347602ab818e05b7dddabb13293df80ecc00db7d |
| tools | notion_retrieve_database | database_id | 426a5adbc31d41fc5f0fd64ff3dbb30f808e79c2fdd2e3e29725562f06b8f3e8 |
| tools | notion_retrieve_database | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_page | description | 97305df3c32cbedc1137577cc02914e0131e5cd05d4da587095f3a8bdd5687b5 |
| tools | notion_retrieve_page | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_page | page_id | bce3e8c0922393634a953830d8b7d7813641e43b6466a7f310cad2c197b75cca |
| tools | notion_retrieve_user | description | eb17b24db944f0b3b200e2893ce59eb3458181540ae34765196efed8e19b776b |
| tools | notion_retrieve_user | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_retrieve_user | user_id | d52a436b7b3c40d48e377578255075a8193516688da879debad40f25a1ab258f |
| tools | notion_search | description | 102f8bd041842e6f82b544a843ac24d35e9fd8b0615c69e16001186619e8aa21 |
| tools | notion_search | filter | e0b27d45ea3aee29097aa4c78fd6205a133669c512c2f78f61ca87af0a6aa55c |
| tools | notion_search | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_search | page_size | 8dd46b11f3dfdaaec00c5f5d36e839eeac355984c2a095d2f23f89b8e138de47 |
| tools | notion_search | query | f6be6000f0258828d868042812394564e520c11639ac51b8a2bd040d687c9f54 |
| tools | notion_search | sort | 1745b12757e940ea45fe7f6c79a461eecbe279229fd6c7019e98aaae3017f952 |
| tools | notion_search | start_cursor | c875a17576a4dad5ed92944746a0d824835bd6cc895cef1417f764df1569b941 |
| tools | notion_update_block | description | 295617647b5a6942a2efd2c44278eb1dd4f000386e2c0e9701911dd87aff59e5 |
| tools | notion_update_block | block | 697a01ddb097f68202bc17cfbb24e3038d6be9b1e5f22a18aca158655323fa53 |
| tools | notion_update_block | block_id | 2ced97bbf8a137f37adddb68976e48e994dd2d24135c2482dbfd0b647ffd2415 |
| tools | notion_update_block | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_update_database | description | 3ff7cc8cab2a5fd7d8108678558128491bbcb08ffb021ee8b58a2ae26e052a8c |
| tools | notion_update_database | database_id | 21b676d251107d05ed2af0b696c4d557158618a231e84049fc7975fd74992a87 |
| tools | notion_update_database | description | bd7b0039f763cc16aec4b224fcef1179cf5edefc358db4bcb9d27c7a32557a5e |
| tools | notion_update_database | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_update_database | properties | 53476a4f6627be4102b9fe8aeb913d40a047c436bde7b00e9566539af5f6cdd7 |
| tools | notion_update_database | title | 234c0aec250f87cdee884c3ba9f043191838b5cdfb10a889ab8e5f287cea58f4 |
| tools | notion_update_page_properties | description | 88944b9c35849d6328bb5fc958ad03d850389b0733c9900c8558fc7a09686f19 |
| tools | notion_update_page_properties | format | 3fe122c0e15d6c91bfab5bcbc133e3d496203080394a437c7f2b2bc48db1b4a8 |
| tools | notion_update_page_properties | page_id | b45759c043357316c7fb264aab296b1b130250ac041b3b02eece1452b11ce049 |
| tools | notion_update_page_properties | properties | 91269f926b9d13af03f765dfa94ed06d401e43de1c288cec5977b60d6ae3fb56 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
