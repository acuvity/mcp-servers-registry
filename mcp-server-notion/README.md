<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://acuvity.ai/wp-content/uploads/2025/09/1.-Acuvity-Logo-Black-scaled-e1758135197226.png" height="90" alt="Acuvity logo"/>
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
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-notion/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-notion/2.0.0?logo=docker&logoColor=fff&label=2.0.0)](https://hub.docker.com/r/acuvity/mcp-server-notion)
[![PyPI](https://img.shields.io/badge/2.0.0-3775A9?logo=pypi&logoColor=fff&label=@notionhq/notion-mcp-server)](https://github.com/makenotion/notion-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-notion/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-notion&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENAPI_MCP_HEADERS%22%2C%22docker.io%2Facuvity%2Fmcp-server-notion%3A2.0.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Interacting with Notion API.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @notionhq/notion-mcp-server original [sources](https://github.com/makenotion/notion-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-notion/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/charts/mcp-server-notion/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @notionhq/notion-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

#### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

#### 🛡️ Guardrails

##### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

##### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

##### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

##### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

##### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

##### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

#### Enable guardrails

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

#### 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, define `BASIC_AUTH_SECRET` environment variable with a shared secret.

Example: add `-e BASIC_AUTH_SECRET="supersecret"` to enable the basic authentication.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

> [!NOTE]
> By default, all guardrails except `resource integrity` are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-notion scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `OPENAPI_MCP_HEADERS` required to be set

For more information and extra configuration you can consult the [package](https://github.com/makenotion/notion-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-notion&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENAPI_MCP_HEADERS%22%2C%22docker.io%2Facuvity%2Fmcp-server-notion%3A2.0.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-notion": {
        "env": {
          "OPENAPI_MCP_HEADERS": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "OPENAPI_MCP_HEADERS",
          "docker.io/acuvity/mcp-server-notion:2.0.0"
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
        "OPENAPI_MCP_HEADERS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENAPI_MCP_HEADERS",
        "docker.io/acuvity/mcp-server-notion:2.0.0"
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
        "OPENAPI_MCP_HEADERS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENAPI_MCP_HEADERS",
        "docker.io/acuvity/mcp-server-notion:2.0.0"
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
        "OPENAPI_MCP_HEADERS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENAPI_MCP_HEADERS",
        "docker.io/acuvity/mcp-server-notion:2.0.0"
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
        "OPENAPI_MCP_HEADERS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENAPI_MCP_HEADERS",
        "docker.io/acuvity/mcp-server-notion:2.0.0"
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
        "env": {"OPENAPI_MCP_HEADERS":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","OPENAPI_MCP_HEADERS","docker.io/acuvity/mcp-server-notion:2.0.0"]
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
- arguments: `run -i --rm --read-only -e OPENAPI_MCP_HEADERS docker.io/acuvity/mcp-server-notion:2.0.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e OPENAPI_MCP_HEADERS docker.io/acuvity/mcp-server-notion:2.0.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-notion": {
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

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `OPENAPI_MCP_HEADERS` secret to be set as secrets.OPENAPI_MCP_HEADERS either by `.value` or from existing with `.valueFrom`

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

## 🧰 Tools (21)
<details>
<summary>API-get-user</summary>

**Description**:

```
Notion | Retrieve a user
Error Responses:
400: 400
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| user_id | string | not set | Yes
</details>
<details>
<summary>API-get-users</summary>

**Description**:

```
Notion | List all users
Error Responses:
400: 400
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| start_cursor | string | If supplied, this endpoint will return a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-get-self</summary>

**Description**:

```
Notion | Retrieve your token's bot user
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
</details>
<details>
<summary>API-post-search</summary>

**Description**:

```
Notion | Search by title
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| filter | object | A set of criteria, `value` and `property` keys, that limits the results to either only pages or only data sources. Possible `value` values are `"page"` or `"data_source"`. The only supported `property` value is `"object"`. | No
| page_size | integer | The number of items from the full list to include in the response. Maximum: `100`. | No
| query | string | The text that the API compares page and database titles against. | No
| sort | object | A set of criteria, `direction` and `timestamp` keys, that orders the results. The **only** supported timestamp value is `"last_edited_time"`. Supported `direction` values are `"ascending"` and `"descending"`. If `sort` is not provided, then the most recently edited results are returned first. | No
| start_cursor | string | A `cursor` value returned in a previous response that If supplied, limits the response to results starting after the `cursor`. If not supplied, then the first page of results is returned. Refer to [pagination](https://developers.notion.com/reference/intro#pagination) for more details. | No
</details>
<details>
<summary>API-get-block-children</summary>

**Description**:

```
Notion | Retrieve block children
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| block_id | string | Identifier for a [block](ref:block) | Yes
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| start_cursor | string | If supplied, this endpoint will return a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-patch-block-children</summary>

**Description**:

```
Notion | Append block children
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| after | string | The ID of the existing block that the new block should be appended after. | No
| block_id | string | Identifier for a [block](ref:block). Also accepts a [page](ref:page) ID. | Yes
| children | array | Child content to append to a container block as an array of [block objects](ref:block) | Yes
</details>
<details>
<summary>API-retrieve-a-block</summary>

**Description**:

```
Notion | Retrieve a block
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| block_id | string | Identifier for a Notion block | Yes
</details>
<details>
<summary>API-update-a-block</summary>

**Description**:

```
Notion | Update a block
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| archived | boolean | Set to true to archive (delete) a block. Set to false to un-archive (restore) a block. | No
| block_id | string | Identifier for a Notion block | Yes
| type | object | The [block object `type`](ref:block#block-object-keys) value with the properties to be updated. Currently only `text` (for supported block types) and `checked` (for `to_do` blocks) fields can be updated. | No
</details>
<details>
<summary>API-delete-a-block</summary>

**Description**:

```
Notion | Delete a block
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| block_id | string | Identifier for a Notion block | Yes
</details>
<details>
<summary>API-retrieve-a-page</summary>

**Description**:

```
Notion | Retrieve a page
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| filter_properties | string | A list of page property value IDs associated with the page. Use this param to limit the response to a specific page property value or values. To retrieve multiple properties, specify each page property ID. For example: `?filter_properties=iAk8&filter_properties=b7dh`. | No
| page_id | string | Identifier for a Notion page | Yes
</details>
<details>
<summary>API-patch-page</summary>

**Description**:

```
Notion | Update page properties
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| archived | boolean | not set | No
| cover | object | A cover image for the page. Only [external file objects](https://developers.notion.com/reference/file-object) are supported. | No
| icon | object | A page icon for the page. Supported types are [external file object](https://developers.notion.com/reference/file-object) or [emoji object](https://developers.notion.com/reference/emoji-object). | No
| in_trash | boolean | Set to true to delete a block. Set to false to restore a block. | No
| page_id | string | The identifier for the Notion page to be updated. | Yes
| properties | object | The property values to update for the page. The keys are the names or IDs of the property and the values are property values. If a page property ID is not included, then it is not changed. | No
</details>
<details>
<summary>API-post-page</summary>

**Description**:

```
Notion | Create a page
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| children | array | The content to be rendered on the new page, represented as an array of [block objects](https://developers.notion.com/reference/block). | No
| cover | string | The cover image of the new page, represented as a [file object](https://developers.notion.com/reference/file-object). | No
| icon | string | The icon of the new page. Either an [emoji object](https://developers.notion.com/reference/emoji-object) or an [external file object](https://developers.notion.com/reference/file-object).. | No
| parent | any | not set | Yes
| properties | object | not set | Yes
</details>
<details>
<summary>API-retrieve-a-page-property</summary>

**Description**:

```
Notion | Retrieve a page property item
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| page_id | string | Identifier for a Notion page | Yes
| page_size | integer | For paginated properties. The max number of property item objects on a page. The default size is 100 | No
| property_id | string | Identifier for a page [property](https://developers.notion.com/reference/page#all-property-values) | Yes
| start_cursor | string | For paginated properties. | No
</details>
<details>
<summary>API-retrieve-a-comment</summary>

**Description**:

```
Notion | Retrieve comments
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| block_id | string | Identifier for a Notion block or page | Yes
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| start_cursor | string | If supplied, this endpoint will return a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-create-a-comment</summary>

**Description**:

```
Notion | Create comment
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| parent | object | The page that contains the comment | Yes
| rich_text | array | not set | Yes
</details>
<details>
<summary>API-query-data-source</summary>

**Description**:

```
Notion | Query a data source
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| archived | boolean | not set | No
| data_source_id | string | Identifier for a Notion data source (database) | Yes
| filter | object | Filter conditions for querying the data source | No
| filter_properties | array | A list of page property value IDs to limit the response | No
| in_trash | boolean | not set | No
| page_size | integer | not set | No
| sorts | array | not set | No
| start_cursor | string | not set | No
</details>
<details>
<summary>API-retrieve-a-data-source</summary>

**Description**:

```
Notion | Retrieve a data source
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| data_source_id | string | Identifier for a Notion data source | Yes
</details>
<details>
<summary>API-update-a-data-source</summary>

**Description**:

```
Notion | Update a data source
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| data_source_id | string | Identifier for a Notion data source | Yes
| description | array | not set | No
| properties | object | Property schema updates | No
| title | array | not set | No
</details>
<details>
<summary>API-create-a-data-source</summary>

**Description**:

```
Notion | Create a data source
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| parent | any | not set | Yes
| properties | object | Property schema of data source | Yes
| title | array | not set | No
</details>
<details>
<summary>API-list-data-source-templates</summary>

**Description**:

```
Notion | List templates in a data source
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| data_source_id | string | Identifier for a Notion data source | Yes
| page_size | integer | not set | No
| start_cursor | string | not set | No
</details>
<details>
<summary>API-move-page</summary>

**Description**:

```
Notion | Move a page
Error Responses:
400: Bad request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Notion-Version | string | The Notion API version | No
| page_id | string | Identifier for a Notion page | Yes
| parent | any | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | API-create-a-comment | description | baa84c26a866545e76b2e304718cbb6e4f8f3d3b63adc7d50f40deadca1c7dd1 |
| tools | API-create-a-comment | parent | 80ad2857740577e2077ef3c462fe8409dbe228a6cdfbb8c9a4c9d25ca7f2965e |
| tools | API-create-a-data-source | description | 47501fa0161dd48ae43d1988bef527e359233c32fff30f707f04704da9a44e0e |
| tools | API-create-a-data-source | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-create-a-data-source | properties | db8581320d6e04dd2a46a856648de1d8a237468cc311641087c44f6077773fc1 |
| tools | API-delete-a-block | description | 9c09dbfb056d0a684ae2d2f5192e74470c50da05c12cb4a42dba8c433e6e2e8f |
| tools | API-delete-a-block | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-delete-a-block | block_id | 4282659befb77e742b5cc853f28d0fba3c013371b1d5a7cd24a13568b31f7b37 |
| tools | API-get-block-children | description | eb03192bdf0df318944e79cc1d22c94345a8c590349363e178fd0bcf7eb77b38 |
| tools | API-get-block-children | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-get-block-children | block_id | 9bcbe2492facf78a4ee18c89806c40c35a87ad4b530c3170a1ff39a880906371 |
| tools | API-get-block-children | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-get-block-children | start_cursor | e5b52e5e2e4b1f29ff2ef0055327c55856d7f55609fe52f8b1f69eaa29530469 |
| tools | API-get-self | description | c9c3e936a7e22c21368d4e93202b91238195259ecf3ad021d66b09f8f37c1d88 |
| tools | API-get-self | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-get-user | description | 4784bfae1cc628191000a5980c2eea05a8aad5ea1349058a7c2ab07d1e68a6fc |
| tools | API-get-user | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-get-users | description | 217e151731f67b8bf1e3aa698782a2cefc378bc6017b0f65dce3eeefe2594f1f |
| tools | API-get-users | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-get-users | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-get-users | start_cursor | e5b52e5e2e4b1f29ff2ef0055327c55856d7f55609fe52f8b1f69eaa29530469 |
| tools | API-list-data-source-templates | description | 6ab08598baadf3ef55cb9a15e927ddf8c7213fce6f87d1100f1a9e87137b0e59 |
| tools | API-list-data-source-templates | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-list-data-source-templates | data_source_id | 1727d263ab28abdb6f031056659ae8dde7d86b2274a753957dc474126a8c37f0 |
| tools | API-move-page | description | 1bcd955cd26680941e669a360844d978fa6af7c5bd66e611d089a16edc788679 |
| tools | API-move-page | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-move-page | page_id | 28634ab8051c0c0b0b533b0830f92e6bea11a3d772ba30db5161f58ea95f68b4 |
| tools | API-patch-block-children | description | a0d239869582e531c132fe846484279d31af9d5d9cedad8cce72ae6b7f828cff |
| tools | API-patch-block-children | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-patch-block-children | after | c727e3b91d2dc39ec83c92b70bda36145409cdfac6fd8dfd73c53be124071343 |
| tools | API-patch-block-children | block_id | 1ac2e0616787fd6470faf44a932a32dc5ae7ecfb910a07316ff2c1c7322ac23e |
| tools | API-patch-block-children | children | 44d9344314eeef73a29c1b254f18b3b88a25123298f00a082863c6ff6c14cb47 |
| tools | API-patch-page | description | afed51affd953402e8d1d53d85626dd526025e78d608af1c57df62c6278de8d7 |
| tools | API-patch-page | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-patch-page | cover | b9815ef939d225a191cfc788e43ae4b549a433471b3fb166e5b20d2a497cdf14 |
| tools | API-patch-page | icon | 58eb56d386c18050173f6394c736007572828633a894fe88e905e12aa6210d79 |
| tools | API-patch-page | in_trash | ab3e9fe89322e3da72f39f596f2033bbec59a0098bf9f0aa672e5c5dddf2aaeb |
| tools | API-patch-page | page_id | b5930097fd9390bac535ec99ebbfaa2927d17bcae8f871695278547f8e7cf346 |
| tools | API-patch-page | properties | 8b7dfc8b81ca3f2eac312bf89b6eb8ef8dc60d95c91523b7f1c07057f1b861f4 |
| tools | API-post-page | description | 54a98f472e6ac6879222d3027f031b27cd44451606e0dfb2bd1143b9ae010516 |
| tools | API-post-page | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-post-page | children | dfef3332fc212d5de83488a378ef5f656620690071b9a4c1bf89224c47117eda |
| tools | API-post-page | cover | b39fea223aa71d6c736f6bdc458887d85629de1450078a67e4f4708fe4407e97 |
| tools | API-post-page | icon | 28975513a8ec2f9437200f6012de26619dc902c7133691c102cfe1c43956549c |
| tools | API-post-search | description | 2575d292c8bd5721863b6491516ee62d66c21b28adccca38b1467a7a6aa2ecf2 |
| tools | API-post-search | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-post-search | filter | cb0dab8fd76cd1c89c2f2958918c3c7d5d58048607789643e64bc93b5676b6cb |
| tools | API-post-search | page_size | ceafdaab204f34d7a79ce05c88b6d698aeee428066057f7512ad1d8c965c14aa |
| tools | API-post-search | query | 4880cdf43451479ef98bf8b0ea9611ddc4c9db89d15387c01da46a2d3893095b |
| tools | API-post-search | sort | 564929275340d84a24f9382adf6a7cf751fa71f4f38a814ce43dedd9f7713f97 |
| tools | API-post-search | start_cursor | 9f0b7de41237ccb79a242da38187fe4acd22c3e69684ece5dad353404c6c62e1 |
| tools | API-query-data-source | description | 415fa8b21f7e000b154cc44e141e71e508e07d45fb6695fe5a2f4c94f58e95c5 |
| tools | API-query-data-source | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-query-data-source | data_source_id | 2742b8ed1c273f333c3c38190a923c9c07a461f63db79bb4833020854028b22d |
| tools | API-query-data-source | filter | d5e3be965dcb2d2c4cd9acd943c85513137ca9a9e4c7e6ff60e1a2616c0e44d3 |
| tools | API-query-data-source | filter_properties | 81fec27e0b5b22b94b5618a0beec004320b55648a08597cbed63cc20e8ed2464 |
| tools | API-retrieve-a-block | description | 95a847762cf7b1589bc16a61a7018b852859bd0d9f5d02e744b94bb301a5564f |
| tools | API-retrieve-a-block | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-retrieve-a-block | block_id | 4282659befb77e742b5cc853f28d0fba3c013371b1d5a7cd24a13568b31f7b37 |
| tools | API-retrieve-a-comment | description | c2ab3fa10f5ead046ae22c5f5dffa1d71a08124fc2946441ecbedfc36fb874e6 |
| tools | API-retrieve-a-comment | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-retrieve-a-comment | block_id | 800e6bacf259e4f525e1c2e5cb8e67f361d1b5bc0c35a68d38d218e5645a889f |
| tools | API-retrieve-a-comment | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-retrieve-a-comment | start_cursor | e5b52e5e2e4b1f29ff2ef0055327c55856d7f55609fe52f8b1f69eaa29530469 |
| tools | API-retrieve-a-data-source | description | 7b07c40b8fe690ab1f0ea53d8d2ebabe105acefbe8eedc453e645824b04eee72 |
| tools | API-retrieve-a-data-source | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-retrieve-a-data-source | data_source_id | 1727d263ab28abdb6f031056659ae8dde7d86b2274a753957dc474126a8c37f0 |
| tools | API-retrieve-a-page | description | 18265ba80d56f6d2032668a7364173058b98df04bb540186df2817f824d8557e |
| tools | API-retrieve-a-page | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-retrieve-a-page | filter_properties | aaa1e89cb9d79b8b24fed89244939f50bca965a928ccd3bd95fe18c7c483634b |
| tools | API-retrieve-a-page | page_id | 28634ab8051c0c0b0b533b0830f92e6bea11a3d772ba30db5161f58ea95f68b4 |
| tools | API-retrieve-a-page-property | description | fc15cb9633a7be4efb5b35c935c18c97af991f3b6351937b087d071b086b1a10 |
| tools | API-retrieve-a-page-property | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-retrieve-a-page-property | page_id | 28634ab8051c0c0b0b533b0830f92e6bea11a3d772ba30db5161f58ea95f68b4 |
| tools | API-retrieve-a-page-property | page_size | 231332689fcc3e6a74772c04121a1778539e4e7a54856a84b86bbeeb11b04fc6 |
| tools | API-retrieve-a-page-property | property_id | 864a243ef35b8ea5e3d0db2712a8a7ade53550c732678977cc84697000695214 |
| tools | API-retrieve-a-page-property | start_cursor | b274bf0ccad01fb37e4fc3ce317fd9d19e33f37f16349f2f61d246dbab289d14 |
| tools | API-update-a-block | description | 500eb9c8deb4b34551b18fbe65105b2c4e60bbe10d6c5a68ceb999ee9a24dfcc |
| tools | API-update-a-block | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-update-a-block | archived | 9507894f6773eba55065ea07d3b4b65014523432442a3bbd5f11242764637bba |
| tools | API-update-a-block | block_id | 4282659befb77e742b5cc853f28d0fba3c013371b1d5a7cd24a13568b31f7b37 |
| tools | API-update-a-block | type | ed6d041bbe1c6569f88f0c4cab0b8021625770aa7651f19e04896ed880b89920 |
| tools | API-update-a-data-source | description | dfec7f655741b7831efd2d2ace9a15bd6a5e6a6e362f7d40b9e34092f02366ca |
| tools | API-update-a-data-source | Notion-Version | be6a350d02e8d70b380a8fdfe1d559f499172eda503a34ae8548df3e1db4b4c5 |
| tools | API-update-a-data-source | data_source_id | 1727d263ab28abdb6f031056659ae8dde7d86b2274a753957dc474126a8c37f0 |
| tools | API-update-a-data-source | properties | 978cafb5e65e291cdeb93141aa857af637b20f0569938b215f0195d41d92b019 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
