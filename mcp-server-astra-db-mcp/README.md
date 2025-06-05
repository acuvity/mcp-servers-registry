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


# What is mcp-server-astra-db-mcp?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-astra-db-mcp/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-astra-db-mcp/1.2.0?logo=docker&logoColor=fff&label=1.2.0)](https://hub.docker.com/r/acuvity/mcp-server-astra-db-mcp)
[![PyPI](https://img.shields.io/badge/1.2.0-3775A9?logo=pypi&logoColor=fff&label=@datastax/astra-db-mcp)](https://github.com/datastax/astra-db-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-astra-db-mcp/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-astra-db-mcp&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ASTRA_DB_API_ENDPOINT%22%2C%22-e%22%2C%22ASTRA_DB_APPLICATION_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-astra-db-mcp%3A1.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for managing and interacting with Astra DB using language models.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @datastax/astra-db-mcp original [sources](https://github.com/datastax/astra-db-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-astra-db-mcp/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-astra-db-mcp/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-astra-db-mcp/charts/mcp-server-astra-db-mcp/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @datastax/astra-db-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-astra-db-mcp/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-astra-db-mcp scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `ASTRA_DB_API_ENDPOINT` required to be set
  - `ASTRA_DB_APPLICATION_TOKEN` required to be set

For more information and extra configuration you can consult the [package](https://github.com/datastax/astra-db-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-astra-db-mcp&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ASTRA_DB_API_ENDPOINT%22%2C%22-e%22%2C%22ASTRA_DB_APPLICATION_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-astra-db-mcp%3A1.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-astra-db-mcp": {
        "env": {
          "ASTRA_DB_API_ENDPOINT": "TO_BE_SET",
          "ASTRA_DB_APPLICATION_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "ASTRA_DB_API_ENDPOINT",
          "-e",
          "ASTRA_DB_APPLICATION_TOKEN",
          "docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0"
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
    "acuvity-mcp-server-astra-db-mcp": {
      "env": {
        "ASTRA_DB_API_ENDPOINT": "TO_BE_SET",
        "ASTRA_DB_APPLICATION_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ASTRA_DB_API_ENDPOINT",
        "-e",
        "ASTRA_DB_APPLICATION_TOKEN",
        "docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0"
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
    "acuvity-mcp-server-astra-db-mcp": {
      "env": {
        "ASTRA_DB_API_ENDPOINT": "TO_BE_SET",
        "ASTRA_DB_APPLICATION_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ASTRA_DB_API_ENDPOINT",
        "-e",
        "ASTRA_DB_APPLICATION_TOKEN",
        "docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0"
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
    "acuvity-mcp-server-astra-db-mcp": {
      "env": {
        "ASTRA_DB_API_ENDPOINT": "TO_BE_SET",
        "ASTRA_DB_APPLICATION_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ASTRA_DB_API_ENDPOINT",
        "-e",
        "ASTRA_DB_APPLICATION_TOKEN",
        "docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0"
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
    "acuvity-mcp-server-astra-db-mcp": {
      "env": {
        "ASTRA_DB_API_ENDPOINT": "TO_BE_SET",
        "ASTRA_DB_APPLICATION_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ASTRA_DB_API_ENDPOINT",
        "-e",
        "ASTRA_DB_APPLICATION_TOKEN",
        "docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0"
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
        "env": {"ASTRA_DB_API_ENDPOINT":"TO_BE_SET","ASTRA_DB_APPLICATION_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","ASTRA_DB_API_ENDPOINT","-e","ASTRA_DB_APPLICATION_TOKEN","docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0"]
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
- arguments: `run -i --rm --read-only -e ASTRA_DB_API_ENDPOINT -e ASTRA_DB_APPLICATION_TOKEN docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e ASTRA_DB_API_ENDPOINT -e ASTRA_DB_APPLICATION_TOKEN docker.io/acuvity/mcp-server-astra-db-mcp:1.2.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-astra-db-mcp": {
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
    "acuvity-mcp-server-astra-db-mcp": {
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
  - `ASTRA_DB_API_ENDPOINT` secret to be set as secrets.ASTRA_DB_API_ENDPOINT either by `.value` or from existing with `.valueFrom`
  - `ASTRA_DB_APPLICATION_TOKEN` secret to be set as secrets.ASTRA_DB_APPLICATION_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-astra-db-mcp --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-astra-db-mcp --version 1.0.0
````

Install with helm

```console
helm install mcp-server-astra-db-mcp oci://docker.io/acuvity/mcp-server-astra-db-mcp --version 1.0.0
```

From there your MCP server mcp-server-astra-db-mcp will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-astra-db-mcp` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-astra-db-mcp/charts/mcp-server-astra-db-mcp/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (16)
<details>
<summary>GetCollections</summary>

**Description**:

```
Get all collections in the Astra DB database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>CreateCollection</summary>

**Description**:

```
Create a new collection in the database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to create | Yes
| dimension | number | The dimensions of the vector collection, if vector is true | No
| vector | boolean | Whether to create a vector collection | No
</details>
<details>
<summary>UpdateCollection</summary>

**Description**:

```
Update an existing collection in the database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to update | Yes
| newName | string | New name for the collection | Yes
</details>
<details>
<summary>DeleteCollection</summary>

**Description**:

```
Delete a collection from the database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to delete | Yes
</details>
<details>
<summary>ListRecords</summary>

**Description**:

```
List records from a collection in the database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to list records from | Yes
| limit | number | Maximum number of records to return | No
</details>
<details>
<summary>GetRecord</summary>

**Description**:

```
Get a specific record from a collection by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to get the record from | Yes
| recordId | string | ID of the record to retrieve | Yes
</details>
<details>
<summary>CreateRecord</summary>

**Description**:

```
Create a new record in a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to create the record in | Yes
| record | object | The record data to insert | Yes
</details>
<details>
<summary>UpdateRecord</summary>

**Description**:

```
Update an existing record in a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection containing the record | Yes
| record | object | The updated record data | Yes
| recordId | string | ID of the record to update | Yes
</details>
<details>
<summary>DeleteRecord</summary>

**Description**:

```
Delete a record from a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection containing the record | Yes
| recordId | string | ID of the record to delete | Yes
</details>
<details>
<summary>FindRecord</summary>

**Description**:

```
Find records in a collection by field value
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to search in | Yes
| field | string | Field name to search by (e.g., 'title', '_id', or any property) | Yes
| limit | number | Maximum number of records to return | No
| value | string | Value to search for in the specified field | Yes
</details>
<details>
<summary>BulkCreateRecords</summary>

**Description**:

```
Create multiple records in a collection at once
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to create the records in | Yes
| records | array | Array of records to insert | Yes
</details>
<details>
<summary>BulkUpdateRecords</summary>

**Description**:

```
Update multiple records in a collection at once
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection containing the records | Yes
| records | array | Array of records to update with their IDs | Yes
</details>
<details>
<summary>BulkDeleteRecords</summary>

**Description**:

```
Delete multiple records from a collection at once
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection containing the records | Yes
| recordIds | array | Array of record IDs to delete | Yes
</details>
<details>
<summary>OpenBrowser</summary>

**Description**:

```
Open a web browser to a specific URL
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | The URL to open in the browser | Yes
</details>
<details>
<summary>EstimateDocumentCount</summary>

**Description**:

```
Estimate the number of documents in a collection using a fast, approximate count method
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collectionName | string | Name of the collection to estimate document count for | Yes
</details>
<details>
<summary>HelpAddToClient</summary>

**Description**:

```
Help the user add the Astra DB client to their MCP client
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | BulkCreateRecords | description | a6366d8980e21e4a3df97b14eba52c31e0409363acf0c006bb4ccaa8fc4f01a8 |
| tools | BulkCreateRecords | collectionName | 7fb89d5f53e6bcd1c01927d03ce92c70f4a07f6d96d839b356c9b1158c3e14a0 |
| tools | BulkCreateRecords | records | e753bd376368bec633df62e031a87087749c530a3bd999f2c4ffb59f8bf0a576 |
| tools | BulkDeleteRecords | description | b6c41610806776f7c32b3373024a7673ddf17994d1781c700bf5ee45bb92fd4f |
| tools | BulkDeleteRecords | collectionName | a5e2bf226966a9a157f37fcaebbca5ac4794ed0f140fa85e1c59b799b4683d62 |
| tools | BulkDeleteRecords | recordIds | 4c5bd36a9eb9a1bfe6cd786d66b95e5a598a09f0ac102ff00ab5acf929b46d37 |
| tools | BulkUpdateRecords | description | d21b94cac4de307dd0b66b6ed448545d1675ae6b8a631374499dddfefd4edef5 |
| tools | BulkUpdateRecords | collectionName | a5e2bf226966a9a157f37fcaebbca5ac4794ed0f140fa85e1c59b799b4683d62 |
| tools | BulkUpdateRecords | records | d5a18949874b3895a09aeeeeb96a471936c11334f19f48ac53ba96e495653ae9 |
| tools | CreateCollection | description | 74d2fe2832a0b8e27a93abf0e75e34d3db2f5639f978e2eb6af22ce116546e56 |
| tools | CreateCollection | collectionName | a1d94d7b1c2c5fa14a726ec29730c117643114d03b0eb8c8b1fdc8f00d383826 |
| tools | CreateCollection | dimension | 1af2eed6611437f4a32a7923fd3b3ca1445a8f87e223f5d05e64f70a0cdb0073 |
| tools | CreateCollection | vector | 5da4d94458da837cf6a38caf9bb4642add9acc9a5ede89aff3dd29c1ca3f50e2 |
| tools | CreateRecord | description | c11a90cda9a2376ed4b6de6a23459a367b9e4ca1809802fe5ad8be8071e4291a |
| tools | CreateRecord | collectionName | d3cebf63f818a14632937e8a90061c236055a8daee2528071bb19d2af3e1e686 |
| tools | CreateRecord | record | b460ebe963e4565997398032d6d4ff74ed1b08a6fa7c12e85d00f2d350e5c06a |
| tools | DeleteCollection | description | eb1ebea61bbb8627675167e92db72276bec08f3da02c5e1defb8fce513ae8606 |
| tools | DeleteCollection | collectionName | a1792d4cced7664aa1037f051bd83c097e0eb64a3cb8dffe9d44d2d2d9185814 |
| tools | DeleteRecord | description | 15e0fb7e46e98798b7ebafdb50761f50da71dd83e8f74110f926205f2486ed63 |
| tools | DeleteRecord | collectionName | 027106ecc1ba2a16006e187b7d48483b09324e9968f76024972dca949253676e |
| tools | DeleteRecord | recordId | 58ac199c2e7d93c840632f9fd49185b8fd4e79b323b06295ed254f6993476c7b |
| tools | EstimateDocumentCount | description | c9d1d2b64e66548e2719c5a07564ba539511c7b6359bb380c8fe6768229fafac |
| tools | EstimateDocumentCount | collectionName | 9279409c44501c68f6c45e94f098c8bf0c6f2875504ff0d648d852d436d65376 |
| tools | FindRecord | description | 92460e487e3945d792930f190be3b90870e75ef3ede2a7e2702f101e45331729 |
| tools | FindRecord | collectionName | 1041d1975255ec941e57bee4e1e91e2f2ae6b4661d36f939c4779eaa3a37d6df |
| tools | FindRecord | field | 0b58cbfe29d155a9dd289e32e757211b190ae1e6f81af1e936aa774c1dd2162b |
| tools | FindRecord | limit | 9546b356fb9fa9ee8ccec844eaeb8ac5809c8536d45bba33e6e5a9d59ff3e067 |
| tools | FindRecord | value | af949cfa24de76a97a253731b2348b74a5f18132709009f3b6160c9d145a3076 |
| tools | GetCollections | description | 6a7fbdb450409d839124f1c2a25468100eccd4c1b142a4f1bbd1ccb629de4e74 |
| tools | GetRecord | description | 498a6cc0b741015113b4e6bb02492bb774c260469562c48704b8e7f80ceb1943 |
| tools | GetRecord | collectionName | 45618dec4ec108406d85f0cc299135c5536e64a2020c801b12ee8c22e7f29c10 |
| tools | GetRecord | recordId | 7a615aab4affca265fc5eadc8b9ba9e02385b3458e4957e9c9f5c69387c3cf79 |
| tools | HelpAddToClient | description | c53ae373bc682667fd317650446d599ec8506cc185bdf9008ff50c5633a18cff |
| tools | ListRecords | description | c3d9e03b1a35af0d32fdf93d30f3fed225296a1a2c7a97226763e3350c6ce1fc |
| tools | ListRecords | collectionName | cbdcc2d02b05a97d226f1b98b101d8779ed71aeab230f90b60ce0916b2854eb3 |
| tools | ListRecords | limit | 9546b356fb9fa9ee8ccec844eaeb8ac5809c8536d45bba33e6e5a9d59ff3e067 |
| tools | OpenBrowser | description | f809bea1a61f69dad46e15e6fc370fab74991931dea6f0273d3a79dfe196f88d |
| tools | OpenBrowser | url | e62c8c64248c119e07f7b5e2d5a343495afac05ef224270cc74a392cce253d3d |
| tools | UpdateCollection | description | 172a433b1d652a174fc4c3d346ea00a94b398d8031b351c70cdadc7de12e6d6b |
| tools | UpdateCollection | collectionName | 03584a6e1dd234bcfaa31ec2ac4f78939393afee2c09f5d6c095ac2c74d9c078 |
| tools | UpdateCollection | newName | 9ce3a175aaa373e0d4cf6a1cbf8e554251c97e9ec091843b2baa353290ebc142 |
| tools | UpdateRecord | description | 8bc9f9c15a7c5392794724165777a92e468c15a0fc7d4b415245d60241b9422f |
| tools | UpdateRecord | collectionName | 027106ecc1ba2a16006e187b7d48483b09324e9968f76024972dca949253676e |
| tools | UpdateRecord | record | bcd7befda4f3a038256ec9fdd221210ebaaf9d521b75342fe1ae01585fa4eb78 |
| tools | UpdateRecord | recordId | 9c902ef8efd17571d218c7d163c838fc09d61bad514c4ea2316a89d5de57f218 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
