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


# What is mcp-server-algolia?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-algolia/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-algolia/v0.0.8?logo=docker&logoColor=fff&label=v0.0.8)](https://hub.docker.com/r/acuvity/mcp-server-algolia)
[![GitHUB](https://img.shields.io/badge/v0.0.8-3775A9?logo=github&logoColor=fff&label=algolia/mcp-node)](https://github.com/algolia/mcp-node)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-algolia/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-algolia&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22-e%22%2C%22ALGOLIA_CREDENTIALS%22%2C%22docker.io%2Facuvity%2Fmcp-server-algolia%3Av0.0.8%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with Algolia APIs - search, analytics, monitoring, and data management

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from algolia/mcp-node original [sources](https://github.com/algolia/mcp-node).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-algolia/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-algolia/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-algolia/charts/mcp-server-algolia/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure algolia/mcp-node run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-algolia/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-algolia scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `HOME` optional (/tmp)
  - `ALGOLIA_CREDENTIALS` required to be set

For more information and extra configuration you can consult the [package](https://github.com/algolia/mcp-node) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-algolia&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22-e%22%2C%22ALGOLIA_CREDENTIALS%22%2C%22docker.io%2Facuvity%2Fmcp-server-algolia%3Av0.0.8%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-algolia": {
        "env": {
          "ALGOLIA_CREDENTIALS": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "-e",
          "ALGOLIA_CREDENTIALS",
          "docker.io/acuvity/mcp-server-algolia:v0.0.8"
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
    "acuvity-mcp-server-algolia": {
      "env": {
        "ALGOLIA_CREDENTIALS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "ALGOLIA_CREDENTIALS",
        "docker.io/acuvity/mcp-server-algolia:v0.0.8"
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
    "acuvity-mcp-server-algolia": {
      "env": {
        "ALGOLIA_CREDENTIALS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "ALGOLIA_CREDENTIALS",
        "docker.io/acuvity/mcp-server-algolia:v0.0.8"
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
    "acuvity-mcp-server-algolia": {
      "env": {
        "ALGOLIA_CREDENTIALS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "ALGOLIA_CREDENTIALS",
        "docker.io/acuvity/mcp-server-algolia:v0.0.8"
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
    "acuvity-mcp-server-algolia": {
      "env": {
        "ALGOLIA_CREDENTIALS": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "ALGOLIA_CREDENTIALS",
        "docker.io/acuvity/mcp-server-algolia:v0.0.8"
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
        "env": {"ALGOLIA_CREDENTIALS":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","-e","ALGOLIA_CREDENTIALS","docker.io/acuvity/mcp-server-algolia:v0.0.8"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev -e ALGOLIA_CREDENTIALS docker.io/acuvity/mcp-server-algolia:v0.0.8`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev -e ALGOLIA_CREDENTIALS docker.io/acuvity/mcp-server-algolia:v0.0.8
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-algolia": {
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
    "acuvity-mcp-server-algolia": {
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
  - `ALGOLIA_CREDENTIALS` secret to be set as secrets.ALGOLIA_CREDENTIALS either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `HOME="/tmp"` environment variable can be changed with env.HOME="/tmp"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-algolia --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-algolia --version 1.0.0
````

Install with helm

```console
helm install mcp-server-algolia oci://docker.io/acuvity/mcp-server-algolia --version 1.0.0
```

From there your MCP server mcp-server-algolia will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-algolia` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-algolia/charts/mcp-server-algolia/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (29)
<details>
<summary>searchSingleIndex</summary>

**Description**:

```
Search an index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
| requestBody | any | not set | Yes
</details>
<details>
<summary>saveObject</summary>

**Description**:

```
Add a new record (with auto-generated object ID)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
| requestBody | object | The record. A schemaless object with attributes that are useful in the context of search and discovery. | Yes
</details>
<details>
<summary>partialUpdateObject</summary>

**Description**:

```
Add or update attributes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| createIfNotExists | boolean | not set | No
| indexName | string | not set | Yes
| objectID | any | not set | Yes
| requestBody | object | Attributes to update. | Yes
</details>
<details>
<summary>batch</summary>

**Description**:

```
Batch indexing operations on one index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
| requestBody | object | Batch parameters. | Yes
</details>
<details>
<summary>multipleBatch</summary>

**Description**:

```
Batch indexing operations on multiple indices
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| requestBody | object | Batch parameters. | Yes
</details>
<details>
<summary>getSettings</summary>

**Description**:

```
Retrieve index settings
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
</details>
<details>
<summary>searchSynonyms</summary>

**Description**:

```
Search for synonyms
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
| requestBody | object | Body of the `searchSynonyms` operation. | Yes
</details>
<details>
<summary>searchRules</summary>

**Description**:

```
Search for rules
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
| requestBody | object | Rules search parameters. | Yes
</details>
<details>
<summary>listIndices</summary>

**Description**:

```
List indices
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hitsPerPage | integer | not set | No
| page | integer | not set | No
</details>
<details>
<summary>getTopSearches</summary>

**Description**:

```
Retrieve top searches
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| clickAnalytics | boolean | not set | No
| direction | any | not set | No
| endDate | string | not set | No
| index | string | not set | Yes
| limit | integer | not set | No
| offset | integer | not set | No
| orderBy | any | not set | No
| region | string | not set | Yes
| revenueAnalytics | boolean | not set | No
| startDate | string | not set | No
| tags | string | not set | No
</details>
<details>
<summary>getNoResultsRate</summary>

**Description**:

```
Retrieve no results rate
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| endDate | string | not set | No
| index | string | not set | Yes
| region | string | not set | Yes
| startDate | string | not set | No
| tags | string | not set | No
</details>
<details>
<summary>getTopHits</summary>

**Description**:

```
Retrieve top search results
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| clickAnalytics | boolean | not set | No
| endDate | string | not set | No
| index | string | not set | Yes
| limit | integer | not set | No
| offset | integer | not set | No
| region | string | not set | Yes
| revenueAnalytics | boolean | not set | No
| search | string | not set | No
| startDate | string | not set | No
| tags | string | not set | No
</details>
<details>
<summary>listABTests</summary>

**Description**:

```
List all A/B tests
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexPrefix | string | not set | No
| indexSuffix | string | not set | No
| limit | integer | not set | No
| offset | integer | not set | No
| region | string | not set | Yes
</details>
<details>
<summary>getClustersStatus</summary>

**Description**:

```
Retrieve status of all clusters
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>getIncidents</summary>

**Description**:

```
Retrieve all incidents
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>listCollections</summary>

**Description**:

```
Get all collections
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | string | not set | Yes
| limit | integer | not set | No
| offset | integer | not set | No
| query | string | not set | No
</details>
<details>
<summary>getCollection</summary>

**Description**:

```
Get collections by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>
<details>
<summary>listQuerySuggestionsConfigs</summary>

**Description**:

```
List Query Suggestions configurations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region | string | not set | Yes
</details>
<details>
<summary>createQuerySuggestionsConfig</summary>

**Description**:

```
Create a Query Suggestions configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region | string | not set | Yes
| requestBody | object | Query Suggestions configuration. | Yes
</details>
<details>
<summary>getQuerySuggestionsConfig</summary>

**Description**:

```
Retrieve a Query Suggestions configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | any | not set | Yes
| region | string | not set | Yes
</details>
<details>
<summary>getQuerySuggestionConfigStatus</summary>

**Description**:

```
Retrieve a Query Suggestions configuration status
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | any | not set | Yes
| region | string | not set | Yes
</details>
<details>
<summary>getQuerySuggestionLogFile</summary>

**Description**:

```
Retrieve a Query Suggestions index logs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indexName | any | not set | Yes
| region | string | not set | Yes
</details>
<details>
<summary>retrieveMetricsRegistry</summary>

**Description**:

```
Returns the list of available metrics
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application | array | not set | Yes
</details>
<details>
<summary>retrieveMetricsDaily</summary>

**Description**:

```
Returns a list of billing metrics per day for the specified applications
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application | array | not set | Yes
| endDate | string | not set | No
| name | array | not set | Yes
| startDate | string | not set | Yes
</details>
<details>
<summary>retrieveApplicationMetricsHourly</summary>

**Description**:

```
Returns a list of billing metrics per hour for the specified application
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application | string | not set | Yes
| endTime | string | not set | No
| name | array | not set | Yes
| startTime | string | not set | Yes
</details>
<details>
<summary>listDestinations</summary>

**Description**:

```
List destinations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| authenticationID | array | not set | No
| itemsPerPage | any | not set | No
| order | any | not set | No
| page | any | not set | No
| region | string | The region where your Algolia application is hosted (either eu or us). | Yes
| sort | any | not set | No
| transformationID | any | not set | No
| type | array | not set | No
</details>
<details>
<summary>listSources</summary>

**Description**:

```
List sources
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| authenticationID | array | not set | No
| itemsPerPage | any | not set | No
| order | any | not set | No
| page | any | not set | No
| region | string | The region where your Algolia application is hosted (either eu or us). | Yes
| sort | any | not set | No
| type | array | not set | No
</details>
<details>
<summary>listTasks</summary>

**Description**:

```
List tasks
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | array | Actions to perform on the Algolia index. | No
| destinationID | array | not set | No
| enabled | boolean | not set | No
| itemsPerPage | any | not set | No
| order | any | not set | No
| page | any | not set | No
| region | string | The region where your Algolia application is hosted (either eu or us). | Yes
| sort | any | not set | No
| sourceID | array | not set | No
| sourceType | array | not set | No
| triggerType | array | not set | No
| withEmailNotifications | boolean | not set | No
</details>
<details>
<summary>listTransformations</summary>

**Description**:

```
List transformations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| itemsPerPage | any | not set | No
| order | any | not set | No
| page | any | not set | No
| region | string | The region where your Algolia application is hosted (either eu or us). | Yes
| sort | any | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | batch | description | 3c7f23a7866bc943eb18644e58c94b56a3bf62628bc7e4e64534d97a1302129e |
| tools | batch | requestBody | ef8518e4d7b3bb72bb98db311d122c4725ad42b42e53967141cc75119ae48618 |
| tools | createQuerySuggestionsConfig | description | 3519a33e483b77e98be4896cbd32f50c98126ab4ae3bcb2cd03294a349100a5c |
| tools | createQuerySuggestionsConfig | requestBody | d0a08c405baea209b2090eff628a18fb9c310753947ae039ab15d1035c0a1016 |
| tools | getClustersStatus | description | 9f08baeabedbfc60111dbacea2ede2d0bfe564644f40d06e1bb27635319c9f77 |
| tools | getCollection | description | 01ce2a597726c70408e04db545e0d6b8222040fa0095e90f948cf5c1627c5e9b |
| tools | getIncidents | description | bce0803ed14e11e72bb27eae422e62b4c95e02a95354da6fc34b9d504a5d574b |
| tools | getNoResultsRate | description | 46f8da9b62dbfac7f93f1173b19813e50e09b5d86375d8c3cb08ae7af0f585f5 |
| tools | getQuerySuggestionConfigStatus | description | 476a9f97294d878fe96cb210831fd57a538cf9a415ef4913c04d5fa3644ee0be |
| tools | getQuerySuggestionLogFile | description | 2e296e7cb8a2a8bfd0e5112b97ac39433e2e0c83a72955f9ba92a9af2e569ae5 |
| tools | getQuerySuggestionsConfig | description | c44ce26b42e2d43d7c0a21635e9a0aa9deba006b1f2170e3898bbbc855d55e34 |
| tools | getSettings | description | 80e04f471ceae682acbd784dc967992a7fd8d7f296b5f739c79d389597c6f367 |
| tools | getTopHits | description | 10da0aad9b5af9cb53784ab8796621fa8144b51b13d36cdf4a14adaf9650da66 |
| tools | getTopSearches | description | 6392f6a088fa2308bd0f2c73112ae7eb5901c012f36b7c12efd2055e9ab1322e |
| tools | listABTests | description | a90fc52df3f0c77d19185cb131d22cc71ce0a985231d0ca7180e17bd461b47ee |
| tools | listCollections | description | cb248fb3bb4a4a1f25d99eb96850361297754543e8b09bf3edcc82db56f9654e |
| tools | listDestinations | description | 74c3a4d884aa8692b9025bb925d57212f06073d0a044656b8ac42a677e119767 |
| tools | listDestinations | region | bb3b265cb4ecb2b5cf6e2f8dd2235f9605113bd1167244a9efe31239380c2bae |
| tools | listIndices | description | 2898ec0539434abe83b7b867fe5af2a2cc90a23e056118e6400185ee9fbe98a3 |
| tools | listQuerySuggestionsConfigs | description | e9318ee1d86c403b1b922acc90c4a471da2e731a9409bd258caa271023a883c1 |
| tools | listSources | description | 97ed65f3096d648cb208a0561cbf7c34f96cde82e8a445512361fe0f322869d9 |
| tools | listSources | region | bb3b265cb4ecb2b5cf6e2f8dd2235f9605113bd1167244a9efe31239380c2bae |
| tools | listTasks | description | 99f58e5022f2041d97663ee19f754bbca2e542983c4cad82223be43ecac93a4b |
| tools | listTasks | action | d28d228bf3f5190b991ce884c2566939c75a8e88c55bc72b7d44e4f79352aa7d |
| tools | listTasks | region | bb3b265cb4ecb2b5cf6e2f8dd2235f9605113bd1167244a9efe31239380c2bae |
| tools | listTransformations | description | fa23fec0f59a66036256228e711174f26317dc8fc2094184babee914e0bd8920 |
| tools | listTransformations | region | bb3b265cb4ecb2b5cf6e2f8dd2235f9605113bd1167244a9efe31239380c2bae |
| tools | multipleBatch | description | 717ba396a06a7bf7185214c389ec858965aac7d7f8ba0dad48ad1f603f3c92f7 |
| tools | multipleBatch | requestBody | ef8518e4d7b3bb72bb98db311d122c4725ad42b42e53967141cc75119ae48618 |
| tools | partialUpdateObject | description | 43323953b44172aed477e24e99b398371f1fc2c6ca583d41a8af47d7d8298ba0 |
| tools | partialUpdateObject | requestBody | 37a38f48dc952a1ae91577e10827a6fea9ae031a18bc8489dd3dde7e31698d2e |
| tools | retrieveApplicationMetricsHourly | description | 10ccdfc387ba08da72fc15ccc9bf4967f004356a9fcea175443af0f1826bd054 |
| tools | retrieveMetricsDaily | description | 3114c7ab255e7f45cf0e0077de80bcb6067109db78f321e556fd634f11edd2f9 |
| tools | retrieveMetricsRegistry | description | b73eb0805ad8bee9197ffc8d880460c0f906dbd0248f94a81b6f09d1b31d717f |
| tools | saveObject | description | 01faa3091eee8d3919ec6e3e93cd114589e900e6f5eb3ea16a8402cd468fd1bd |
| tools | saveObject | requestBody | 37b07922d1570e44d5abacbb5db414a026b2f141a236f0bd12996dfe67a7502c |
| tools | searchRules | description | 6d847bfa9acf15a6e6a051a1523f9ee9c101da8c80c78f523a8daf5516d7bef8 |
| tools | searchRules | requestBody | 6097abf0d9320124087364d5d716fcb998f48cd92e420d69addcaaac17801c33 |
| tools | searchSingleIndex | description | 84b48593501028564d85719d21b46fef13d4f19967077bfb74b2c9b234cd6e23 |
| tools | searchSynonyms | description | 91f2cc53f20a92fb894000428aee4f54f00605f255380dd82135a59005742168 |
| tools | searchSynonyms | requestBody | cb9abc1984db46da0f3cd058594b573869425b6e2c5d984cd01d762a12326d80 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
