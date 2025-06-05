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


# What is mcp-server-postgres?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-postgres/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-postgres/0.3.0?logo=docker&logoColor=fff&label=0.3.0)](https://hub.docker.com/r/acuvity/mcp-server-postgres)
[![PyPI](https://img.shields.io/badge/0.3.0-3775A9?logo=pypi&logoColor=fff&label=postgres-mcp)](https://github.com/crystaldba/postgres-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-postgres/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-postgres&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DATABASE_URI%22%2C%22docker.io%2Facuvity%2Fmcp-server-postgres%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** PostgreSQL database integration with schema inspection and query capabilities.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from postgres-mcp original [sources](https://github.com/crystaldba/postgres-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-postgres/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-postgres/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-postgres/charts/mcp-server-postgres/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure postgres-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-postgres/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-postgres scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `DATABASE_URI` required to be set

For more information and extra configuration you can consult the [package](https://github.com/crystaldba/postgres-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-postgres&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DATABASE_URI%22%2C%22docker.io%2Facuvity%2Fmcp-server-postgres%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-postgres": {
        "env": {
          "DATABASE_URI": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "DATABASE_URI",
          "docker.io/acuvity/mcp-server-postgres:0.3.0"
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
    "acuvity-mcp-server-postgres": {
      "env": {
        "DATABASE_URI": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DATABASE_URI",
        "docker.io/acuvity/mcp-server-postgres:0.3.0"
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
    "acuvity-mcp-server-postgres": {
      "env": {
        "DATABASE_URI": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DATABASE_URI",
        "docker.io/acuvity/mcp-server-postgres:0.3.0"
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
    "acuvity-mcp-server-postgres": {
      "env": {
        "DATABASE_URI": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DATABASE_URI",
        "docker.io/acuvity/mcp-server-postgres:0.3.0"
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
    "acuvity-mcp-server-postgres": {
      "env": {
        "DATABASE_URI": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DATABASE_URI",
        "docker.io/acuvity/mcp-server-postgres:0.3.0"
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
        "env": {"DATABASE_URI":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","DATABASE_URI","docker.io/acuvity/mcp-server-postgres:0.3.0"]
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
- arguments: `run -i --rm --read-only -e DATABASE_URI docker.io/acuvity/mcp-server-postgres:0.3.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e DATABASE_URI docker.io/acuvity/mcp-server-postgres:0.3.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-postgres": {
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
    "acuvity-mcp-server-postgres": {
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
  - `DATABASE_URI` secret to be set as secrets.DATABASE_URI either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-postgres --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-postgres --version 1.0.0
````

Install with helm

```console
helm install mcp-server-postgres oci://docker.io/acuvity/mcp-server-postgres --version 1.0.0
```

From there your MCP server mcp-server-postgres will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-postgres` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-postgres/charts/mcp-server-postgres/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>list_schemas</summary>

**Description**:

```
List all schemas in the database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_objects</summary>

**Description**:

```
List objects in a schema
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| object_type | string | Object type: 'table', 'view', 'sequence', or 'extension' | No
| schema_name | string | Schema name | Yes
</details>
<details>
<summary>get_object_details</summary>

**Description**:

```
Show detailed information about a database object
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| object_name | string | Object name | Yes
| object_type | string | Object type: 'table', 'view', 'sequence', or 'extension' | No
| schema_name | string | Schema name | Yes
</details>
<details>
<summary>explain_query</summary>

**Description**:

```
Explains the execution plan for a SQL query, showing how the database will execute it and provides detailed cost estimates.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| analyze | boolean | When True, actually runs the query to show real execution statistics instead of estimates. Takes longer but provides more accurate information. | No
| hypothetical_indexes | array | A list of hypothetical indexes to simulate. Each index must be a dictionary with these keys:
    - 'table': The table name to add the index to (e.g., 'users')
    - 'columns': List of column names to include in the index (e.g., ['email'] or ['last_name', 'first_name'])
    - 'using': Optional index method (default: 'btree', other options include 'hash', 'gist', etc.)

Examples: [
    {"table": "users", "columns": ["email"], "using": "btree"},
    {"table": "orders", "columns": ["user_id", "created_at"]}
]
If there is no hypothetical index, you can pass an empty list. | No
| sql | string | SQL query to explain | Yes
</details>
<details>
<summary>analyze_workload_indexes</summary>

**Description**:

```
Analyze frequently executed queries in the database and recommend optimal indexes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_index_size_mb | integer | Max index size in MB | No
| method | string | Method to use for analysis | No
</details>
<details>
<summary>analyze_query_indexes</summary>

**Description**:

```
Analyze a list of (up to 10) SQL queries and recommend optimal indexes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_index_size_mb | integer | Max index size in MB | No
| method | string | Method to use for analysis | No
| queries | array | List of Query strings to analyze | Yes
</details>
<details>
<summary>analyze_db_health</summary>

**Description**:

```
Analyzes database health. Here are the available health checks:
- index - checks for invalid, duplicate, and bloated indexes
- connection - checks the number of connection and their utilization
- vacuum - checks vacuum health for transaction id wraparound
- sequence - checks sequences at risk of exceeding their maximum value
- replication - checks replication health including lag and slots
- buffer - checks for buffer cache hit rates for indexes and tables
- constraint - checks for invalid constraints
- all - runs all checks
You can optionally specify a single health check or a comma-separated list of health checks. The default is 'all' checks.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| health_type | string | Optional. Valid values are: all, buffer, connection, constraint, index, replication, sequence, vacuum. | No
</details>
<details>
<summary>get_top_queries</summary>

**Description**:

```
Reports the slowest or most resource-intensive queries using data from the 'pg_stat_statements' extension.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Number of queries to return when ranking based on mean_time or total_time | No
| sort_by | string | Ranking criteria: 'total_time' for total execution time or 'mean_time' for mean execution time per call, or 'resources' for resource-intensive queries | No
</details>
<details>
<summary>execute_sql</summary>

**Description**:

```
Execute any SQL query
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sql | string | SQL to run | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | analyze_db_health | description | f7148791d5b33e833b73cc3054bacaead5bba789cbb5d6583fceaa6cc4b9a662 |
| tools | analyze_db_health | health_type | 14878b4180ed2ef8918d19c81733614b669c6037dc0f3b372c21dfd5b61781ae |
| tools | analyze_query_indexes | description | bc0efac95f78a27c3c488baed465aab8af52c27dd4b8ad003cd710783aa772ed |
| tools | analyze_query_indexes | max_index_size_mb | c20c4a8086531840f7b8613bb6a727ecf4df8e6ba1a583324dec1cce49557fab |
| tools | analyze_query_indexes | method | 139a66256b11bfa512f6a832dd53b6d753efcba3ffc470e8c766cf1c64a2a675 |
| tools | analyze_query_indexes | queries | ed6cddd1d2696378d5576f31ac8a7a5526c5770b1bd615e0e0591642763b7166 |
| tools | analyze_workload_indexes | description | df7be2f96040f337a8e05d24356d6aecd8a4e78710502bfae38eaccca4d6f4ac |
| tools | analyze_workload_indexes | max_index_size_mb | c20c4a8086531840f7b8613bb6a727ecf4df8e6ba1a583324dec1cce49557fab |
| tools | analyze_workload_indexes | method | 139a66256b11bfa512f6a832dd53b6d753efcba3ffc470e8c766cf1c64a2a675 |
| tools | execute_sql | description | c7226bd9d8c1f4c84cf1c5a8c57618e1dc85db2f8c40d0ed7f1624697b295d8c |
| tools | execute_sql | sql | b8a5c519bdb14c5370438d5141feb96876cf5ac75e776518fd8b0f8b014c16a6 |
| tools | explain_query | description | f2dcf6ffa7460337d12bd9295951f033fe7b8267ea15e45f5666396eaf53722b |
| tools | explain_query | analyze | be4a5dfa6cee8f33d88df07750f50e4426b9669c82fc92ff79eed6ab4d4ff4ff |
| tools | explain_query | hypothetical_indexes | 3debb477ff31f4b115b6ce8887357b81579d127d790ddd8d4168d6119481835c |
| tools | explain_query | sql | 7109b79cc465d06a36d4854c4265bca435b052be4441707775878f937581ad4d |
| tools | get_object_details | description | d2784c403d86048e9dd527aab41d68aa9048a07702c792bdfe7b2c9e736a1f94 |
| tools | get_object_details | object_name | a108c4391925fcd8cda31f797f34e7ba51924da254f2c0922fa816dc5ae21278 |
| tools | get_object_details | object_type | 9055770ac21ad8677c8ad4f627458157786b16893d736044be098bfbc9bf9d1e |
| tools | get_object_details | schema_name | 1daa899b43c9984e852089fddb3624fa21b1c5c68a1fbb6ac87c74e6f75cfefd |
| tools | get_top_queries | description | de410f40e6b1e6576e2b1d4b99277ffd130b35199755de8b2620bb0cabf421bd |
| tools | get_top_queries | limit | f92de7caff66ecdad81aa1101f396ffbdfe8bc66ddf181e325fc36d91bc92454 |
| tools | get_top_queries | sort_by | 6846a1b1dc1dc3895a3689c173df4abe1675c95a4f72533bd7b4e1d939073db7 |
| tools | list_objects | description | ad81d46b1c075a113eb081ff16e16249d216d834f03516fd17db0c58565c0b1d |
| tools | list_objects | object_type | 9055770ac21ad8677c8ad4f627458157786b16893d736044be098bfbc9bf9d1e |
| tools | list_objects | schema_name | 1daa899b43c9984e852089fddb3624fa21b1c5c68a1fbb6ac87c74e6f75cfefd |
| tools | list_schemas | description | 6d51dca49f95aa8b3e2eeffc443e63c2c858d018e915ff1dc10f7349c96fd65b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
