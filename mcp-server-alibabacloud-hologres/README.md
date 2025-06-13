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


# What is mcp-server-alibabacloud-hologres?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-hologres/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-hologres/0.1.9?logo=docker&logoColor=fff&label=0.1.9)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-hologres)
[![PyPI](https://img.shields.io/badge/0.1.9-3775A9?logo=pypi&logoColor=fff&label=hologres-mcp-server)](https://github.com/aliyun/alibabacloud-hologres-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-hologres/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-hologres&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HOLOGRES_HOST%22%2C%22-e%22%2C%22HOLOGRES_PASSWORD%22%2C%22-e%22%2C%22HOLOGRES_DATABASE%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-hologres%3A0.1.9%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connect to Hologres instance, get table metadata, query and analyze data.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from hologres-mcp-server original [sources](https://github.com/aliyun/alibabacloud-hologres-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-hologres/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-hologres/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-hologres/charts/mcp-server-alibabacloud-hologres/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure hologres-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-hologres/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-alibabacloud-hologres scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `HOLOGRES_HOST` required to be set
  - `HOLOGRES_PORT` optional (5432)
  - `HOLOGRES_USER` optional (not set)
  - `HOLOGRES_PASSWORD` required to be set
  - `HOLOGRES_DATABASE` required to be set

For more information and extra configuration you can consult the [package](https://github.com/aliyun/alibabacloud-hologres-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-hologres&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HOLOGRES_HOST%22%2C%22-e%22%2C%22HOLOGRES_PASSWORD%22%2C%22-e%22%2C%22HOLOGRES_DATABASE%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-hologres%3A0.1.9%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-alibabacloud-hologres": {
        "env": {
          "HOLOGRES_DATABASE": "TO_BE_SET",
          "HOLOGRES_HOST": "TO_BE_SET",
          "HOLOGRES_PASSWORD": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "HOLOGRES_HOST",
          "-e",
          "HOLOGRES_PASSWORD",
          "-e",
          "HOLOGRES_DATABASE",
          "docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9"
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
    "acuvity-mcp-server-alibabacloud-hologres": {
      "env": {
        "HOLOGRES_DATABASE": "TO_BE_SET",
        "HOLOGRES_HOST": "TO_BE_SET",
        "HOLOGRES_PASSWORD": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HOLOGRES_HOST",
        "-e",
        "HOLOGRES_PASSWORD",
        "-e",
        "HOLOGRES_DATABASE",
        "docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9"
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
    "acuvity-mcp-server-alibabacloud-hologres": {
      "env": {
        "HOLOGRES_DATABASE": "TO_BE_SET",
        "HOLOGRES_HOST": "TO_BE_SET",
        "HOLOGRES_PASSWORD": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HOLOGRES_HOST",
        "-e",
        "HOLOGRES_PASSWORD",
        "-e",
        "HOLOGRES_DATABASE",
        "docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9"
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
    "acuvity-mcp-server-alibabacloud-hologres": {
      "env": {
        "HOLOGRES_DATABASE": "TO_BE_SET",
        "HOLOGRES_HOST": "TO_BE_SET",
        "HOLOGRES_PASSWORD": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HOLOGRES_HOST",
        "-e",
        "HOLOGRES_PASSWORD",
        "-e",
        "HOLOGRES_DATABASE",
        "docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9"
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
    "acuvity-mcp-server-alibabacloud-hologres": {
      "env": {
        "HOLOGRES_DATABASE": "TO_BE_SET",
        "HOLOGRES_HOST": "TO_BE_SET",
        "HOLOGRES_PASSWORD": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HOLOGRES_HOST",
        "-e",
        "HOLOGRES_PASSWORD",
        "-e",
        "HOLOGRES_DATABASE",
        "docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9"
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
        "env": {"HOLOGRES_DATABASE":"TO_BE_SET","HOLOGRES_HOST":"TO_BE_SET","HOLOGRES_PASSWORD":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","HOLOGRES_HOST","-e","HOLOGRES_PASSWORD","-e","HOLOGRES_DATABASE","docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9"]
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
- arguments: `run -i --rm --read-only -e HOLOGRES_HOST -e HOLOGRES_PASSWORD -e HOLOGRES_DATABASE docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e HOLOGRES_HOST -e HOLOGRES_PASSWORD -e HOLOGRES_DATABASE docker.io/acuvity/mcp-server-alibabacloud-hologres:0.1.9
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-alibabacloud-hologres": {
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
    "acuvity-mcp-server-alibabacloud-hologres": {
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
  - `HOLOGRES_PASSWORD` secret to be set as secrets.HOLOGRES_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `HOLOGRES_HOST` environment variable to be set by env.HOLOGRES_HOST
  - `HOLOGRES_DATABASE` environment variable to be set by env.HOLOGRES_DATABASE

**Optional Environment variables**:
  - `HOLOGRES_PORT="5432"` environment variable can be changed with env.HOLOGRES_PORT="5432"
  - `HOLOGRES_USER=""` environment variable can be changed with env.HOLOGRES_USER=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-alibabacloud-hologres --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-hologres --version 1.0.0
````

Install with helm

```console
helm install mcp-server-alibabacloud-hologres oci://docker.io/acuvity/mcp-server-alibabacloud-hologres --version 1.0.0
```

From there your MCP server mcp-server-alibabacloud-hologres will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-hologres` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-hologres/charts/mcp-server-alibabacloud-hologres/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>execute_hg_select_sql</summary>

**Description**:

```
Execute SELECT SQL to query data from Hologres database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The (SELECT) SQL query to execute in Hologres database. | Yes
</details>
<details>
<summary>execute_hg_select_sql_with_serverless</summary>

**Description**:

```
Use Serverless Computing resources to execute SELECT SQL to query data in Hologres database. When the error like "Total memory used by all existing queries exceeded memory limitation" occurs during execute_hg_select_sql execution, you can re-execute the SQL with the tool execute_hg_select_sql_with_serverless.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The (SELECT) SQL query to execute with serverless computing in Hologres database | Yes
</details>
<details>
<summary>execute_hg_dml_sql</summary>

**Description**:

```
Execute (INSERT, UPDATE, DELETE) SQL to insert, update, and delete data in Hologres databse.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The DML SQL query to execute in Hologres database | Yes
</details>
<details>
<summary>execute_hg_ddl_sql</summary>

**Description**:

```
Execute (CREATE, ALTER, DROP) SQL statements to CREATE, ALTER, or DROP tables, views, procedures, GUCs etc. in Hologres databse.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The DDL SQL query to execute in Hologres database | Yes
</details>
<details>
<summary>gather_hg_table_statistics</summary>

**Description**:

```
Execute the ANALYZE TABLE command to have Hologres collect table statistics, enabling QO to generate better query plans
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| schema | string | Schema name in Hologres database | Yes
| table | string | Table name in Hologres database | Yes
</details>
<details>
<summary>get_hg_query_plan</summary>

**Description**:

```
Get query plan for a SQL query in Hologres database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The SQL query to analyze in Hologres database | Yes
</details>
<details>
<summary>get_hg_execution_plan</summary>

**Description**:

```
Get actual execution plan with runtime statistics for a SQL query in Hologres database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The SQL query to analyze in Hologres database | Yes
</details>
<details>
<summary>call_hg_procedure</summary>

**Description**:

```
Call a stored procedure in Hologres database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| arguments | array | The arguments to pass to the stored procedure in Hologres database | No
| procedure_name | string | The name of the stored procedure to call in Hologres database | Yes
</details>
<details>
<summary>create_hg_maxcompute_foreign_table</summary>

**Description**:

```
Create a MaxCompute foreign table in Hologres database to accelerate queries on MaxCompute data.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| local_schema | string | The local schema name in Hologres (optional, default: 'public') | No
| maxcompute_project | string | The MaxCompute project name (required) | Yes
| maxcompute_schema | string | The MaxCompute schema name (optional, default: 'default') | No
| maxcompute_tables | array | The MaxCompute table names (required) | Yes
</details>
<details>
<summary>list_hg_schemas</summary>

**Description**:

```
List all schemas in the current Hologres database, excluding system schemas.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_hg_tables_in_a_schema</summary>

**Description**:

```
List all tables in a specific schema in the current Hologres database, including their types (table, view, foreign table, partitioned table).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| schema | string | Schema name to list tables from in Hologres database | Yes
</details>
<details>
<summary>show_hg_table_ddl</summary>

**Description**:

```
Show DDL script for a table, view, or foreign table in Hologres database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| schema | string | Schema name in Hologres database | Yes
| table | string | Table name in Hologres database | Yes
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| All Schemas in Hologres database | text/plain | hologres:///schemas | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | call_hg_procedure | description | 3532b7af326cdae8c98d2abe2a28227c2f2861bebf84ab714b44c14d1051043c |
| tools | call_hg_procedure | arguments | 5ce2cdf29c62437f8435b591841ccf621a5c05a01aec99e12dfc79f15643f8ac |
| tools | call_hg_procedure | procedure_name | 8d5abcaa1cf231502c0ef0a793777a37bf864df70828e8ad94ed7d6ba2f49b42 |
| tools | create_hg_maxcompute_foreign_table | description | 1f01c718d67cae7f97a81e323f5281714d914dcdca47153280683ef3df451318 |
| tools | create_hg_maxcompute_foreign_table | local_schema | de2fc22827aedb95ce3151b3d586ee1ab8997608be485f6dfacae52b76de1165 |
| tools | create_hg_maxcompute_foreign_table | maxcompute_project | 70a4a86561d6edce22167db9d761758ad9d1f1e2ee09ddc7d4a8472f56ffe56c |
| tools | create_hg_maxcompute_foreign_table | maxcompute_schema | 088e608ce3b094fcf6902167f5423a010542217c449f5f2fab3bd73e921d5efd |
| tools | create_hg_maxcompute_foreign_table | maxcompute_tables | a094b5b203e31a1c3511e98e7f88980fac15299151f050fd841fc1de4edb2ad7 |
| tools | execute_hg_ddl_sql | description | 250d5e586addcef2f2ca418fd2d215d2234a1689c1995e6619841431efae0a6a |
| tools | execute_hg_ddl_sql | query | ace55a62d7b8815e33664a775bef93c2252853c09c726495bef3e89746b7a265 |
| tools | execute_hg_dml_sql | description | 8de513edebc0c298ef7f1569d9d253fb3fa5f5492d5fa357acf89028227e261c |
| tools | execute_hg_dml_sql | query | 52b8f4c0d943289b7408b197401a5896df2bb38dfc0aa7b22feff263494119b6 |
| tools | execute_hg_select_sql | description | c0509b31c58bfb5e90210f18c927651fd69be1182830a16f4aaedfa94e0634b4 |
| tools | execute_hg_select_sql | query | e575f6f5705df0a9e37391cc9bd63516c85ab88aa53d304331a373e87aa343bf |
| tools | execute_hg_select_sql_with_serverless | description | 838b25b1e858ad7d7774fa9aa5ef67996cb918f2e87df26c20d4daa7ad6edf41 |
| tools | execute_hg_select_sql_with_serverless | query | c2ea0c50cb3540e469811ac16b063f6b0cb837df481d0012b4f82cdbac2c33cf |
| tools | gather_hg_table_statistics | description | afa02a2783ce69fdc6652a02ae4f955adc4446845f67e0f7c78fe9d25f0e4f42 |
| tools | gather_hg_table_statistics | schema | 96a3fd04397c0fa26c7f3c8179c36a28e7ba2f486fc721a4e89d9dcc6c67c9d0 |
| tools | gather_hg_table_statistics | table | 5d827bf8b563fe50ac06f838a4e03f03389f9037252c0ac90dbfb67cdf96354a |
| tools | get_hg_execution_plan | description | 5b44540e5d9d0d42be0eef651147b01b198b06adb628f05ba406f88c357c7895 |
| tools | get_hg_execution_plan | query | bc60df86b9a9084eccbbd5d50fb6257aab40741f4a9472e177c2ae9b76766bc0 |
| tools | get_hg_query_plan | description | fd8604103b131ca3321e1b9c550c7701b35e10102eb64c3b82a8a0c4b2a54d6f |
| tools | get_hg_query_plan | query | bc60df86b9a9084eccbbd5d50fb6257aab40741f4a9472e177c2ae9b76766bc0 |
| tools | list_hg_schemas | description | 5154d8cb06eb333e610327873a64d75e4c2bc2f320c95539a68397cac3a16059 |
| tools | list_hg_tables_in_a_schema | description | 85e29b1e49479a5d1e682c204023fdd16aa0644bf34fb7849ad5c27ed22049b0 |
| tools | list_hg_tables_in_a_schema | schema | 5fa567de4deabd66cd57f8cba3d1d4473f5a0f2ece0fd88622e299ed324367c7 |
| tools | show_hg_table_ddl | description | da8dffb878c11791a50ed0f6187b27ae2327da8f7623c4a0b7b102edfb398ae9 |
| tools | show_hg_table_ddl | schema | 96a3fd04397c0fa26c7f3c8179c36a28e7ba2f486fc721a4e89d9dcc6c67c9d0 |
| tools | show_hg_table_ddl | table | 5d827bf8b563fe50ac06f838a4e03f03389f9037252c0ac90dbfb67cdf96354a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
