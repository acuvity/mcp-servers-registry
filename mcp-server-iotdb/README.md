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


# What is mcp-server-iotdb?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-iotdb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-iotdb/cf77711?logo=docker&logoColor=fff&label=cf77711)](https://hub.docker.com/r/acuvity/mcp-server-iotdb)
[![GitHUB](https://img.shields.io/badge/cf77711-3775A9?logo=github&logoColor=fff&label=apache/iotdb-mcp-server)](https://github.com/apache/iotdb-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-iotdb/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-iotdb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22IOTDB_HOST%22%2C%22-e%22%2C%22IOTDB_USER%22%2C%22-e%22%2C%22IOTDB_PASSWORD%22%2C%22-e%22%2C%22IOTDB_DATABASE%22%2C%22docker.io%2Facuvity%2Fmcp-server-iotdb%3Acf77711%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP Server for Apache IoTDB database and its tools

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from apache/iotdb-mcp-server original [sources](https://github.com/apache/iotdb-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-iotdb/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iotdb/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iotdb/charts/mcp-server-iotdb/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure apache/iotdb-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iotdb/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-iotdb scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `IOTDB_HOST` required to be set
  - `IOTDB_PORT` optional (6667)
  - `IOTDB_USER` required to be set
  - `IOTDB_PASSWORD` required to be set
  - `IOTDB_DATABASE` required to be set
  - `IOTDB_SQL_DIALECT` optional (table)

For more information and extra configuration you can consult the [package](https://github.com/apache/iotdb-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-iotdb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22IOTDB_HOST%22%2C%22-e%22%2C%22IOTDB_USER%22%2C%22-e%22%2C%22IOTDB_PASSWORD%22%2C%22-e%22%2C%22IOTDB_DATABASE%22%2C%22docker.io%2Facuvity%2Fmcp-server-iotdb%3Acf77711%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-iotdb": {
        "env": {
          "IOTDB_DATABASE": "TO_BE_SET",
          "IOTDB_HOST": "TO_BE_SET",
          "IOTDB_PASSWORD": "TO_BE_SET",
          "IOTDB_USER": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "IOTDB_HOST",
          "-e",
          "IOTDB_USER",
          "-e",
          "IOTDB_PASSWORD",
          "-e",
          "IOTDB_DATABASE",
          "docker.io/acuvity/mcp-server-iotdb:cf77711"
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
    "acuvity-mcp-server-iotdb": {
      "env": {
        "IOTDB_DATABASE": "TO_BE_SET",
        "IOTDB_HOST": "TO_BE_SET",
        "IOTDB_PASSWORD": "TO_BE_SET",
        "IOTDB_USER": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "IOTDB_HOST",
        "-e",
        "IOTDB_USER",
        "-e",
        "IOTDB_PASSWORD",
        "-e",
        "IOTDB_DATABASE",
        "docker.io/acuvity/mcp-server-iotdb:cf77711"
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
    "acuvity-mcp-server-iotdb": {
      "env": {
        "IOTDB_DATABASE": "TO_BE_SET",
        "IOTDB_HOST": "TO_BE_SET",
        "IOTDB_PASSWORD": "TO_BE_SET",
        "IOTDB_USER": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "IOTDB_HOST",
        "-e",
        "IOTDB_USER",
        "-e",
        "IOTDB_PASSWORD",
        "-e",
        "IOTDB_DATABASE",
        "docker.io/acuvity/mcp-server-iotdb:cf77711"
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
    "acuvity-mcp-server-iotdb": {
      "env": {
        "IOTDB_DATABASE": "TO_BE_SET",
        "IOTDB_HOST": "TO_BE_SET",
        "IOTDB_PASSWORD": "TO_BE_SET",
        "IOTDB_USER": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "IOTDB_HOST",
        "-e",
        "IOTDB_USER",
        "-e",
        "IOTDB_PASSWORD",
        "-e",
        "IOTDB_DATABASE",
        "docker.io/acuvity/mcp-server-iotdb:cf77711"
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
    "acuvity-mcp-server-iotdb": {
      "env": {
        "IOTDB_DATABASE": "TO_BE_SET",
        "IOTDB_HOST": "TO_BE_SET",
        "IOTDB_PASSWORD": "TO_BE_SET",
        "IOTDB_USER": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "IOTDB_HOST",
        "-e",
        "IOTDB_USER",
        "-e",
        "IOTDB_PASSWORD",
        "-e",
        "IOTDB_DATABASE",
        "docker.io/acuvity/mcp-server-iotdb:cf77711"
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
        "env": {"IOTDB_DATABASE":"TO_BE_SET","IOTDB_HOST":"TO_BE_SET","IOTDB_PASSWORD":"TO_BE_SET","IOTDB_USER":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","IOTDB_HOST","-e","IOTDB_USER","-e","IOTDB_PASSWORD","-e","IOTDB_DATABASE","docker.io/acuvity/mcp-server-iotdb:cf77711"]
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
- arguments: `run -i --rm --read-only -e IOTDB_HOST -e IOTDB_USER -e IOTDB_PASSWORD -e IOTDB_DATABASE docker.io/acuvity/mcp-server-iotdb:cf77711`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e IOTDB_HOST -e IOTDB_USER -e IOTDB_PASSWORD -e IOTDB_DATABASE docker.io/acuvity/mcp-server-iotdb:cf77711
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-iotdb": {
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
    "acuvity-mcp-server-iotdb": {
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
  - `IOTDB_PASSWORD` secret to be set as secrets.IOTDB_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `IOTDB_HOST` environment variable to be set by env.IOTDB_HOST
  - `IOTDB_USER` environment variable to be set by env.IOTDB_USER
  - `IOTDB_DATABASE` environment variable to be set by env.IOTDB_DATABASE

**Optional Environment variables**:
  - `IOTDB_PORT="%!s(int=6667)"` environment variable can be changed with env.IOTDB_PORT="%!s(int=6667)"
  - `IOTDB_SQL_DIALECT="table"` environment variable can be changed with env.IOTDB_SQL_DIALECT="table"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-iotdb --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-iotdb --version 1.0.0
````

Install with helm

```console
helm install mcp-server-iotdb oci://docker.io/acuvity/mcp-server-iotdb --version 1.0.0
```

From there your MCP server mcp-server-iotdb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-iotdb` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iotdb/charts/mcp-server-iotdb/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (3)
<details>
<summary>read_query</summary>

**Description**:

```
Execute a SELECT query on the IoTDB. Please use table sql_dialect when generating SQL queries.

        Args:
            query_sql: The SQL query to execute (using TABLE dialect)
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query_sql | string | not set | Yes
</details>
<details>
<summary>list_tables</summary>

**Description**:

```
List all tables in the IoTDB database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>describe_table</summary>

**Description**:

```
Get the schema information for a specific table
        Args:
            table_name: name of the table to describe
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| table_name | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | describe_table | description | b0250168b846673d0700066ec9df10a63b621908132f95fa2c6f537c35e404e0 |
| tools | list_tables | description | a2f64219af7493595c9a66288dc578a80a052e7099a2eabc47c6ea2aace7d7a9 |
| tools | read_query | description | 1d0edc0e16433ebd382eb7dc390278c5925908145a2035a47264efca4b827695 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
