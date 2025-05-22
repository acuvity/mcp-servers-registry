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


# What is mcp-server-fibery?

[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-fibery/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fibery/0.1.3?logo=docker&logoColor=fff&label=0.1.3)](https://hub.docker.com/r/acuvity/mcp-server-fibery)
[![PyPI](https://img.shields.io/badge/0.1.3-3775A9?logo=pypi&logoColor=fff&label=fibery-mcp-server)](https://github.com/Fibery-inc/fibery-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fibery/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-fibery&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIBERY_API_TOKEN%22%2C%22-e%22%2C%22FIBERY_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-fibery%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates Fibery workspace with LLMs using natural language queries.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from fibery-mcp-server original [sources](https://github.com/Fibery-inc/fibery-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-fibery/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/charts/mcp-server-fibery/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure fibery-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-fibery scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `FIBERY_API_TOKEN` required to be set
  - `FIBERY_HOST` required to be set

For more information and extra configuration you can consult the [package](https://github.com/Fibery-inc/fibery-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-fibery&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIBERY_API_TOKEN%22%2C%22-e%22%2C%22FIBERY_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-fibery%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-fibery": {
        "env": {
          "FIBERY_API_TOKEN": "TO_BE_SET",
          "FIBERY_HOST": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "FIBERY_API_TOKEN",
          "-e",
          "FIBERY_HOST",
          "docker.io/acuvity/mcp-server-fibery:0.1.3"
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
    "acuvity-mcp-server-fibery": {
      "env": {
        "FIBERY_API_TOKEN": "TO_BE_SET",
        "FIBERY_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIBERY_API_TOKEN",
        "-e",
        "FIBERY_HOST",
        "docker.io/acuvity/mcp-server-fibery:0.1.3"
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
    "acuvity-mcp-server-fibery": {
      "env": {
        "FIBERY_API_TOKEN": "TO_BE_SET",
        "FIBERY_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIBERY_API_TOKEN",
        "-e",
        "FIBERY_HOST",
        "docker.io/acuvity/mcp-server-fibery:0.1.3"
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
    "acuvity-mcp-server-fibery": {
      "env": {
        "FIBERY_API_TOKEN": "TO_BE_SET",
        "FIBERY_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIBERY_API_TOKEN",
        "-e",
        "FIBERY_HOST",
        "docker.io/acuvity/mcp-server-fibery:0.1.3"
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
    "acuvity-mcp-server-fibery": {
      "env": {
        "FIBERY_API_TOKEN": "TO_BE_SET",
        "FIBERY_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIBERY_API_TOKEN",
        "-e",
        "FIBERY_HOST",
        "docker.io/acuvity/mcp-server-fibery:0.1.3"
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
        "env": {"FIBERY_API_TOKEN":"TO_BE_SET","FIBERY_HOST":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","FIBERY_API_TOKEN","-e","FIBERY_HOST","docker.io/acuvity/mcp-server-fibery:0.1.3"]
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
- arguments: `run -i --rm --read-only -e FIBERY_API_TOKEN -e FIBERY_HOST docker.io/acuvity/mcp-server-fibery:0.1.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e FIBERY_API_TOKEN -e FIBERY_HOST docker.io/acuvity/mcp-server-fibery:0.1.3
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-fibery": {
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
    "acuvity-mcp-server-fibery": {
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
  - `FIBERY_API_TOKEN` secret to be set as secrets.FIBERY_API_TOKEN either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `FIBERY_HOST` environment variable to be set by env.FIBERY_HOST

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
````

Install with helm

```console
helm install mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
```

From there your MCP server mcp-server-fibery will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-fibery` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/charts/mcp-server-fibery/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>current_date</summary>

**Description**:

```
Get today's date in ISO 8601 format (YYYY-mm-dd.HH:MM:SS.000Z)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_databases</summary>

**Description**:

```
Get list of all databases (their names) in user's Fibery workspace (schema)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>describe_database</summary>

**Description**:

```
Get list of all fields (in format of 'Title [name]: type') in the selected Fibery database and for all related databases.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_name | string | Database name as defined in Fibery schema | Yes
</details>
<details>
<summary>query_database</summary>

**Description**:

```
Run any Fibery API command. This gives tremendous flexibility, but requires a bit of experience with the low-level Fibery API. In case query succeeded, return value contains a list of records with fields you specified in select. If request failed, will return detailed error message.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: What newly created Features do we have for the past 2 months?
Tool use:
{
    "q_from": "Dev/Feature",
    "q_select": {
        "Name": ["Dev/Name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"]
    },
    "q_where": [">", ["fibery/creation-date"], "$twoMonthsAgo"],
    "q_order_by": {"fibery/creation-date": "q/desc"},
    "q_limit": 100,
    "q_offset": 0,
    "q_params": {
        $twoMonthsAgo: "2025-01-16T00:00:00.000Z"
    }
}

Query: What Admin Tasks for the past week are Approval or Done?
Tool use:
{
    "q_from": "Administrative/Admin Task",
    "q_select": {
        "Name": ["Administrative/Name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"],
        "State": ["workflow/state", "enum/name"]
    },
    "q_where": [
        "q/and", # satisfy time AND states condition
            [">", ["fibery/creation-date"], "$oneWeekAgo"],
            [
                "q/or", # nested or, since entity can be in either of these states
                    ["=", ["workflow/state", "enum/name"], "$state1"],
                    ["=", ["workflow/state", "enum/name"], "$state2"]
            ]
    ],
    "q_order_by": {"fibery/creation-date": "q/desc"},
    "q_limit": 100,
    "q_offset": 0,
    "q_params": { # notice that parameters used in "where" are always passed in params!
        $oneWeekAgo: "2025-03-07T00:00:00.000Z",
        $state1: "Approval",
        $state2: "Done"
    }
}

Query: What Admin Tasks for the past week are Approval or Done?
Tool use:
{
    "q_from": "Administrative/Admin Task",
    "q_select": {
        "State": ["workflow/state", "enum/name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"],
        "Modification Date": ["fibery/modification-date"],
        "Deadline": ["Administrative/Deadline"],
        "Group": ["Administrative/Group", "Administrative/name"],
        "Name": ["Administrative/Name"],
        "Priority": ["Administrative/Priority_Administrative/Admin Task", "enum/name"]
    },
    "q_where": ["!=", ["workflow/state", "workflow/Final"], "$stateType"], # Administrative/Admin Task is not "Finished" yet
    "q_order_by": {"fibery/creation-date": "q/desc"},
    "q_limit": 100,
    "q_offset": 0,
    "q_params: {
        "$stateType": true
    }
}

Query: Summarize acc contacts with public id 1.
Tool use:
{
    "q_from": "Accounting/Acc Contacts",
    "q_select": {
        "Name": ["Accounting/Name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"],
        "Description": ["Accounting/Description"]
    },
    "q_where": ["=", ["fibery/public-id"], "$publicId"],
    "q_limit": 1,
    "q_params": {
        $publicId: "1",
    }
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| q_from | string | Specifies the entity type in "Space/Type" format (e.g., "Product Management/feature", "Product Management/Insight") | Yes
| q_limit | integer | Number of results per page (defaults to 50). Maximum allowed value is 1000 | No
| q_offset | integer | Number of results to skip. Mainly used in combination with limit and orderBy for pagination. | No
| q_order_by | object | List of sorting criteria in format {"field1": "q/asc", "field2": "q/desc"} | No
| q_params | object | Dictionary of parameter values referenced in where using "$param" syntax. For example, {$fromDate: "2025-01-01"} | No
| q_select | object | Defines what fields to retrieve. Can include:
  - Primitive fields using format {"AliasName": "FieldName"} (i.e. {"Name": "Product Management/Name"})
  - Related entity fields using format {"AliasName": ["Related entity", "related entity field"]} (i.e. {"Secret": ["Product Management/Description", "Collaboration~Documents/secret"]}). Careful, does not work with 1-* connection!
To work with 1-* relationships, you can use sub-querying: {"AliasName": {"q/from": "Related type", "q/select": {"AliasName 2": "fibery/id"}, "q/limit": 50}}
AliasName can be of any arbitrary value. | Yes
| q_where | object | Filter conditions in format [operator, [field_path], value] or ["q/and"|"q/or", ...conditions]. Common usages:
- Simple comparison: ["=", ["field", "path"], "$param"]. You cannot pass value of $param directly in where clause. Use params object instead. Pay really close attention to it as it is not common practice, but that's how it works in our case!
- Logical combinations: ["q/and", ["<", ["field1"], "$param1"], ["=", ["field2"], "$param2"]]
- Available operators: =, !=, <, <=, >, >=, q/contains, q/not-contains, q/in, q/not-in | No
</details>
<details>
<summary>create_entity</summary>

**Description**:

```
Create Fibery entity with specified fields.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: Create a feature
Tool use:
{
    "database": "Product Management/Feature",
    "entity": {
        "Product Management/Name": "New Feature",
        "Product Management/Description": "Description of the new feature",
        "workflow/state": "To Do" # notice how we use string literal for workflow field here
    }
}
In case of successful execution, you will get a link to created entity. Make sure to give that link to the user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Fibery Database where to create an entity. | Yes
| entity | object | Dictionary that defines what fields to set in format {"FieldName": value} (i.e. {"Product Management/Name": "My new entity"}). | Yes
</details>
<details>
<summary>create_entities_batch</summary>

**Description**:

```
Create multiple Fibery entities at once with specified fields.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: Create some features
Tool use:
{
    "database": "Product Management/Feature",
    "entities": [
        {
            "Product Management/Name": "New Feature 1",
            "Product Management/Description": "Description of the new feature 1",
            "workflow/state": "To Do" # notice how we use string literal for workflow field here
        },
        {
            "Product Management/Name": "New Feature 2",
            "Product Management/Description": "Description of the new feature 2",
            "workflow/state": "In Progress" # notice how we use string literal for workflow field here
        }
    ]
}
In case of successful execution, you will get links to created entities. Make sure to give the links to the user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Fibery Database where entities will be created. | Yes
| entities | object | List of dictionaries that define what fields to set in format [{"FieldName": value}] (i.e. [{"Product Management/Name": "My new entity"}]). | Yes
</details>
<details>
<summary>update_entity</summary>

**Description**:

```
Update Fibery entity with specified fields.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: Update a feature we talked about
Tool use:
{
    "database": "Product Management/Feature",
    "entity": {
        "fibery/id": "12345678-1234-5678-1234-567812345678",
        "Product Management/Name": "New Feature 2",
        "Product Management/Description": {"append": true, "content": "Notes: some notes"},
        "workflow/state": "In Progress"
    }
}
In case of successful execution, you will get a link to updated entity. Make sure to give that link to the user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Fibery Database where to update an entity. | Yes
| entity | object | Dictionary that defines what fields to set in format {"FieldName": value} (i.e. {"Product Management/Name": "My new entity"}).
Exception are document fields. For them you must specify append (boolean, whether to append to current content) and content itself: {"Product Management/Description": {"append": true, "content": "Additional info"}} | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_entities_batch | description | c6f857d3c26c430f3384b261e07c2ce8a40461d69c87ad70f68e2f1ce412400e |
| tools | create_entities_batch | database | 39755006c2083326d7be886a44b1b500f3d940d19045308865d79778927aa850 |
| tools | create_entities_batch | entities | aec365d872c358a769b5ab1ff9296903a439acb867a79146472276537fb3f47c |
| tools | create_entity | description | 4f0d98b2969f712d23cfb26ea25a3cc57d5a469193d44ca549ec25ac88ddf258 |
| tools | create_entity | database | 1c63dc9e3bd2f976b1bfda7c3717f502630a6350e4aba4f50fc5dab2dde0de2a |
| tools | create_entity | entity | fcabe74fe31032d7633f2dd334a10c65d58306c1dd4e180379c5deb42cc57781 |
| tools | current_date | description | 9317cd62334b10a1e0fbd0c93e08392dfee2c80efeb713d9ae35f2f4acaabda4 |
| tools | describe_database | description | dc90cb89fb73651dd904c01892c987de818b462e502d9bd7285a262b3e4bf47c |
| tools | describe_database | database_name | da77a6362dc6213860767ae59face55d4bb3a5daa170e1035c98a933c7c40597 |
| tools | list_databases | description | 8651205b8fe64666d30925db3bd8b0cc41647b106c220aaa3de1dc7b7a893d20 |
| tools | query_database | description | a5d75f5125a10f03de4ee4e8c275c2c5f451563ff21c0f2ef5d57404a390fe66 |
| tools | query_database | q_from | 53a846dbac5b74f897204f60d0150e698c320b33651518eecf90a6bc2c36b8ef |
| tools | query_database | q_limit | 1c9265f863e3f607bc79971e65107a114165dcfd66299a7b675d29b5c454d145 |
| tools | query_database | q_offset | 469a88dc989a485be5cb148dc492667da857259280084542915660d60fec02b3 |
| tools | query_database | q_order_by | 4076133f1c17635f9e2562f63d15eed0f67f437d6e73bb661aac31ea21497948 |
| tools | query_database | q_params | eefc09ae29d168d8e72ce3d4b28178b0f57192caa17b86c4321bd781d0927290 |
| tools | query_database | q_select | 47ef35a67e17868154e6268c8c53f604ab594c1a63b646881cb8a0bce8d81ce7 |
| tools | query_database | q_where | cc7a22d2d86cab4962b1dc336eaee161bf148749ad450e6137e53ce393c36146 |
| tools | update_entity | description | de2dbdcda08f5527eaa3226a59c7da409138d3c0dacee9e7907b5f1334f36f39 |
| tools | update_entity | database | 5f77c9ecd12602e71c8f30d3cf7c8ec3ec94cb6c107d08532b53e4b40ae5fe41 |
| tools | update_entity | entity | b7809c3e6e79f633abc36f03f943063c5390b870b0426b21795445aa9eea5d49 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
