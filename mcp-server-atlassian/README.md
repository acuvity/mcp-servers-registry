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


# What is mcp-server-atlassian?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-atlassian/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-atlassian/0.13.0?logo=docker&logoColor=fff&label=0.13.0)](https://hub.docker.com/r/acuvity/mcp-server-atlassian)
[![PyPI](https://img.shields.io/badge/0.13.0-3775A9?logo=pypi&logoColor=fff&label=mcp-atlassian)](https://github.com/sooperset/mcp-atlassian)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-atlassian/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-atlassian&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CONFLUENCE_API_TOKEN%22%2C%22-e%22%2C%22CONFLUENCE_URL%22%2C%22-e%22%2C%22CONFLUENCE_USERNAME%22%2C%22-e%22%2C%22JIRA_API_TOKEN%22%2C%22-e%22%2C%22JIRA_URL%22%2C%22-e%22%2C%22JIRA_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-atlassian%3A0.13.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates AI tools for Jira and Confluence tasks and automation.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-atlassian original [sources](https://github.com/sooperset/mcp-atlassian).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-atlassian/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlassian/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlassian/charts/mcp-server-atlassian/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-atlassian run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlassian/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-atlassian scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `CONFLUENCE_API_TOKEN` required to be set
  - `CONFLUENCE_URL` required to be set
  - `CONFLUENCE_USERNAME` required to be set
  - `JIRA_API_TOKEN` required to be set
  - `JIRA_URL` required to be set
  - `JIRA_USERNAME` required to be set

For more information and extra configuration you can consult the [package](https://github.com/sooperset/mcp-atlassian) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-atlassian&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CONFLUENCE_API_TOKEN%22%2C%22-e%22%2C%22CONFLUENCE_URL%22%2C%22-e%22%2C%22CONFLUENCE_USERNAME%22%2C%22-e%22%2C%22JIRA_API_TOKEN%22%2C%22-e%22%2C%22JIRA_URL%22%2C%22-e%22%2C%22JIRA_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-atlassian%3A0.13.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-atlassian": {
        "env": {
          "CONFLUENCE_API_TOKEN": "TO_BE_SET",
          "CONFLUENCE_URL": "TO_BE_SET",
          "CONFLUENCE_USERNAME": "TO_BE_SET",
          "JIRA_API_TOKEN": "TO_BE_SET",
          "JIRA_URL": "TO_BE_SET",
          "JIRA_USERNAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "CONFLUENCE_API_TOKEN",
          "-e",
          "CONFLUENCE_URL",
          "-e",
          "CONFLUENCE_USERNAME",
          "-e",
          "JIRA_API_TOKEN",
          "-e",
          "JIRA_URL",
          "-e",
          "JIRA_USERNAME",
          "docker.io/acuvity/mcp-server-atlassian:0.13.0"
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
    "acuvity-mcp-server-atlassian": {
      "env": {
        "CONFLUENCE_API_TOKEN": "TO_BE_SET",
        "CONFLUENCE_URL": "TO_BE_SET",
        "CONFLUENCE_USERNAME": "TO_BE_SET",
        "JIRA_API_TOKEN": "TO_BE_SET",
        "JIRA_URL": "TO_BE_SET",
        "JIRA_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONFLUENCE_API_TOKEN",
        "-e",
        "CONFLUENCE_URL",
        "-e",
        "CONFLUENCE_USERNAME",
        "-e",
        "JIRA_API_TOKEN",
        "-e",
        "JIRA_URL",
        "-e",
        "JIRA_USERNAME",
        "docker.io/acuvity/mcp-server-atlassian:0.13.0"
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
    "acuvity-mcp-server-atlassian": {
      "env": {
        "CONFLUENCE_API_TOKEN": "TO_BE_SET",
        "CONFLUENCE_URL": "TO_BE_SET",
        "CONFLUENCE_USERNAME": "TO_BE_SET",
        "JIRA_API_TOKEN": "TO_BE_SET",
        "JIRA_URL": "TO_BE_SET",
        "JIRA_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONFLUENCE_API_TOKEN",
        "-e",
        "CONFLUENCE_URL",
        "-e",
        "CONFLUENCE_USERNAME",
        "-e",
        "JIRA_API_TOKEN",
        "-e",
        "JIRA_URL",
        "-e",
        "JIRA_USERNAME",
        "docker.io/acuvity/mcp-server-atlassian:0.13.0"
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
    "acuvity-mcp-server-atlassian": {
      "env": {
        "CONFLUENCE_API_TOKEN": "TO_BE_SET",
        "CONFLUENCE_URL": "TO_BE_SET",
        "CONFLUENCE_USERNAME": "TO_BE_SET",
        "JIRA_API_TOKEN": "TO_BE_SET",
        "JIRA_URL": "TO_BE_SET",
        "JIRA_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONFLUENCE_API_TOKEN",
        "-e",
        "CONFLUENCE_URL",
        "-e",
        "CONFLUENCE_USERNAME",
        "-e",
        "JIRA_API_TOKEN",
        "-e",
        "JIRA_URL",
        "-e",
        "JIRA_USERNAME",
        "docker.io/acuvity/mcp-server-atlassian:0.13.0"
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
    "acuvity-mcp-server-atlassian": {
      "env": {
        "CONFLUENCE_API_TOKEN": "TO_BE_SET",
        "CONFLUENCE_URL": "TO_BE_SET",
        "CONFLUENCE_USERNAME": "TO_BE_SET",
        "JIRA_API_TOKEN": "TO_BE_SET",
        "JIRA_URL": "TO_BE_SET",
        "JIRA_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONFLUENCE_API_TOKEN",
        "-e",
        "CONFLUENCE_URL",
        "-e",
        "CONFLUENCE_USERNAME",
        "-e",
        "JIRA_API_TOKEN",
        "-e",
        "JIRA_URL",
        "-e",
        "JIRA_USERNAME",
        "docker.io/acuvity/mcp-server-atlassian:0.13.0"
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
        "env": {"CONFLUENCE_API_TOKEN":"TO_BE_SET","CONFLUENCE_URL":"TO_BE_SET","CONFLUENCE_USERNAME":"TO_BE_SET","JIRA_API_TOKEN":"TO_BE_SET","JIRA_URL":"TO_BE_SET","JIRA_USERNAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","CONFLUENCE_API_TOKEN","-e","CONFLUENCE_URL","-e","CONFLUENCE_USERNAME","-e","JIRA_API_TOKEN","-e","JIRA_URL","-e","JIRA_USERNAME","docker.io/acuvity/mcp-server-atlassian:0.13.0"]
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
- arguments: `run -i --rm --read-only -e CONFLUENCE_API_TOKEN -e CONFLUENCE_URL -e CONFLUENCE_USERNAME -e JIRA_API_TOKEN -e JIRA_URL -e JIRA_USERNAME docker.io/acuvity/mcp-server-atlassian:0.13.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e CONFLUENCE_API_TOKEN -e CONFLUENCE_URL -e CONFLUENCE_USERNAME -e JIRA_API_TOKEN -e JIRA_URL -e JIRA_USERNAME docker.io/acuvity/mcp-server-atlassian:0.13.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-atlassian": {
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
    "acuvity-mcp-server-atlassian": {
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
  - `CONFLUENCE_API_TOKEN` secret to be set as secrets.CONFLUENCE_API_TOKEN either by `.value` or from existing with `.valueFrom`
  - `JIRA_API_TOKEN` secret to be set as secrets.JIRA_API_TOKEN either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `CONFLUENCE_URL` environment variable to be set by env.CONFLUENCE_URL
  - `CONFLUENCE_USERNAME` environment variable to be set by env.CONFLUENCE_USERNAME
  - `JIRA_URL` environment variable to be set by env.JIRA_URL
  - `JIRA_USERNAME` environment variable to be set by env.JIRA_USERNAME

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-atlassian --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-atlassian --version 1.0.0
````

Install with helm

```console
helm install mcp-server-atlassian oci://docker.io/acuvity/mcp-server-atlassian --version 1.0.0
```

From there your MCP server mcp-server-atlassian will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-atlassian` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlassian/charts/mcp-server-atlassian/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (43)
<details>
<summary>jira_get_user_profile</summary>

**Description**:

```
Retrieve profile information for a specific Jira user.

Args:
    ctx: The FastMCP context.
    user_identifier: User identifier (email, username, key, or account ID).

Returns:
    JSON string representing the Jira user profile object, or an error object if not found.

Raises:
    ValueError: If the Jira client is not configured or available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user_identifier | string | Identifier for the user (e.g., email address 'user@example.com', username 'johndoe', account ID 'accountid:...', or key for Server/DC). | Yes
</details>
<details>
<summary>jira_get_issue</summary>

**Description**:

```
Get details of a specific Jira issue including its Epic links and relationship information.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    fields: Comma-separated list of fields to return (e.g., 'summary,status,customfield_10010'), a single field as a string (e.g., 'duedate'), '*all' for all fields, or omitted for essentials.
    expand: Optional fields to expand.
    comment_limit: Maximum number of comments.
    properties: Issue properties to return.
    update_history: Whether to update issue view history.

Returns:
    JSON string representing the Jira issue object.

Raises:
    ValueError: If the Jira client is not configured or available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment_limit | integer | Maximum number of comments to include (0 or null for no comments) | No
| expand | any | (Optional) Fields to expand. Examples: 'renderedFields' (for rendered content), 'transitions' (for available status transitions), 'changelog' (for history) | No
| fields | string | (Optional) Comma-separated list of fields to return (e.g., 'summary,status,customfield_10010'). You may also provide a single field as a string (e.g., 'duedate'). Use '*all' for all fields (including custom fields), or omit for essential fields only. | No
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
| properties | any | (Optional) A comma-separated list of issue properties to return | No
| update_history | boolean | Whether to update the issue view history for the requesting user | No
</details>
<details>
<summary>jira_search</summary>

**Description**:

```
Search Jira issues using JQL (Jira Query Language).

Args:
    ctx: The FastMCP context.
    jql: JQL query string.
    fields: Comma-separated fields to return.
    limit: Maximum number of results.
    start_at: Starting index for pagination.
    projects_filter: Comma-separated list of project keys to filter by.
    expand: Optional fields to expand.

Returns:
    JSON string representing the search results including pagination info.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expand | any | (Optional) fields to expand. Examples: 'renderedFields', 'transitions', 'changelog' | No
| fields | string | (Optional) Comma-separated fields to return in the results. Use '*all' for all fields, or specify individual fields like 'summary,status,assignee,priority' | No
| jql | string | JQL query string (Jira Query Language). Examples:
- Find Epics: "issuetype = Epic AND project = PROJ"
- Find issues in Epic: "parent = PROJ-123"
- Find by status: "status = 'In Progress' AND project = PROJ"
- Find by assignee: "assignee = currentUser()"
- Find recently updated: "updated >= -7d AND project = PROJ"
- Find by label: "labels = frontend AND project = PROJ"
- Find by priority: "priority = High AND project = PROJ" | Yes
| limit | integer | Maximum number of results (1-50) | No
| projects_filter | any | (Optional) Comma-separated list of project keys to filter results by. Overrides the environment variable JIRA_PROJECTS_FILTER if provided. | No
| start_at | integer | Starting index for pagination (0-based) | No
</details>
<details>
<summary>jira_search_fields</summary>

**Description**:

```
Search Jira fields by keyword with fuzzy match.

Args:
    ctx: The FastMCP context.
    keyword: Keyword for fuzzy search.
    limit: Maximum number of results.
    refresh: Whether to force refresh the field list.

Returns:
    JSON string representing a list of matching field definitions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keyword | string | Keyword for fuzzy search. If left empty, lists the first 'limit' available fields in their default order. | No
| limit | integer | Maximum number of results | No
| refresh | boolean | Whether to force refresh the field list | No
</details>
<details>
<summary>jira_get_project_issues</summary>

**Description**:

```
Get all issues for a specific Jira project.

Args:
    ctx: The FastMCP context.
    project_key: The project key.
    limit: Maximum number of results.
    start_at: Starting index for pagination.

Returns:
    JSON string representing the search results including pagination info.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Maximum number of results (1-50) | No
| project_key | string | The project key | Yes
| start_at | integer | Starting index for pagination (0-based) | No
</details>
<details>
<summary>jira_get_transitions</summary>

**Description**:

```
Get available status transitions for a Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.

Returns:
    JSON string representing a list of available transitions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
</details>
<details>
<summary>jira_get_worklog</summary>

**Description**:

```
Get worklog entries for a Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.

Returns:
    JSON string representing the worklog entries.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
</details>
<details>
<summary>jira_download_attachments</summary>

**Description**:

```
Download attachments from a Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    target_dir: Directory to save attachments.

Returns:
    JSON string indicating the result of the download operation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
| target_dir | string | Directory where attachments should be saved | Yes
</details>
<details>
<summary>jira_get_agile_boards</summary>

**Description**:

```
Get jira agile boards by name, project key, or type.

Args:
    ctx: The FastMCP context.
    board_name: Name of the board (fuzzy search).
    project_key: Project key.
    board_type: Board type ('scrum' or 'kanban').
    start_at: Starting index.
    limit: Maximum results.

Returns:
    JSON string representing a list of board objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| board_name | any | (Optional) The name of board, support fuzzy search | No
| board_type | any | (Optional) The type of jira board (e.g., 'scrum', 'kanban') | No
| limit | integer | Maximum number of results (1-50) | No
| project_key | any | (Optional) Jira project key (e.g., 'PROJ-123') | No
| start_at | integer | Starting index for pagination (0-based) | No
</details>
<details>
<summary>jira_get_board_issues</summary>

**Description**:

```
Get all issues linked to a specific board filtered by JQL.

Args:
    ctx: The FastMCP context.
    board_id: The ID of the board.
    jql: JQL query string to filter issues.
    fields: Comma-separated fields to return.
    start_at: Starting index for pagination.
    limit: Maximum number of results.
    expand: Optional fields to expand.

Returns:
    JSON string representing the search results including pagination info.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| board_id | string | The id of the board (e.g., '1001') | Yes
| expand | string | Optional fields to expand in the response (e.g., 'changelog'). | No
| fields | string | Comma-separated fields to return in the results. Use '*all' for all fields, or specify individual fields like 'summary,status,assignee,priority' | No
| jql | string | JQL query string (Jira Query Language). Examples:
- Find Epics: "issuetype = Epic AND project = PROJ"
- Find issues in Epic: "parent = PROJ-123"
- Find by status: "status = 'In Progress' AND project = PROJ"
- Find by assignee: "assignee = currentUser()"
- Find recently updated: "updated >= -7d AND project = PROJ"
- Find by label: "labels = frontend AND project = PROJ"
- Find by priority: "priority = High AND project = PROJ" | Yes
| limit | integer | Maximum number of results (1-50) | No
| start_at | integer | Starting index for pagination (0-based) | No
</details>
<details>
<summary>jira_get_sprints_from_board</summary>

**Description**:

```
Get jira sprints from board by state.

Args:
    ctx: The FastMCP context.
    board_id: The ID of the board.
    state: Sprint state ('active', 'future', 'closed'). If None, returns all sprints.
    start_at: Starting index.
    limit: Maximum results.

Returns:
    JSON string representing a list of sprint objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| board_id | string | The id of board (e.g., '1000') | Yes
| limit | integer | Maximum number of results (1-50) | No
| start_at | integer | Starting index for pagination (0-based) | No
| state | any | Sprint state (e.g., 'active', 'future', 'closed') | No
</details>
<details>
<summary>jira_get_sprint_issues</summary>

**Description**:

```
Get jira issues from sprint.

Args:
    ctx: The FastMCP context.
    sprint_id: The ID of the sprint.
    fields: Comma-separated fields to return.
    start_at: Starting index.
    limit: Maximum results.

Returns:
    JSON string representing the search results including pagination info.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fields | string | Comma-separated fields to return in the results. Use '*all' for all fields, or specify individual fields like 'summary,status,assignee,priority' | No
| limit | integer | Maximum number of results (1-50) | No
| sprint_id | string | The id of sprint (e.g., '10001') | Yes
| start_at | integer | Starting index for pagination (0-based) | No
</details>
<details>
<summary>jira_get_link_types</summary>

**Description**:

```
Get all available issue link types.

Args:
    ctx: The FastMCP context.

Returns:
    JSON string representing a list of issue link type objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>jira_create_issue</summary>

**Description**:

```
Create a new Jira issue with optional Epic link or parent for subtasks.

Args:
    ctx: The FastMCP context.
    project_key: The JIRA project key.
    summary: Summary/title of the issue.
    issue_type: Issue type (e.g., 'Task', 'Bug', 'Story', 'Epic', 'Subtask').
    assignee: Assignee's user identifier (string): Email, display name, or account ID (e.g., 'user@example.com', 'John Doe', 'accountid:...').
    description: Issue description.
    components: Comma-separated list of component names.
    additional_fields: Dictionary or JSON string of additional fields.

Returns:
    JSON string representing the created issue object.

Raises:
    ValueError: If in read-only mode or Jira client is unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additional_fields | any | (Optional) Dictionary of additional fields to set. Examples:
- Set priority: {'priority': {'name': 'High'}}
- Add labels: {'labels': ['frontend', 'urgent']}
- Link to parent (for any issue type): {'parent': 'PROJ-123'}
- Set Fix Version/s: {'fixVersions': [{'id': '10020'}]}
- Custom fields: {'customfield_10010': 'value'} | No
| assignee | any | (Optional) Assignee's user identifier (string): Email, display name, or account ID (e.g., 'user@example.com', 'John Doe', 'accountid:...') | No
| components | any | (Optional) Comma-separated list of component names to assign (e.g., 'Frontend,API') | No
| description | any | Issue description | No
| issue_type | string | Issue type (e.g. 'Task', 'Bug', 'Story', 'Epic', 'Subtask'). The available types depend on your project configuration. For subtasks, use 'Subtask' (not 'Sub-task') and include parent in additional_fields. | Yes
| project_key | string | The JIRA project key (e.g. 'PROJ', 'DEV', 'SUPPORT'). This is the prefix of issue keys in your project. Never assume what it might be, always ask the user. | Yes
| summary | string | Summary/title of the issue | Yes
</details>
<details>
<summary>jira_batch_create_issues</summary>

**Description**:

```
Create multiple Jira issues in a batch.

Args:
    ctx: The FastMCP context.
    issues: JSON array string of issue objects.
    validate_only: If true, only validates without creating.

Returns:
    JSON string indicating success and listing created issues (or validation result).

Raises:
    ValueError: If in read-only mode, Jira client unavailable, or invalid JSON.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issues | string | JSON array of issue objects. Each object should contain:
- project_key (required): The project key (e.g., 'PROJ')
- summary (required): Issue summary/title
- issue_type (required): Type of issue (e.g., 'Task', 'Bug')
- description (optional): Issue description
- assignee (optional): Assignee username or email
- components (optional): Array of component names
Example: [
  {"project_key": "PROJ", "summary": "Issue 1", "issue_type": "Task"},
  {"project_key": "PROJ", "summary": "Issue 2", "issue_type": "Bug", "components": ["Frontend"]}
] | Yes
| validate_only | boolean | If true, only validates the issues without creating them | No
</details>
<details>
<summary>jira_batch_get_changelogs</summary>

**Description**:

```
Get changelogs for multiple Jira issues (Cloud only).

Args:
    ctx: The FastMCP context.
    issue_ids_or_keys: List of issue IDs or keys.
    fields: List of fields to filter changelogs by. None for all fields.
    limit: Maximum changelogs per issue (-1 for all).

Returns:
    JSON string representing a list of issues with their changelogs.

Raises:
    NotImplementedError: If run on Jira Server/Data Center.
    ValueError: If Jira client is unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fields | any | (Optional) Filter the changelogs by fields, e.g. ['status', 'assignee']. Default to None for all fields. | No
| issue_ids_or_keys | array | List of Jira issue IDs or keys, e.g. ['PROJ-123', 'PROJ-124'] | Yes
| limit | integer | Maximum number of changelogs to return in result for each issue. Default to -1 for all changelogs. Notice that it only limits the results in the response, the function will still fetch all the data. | No
</details>
<details>
<summary>jira_update_issue</summary>

**Description**:

```
Update an existing Jira issue including changing status, adding Epic links, updating fields, etc.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    fields: Dictionary of fields to update.
    additional_fields: Optional dictionary of additional fields.
    attachments: Optional JSON array string or comma-separated list of file paths.

Returns:
    JSON string representing the updated issue object and attachment results.

Raises:
    ValueError: If in read-only mode or Jira client unavailable, or invalid input.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additional_fields | any | (Optional) Dictionary of additional fields to update. Use this for custom fields or more complex updates. | No
| attachments | any | (Optional) JSON string array or comma-separated list of file paths to attach to the issue. Example: '/path/to/file1.txt,/path/to/file2.txt' or ['/path/to/file1.txt','/path/to/file2.txt'] | No
| fields | object | Dictionary of fields to update. For 'assignee', provide a string identifier (email, name, or accountId). Example: `{'assignee': 'user@example.com', 'summary': 'New Summary'}` | Yes
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
</details>
<details>
<summary>jira_delete_issue</summary>

**Description**:

```
Delete an existing Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.

Returns:
    JSON string indicating success.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_key | string | Jira issue key (e.g. PROJ-123) | Yes
</details>
<details>
<summary>jira_add_comment</summary>

**Description**:

```
Add a comment to a Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    comment: Comment text in Markdown.
    visibility: (Optional) Comment visibility (e.g. {"type":"group","value":"jira-users"}).

Returns:
    JSON string representing the added comment object.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | string | Comment text in Markdown format | Yes
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
| visibility | any | (Optional) Comment visibility (e.g. {"type":"group","value":"jira-users"}) | No
</details>
<details>
<summary>jira_edit_comment</summary>

**Description**:

```
Edit an existing comment on a Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    comment_id: The ID of the comment to edit.
    comment: Updated comment text in Markdown.
    visibility: (Optional) Comment visibility (e.g. {"type":"group","value":"jira-users"}).

Returns:
    JSON string representing the updated comment object.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | string | Updated comment text in Markdown format | Yes
| comment_id | string | The ID of the comment to edit | Yes
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
| visibility | any | (Optional) Comment visibility (e.g. {"type":"group","value":"jira-users"}) | No
</details>
<details>
<summary>jira_add_worklog</summary>

**Description**:

```
Add a worklog entry to a Jira issue.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    time_spent: Time spent in Jira format.
    comment: Optional comment in Markdown.
    started: Optional start time in ISO format.
    original_estimate: Optional new original estimate.
    remaining_estimate: Optional new remaining estimate.


Returns:
    JSON string representing the added worklog object.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | any | (Optional) Comment for the worklog in Markdown format | No
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
| original_estimate | any | (Optional) New value for the original estimate | No
| remaining_estimate | any | (Optional) New value for the remaining estimate | No
| started | any | (Optional) Start time in ISO format. If not provided, the current time will be used. Example: '2023-08-01T12:00:00.000+0000' | No
| time_spent | string | Time spent in Jira format. Examples: '1h 30m' (1 hour and 30 minutes), '1d' (1 day), '30m' (30 minutes), '4h' (4 hours) | Yes
</details>
<details>
<summary>jira_link_to_epic</summary>

**Description**:

```
Link an existing issue to an epic.

Args:
    ctx: The FastMCP context.
    issue_key: The key of the issue to link.
    epic_key: The key of the epic to link to.

Returns:
    JSON string representing the updated issue object.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| epic_key | string | The key of the epic to link to (e.g., 'PROJ-456') | Yes
| issue_key | string | The key of the issue to link (e.g., 'PROJ-123') | Yes
</details>
<details>
<summary>jira_create_issue_link</summary>

**Description**:

```
Create a link between two Jira issues.

Args:
    ctx: The FastMCP context.
    link_type: The type of link (e.g., 'Blocks').
    inward_issue_key: The key of the source issue.
    outward_issue_key: The key of the target issue.
    comment: Optional comment text.
    comment_visibility: Optional dictionary for comment visibility.

Returns:
    JSON string indicating success or failure.

Raises:
    ValueError: If required fields are missing, invalid input, in read-only mode, or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | any | (Optional) Comment to add to the link | No
| comment_visibility | any | (Optional) Visibility settings for the comment (e.g., {'type': 'group', 'value': 'jira-users'}) | No
| inward_issue_key | string | The key of the inward issue (e.g., 'PROJ-123') | Yes
| link_type | string | The type of link to create (e.g., 'Duplicate', 'Blocks', 'Relates to') | Yes
| outward_issue_key | string | The key of the outward issue (e.g., 'PROJ-456') | Yes
</details>
<details>
<summary>jira_create_remote_issue_link</summary>

**Description**:

```
Create a remote issue link (web link or Confluence link) for a Jira issue.

This tool allows you to add web links and Confluence links to Jira issues.
The links will appear in the issue's "Links" section and can be clicked to navigate to external resources.

Args:
    ctx: The FastMCP context.
    issue_key: The key of the issue to add the link to.
    url: The URL to link to (can be any web page or Confluence page).
    title: The title/name that will be displayed for the link.
    summary: Optional description of what the link is for.
    relationship: Optional relationship description.
    icon_url: Optional URL to a 16x16 icon for the link.

Returns:
    JSON string indicating success or failure.

Raises:
    ValueError: If required fields are missing, invalid input, in read-only mode, or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| icon_url | any | (Optional) URL to a 16x16 icon for the link | No
| issue_key | string | The key of the issue to add the link to (e.g., 'PROJ-123') | Yes
| relationship | any | (Optional) Relationship description (e.g., 'causes', 'relates to', 'documentation') | No
| summary | any | (Optional) Description of the link | No
| title | string | The title/name of the link (e.g., 'Documentation Page', 'Confluence Page') | Yes
| url | string | The URL to link to (e.g., 'https://example.com/page' or Confluence page URL) | Yes
</details>
<details>
<summary>jira_remove_issue_link</summary>

**Description**:

```
Remove a link between two Jira issues.

Args:
    ctx: The FastMCP context.
    link_id: The ID of the link to remove.

Returns:
    JSON string indicating success.

Raises:
    ValueError: If link_id is missing, in read-only mode, or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| link_id | string | The ID of the link to remove | Yes
</details>
<details>
<summary>jira_transition_issue</summary>

**Description**:

```
Transition a Jira issue to a new status.

Args:
    ctx: The FastMCP context.
    issue_key: Jira issue key.
    transition_id: ID of the transition.
    fields: Optional dictionary of fields to update during transition.
    comment: Optional comment for the transition.

Returns:
    JSON string representing the updated issue object.

Raises:
    ValueError: If required fields missing, invalid input, in read-only mode, or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | any | (Optional) Comment to add during the transition. This will be visible in the issue history. | No
| fields | any | (Optional) Dictionary of fields to update during the transition. Some transitions require specific fields to be set (e.g., resolution). Example: {'resolution': {'name': 'Fixed'}} | No
| issue_key | string | Jira issue key (e.g., 'PROJ-123') | Yes
| transition_id | string | ID of the transition to perform. Use the jira_get_transitions tool first to get the available transition IDs for the issue. Example values: '11', '21', '31' | Yes
</details>
<details>
<summary>jira_create_sprint</summary>

**Description**:

```
Create Jira sprint for a board.

Args:
    ctx: The FastMCP context.
    board_id: Board ID.
    sprint_name: Sprint name.
    start_date: Start date (ISO format).
    end_date: End date (ISO format).
    goal: Optional sprint goal.

Returns:
    JSON string representing the created sprint object.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| board_id | string | The id of board (e.g., '1000') | Yes
| end_date | string | End time for sprint (ISO 8601 format) | Yes
| goal | any | (Optional) Goal of the sprint | No
| sprint_name | string | Name of the sprint (e.g., 'Sprint 1') | Yes
| start_date | string | Start time for sprint (ISO 8601 format) | Yes
</details>
<details>
<summary>jira_update_sprint</summary>

**Description**:

```
Update jira sprint.

Args:
    ctx: The FastMCP context.
    sprint_id: The ID of the sprint.
    sprint_name: Optional new name.
    state: Optional new state (future|active|closed).
    start_date: Optional new start date.
    end_date: Optional new end date.
    goal: Optional new goal.

Returns:
    JSON string representing the updated sprint object or an error message.

Raises:
    ValueError: If in read-only mode or Jira client unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end_date | any | (Optional) New end date for the sprint | No
| goal | any | (Optional) New goal for the sprint | No
| sprint_id | string | The id of sprint (e.g., '10001') | Yes
| sprint_name | any | (Optional) New name for the sprint | No
| start_date | any | (Optional) New start date for the sprint | No
| state | any | (Optional) New state for the sprint (future|active|closed) | No
</details>
<details>
<summary>jira_get_project_versions</summary>

**Description**:

```
Get all fix versions for a specific Jira project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_key | string | Jira project key (e.g., 'PROJ') | Yes
</details>
<details>
<summary>jira_get_all_projects</summary>

**Description**:

```
Get all Jira projects accessible to the current user.

Args:
    ctx: The FastMCP context.
    include_archived: Whether to include archived projects.

Returns:
    JSON string representing a list of project objects accessible to the user.
    Project keys are always returned in uppercase.
    If JIRA_PROJECTS_FILTER is configured, only returns projects matching those keys.

Raises:
    ValueError: If the Jira client is not configured or available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| include_archived | boolean | Whether to include archived projects in the results | No
</details>
<details>
<summary>jira_create_version</summary>

**Description**:

```
Create a new fix version in a Jira project.

Args:
    ctx: The FastMCP context.
    project_key: The project key.
    name: Name of the version.
    start_date: Start date (optional).
    release_date: Release date (optional).
    description: Description (optional).

Returns:
    JSON string of the created version object.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | Description of the version | No
| name | string | Name of the version | Yes
| project_key | string | Jira project key (e.g., 'PROJ') | Yes
| release_date | any | Release date (YYYY-MM-DD) | No
| start_date | any | Start date (YYYY-MM-DD) | No
</details>
<details>
<summary>jira_batch_create_versions</summary>

**Description**:

```
Batch create multiple versions in a Jira project.

Args:
    ctx: The FastMCP context.
    project_key: The project key.
    versions: JSON array string of version objects.

Returns:
    JSON array of results, each with success flag, version or error.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_key | string | Jira project key (e.g., 'PROJ') | Yes
| versions | string | JSON array of version objects. Each object should contain:
- name (required): Name of the version
- startDate (optional): Start date (YYYY-MM-DD)
- releaseDate (optional): Release date (YYYY-MM-DD)
- description (optional): Description of the version
Example: [
  {"name": "v1.0", "startDate": "2025-01-01", "releaseDate": "2025-02-01", "description": "First release"},
  {"name": "v2.0"}
] | Yes
</details>
<details>
<summary>confluence_search</summary>

**Description**:

```
Search Confluence content using simple terms or CQL.

Args:
    ctx: The FastMCP context.
    query: Search query - can be simple text or a CQL query string.
    limit: Maximum number of results (1-50).
    spaces_filter: Comma-separated list of space keys to filter by.

Returns:
    JSON string representing a list of simplified Confluence page objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Maximum number of results (1-50) | No
| query | string | Search query - can be either a simple text (e.g. 'project documentation') or a CQL query string. Simple queries use 'siteSearch' by default, to mimic the WebUI search, with an automatic fallback to 'text' search if not supported. Examples of CQL:
- Basic search: 'type=page AND space=DEV'
- Personal space search: 'space="~username"' (note: personal space keys starting with ~ must be quoted)
- Search by title: 'title~"Meeting Notes"'
- Use siteSearch: 'siteSearch ~ "important concept"'
- Use text search: 'text ~ "important concept"'
- Recent content: 'created >= "2023-01-01"'
- Content with specific label: 'label=documentation'
- Recently modified content: 'lastModified > startOfMonth("-1M")'
- Content modified this year: 'creator = currentUser() AND lastModified > startOfYear()'
- Content you contributed to recently: 'contributor = currentUser() AND lastModified > startOfWeek()'
- Content watched by user: 'watcher = "user@domain.com" AND type = page'
- Exact phrase in content: 'text ~ "\"Urgent Review Required\"" AND label = "pending-approval"'
- Title wildcards: 'title ~ "Minutes*" AND (space = "HR" OR space = "Marketing")'
Note: Special identifiers need proper quoting in CQL: personal space keys (e.g., "~username"), reserved words, numeric IDs, and identifiers with special characters. | Yes
| spaces_filter | any | (Optional) Comma-separated list of space keys to filter results by. Overrides the environment variable CONFLUENCE_SPACES_FILTER if provided. Use empty string to disable filtering. | No
</details>
<details>
<summary>confluence_get_page</summary>

**Description**:

```
Get content of a specific Confluence page by its ID, or by its title and space key.

Args:
    ctx: The FastMCP context.
    page_id: Confluence page ID. If provided, 'title' and 'space_key' are ignored.
    title: The exact title of the page. Must be used with 'space_key'.
    space_key: The key of the space. Must be used with 'title'.
    include_metadata: Whether to include page metadata.
    convert_to_markdown: Convert content to markdown (true) or keep raw HTML (false).

Returns:
    JSON string representing the page content and/or metadata, or an error if not found or parameters are invalid.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| convert_to_markdown | boolean | Whether to convert page to markdown (true) or keep it in raw HTML format (false). Raw HTML can reveal macros (like dates) not visible in markdown, but CAUTION: using HTML significantly increases token usage in AI responses. | No
| include_metadata | boolean | Whether to include page metadata such as creation date, last update, version, and labels. | No
| page_id | any | Confluence page ID (numeric ID, can be found in the page URL). For example, in the URL 'https://example.atlassian.net/wiki/spaces/TEAM/pages/123456789/Page+Title', the page ID is '123456789'. Provide this OR both 'title' and 'space_key'. If page_id is provided, title and space_key will be ignored. | No
| space_key | any | The key of the Confluence space where the page resides (e.g., 'DEV', 'TEAM'). Required if using 'title'. | No
| title | any | The exact title of the Confluence page. Use this with 'space_key' if 'page_id' is not known. | No
</details>
<details>
<summary>confluence_get_page_children</summary>

**Description**:

```
Get child pages and folders of a specific Confluence page.

Args:
    ctx: The FastMCP context.
    parent_id: The ID of the parent page.
    expand: Fields to expand.
    limit: Maximum number of child items.
    include_content: Whether to include page content.
    convert_to_markdown: Convert content to markdown if include_content is true.
    start: Starting index for pagination.
    include_folders: Whether to include child folders (default: True).

Returns:
    JSON string representing a list of child page and folder objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| convert_to_markdown | boolean | Whether to convert page content to markdown (true) or keep it in raw HTML format (false). Only relevant if include_content is true. | No
| expand | string | Fields to expand in the response (e.g., 'version', 'body.storage') | No
| include_content | boolean | Whether to include the page content in the response | No
| include_folders | boolean | Whether to include child folders in addition to child pages | No
| limit | integer | Maximum number of child items to return (1-50) | No
| parent_id | string | The ID of the parent page whose children you want to retrieve | Yes
| start | integer | Starting index for pagination (0-based) | No
</details>
<details>
<summary>confluence_get_comments</summary>

**Description**:

```
Get comments for a specific Confluence page.

Args:
    ctx: The FastMCP context.
    page_id: Confluence page ID.

Returns:
    JSON string representing a list of comment objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page_id | string | Confluence page ID (numeric ID, can be parsed from URL, e.g. from 'https://example.atlassian.net/wiki/spaces/TEAM/pages/123456789/Page+Title' -> '123456789') | Yes
</details>
<details>
<summary>confluence_get_labels</summary>

**Description**:

```
Get labels for a specific Confluence page.

Args:
    ctx: The FastMCP context.
    page_id: Confluence page ID.

Returns:
    JSON string representing a list of label objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page_id | string | Confluence page ID (numeric ID, can be parsed from URL, e.g. from 'https://example.atlassian.net/wiki/spaces/TEAM/pages/123456789/Page+Title' -> '123456789') | Yes
</details>
<details>
<summary>confluence_add_label</summary>

**Description**:

```
Add label to an existing Confluence page.

Args:
    ctx: The FastMCP context.
    page_id: The ID of the page to update.
    name: The name of the label.

Returns:
    JSON string representing the updated list of label objects for the page.

Raises:
    ValueError: If in read-only mode or Confluence client is unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | The name of the label | Yes
| page_id | string | The ID of the page to update | Yes
</details>
<details>
<summary>confluence_create_page</summary>

**Description**:

```
Create a new Confluence page.

Args:
    ctx: The FastMCP context.
    space_key: The key of the space.
    title: The title of the page.
    content: The content of the page (format depends on content_format).
    parent_id: Optional parent page ID.
    content_format: The format of the content ('markdown', 'wiki', or 'storage').
    enable_heading_anchors: Whether to enable heading anchors (markdown only).

Returns:
    JSON string representing the created page object.

Raises:
    ValueError: If in read-only mode, Confluence client is unavailable, or invalid content_format.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The content of the page. Format depends on content_format parameter. Can be Markdown (default), wiki markup, or storage format | Yes
| content_format | string | (Optional) The format of the content parameter. Options: 'markdown' (default), 'wiki', or 'storage'. Wiki format uses Confluence wiki markup syntax | No
| enable_heading_anchors | boolean | (Optional) Whether to enable automatic heading anchor generation. Only applies when content_format is 'markdown' | No
| parent_id | any | (Optional) parent page ID. If provided, this page will be created as a child of the specified page | No
| space_key | string | The key of the space to create the page in (usually a short uppercase code like 'DEV', 'TEAM', or 'DOC') | Yes
| title | string | The title of the page | Yes
</details>
<details>
<summary>confluence_update_page</summary>

**Description**:

```
Update an existing Confluence page.

Args:
    ctx: The FastMCP context.
    page_id: The ID of the page to update.
    title: The new title of the page.
    content: The new content of the page (format depends on content_format).
    is_minor_edit: Whether this is a minor edit.
    version_comment: Optional comment for this version.
    parent_id: Optional new parent page ID.
    content_format: The format of the content ('markdown', 'wiki', or 'storage').
    enable_heading_anchors: Whether to enable heading anchors (markdown only).

Returns:
    JSON string representing the updated page object.

Raises:
    ValueError: If Confluence client is not configured, available, or invalid content_format.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The new content of the page. Format depends on content_format parameter | Yes
| content_format | string | (Optional) The format of the content parameter. Options: 'markdown' (default), 'wiki', or 'storage'. Wiki format uses Confluence wiki markup syntax | No
| enable_heading_anchors | boolean | (Optional) Whether to enable automatic heading anchor generation. Only applies when content_format is 'markdown' | No
| is_minor_edit | boolean | Whether this is a minor edit | No
| page_id | string | The ID of the page to update | Yes
| parent_id | any | Optional the new parent page ID | No
| title | string | The new title of the page | Yes
| version_comment | any | Optional comment for this version | No
</details>
<details>
<summary>confluence_delete_page</summary>

**Description**:

```
Delete an existing Confluence page.

Args:
    ctx: The FastMCP context.
    page_id: The ID of the page to delete.

Returns:
    JSON string indicating success or failure.

Raises:
    ValueError: If Confluence client is not configured or available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page_id | string | The ID of the page to delete | Yes
</details>
<details>
<summary>confluence_add_comment</summary>

**Description**:

```
Add a comment to a Confluence page.

Args:
    ctx: The FastMCP context.
    page_id: The ID of the page to add a comment to.
    content: The comment content in Markdown format.

Returns:
    JSON string representing the created comment.

Raises:
    ValueError: If in read-only mode or Confluence client is unavailable.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The comment content in Markdown format | Yes
| page_id | string | The ID of the page to add a comment to | Yes
</details>
<details>
<summary>confluence_search_user</summary>

**Description**:

```
Search Confluence users using CQL.

Args:
    ctx: The FastMCP context.
    query: Search query - a CQL query string for user search.
    limit: Maximum number of results (1-50).

Returns:
    JSON string representing a list of simplified Confluence user search result objects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Maximum number of results (1-50) | No
| query | string | Search query - a CQL query string for user search. Examples of CQL:
- Basic user lookup by full name: 'user.fullname ~ "First Last"'
Note: Special identifiers need proper quoting in CQL: personal space keys (e.g., "~username"), reserved words, numeric IDs, and identifiers with special characters. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | confluence_add_comment | description | aa41a0aad0d129d98f9f6d5ce679d33ac563a237f63b679f0812814c7b9312fb |
| tools | confluence_add_comment | content | 7c17579c8ed4668bfb1fede68f965a86d8d3c01ebe2b1973daa8661bc3ca1b48 |
| tools | confluence_add_comment | page_id | 543df92d5561df462a69efd068e757a4acc43aa650b6ff274330eb3c09a60ebe |
| tools | confluence_add_label | description | 47508c7f6551e8d48125b63589af9c207312385d9652ee5128e757b2977f7a92 |
| tools | confluence_add_label | name | 83b624868488cf0fca8c1fe17f6c17e770456ad44bfad7df2d476315214a5677 |
| tools | confluence_add_label | page_id | 628f40cbdf75d0b2a88b54ab4b80a110c97055e424362411e7e7c300a08acf29 |
| tools | confluence_create_page | description | dfdc6647308811dc00af881826f709d9c27ebeb96a52e1729780cec7c8924a60 |
| tools | confluence_create_page | content | 338fd2e6e0244dd9e7f2df4e78f1b951fb7f2cc3c92f68e2d6b4fdf4f4c20470 |
| tools | confluence_create_page | content_format | 7a1a1c9dd7caae1ebceb2f33abb74bfd2ef1a4c2e6e738f1bd4d5cc999607568 |
| tools | confluence_create_page | enable_heading_anchors | 13a0eb535794cafb7eb7a4d0e3b12c66a83269da11aa8d4c715a660f1c7abaa1 |
| tools | confluence_create_page | parent_id | ea7a393c543e725e927ca85661106a9d664e448e127f10a11c7bb4d5cef9dff9 |
| tools | confluence_create_page | space_key | c43f5fd2a37f5582a919389b95c48764e771efd0e9d42b3475f84da37f62ae2c |
| tools | confluence_create_page | title | 5e5f34e9ae8d16f123915d19ec7cb196a3168a410861b210f724d261b5918d63 |
| tools | confluence_delete_page | description | 454f53f1ca0543c260b982c4119c00b798c3913de684bd328863fd21648d74f3 |
| tools | confluence_delete_page | page_id | d0f5fcabd1d0d4c22f81c71c512528d98c7cd51c430db935418c6fd70d8abb2e |
| tools | confluence_get_comments | description | 2fb1e523c00f26dcd47d1efbddec7c2c2d03eca4205357988d8a08807173b339 |
| tools | confluence_get_comments | page_id | 4e8337cd080af0704ee50874ebf511a2066dfa3bedb20581c1833f144db65913 |
| tools | confluence_get_labels | description | f0c4d9acb6caea2702b3ae945033092f1d13879b4fd9b233e5819dc994581426 |
| tools | confluence_get_labels | page_id | 4e8337cd080af0704ee50874ebf511a2066dfa3bedb20581c1833f144db65913 |
| tools | confluence_get_page | description | 10d104ee3104b10e9e4d7dd67a91d9ea3edb4f1ac1de93c0d5cfe3290048e19a |
| tools | confluence_get_page | convert_to_markdown | 5e0310f6fd031e76ec1bb867d17c36ca451234566d65ee5a85bd4a8683093f1c |
| tools | confluence_get_page | include_metadata | 3f9b30c4a1f2d49ab161c49f058909619c2908c3bc25e720cae71f06f7d83ff4 |
| tools | confluence_get_page | page_id | 00e40cf2940db9108b8feaadd6bbf68225215607f8e28137370e61b918cc1f47 |
| tools | confluence_get_page | space_key | fd37c56e395d974efde7e244e4bc60cc77712a571b4602e56e85a843325a3413 |
| tools | confluence_get_page | title | 7cab7fa312acf7dc04caee58bbaac4ab31f1095aa72ac6c2632653dc6f007716 |
| tools | confluence_get_page_children | description | 6d49891e4f668bd0a8d4a75d2c6b99c6114222b9a9e04e25b3d18a93d9977b76 |
| tools | confluence_get_page_children | convert_to_markdown | 155584fd2c3ce92b8f65e4f67ac5d1b82d7b8fb05db3ef9229e4d41b7d10a976 |
| tools | confluence_get_page_children | expand | 0eee18d0119ee5918f7c0da3cf66cd527804215916c6731d7fa96be1ed1c5983 |
| tools | confluence_get_page_children | include_content | 99329bd3e096fdf00a432d23fc9e19aee930348d6c5b7e2e7d79dcb642377844 |
| tools | confluence_get_page_children | include_folders | 1e4697e5d7f3f7fa8a77d98c999db33cdeecc23c5f49a8a49e340c2e7ebc43a9 |
| tools | confluence_get_page_children | limit | d04935dc44da76fa76889949648e5178f215e77a1ffb70bbe6c06ad706cede2e |
| tools | confluence_get_page_children | parent_id | 636a543a94d8b06ce3e9c05d183730cc19406ca19a0b099b6d425e2bd4a62f45 |
| tools | confluence_get_page_children | start | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | confluence_search | description | c6ee1bec516ad0616c5a7bfb2552e96c60c4b57a7bdc6bfaf6771b762d8af29c |
| tools | confluence_search | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | confluence_search | query | 509ec80b2a301105e24b1620fb16274ddeaf9b6a5399a1e4146dec158bbb8a66 |
| tools | confluence_search | spaces_filter | 9735159fdf99e15470aba55b0c3be9a48b12ca93e83e1e5dcbe674044cfbc3ba |
| tools | confluence_search_user | description | 2ef51639f475f6a454fd29d8b7831828be9866b1804d78402a55a69f49536944 |
| tools | confluence_search_user | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | confluence_search_user | query | 98fba6f89d08a4b6ffd8e15a52712aa08f8b0c748b57907cb390d484efa145fc |
| tools | confluence_update_page | description | 4df9ade93f6427a07f1fa5d55456f97692ac9ab517736896c2d0e4cb6937451b |
| tools | confluence_update_page | content | 5528c13cd406d5a6abcf235578d8fc1fa3dbda78991a434060a6c7064fe2c270 |
| tools | confluence_update_page | content_format | 7a1a1c9dd7caae1ebceb2f33abb74bfd2ef1a4c2e6e738f1bd4d5cc999607568 |
| tools | confluence_update_page | enable_heading_anchors | 13a0eb535794cafb7eb7a4d0e3b12c66a83269da11aa8d4c715a660f1c7abaa1 |
| tools | confluence_update_page | is_minor_edit | 845eb97892e676d0197bb05161bd9a0a494dd8462057602bed796afe2816e9e5 |
| tools | confluence_update_page | page_id | 628f40cbdf75d0b2a88b54ab4b80a110c97055e424362411e7e7c300a08acf29 |
| tools | confluence_update_page | parent_id | 20ec0828aa357c716035d5dee2a27b1086dde5617017b20e99460d6443ad28ae |
| tools | confluence_update_page | title | 24b82e455847b5c18117ed1bbcb3a7582767ce9309070b779d97305a1895b425 |
| tools | confluence_update_page | version_comment | 6ac3b24c7c2685cfc9fcf102fd9a18859fb350564fe68dc3b5624301ad2264d6 |
| tools | jira_add_comment | description | 29fa0907f38de0c74c689741f8aa734fc1c1e7888371ac952e472115fa8c6f70 |
| tools | jira_add_comment | comment | feaaa62ac0325f7648e7427dc02b3d0a32e10387b619c88feee8b80eec6bf003 |
| tools | jira_add_comment | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_add_comment | visibility | f5b328ffb9d982dbe8214c433f5383d0a117a8b30c16bc30237e641f9e50cd9a |
| tools | jira_add_worklog | description | 7963a7e221b8304a1392fc8496b7ae401e530babe18bb4d0424ccbe4afe4a9f3 |
| tools | jira_add_worklog | comment | 62eb737a8c31aab8cb4a02db3b349535ab1f310ce1ed69514a99dd8f6a81e3a8 |
| tools | jira_add_worklog | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_add_worklog | original_estimate | f2b8bfea404e531fbfb707fc44e96153734ccf0477a8a0c48d8275472b3c0e1b |
| tools | jira_add_worklog | remaining_estimate | 395a8af590b32288adcbbc33068a5bca15cd7132387fdfb2dddccd56bdf44bf1 |
| tools | jira_add_worklog | started | 0e8c988e138f92874c5bb74b1a9307c992f447651fd611d24cf505a76341e959 |
| tools | jira_add_worklog | time_spent | 1dbeddece738456a2c5bc1c726981bf25dbd11c8f1137a80fa8e991eba43441f |
| tools | jira_batch_create_issues | description | a3db149c4d008a9d3d222918024128ae784188517aa08238bfe5c156fa2bf02f |
| tools | jira_batch_create_issues | issues | 20c57eb405139e2cd89f22da4e3c69c158b071757e07ae0048d2eebaa7ed4ef6 |
| tools | jira_batch_create_issues | validate_only | 04cb567c3ea4b026ca81a3d5cd6ccdddd2f39fcf6dd14745d9b0beefe7eabbeb |
| tools | jira_batch_create_versions | description | 78ff7d232ee21914db5d28c6ee242ae3442680e1b2fc3ff122f634332e1f0bd0 |
| tools | jira_batch_create_versions | project_key | 37c11040956303aad07ac1ae16fcafa7ef61289a757e20fd988cc397a212fda9 |
| tools | jira_batch_create_versions | versions | e90dc70f2f0a20f92ffb24a0758649f520129d7463774095fc86a527c19829e6 |
| tools | jira_batch_get_changelogs | description | cff6855b84b99d2fad791d88b5263af0cd5da576d9c955f603c5965bb7ca9fa8 |
| tools | jira_batch_get_changelogs | fields | 802da38485c7fe906e3bf9778a9a55826efb3124c832adb20174c70793ed934a |
| tools | jira_batch_get_changelogs | issue_ids_or_keys | 0b82a55d40fc36a3c0b77623c7bc04667cdf7b79878791d6df8eb912a00ed36d |
| tools | jira_batch_get_changelogs | limit | ddde08929127f5b25f815057acd9494af1adf1bd621a5513f6834663623ca7c2 |
| tools | jira_create_issue | description | 7a426dedcdca3c7bdd3bc8a1536200802216ba2950fb3ee67f90e8a75a5f7905 |
| tools | jira_create_issue | additional_fields | 3da1a5be8aa3c4e875d914970ef71d169b087551d21fff48a1b155bc2b87ba05 |
| tools | jira_create_issue | assignee | b685b296e3c7ea3b1f07de8e80307213ca945eca31a8f6709be50d8796512bb3 |
| tools | jira_create_issue | components | b790821b382a406f963c428e50ec5a7c9df9419e35ce2584b25c76507f291de7 |
| tools | jira_create_issue | description | 6fdf4c7fb5a19e122d009b8deed663a56034d8170be9300906c4368c423da250 |
| tools | jira_create_issue | issue_type | 91e553985a8fed7d99c70aaa9461508621f3eab88e2ec2b0c8185782479a65b2 |
| tools | jira_create_issue | project_key | da3101264495f5cdbab2461feafd7eb4806c8985d8d4d5d3e7cfd41920f60e29 |
| tools | jira_create_issue | summary | a9d039cb72b5215c9b7845dc5e6bbba0dabad0549d6b477b07d4b24fb1132969 |
| tools | jira_create_issue_link | description | 7115bdd90e929f30e345281b00af9cba62a044905c0d8183764286fd3cf14398 |
| tools | jira_create_issue_link | comment | a1491a2f9e3776646f9b498b7ce357946c5e45cfdd91faa8307ac03cfc5120b4 |
| tools | jira_create_issue_link | comment_visibility | 66e798a84889e96feb2133394841acee326c62aeb51cb46171e6e5fdf1c02299 |
| tools | jira_create_issue_link | inward_issue_key | c2ee077a664e4bc77a9e0a9baeee9df27f4123ec3466ade841c52ba0b2c96fd8 |
| tools | jira_create_issue_link | link_type | 2dbfd8ea027e2016c0b342b19d4baef7b202cbc9210a30ea7a617f7374492a4a |
| tools | jira_create_issue_link | outward_issue_key | e876612f2e3b7dd6cff02c7d4c60d5791735cd91266efa1b650bbe08564fe840 |
| tools | jira_create_remote_issue_link | description | ccaa6d986384c13399c20f416807f0268a17de90c4af5c228dc1238e52179bc8 |
| tools | jira_create_remote_issue_link | icon_url | c0228a056cdb07b305431455eba3ee6562a443716df13c7c17fe7b85982400e0 |
| tools | jira_create_remote_issue_link | issue_key | ace82cda394c70be6e5c847eb8613e42fe24e17e7324e368ca64657fcc537392 |
| tools | jira_create_remote_issue_link | relationship | 0a4a78ee469c9c7b5ab7effd1e929efa38442de7f3a3260ff27e2a5825346c5d |
| tools | jira_create_remote_issue_link | summary | 5d89b887209a45f205c0f99d3eade1333956da186e9931a6886e7b0083afaf3c |
| tools | jira_create_remote_issue_link | title | b1bc56b4a7c418ac57c9b7ebc4e2aacf3f8d3498227f85bb28a38516d0d18b08 |
| tools | jira_create_remote_issue_link | url | c52d44bf6e0c4e4e78e8e4eadc4dc09e78b1b0670159aed2ae42c143e8e0cf6c |
| tools | jira_create_sprint | description | a6e8eb7b2b30e88bb0bd9d58692685f3e9e9370dde986075eabc5131132b14b6 |
| tools | jira_create_sprint | board_id | 3bceb81a0bed22704222cd1d3eec9d075513a5d6e5a3cc75c633328ccdfcd74d |
| tools | jira_create_sprint | end_date | 404919fdbefa9b32582c7d26defb199ece6f292e51a114031b3bcaa10b6532c8 |
| tools | jira_create_sprint | goal | 87c9795a288b323bd5e1358af05a1a132f38dd9c5920ccc69cecbf695a3aa5c9 |
| tools | jira_create_sprint | sprint_name | da613f1ae8a7896e8a2964512b8b641d8382ae7c45280a5deb9ac2240e541471 |
| tools | jira_create_sprint | start_date | de5739e9fcf9465c8fa2440420bb9904ae87041f6e515e21222e0f343d3ab88f |
| tools | jira_create_version | description | c2d331f6e2305edd28d4bac929b9e49d1d838879ac10e687d1a907d169765030 |
| tools | jira_create_version | description | 50a25918fca3786e02cb408a6e69a747dfa43972a96bf5bb1413dde13bd3df4c |
| tools | jira_create_version | name | d6ea5e7e5b8f5f9c20a1319a54f46e9770b3dc0e4ae3e222c29fccb28e1affa3 |
| tools | jira_create_version | project_key | 37c11040956303aad07ac1ae16fcafa7ef61289a757e20fd988cc397a212fda9 |
| tools | jira_create_version | release_date | 60c96238c6142fc02dd9e65bd88a76789931c82ab231a5fbb30a258466c4aeb9 |
| tools | jira_create_version | start_date | f66061bb997c584ac2a2d93d0bab2c80135d3aa38f478f94d964cec8decf1c1e |
| tools | jira_delete_issue | description | f47d36d223e3c3795367cb929bc423a8a4ebee79321664a5fbce9a86704464be |
| tools | jira_delete_issue | issue_key | cad37056ba72d245c7048c495c53595ee42bc44a837258d4a5157f6044592d8f |
| tools | jira_download_attachments | description | 2a93fec2f28527cf51f96219585a3991434aa48e7f47a3861843435eff14305e |
| tools | jira_download_attachments | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_download_attachments | target_dir | 08ea6d792f026f897a8a326bbdb202c164ad0157fc01c07fe7902bd30e89eb43 |
| tools | jira_edit_comment | description | becf9acc4befe17329a0967e9bce9ac8ab4e0617b6c43cb08ce61cc81c026409 |
| tools | jira_edit_comment | comment | 024133ff92dee06a0d7b04035aace58c2a985404341976abdddacd39b676de0f |
| tools | jira_edit_comment | comment_id | f970c72b107a8307882e2b4ed76ed013e1bb392f600136c14f8cdb1c06d06ba0 |
| tools | jira_edit_comment | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_edit_comment | visibility | f5b328ffb9d982dbe8214c433f5383d0a117a8b30c16bc30237e641f9e50cd9a |
| tools | jira_get_agile_boards | description | 5315cea73e5527d80d8e8770707d870e3915be1354d617d5e8b122a0e9443ad6 |
| tools | jira_get_agile_boards | board_name | 3ddf4ce62603681d9a725ade6d994638dfaf5ff3abee8c226114cdbf9a8e77d7 |
| tools | jira_get_agile_boards | board_type | 4f057abd38735e33e9b41546fa20195f2caa1efa656f3fabe94a68f4e8be61e3 |
| tools | jira_get_agile_boards | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | jira_get_agile_boards | project_key | be010ba2811a3f96f5eccdc36d885e75dee23eb4222472d4859935809f286930 |
| tools | jira_get_agile_boards | start_at | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | jira_get_all_projects | description | d808a26e0843a54f327dbaf23ed1f2adb0a9f1020f9f1b6c0c330d6eb30db5bc |
| tools | jira_get_all_projects | include_archived | c5620d3100fe6cca745b0218a5018f5518285d20f34fb6dfc7032c6d247a12d0 |
| tools | jira_get_board_issues | description | 2740a7fc45259394cfe09fe5a9fbc953e751d844ad83e3952ceced62932d53a7 |
| tools | jira_get_board_issues | board_id | d5402e29c3290f72a75ac45cf94ae99d5e9b1b40ce03a9daa5354766251238dc |
| tools | jira_get_board_issues | expand | e718ce177f50a2d1e01af0062ccaca4183afac09e87d22d759eaa4fb006c20bf |
| tools | jira_get_board_issues | fields | 8e427a5d6fe268c069fbb170c94dd766a7efe78abc6106f96791bb4f9c65c265 |
| tools | jira_get_board_issues | jql | 49a6be7752b8f41ec2116a95046fedf2411b2375320ac57d4e3da123c64a9e26 |
| tools | jira_get_board_issues | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | jira_get_board_issues | start_at | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | jira_get_issue | description | 88f7c1fe02f74e4bfaeb522c89c4b02270b8f467d9d81e68c2d09588f29da6c5 |
| tools | jira_get_issue | comment_limit | 3a794a3ce020aef98296d75544aa44ef0ea0337e38d20abc30a0f2e210b1e17f |
| tools | jira_get_issue | expand | f8ca28a870f0fd13a1ac1c5e75dda085b713cf5616936e1da39c2c4177ad711f |
| tools | jira_get_issue | fields | e31b57652ba6fa247a30e500000acaaf8b08aa6d7604d18fd5d9fcb7aec55fda |
| tools | jira_get_issue | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_get_issue | properties | ad52f0636a494334e0d392441437422e29a3895ae505a0271dc7c42b29b5b3d2 |
| tools | jira_get_issue | update_history | fde354c074efef28d0f9b919fc83f92bfa022feb63be1c974e0269610a0a1570 |
| tools | jira_get_link_types | description | 61459d6a64cf4f0d8e66ff5642c1adde70498da34a5db7f6010201dae21f71a0 |
| tools | jira_get_project_issues | description | 66561a6c28f9b44de44e8fc43136586370659133f6d2264014eef10d7a17fcb8 |
| tools | jira_get_project_issues | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | jira_get_project_issues | project_key | 6c54057c36a116ca60a070dfebe6b0c142ad9091ef4af62d3cb7d0d9e8c8f557 |
| tools | jira_get_project_issues | start_at | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | jira_get_project_versions | description | 438aa4b1f6ce74efd36e12633fd614e45656b6e9a53df334e28ea8ff2aa6f80b |
| tools | jira_get_project_versions | project_key | 37c11040956303aad07ac1ae16fcafa7ef61289a757e20fd988cc397a212fda9 |
| tools | jira_get_sprint_issues | description | b7ef2226c8fa6e807d68a935d851d5a4e8732949586099a741c870745a17329a |
| tools | jira_get_sprint_issues | fields | 8e427a5d6fe268c069fbb170c94dd766a7efe78abc6106f96791bb4f9c65c265 |
| tools | jira_get_sprint_issues | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | jira_get_sprint_issues | sprint_id | f56e64d821db2b7eecb421d317c1fe2cd3b26959d9f9d07e2a3ebafc7960ecdb |
| tools | jira_get_sprint_issues | start_at | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | jira_get_sprints_from_board | description | b93d9a57b0b10c995f24b756a31ab6036d07de1daeec11d8746a58d18bb58a7f |
| tools | jira_get_sprints_from_board | board_id | 3bceb81a0bed22704222cd1d3eec9d075513a5d6e5a3cc75c633328ccdfcd74d |
| tools | jira_get_sprints_from_board | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | jira_get_sprints_from_board | start_at | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | jira_get_sprints_from_board | state | 88cb545cf23d3c563c9fd0e1def23ea0813da12608f1bef918ea382dd5518d45 |
| tools | jira_get_transitions | description | 3e8f5c1f0e098c28fdff4b4f4d29e0fd30142a8c8f72236f00a98b95537a8c04 |
| tools | jira_get_transitions | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_get_user_profile | description | f4a960114b7e565d6ae5ecad340afb0419b131abca879167b65eeae0457e9adb |
| tools | jira_get_user_profile | user_identifier | b29eae413c2a6d06dc9da359d93caf8ed7c1ebeb457e6f9a5870aa0b2cd23aa5 |
| tools | jira_get_worklog | description | 2115088f853a4b461a7a0c72d8376b466ed8e6168b8be9f5527d319af885eccf |
| tools | jira_get_worklog | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_link_to_epic | description | fb55d73b3f12a1216c714d2fdfe30b9d969480698698de779b36d5de1d84f3d9 |
| tools | jira_link_to_epic | epic_key | 2ae4e74939f8a1435727cc7b006eeab1f5d7eeefd46ea20d7f81ac3fef468b8b |
| tools | jira_link_to_epic | issue_key | fea213983a7c5e2d84b0416572d1aa9c2d899bfd45ba06f889a81e390414f7a1 |
| tools | jira_remove_issue_link | description | 39c8467fa53ecc928eb04a55f3a361a7c62f9ecdf893baec95ba336551115aae |
| tools | jira_remove_issue_link | link_id | f94c86ced7a4bb0ecb26ee059e916ef780e7f2a744ab93a48b1ddf8b592bc993 |
| tools | jira_search | description | cdc059447b8c2e924ec47b82ec60e751fcfdc03f6edd7c3a24c771856ea77abf |
| tools | jira_search | expand | 005989f3f5516635e527d483afb0393fc9e374e244772c6407194279e35e414b |
| tools | jira_search | fields | 5cb63bd4a76cf94f8fba036084341be5a31de975cbd9d9f12eb13b3bd5985ea4 |
| tools | jira_search | jql | 49a6be7752b8f41ec2116a95046fedf2411b2375320ac57d4e3da123c64a9e26 |
| tools | jira_search | limit | d2f53210f2f0e66d63c3540c3b450f90770826326b68f40a055d79c38ec4440b |
| tools | jira_search | projects_filter | 55775c002c791bde5d68ae41ea0a8262dc6b027911c7d1e15c8e010b630ab7ac |
| tools | jira_search | start_at | a155000534e51a9045331d4a7494269871f0d79073ba94812965b3c1545fcc4a |
| tools | jira_search_fields | description | 88b67ec75239633b6f923ec00013e42ad8e73e2efce585598c5bd7c30ee6347e |
| tools | jira_search_fields | keyword | 9f17a2ed65a0ef57f88dcf4ba31dc191f02fe11d78a36f8401cf5b5cd0a99e73 |
| tools | jira_search_fields | limit | 3e509177106b4e186205442ecef7ab2bce66e64a4376b73cc7627cc0e9a3adba |
| tools | jira_search_fields | refresh | 6bb12240df30b8c9501b6ea49c9b5f1de99a216d0d4c7cc42e94a7bb9783a658 |
| tools | jira_transition_issue | description | 622a7447788e95a0aca274ea752e50d2e57e5f40333b4c4a71fd55af1cf55f24 |
| tools | jira_transition_issue | comment | 2173f25be1356ebb1e0733d6c34dcf413d95e7daa2f83fdacb2ec386151239d4 |
| tools | jira_transition_issue | fields | d1b5351cb0ea67246f3387018055e2a44eadc2d827ad852c13b48dd76722a4ca |
| tools | jira_transition_issue | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_transition_issue | transition_id | 76f0e261d6b43d78c236119a06ec0dfb60e80cb86843b484f3f3b4b7eb2ad528 |
| tools | jira_update_issue | description | d309eff3dc3bc82a639bf673976101e6069bf3ba0e03b9f5164dd1e1815ee4f1 |
| tools | jira_update_issue | additional_fields | 5842962afbd51ecf06e1b676d53ecc889cd2f2d165486c8fa3c270b117339232 |
| tools | jira_update_issue | attachments | 83eb360df9574c57b2a5e1383db5701dd38f72bfde45f6e8606ef06cc3a95a17 |
| tools | jira_update_issue | fields | 7ce353e459d334ff1333e8c2b96300c8a7d9d59124ddffe852dfd94e9641b505 |
| tools | jira_update_issue | issue_key | 503242ce27877eab3bd3119ada2d73de27685ce83650f4cbf91aa58f95e5f050 |
| tools | jira_update_sprint | description | 175d3ffb09228d4ca0d2ced051eecb64662e1151f691f2ad4ce41ec593b8311a |
| tools | jira_update_sprint | end_date | 2cfb541595f4f53415c22296d82daa2911443c2dc765eac5ace2655e36d6ce91 |
| tools | jira_update_sprint | goal | bcb38f47914024fdc9abb1662844e02527f36eacf229be8a558acf167d8b7dff |
| tools | jira_update_sprint | sprint_id | f56e64d821db2b7eecb421d317c1fe2cd3b26959d9f9d07e2a3ebafc7960ecdb |
| tools | jira_update_sprint | sprint_name | 4f7066d775e533a082b8d6e5e5c20f8c31349dd20f11619b417122057b2de572 |
| tools | jira_update_sprint | start_date | 6682f0a15074c484e343fd015a563d6f7a66f5827a9618adb81bd41ed2a96d5c |
| tools | jira_update_sprint | state | 2689ffab5c471019b7e9752abae3b4d4d3c6d0b993e3a65c50c3627acef0a0b3 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
