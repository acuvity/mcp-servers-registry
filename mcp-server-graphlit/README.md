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


# What is mcp-server-graphlit?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-graphlit/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-graphlit/1.0.20250508004?logo=docker&logoColor=fff&label=1.0.20250508004)](https://hub.docker.com/r/acuvity/mcp-server-graphlit)
[![PyPI](https://img.shields.io/badge/1.0.20250508004-3775A9?logo=pypi&logoColor=fff&label=graphlit-mcp-server)](https://github.com/graphlit/graphlit-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-graphlit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GRAPHLIT_ORGANIZATION_ID%22%2C%22-e%22%2C%22GRAPHLIT_ENVIRONMENT_ID%22%2C%22-e%22%2C%22GRAPHLIT_JWT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-graphlit%3A1.0.20250508004%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates your MCP client with Graphlit to ingest and search content from dev tools.

Packaged by Acuvity from graphlit-mcp-server original [sources](https://github.com/graphlit/graphlit-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-graphlit/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/charts/mcp-server-graphlit/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure graphlit-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/charts/mcp-server-graphlit#minibridge) for Helm charts).


# 📦 How to Install


> [!TIP]
> Given mcp-server-graphlit scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-graphlit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GRAPHLIT_ORGANIZATION_ID%22%2C%22-e%22%2C%22GRAPHLIT_ENVIRONMENT_ID%22%2C%22-e%22%2C%22GRAPHLIT_JWT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-graphlit%3A1.0.20250508004%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-graphlit": {
        "env": {
          "GRAPHLIT_ENVIRONMENT_ID": "TO_BE_SET",
          "GRAPHLIT_JWT_SECRET": "TO_BE_SET",
          "GRAPHLIT_ORGANIZATION_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "GRAPHLIT_ORGANIZATION_ID",
          "-e",
          "GRAPHLIT_ENVIRONMENT_ID",
          "-e",
          "GRAPHLIT_JWT_SECRET",
          "docker.io/acuvity/mcp-server-graphlit:1.0.20250508004"
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
    "acuvity-mcp-server-graphlit": {
      "env": {
        "GRAPHLIT_ENVIRONMENT_ID": "TO_BE_SET",
        "GRAPHLIT_JWT_SECRET": "TO_BE_SET",
        "GRAPHLIT_ORGANIZATION_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GRAPHLIT_ORGANIZATION_ID",
        "-e",
        "GRAPHLIT_ENVIRONMENT_ID",
        "-e",
        "GRAPHLIT_JWT_SECRET",
        "docker.io/acuvity/mcp-server-graphlit:1.0.20250508004"
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
    "acuvity-mcp-server-graphlit": {
      "env": {
        "GRAPHLIT_ENVIRONMENT_ID": "TO_BE_SET",
        "GRAPHLIT_JWT_SECRET": "TO_BE_SET",
        "GRAPHLIT_ORGANIZATION_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GRAPHLIT_ORGANIZATION_ID",
        "-e",
        "GRAPHLIT_ENVIRONMENT_ID",
        "-e",
        "GRAPHLIT_JWT_SECRET",
        "docker.io/acuvity/mcp-server-graphlit:1.0.20250508004"
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
    "acuvity-mcp-server-graphlit": {
      "env": {
        "GRAPHLIT_ENVIRONMENT_ID": "TO_BE_SET",
        "GRAPHLIT_JWT_SECRET": "TO_BE_SET",
        "GRAPHLIT_ORGANIZATION_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GRAPHLIT_ORGANIZATION_ID",
        "-e",
        "GRAPHLIT_ENVIRONMENT_ID",
        "-e",
        "GRAPHLIT_JWT_SECRET",
        "docker.io/acuvity/mcp-server-graphlit:1.0.20250508004"
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
    "acuvity-mcp-server-graphlit": {
      "env": {
        "GRAPHLIT_ENVIRONMENT_ID": "TO_BE_SET",
        "GRAPHLIT_JWT_SECRET": "TO_BE_SET",
        "GRAPHLIT_ORGANIZATION_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GRAPHLIT_ORGANIZATION_ID",
        "-e",
        "GRAPHLIT_ENVIRONMENT_ID",
        "-e",
        "GRAPHLIT_JWT_SECRET",
        "docker.io/acuvity/mcp-server-graphlit:1.0.20250508004"
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
        "env": {"GRAPHLIT_ENVIRONMENT_ID":"TO_BE_SET","GRAPHLIT_JWT_SECRET":"TO_BE_SET","GRAPHLIT_ORGANIZATION_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","GRAPHLIT_ORGANIZATION_ID","-e","GRAPHLIT_ENVIRONMENT_ID","-e","GRAPHLIT_JWT_SECRET","docker.io/acuvity/mcp-server-graphlit:1.0.20250508004"]
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
  - `GRAPHLIT_ORGANIZATION_ID` required to be set
  - `GRAPHLIT_ENVIRONMENT_ID` required to be set
  - `GRAPHLIT_JWT_SECRET` required to be set
  - `SLACK_BOT_TOKEN` optional (not set)
  - `DISCORD_BOT_TOKEN` optional (not set)
  - `TWITTER_TOKEN` optional (not set)
  - `GOOGLE_EMAIL_REFRESH_TOKEN` optional (not set)
  - `GOOGLE_EMAIL_CLIENT_ID` optional (not set)
  - `GOOGLE_EMAIL_CLIENT_SECRET` optional (not set)
  - `LINEAR_API_KEY` optional (not set)
  - `GITHUB_PERSONAL_ACCESS_TOKEN` optional (not set)
  - `JIRA_EMAIL` optional (not set)
  - `JIRA_TOKEN` optional (not set)
  - `NOTION_API_KEY` optional (not set)


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e GRAPHLIT_ORGANIZATION_ID -e GRAPHLIT_ENVIRONMENT_ID -e GRAPHLIT_JWT_SECRET docker.io/acuvity/mcp-server-graphlit:1.0.20250508004`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e GRAPHLIT_ORGANIZATION_ID -e GRAPHLIT_ENVIRONMENT_ID -e GRAPHLIT_JWT_SECRET docker.io/acuvity/mcp-server-graphlit:1.0.20250508004
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-graphlit": {
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
    "acuvity-mcp-server-graphlit": {
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
  - `GRAPHLIT_JWT_SECRET` secret to be set as secrets.GRAPHLIT_JWT_SECRET either by `.value` or from existing with `.valueFrom`

**Optional Secrets**:
  - `SLACK_BOT_TOKEN` secret to be set as secrets.SLACK_BOT_TOKEN either by `.value` or from existing with `.valueFrom`
  - `DISCORD_BOT_TOKEN` secret to be set as secrets.DISCORD_BOT_TOKEN either by `.value` or from existing with `.valueFrom`
  - `TWITTER_TOKEN` secret to be set as secrets.TWITTER_TOKEN either by `.value` or from existing with `.valueFrom`
  - `GOOGLE_EMAIL_REFRESH_TOKEN` secret to be set as secrets.GOOGLE_EMAIL_REFRESH_TOKEN either by `.value` or from existing with `.valueFrom`
  - `GOOGLE_EMAIL_CLIENT_ID` secret to be set as secrets.GOOGLE_EMAIL_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `GOOGLE_EMAIL_CLIENT_SECRET` secret to be set as secrets.GOOGLE_EMAIL_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`
  - `LINEAR_API_KEY` secret to be set as secrets.LINEAR_API_KEY either by `.value` or from existing with `.valueFrom`
  - `GITHUB_PERSONAL_ACCESS_TOKEN` secret to be set as secrets.GITHUB_PERSONAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`
  - `JIRA_EMAIL` secret to be set as secrets.JIRA_EMAIL either by `.value` or from existing with `.valueFrom`
  - `JIRA_TOKEN` secret to be set as secrets.JIRA_TOKEN either by `.value` or from existing with `.valueFrom`
  - `NOTION_API_KEY` secret to be set as secrets.NOTION_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `GRAPHLIT_ORGANIZATION_ID` environment variable to be set by env.GRAPHLIT_ORGANIZATION_ID
  - `GRAPHLIT_ENVIRONMENT_ID` environment variable to be set by env.GRAPHLIT_ENVIRONMENT_ID

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-graphlit --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-graphlit --version 1.0.0
````

Install with helm

```console
helm install mcp-server-graphlit oci://docker.io/acuvity/mcp-server-graphlit --version 1.0.0
```

From there your MCP server mcp-server-graphlit will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-graphlit` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-graphlit/charts/mcp-server-graphlit/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (64)
<details>
<summary>configureProject</summary>

**Description**:

```
Configures the default content workflow and conversation specification for the Graphlit project.
    Only needed if user asks to configure the project defaults. *Do not* call unless specifically asked for by the user.
    To reset the project configuration to 'factory state', assign False or null to all parameters.
    Optionally accepts whether to configure the default specification for LLM conversations. Defaults to using OpenAI GPT-4o, if not assigned.
    Optionally accepts whether to enable high-quality document and web page preparation using a vision LLM. Defaults to using Azure AI Document Intelligence for document preparation, if not assigned.
    Optionally accepts whether to enable entity extraction using LLM into the knowledge graph. Defaults to no entity extraction, if not assigned.
    Optionally accepts the preferred model provider service type, i.e. Anthropic, OpenAI, Google. Defaults to Anthropic if not provided.
    Returns the project identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| configureConversationSpecification | boolean | Whether to configure the default specification for LLM conversations. Defaults to False. | No
| configureExtractionSpecification | boolean | Whether to configure entity extraction using LLM into the knowledge graph. Defaults to False. | No
| configurePreparationSpecification | boolean | Whether to configure high-quality document and web page preparation using vision LLM. Defaults to False. | No
| modelServiceType | string | Preferred model provider service type for all specifications, i.e. Anthropic, OpenAI, Google. Defaults to Anthropic if not provided. | No
</details>
<details>
<summary>queryProjectUsage</summary>

**Description**:

```
Queries project usage records.
    Usage record name describes the operation, i.e. 'Prompt completion', 'Text embedding', 'GraphQL', 'Entity Event'.
    'GraphQL' usage records are used for GraphQL operations, i.e. 'queryContents', 'retrieveSources', 'askGraphlit', etc.
    'Entity Event' usage records are used for async compute operations.
    'Text embedding' usage records are used for text embedding operations.
    'Prompt completion' usage records are used for LLM prompt completion operations, i.e. when using 'promptConversation'.
    'Data extraction' usage records are used for data extraction operations, using LLMs to extract knowledge graph entities.
    Look at 'metric' field for the type of metric captured in the usage record, i.e. BYTES, TOKENS, UNITS, REQUESTS.
    Look for 'credits' field which describes how many credits were charged by the operation.
    Look for 'promptTokens', 'completionTokens' and (total) 'tokens' fields which describe the number of tokens used by the operation.
    Look for 'request', 'response' and 'variables' fields which describe the GraphQL operation.
    Look for 'count' for the number of units used by the operation, for example, number of pages processed by document preparation.
    Accepts an optional recency filter for usage records 'in last' timespan.
    Returns a list of usage records, which describe the billable audit log of all Graphlit API operations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| inLast | string | Recency filter for usage records 'in last' timespan, optional. Defaults to PT1H. Should be ISO 8601 format, for example, 'PT1H' for last hour, 'P1D' for last day, 'P7D' for last week, 'P30D' for last month. Doesn't support weeks or months explicitly. | No
</details>
<details>
<summary>askGraphlit</summary>

**Description**:

```
Ask questions about using the Graphlit Platform, or specifically about the Graphlit API or SDKs.
    When the user asks about how to use the Graphlit API or SDKs, use this tool to provide a code sample in Python, TypeScript or C#.
    Accepts an LLM user prompt.
    Returns the LLM prompt completion in Markdown format.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt | string | LLM user prompt. | Yes
</details>
<details>
<summary>promptConversation</summary>

**Description**:

```
Prompts an LLM conversation about your entire Graphlit knowledge base. 
    Uses hybrid vector search based on user prompt for locating relevant content sources. Uses LLM to complete the user prompt with the configured LLM.
    Maintains conversation history between 'user' and LLM 'assistant'. 
    Prefer 'promptConversation' when the user intends to start or continue an ongoing conversation about the entire Graphlit knowledge base.
    Similar to 'retrieveSources' but does not perform content metadata filtering.
    Accepts an LLM user prompt and optional conversation identifier. Will either create a new conversation or continue an existing one.
    Will use the default specification for LLM conversations, which is optionally configured with the 'configureProject' tool.
    Returns the conversation identifier, completed LLM message, and any citations from the LLM response.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conversationId | string | Conversation identifier, optional. | No
| prompt | string | User prompt. | Yes
</details>
<details>
<summary>retrieveSources</summary>

**Description**:

```
Retrieve relevant content sources from Graphlit knowledge base. Do *not* use for retrieving content by content identifier - retrieve content resource instead, with URI 'contents://{id}'.
    Accepts an LLM user prompt for content retrieval. For best retrieval quality, provide only key words or phrases from the user prompt, which will be used to create text embeddings for a vector search query.
    Only use when there is a valid LLM user prompt for content retrieval, otherwise use 'queryContents'. For example 'recent content' is not a useful user prompt, since it doesn't reference the text in the content.
    Only use for 'one shot' retrieval of content sources, i.e. when the user is not interested in having a conversation about the content.
    Accepts an optional ingestion recency filter (defaults to null, meaning all time), and optional content type and file type filters.
    Also accepts optional feed and collection identifiers to filter content by.
    Returns the ranked content sources, including their content resource URI to retrieve the complete Markdown text.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collections | array | Collection identifiers to filter content by, optional. | No
| feeds | array | Feed identifiers to filter content by, optional. | No
| fileType | string | File type filter, optional. One of: Animation, Audio, Code, Data, Document, Drawing, Email, Geometry, Image, Package, PointCloud, Shape, Video. | No
| inLast | string | Recency filter for content ingested 'in last' timespan, optional. Should be ISO 8601 format, for example, 'PT1H' for last hour, 'P1D' for last day, 'P7D' for last week, 'P30D' for last month. Doesn't support weeks or months explicitly. | No
| prompt | string | LLM user prompt for content retrieval. | Yes
| type | string | Content type filter, optional. One of: Email, Event, File, Issue, Message, Page, Post, Text. | No
</details>
<details>
<summary>retrieveImages</summary>

**Description**:

```
Retrieve images from Graphlit knowledge base. Provides image-specific retrieval when image similarity search is desired.
    Do *not* use for retrieving content by content identifier - retrieve content resource instead, with URI 'contents://{id}'.
    Accepts image URL. Image will be used for similarity search using image embeddings.
    Accepts optional geo-location filter for search by latitude, longitude and optional distance radius. Images taken with GPS enabled are searchable by geo-location.
    Also accepts optional recency filter (defaults to null, meaning all time), and optional feed and collection identifiers to filter images by.
    Returns the matching images, including their content resource URI to retrieve the complete Markdown text.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collections | array | Collection identifiers to filter images by, optional. | No
| feeds | array | Feed identifiers to filter images by, optional. | No
| inLast | string | Recency filter for images ingested 'in last' timespan, optional. Should be ISO 8601 format, for example, 'PT1H' for last hour, 'P1D' for last day, 'P7D' for last week, 'P30D' for last month. Doesn't support weeks or months explicitly. | No
| limit | number | Limit the number of images to be returned. Defaults to 100. | No
| location | object | Geo-location filter for search by latitude, longitude and optional distance radius. | No
| url | string | URL of image which will be used for similarity search using image embeddings. | Yes
</details>
<details>
<summary>extractText</summary>

**Description**:

```
Extracts JSON data from text using LLM.
    Accepts text to be extracted, and JSON schema which describes the data which will be extracted. JSON schema needs be of type 'object' and include 'properties' and 'required' fields.
    Optionally accepts text prompt which is provided to LLM to guide data extraction. Defaults to 'Extract data using the tools provided'.
    Returns extracted JSON from text.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt | string | Text prompt which is provided to LLM to guide data extraction, optional. | No
| schema | string | JSON schema which describes the data which will be extracted. JSON schema needs be of type 'object' and include 'properties' and 'required' fields. | Yes
| text | string | Text to be extracted with LLM. | Yes
</details>
<details>
<summary>createCollection</summary>

**Description**:

```
Create a collection.
    Accepts a collection name, and optional list of content identifiers to add to collection.
    Returns the collection identifier
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contents | array | Content identifiers to add to collection, optional. | No
| name | string | Collection name. | Yes
</details>
<details>
<summary>addContentsToCollection</summary>

**Description**:

```
Add contents to a collection.
    Accepts a collection identifier and a list of content identifiers to add to collection.
    Returns the collection identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contents | array | Content identifiers to add to collection. | Yes
| id | string | Collection identifier. | Yes
</details>
<details>
<summary>removeContentsFromCollection</summary>

**Description**:

```
Remove contents from collection.
    Accepts a collection identifier and a list of content identifiers to remove from collection.
    Returns the collection identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contents | array | Content identifiers to remove from collection. | Yes
| id | string | Collection identifier. | Yes
</details>
<details>
<summary>deleteContent</summary>

**Description**:

```
Deletes content from Graphlit knowledge base.
    Accepts content identifier.
    Returns the content identifier and content state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Content identifier. | Yes
</details>
<details>
<summary>deleteConversation</summary>

**Description**:

```
Deletes conversation from Graphlit knowledge base.
    Accepts conversation identifier.
    Returns the conversation identifier and content state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Conversation identifier. | Yes
</details>
<details>
<summary>deleteCollection</summary>

**Description**:

```
Deletes collection from Graphlit knowledge base.
    Does *not* delete the contents in the collection, only the collection itself.
    Accepts collection identifier.
    Returns the collection identifier and collection state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Collection identifier. | Yes
</details>
<details>
<summary>deleteFeed</summary>

**Description**:

```
Deletes feed from Graphlit knowledge base.
    *Does* delete the contents in the feed, in addition to the feed itself.
    Accepts feed identifier.
    Returns the feed identifier and feed state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Feed identifier. | Yes
</details>
<details>
<summary>deleteFeeds</summary>

**Description**:

```
Deletes feeds from Graphlit knowledge base.
    *Does* delete the contents in the feed, in addition to the feed itself.
    Accepts optional feed type filter to limit the feeds which will be deleted.
    Also accepts optional limit of how many feeds to delete, defaults to 100.
    Returns the feed identifiers and feed state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| feedType | string | Feed type filter, optional. One of: Discord, Email, Intercom, Issue, MicrosoftTeams, Notion, Reddit, Rss, Search, Site, Slack, Web, YouTube, Zendesk. | No
| limit | number | Limit the number of feeds to be deleted. Defaults to 100. | No
</details>
<details>
<summary>deleteCollections</summary>

**Description**:

```
Deletes collections from Graphlit knowledge base.
    Does *not* delete the contents in the collections, only the collections themselves.
    Accepts optional limit of how many collections to delete, defaults to 100.
    Returns the collection identifiers and collection state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Limit the number of collections to be deleted. Defaults to 100. | No
</details>
<details>
<summary>deleteConversations</summary>

**Description**:

```
Deletes conversations from Graphlit knowledge base.
    Accepts optional limit of how many conversations to delete, defaults to 100.
    Returns the conversation identifiers and conversation state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Limit the number of conversations to be deleted. Defaults to 100. | No
</details>
<details>
<summary>deleteContents</summary>

**Description**:

```
Deletes contents from Graphlit knowledge base.
    Accepts optional content type and file type filters to limit the contents which will be deleted.
    Also accepts optional limit of how many contents to delete, defaults to 1000.
    Returns the content identifiers and content state, i.e. Deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentType | string | Content type filter, optional. One of: Email, Event, File, Issue, Message, Page, Post, Text. | No
| fileType | string | File type filter, optional. One of: Animation, Audio, Code, Data, Document, Drawing, Email, Geometry, Image, Package, PointCloud, Shape, Video. | No
| limit | number | Limit the number of contents to be deleted. Defaults to 1000. | No
</details>
<details>
<summary>queryContents</summary>

**Description**:

```
Query contents from Graphlit knowledge base. Do *not* use for retrieving content by content identifier - retrieve content resource instead, with URI 'contents://{id}'.
    Accepts optional content name, content type and file type for metadata filtering.
    Accepts optional hybrid vector search query.
    Accepts optional recency filter (defaults to null, meaning all time), and optional feed and collection identifiers to filter images by.
    Accepts optional geo-location filter for search by latitude, longitude and optional distance radius. Images and videos taken with GPS enabled are searchable by geo-location.
    Returns the matching contents, including their content resource URI to retrieve the complete Markdown text.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collections | array | Collection identifiers to filter contents by, optional. | No
| feeds | array | Feed identifiers to filter contents by, optional. | No
| fileType | string | Filter by file type. | No
| inLast | string | Recency filter for content ingested 'in last' timespan, optional. Should be ISO 8601 format, for example, 'PT1H' for last hour, 'P1D' for last day, 'P7D' for last week, 'P30D' for last month. Doesn't support weeks or months explicitly. | No
| limit | number | Limit the number of contents to be returned. Defaults to 100. | No
| location | object | Geo-location filter for search by latitude, longitude and optional distance radius. | No
| name | string | Textual match on content name. | No
| query | string | Search query. | No
| type | string | Filter by content type. | No
</details>
<details>
<summary>queryCollections</summary>

**Description**:

```
Query collections from Graphlit knowledge base. Do *not* use for retrieving collection by collection identifier - retrieve collection resource instead, with URI 'collections://{id}'.
    Accepts optional collection name for metadata filtering.
    Returns the matching collections, including their collection resource URI to retrieve the collection contents.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Limit the number of collections to be returned. Defaults to 100. | No
| name | string | Textual match on collection name. | No
</details>
<details>
<summary>queryFeeds</summary>

**Description**:

```
Query feeds from Graphlit knowledge base. Do *not* use for retrieving feed by feed identifier - retrieve feed resource instead, with URI 'feeds://{id}'.
    Accepts optional feed name and feed type for metadata filtering.
    Returns the matching feeds, including their feed resource URI to retrieve the feed contents.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Limit the number of feeds to be returned. Defaults to 100. | No
| name | string | Textual match on feed name. | No
| type | string | Filter by feed type. | No
</details>
<details>
<summary>queryConversations</summary>

**Description**:

```
Query conversations from Graphlit knowledge base. Do *not* use for retrieving conversation by conversation identifier - retrieve conversation resource instead, with URI 'conversations://{id}'.
    Accepts optional hybrid vector search query.
    Accepts optional recency filter (defaults to null, meaning all time).
    Returns the matching conversations, including their conversation resource URI to retrieve the complete conversation message history.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| inLast | string | Recency filter for conversations created 'in last' timespan, optional. Should be ISO 8601 format, for example, 'PT1H' for last hour, 'P1D' for last day, 'P7D' for last week, 'P30D' for last month. Doesn't support weeks or months explicitly. | No
| limit | number | Limit the number of conversations to be returned. Defaults to 100. | No
| query | string | Search query. | No
</details>
<details>
<summary>isContentDone</summary>

**Description**:

```
Check if content has completed asynchronous ingestion.
    Accepts a content identifier which was returned from one of the non-feed ingestion tools, like ingestUrl.
    Returns whether the content is done or not.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Content identifier. | Yes
</details>
<details>
<summary>isFeedDone</summary>

**Description**:

```
Check if an asynchronous feed has completed ingesting all the available content.
    Accepts a feed identifier which was returned from one of the ingestion tools, like ingestGoogleDriveFiles.
    Returns whether the feed is done or not.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Feed identifier. | Yes
</details>
<details>
<summary>listNotionDatabases</summary>

**Description**:

```
Lists available Notion databases.
    Requires environment variable to be configured: NOTION_API_KEY.
    Returns a list of Notion databases, where the database identifier can be used with ingestNotionPages to ingest pages into Graphlit knowledge base.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>listLinearProjects</summary>

**Description**:

```
Lists available Linear projects.
    Requires environment variable to be configured: LINEAR_API_KEY.
    Returns a list of Linear projects, where the project name can be used with ingestLinearIssues to ingest issues into Graphlit knowledge base.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>listSlackChannels</summary>

**Description**:

```
Lists available Slack channels.
    Requires environment variable to be configured: SLACK_BOT_TOKEN.
    Returns a list of Slack channels, where the channel name can be used with ingestSlackMessages to ingest messages into Graphlit knowledge base.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>listSharePointLibraries</summary>

**Description**:

```
Lists available SharePoint libraries.
    Requires environment variables to be configured: SHAREPOINT_CLIENT_ID, SHAREPOINT_CLIENT_SECRET, SHAREPOINT_REFRESH_TOKEN.
    Returns a list of SharePoint libraries, where the selected libraryId can be used with listSharePointFolders to enumerate SharePoint folders in a library.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>listSharePointFolders</summary>

**Description**:

```
Lists available SharePoint folders.
    Requires environment variables to be configured: SHAREPOINT_CLIENT_ID, SHAREPOINT_CLIENT_SECRET, SHAREPOINT_REFRESH_TOKEN.
    Returns a list of SharePoint folders, which can be used with ingestSharePointFiles to ingest files into Graphlit knowledge base.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| libraryId | string | SharePoint library identifier. | Yes
</details>
<details>
<summary>ingestSharePointFiles</summary>

**Description**:

```
Ingests files from SharePoint library into Graphlit knowledge base.
    Accepts a SharePoint libraryId and an optional folderId to ingest files from a specific SharePoint folder.
    Libraries can be enumerated with listSharePointLibraries and library folders with listSharePointFolders.
    Requires environment variables to be configured: SHAREPOINT_ACCOUNT_NAME, SHAREPOINT_CLIENT_ID, SHAREPOINT_CLIENT_SECRET, SHAREPOINT_REFRESH_TOKEN.
    Accepts an optional read limit for the number of files to ingest.
    Executes asynchronously, creates SharePoint feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folderId | string | SharePoint folder identifier, optional. | No
| libraryId | string | SharePoint library identifier. | Yes
| readLimit | number | Number of files to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestOneDriveFiles</summary>

**Description**:

```
Ingests files from OneDrive into Graphlit knowledge base.
    Accepts optional OneDrive folder identifier, and an optional read limit for the number of files to ingest.
    If no folder identifier provided, ingests files from root OneDrive folder.
    Requires environment variables to be configured: ONEDRIVE_CLIENT_ID, ONEDRIVE_CLIENT_SECRET, ONEDRIVE_REFRESH_TOKEN.
    Executes asynchronously, creates OneDrive feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folderId | string | OneDrive folder identifier, optional. | No
| readLimit | number | Number of files to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestGoogleDriveFiles</summary>

**Description**:

```
Ingests files from Google Drive into Graphlit knowledge base.
    Accepts optional Google Drive folder identifier, and an optional read limit for the number of files to ingest.
    For example, with Google Drive URI (https://drive.google.com/drive/u/0/folders/32tzhRD12KDh2hXABY8OZRFv7Smy8WBkQ), the folder identifier is 32tzhRD12KDh2hXABY8OZRFv7Smy8WBkQ.
    If no folder identifier provided, ingests files from root Google Drive folder.
    Requires environment variables to be configured: GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON -or- GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET, GOOGLE_DRIVE_REFRESH_TOKEN.
    If service account JSON is provided, uses service account authentication. Else, uses user authentication.
    Executes asynchronously, creates Google Drive feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folderId | string | Google Drive folder identifier, optional. | No
| readLimit | number | Number of files to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestDropboxFiles</summary>

**Description**:

```
Ingests files from Dropbox into Graphlit knowledge base.
    Accepts optional relative path to Dropbox folder (i.e. /Pictures), and an optional read limit for the number of files to ingest.
    If no path provided, ingests files from root Dropbox folder.
    Requires environment variables to be configured: DROPBOX_APP_KEY, DROPBOX_APP_SECRET, DROPBOX_REDIRECT_URI, DROPBOX_REFRESH_TOKEN.
    Executes asynchronously, creates Dropbox feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | Relative path to Dropbox folder, optional. | No
| readLimit | number | Number of files to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestBoxFiles</summary>

**Description**:

```
Ingests files from Box into Graphlit knowledge base.
    Accepts optional Box folder identifier, and an optional read limit for the number of files to ingest.
    If no folder identifier provided, ingests files from root Box folder (i.e. "0").
    Folder identifier can be inferred from Box URL. https://app.box.com/folder/123456 -> folder identifier is "123456".
    Requires environment variables to be configured: BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_REDIRECT_URI, BOX_REFRESH_TOKEN.
    Executes asynchronously, creates Box feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folderId | string | Box folder identifier, optional. Defaults to root folder. | No
| readLimit | number | Number of files to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestGitHubFiles</summary>

**Description**:

```
Ingests files from GitHub repository into Graphlit knowledge base.
    Accepts GitHub repository owner and repository name and an optional read limit for the number of files to ingest.
    For example, for GitHub repository (https://github.com/openai/tiktoken), 'openai' is the repository owner, and 'tiktoken' is the repository name.
    Requires environment variable to be configured: GITHUB_PERSONAL_ACCESS_TOKEN.
    Executes asynchronously, creates GitHub feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of files to ingest, optional. Defaults to 100. | No
| repositoryName | string | GitHub repository name. | Yes
| repositoryOwner | string | GitHub repository owner. | Yes
</details>
<details>
<summary>ingestNotionPages</summary>

**Description**:

```
Ingests pages from Notion database into Graphlit knowledge base.
    Accepts Notion database identifier and an optional read limit for the number of pages to ingest.
    You can list the available Notion database identifiers with listNotionDatabases.
    Or, for a Notion URL, https://www.notion.so/Example/Engineering-Wiki-114abc10cb38487e91ec906fc6c6f350, 'Engineering-Wiki-114abc10cb38487e91ec906fc6c6f350' is an example of a Notion database identifier.
    Requires environment variable to be configured: NOTION_API_KEY.
    Executes asynchronously, creates Notion feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| databaseId | string | Notion database identifier. | Yes
| readLimit | number | Number of pages to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestMicrosoftTeamsMessages</summary>

**Description**:

```
Ingests messages from Microsoft Teams channel into Graphlit knowledge base.
    Accepts Microsoft Teams team identifier and channel identifier, and an optional read limit for the number of messages to ingest.
    Requires environment variables to be configured: MICROSOFT_TEAMS_CLIENT_ID, MICROSOFT_TEAMS_CLIENT_SECRET, MICROSOFT_TEAMS_REFRESH_TOKEN.
    Executes asynchronously, creates Microsoft Teams feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channelId | string | Microsoft Teams channel identifier. | Yes
| readLimit | number | Number of messages to ingest, optional. Defaults to 100. | No
| teamId | string | Microsoft Teams team identifier. | Yes
</details>
<details>
<summary>ingestSlackMessages</summary>

**Description**:

```
Ingests messages from Slack channel into Graphlit knowledge base.
    Accepts Slack channel name and an optional read limit for the number of messages to ingest.
    Requires environment variable to be configured: SLACK_BOT_TOKEN.
    Executes asynchronously, creates Slack feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channelName | string | Slack channel name. | Yes
| readLimit | number | Number of messages to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestDiscordMessages</summary>

**Description**:

```
Ingests messages from Discord channel into Graphlit knowledge base.
    Accepts Discord channel name and an optional read limit for the number of messages to ingest.
    Requires environment variable to be configured: DISCORD_BOT_TOKEN.
    Executes asynchronously, creates Discord feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channelName | string | Discord channel name. | Yes
| readLimit | number | Number of messages to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestTwitterPosts</summary>

**Description**:

```
Ingests posts by user from Twitter/X into Graphlit knowledge base.
    Accepts Twitter/X user name, without the leading @ symbol, and an optional read limit for the number of posts to ingest.
    Requires environment variable to be configured: TWITTER_TOKEN.
    Executes asynchronously, creates Twitter feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of posts to ingest, optional. Defaults to 100. | No
| userName | string | Twitter/X user name, without the leading @ symbol, i.e. 'graphlit'. | Yes
</details>
<details>
<summary>ingestTwitterSearch</summary>

**Description**:

```
Searches for recent posts from Twitter/X, and ingests them into Graphlit knowledge base.
    Accepts search query, and an optional read limit for the number of posts to ingest.
    Requires environment variable to be configured: TWITTER_TOKEN.
    Executes asynchronously, creates Twitter feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Search query | Yes
| readLimit | number | Number of posts to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestRedditPosts</summary>

**Description**:

```
Ingests posts from Reddit subreddit into Graphlit knowledge base.
    Accepts a subreddit name and an optional read limit for the number of posts to ingest.
    Executes asynchronously, creates Reddit feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of posts to ingest, optional. Defaults to 100. | No
| subredditName | string | Subreddit name. | Yes
</details>
<details>
<summary>ingestGoogleEmail</summary>

**Description**:

```
Ingests emails from Google Email account into Graphlit knowledge base.
    Accepts an optional read limit for the number of emails to ingest.
    Requires environment variables to be configured: GOOGLE_EMAIL_CLIENT_ID, GOOGLE_EMAIL_CLIENT_SECRET, GOOGLE_EMAIL_REFRESH_TOKEN.
    Executes asynchronously, creates Google Email feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of emails to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestMicrosoftEmail</summary>

**Description**:

```
Ingests emails from Microsoft Email account into Graphlit knowledge base.
    Accepts an optional read limit for the number of emails to ingest.
    Requires environment variables to be configured: MICROSOFT_EMAIL_CLIENT_ID, MICROSOFT_EMAIL_CLIENT_SECRET, MICROSOFT_EMAIL_REFRESH_TOKEN.
    Executes asynchronously, creates Microsoft Email feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of emails to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestLinearIssues</summary>

**Description**:

```
Ingests issues from Linear project into Graphlit knowledge base.
    Accepts Linear project name and an optional read limit for the number of issues to ingest.
    Requires environment variable to be configured: LINEAR_API_KEY.
    Executes asynchronously, creates Linear issue feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectName | string | Linear project name. | Yes
| readLimit | number | Number of issues to ingest, optional. Defaults to 100. | No
</details>
<details>
<summary>ingestGitHubIssues</summary>

**Description**:

```
Ingests issues from GitHub repository into Graphlit knowledge base.
    Accepts GitHub repository owner and repository name and an optional read limit for the number of issues to ingest.
    For example, for GitHub repository (https://github.com/openai/tiktoken), 'openai' is the repository owner, and 'tiktoken' is the repository name.
    Requires environment variable to be configured: GITHUB_PERSONAL_ACCESS_TOKEN.
    Executes asynchronously, creates GitHub issue feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of issues to ingest, optional. Defaults to 100. | No
| repositoryName | string | GitHub repository name. | Yes
| repositoryOwner | string | GitHub repository owner. | Yes
</details>
<details>
<summary>ingestJiraIssues</summary>

**Description**:

```
Ingests issues from Atlassian Jira repository into Graphlit knowledge base.
    Accepts Atlassian Jira server URL and project name, and an optional read limit for the number of issues to ingest.
    Requires environment variables to be configured: JIRA_EMAIL, JIRA_TOKEN.
    Executes asynchronously, creates Atlassian Jira issue feed, and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectName | string | Atlassian Jira project name. | Yes
| readLimit | number | Number of issues to ingest, optional. Defaults to 100. | No
| url | string | Atlassian Jira server URL. | Yes
</details>
<details>
<summary>webCrawl</summary>

**Description**:

```
Crawls web pages from web site into Graphlit knowledge base.
    Accepts a URL and an optional read limit for the number of pages to crawl.
    Uses sitemap.xml to discover pages to be crawled from website.
    Executes asynchronously and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of web pages to ingest, optional. Defaults to 100. | No
| url | string | Web site URL. | Yes
</details>
<details>
<summary>webMap</summary>

**Description**:

```
Enumerates the web pages at or beneath the provided URL using web sitemap. 
    Does *not* ingest web pages into Graphlit knowledge base.
    Accepts web site URL as string.
    Returns list of mapped URIs from web site.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | Web site URL. | Yes
</details>
<details>
<summary>webSearch</summary>

**Description**:

```
Performs web or podcast search based on search query. Can search for web pages or anything about podcasts (i.e. episodes, topics, guest appearances). 
    Format the search query as what would be entered into a Google search. You can use site filtering in the search query, like 'site:twitter.com'.    
    Accepts search query as string, and optional search service type.    
    Prefer calling this tool over using 'curl' directly for any web search.
    Use 'PODSCAN' search service type to search podcasts.
    Does *not* ingest pages or podcast episodes into Graphlit knowledge base.  
    When searching podcasts, *don't* include the term 'podcast' or 'episode' in the search query - that would be redundant.
    Search service types: Tavily (web pages), Exa (web pages) and Podscan (podcasts). Defaults to Exa.
    Returns URL, title and relevant Markdown text from resulting web pages or podcast episode descriptions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Limit the number of search hits to be returned. Defaults to 10. | No
| query | string | Search query. | Yes
| searchService | string | Search service type (Tavily, Exa, Podscan). Defaults to Exa. | No
</details>
<details>
<summary>ingestRSS</summary>

**Description**:

```
Ingests posts from RSS feed into Graphlit knowledge base.
    For podcast RSS feeds, audio will be downloaded, transcribed and ingested into Graphlit knowledge base.
    Accepts RSS URL and an optional read limit for the number of posts to read.
    Executes asynchronously and returns the feed identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readLimit | number | Number of issues to posts, optional. Defaults to 25. | No
| url | string | RSS URL. | Yes
</details>
<details>
<summary>ingestUrl</summary>

**Description**:

```
Ingests content from URL into Graphlit knowledge base.
    Can scrape a single web page, and can ingest individual Word documents, PDFs, audio recordings, videos, images, or any other unstructured data.
    Do *not* use for crawling a web site, which is done with 'webCrawl' tool.
    Executes asynchronously and returns the content identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | URL to ingest content from. | Yes
</details>
<details>
<summary>ingestText</summary>

**Description**:

```
Ingests text as content into Graphlit knowledge base.
    Accepts the text itself, and an optional text type (Plain, Markdown, Html). Defaults to Markdown text type.
    Optionally accepts the content name and an identifier for an existing content object. Will overwrite existing content, if provided.
    Can use for storing the output from LLM or other tools as content resources, which can be later searched or retrieved.
    Executes *synchronously* and returns the content identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Optional content identifier. Will overwrite existing content, if provided. | No
| name | string | Name for the content object, optional. | No
| text | string | Text content to ingest. | Yes
| textType | string | Text type (Plain, Markdown, Html). Defaults to Markdown. | No
</details>
<details>
<summary>ingestMemory</summary>

**Description**:

```
Ingests short-term textual memory as content into Graphlit knowledge base.
    Accepts an optional text type (Plain, Markdown, Html). Defaults to Markdown text type. Optionally accepts the content name.
    Will automatically be entity extracted into a knowledge graph.
    Use for storing short-term memories about the user or agent, which can be later searched or retrieved. Memories are transient and will be deleted after a period of time.
    Can use 'queryContents' or 'retrieveSources' tools to search for memories, by specifying the 'MEMORY' content type.
    Executes asynchronously and returns the content identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name for the content object. | No
| text | string | Textual memory to ingest, i.e. 'Kirk likes raccoons' or 'Graphlit is based in Seattle' | Yes
| textType | string | Text type (Plain, Markdown, Html). Defaults to Markdown. | No
| timeToLive | string | Time to live for ingested memory. Should be ISO 8601 format, for example, 'PT1H' for one hour, 'P1D' for one day, 'P7D' for one week, 'P30D' for one month. Doesn't support weeks or months explicitly. | No
</details>
<details>
<summary>ingestFile</summary>

**Description**:

```
Ingests local file into Graphlit knowledge base.
    Accepts the path to the file in the local filesystem.
    Can use for storing *large* long-term textual memories or the output from LLM or other tools as content resources, which can be later searched or retrieved.
    Executes asynchronously and returns the content identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filePath | string | Path to the file in the local filesystem. | Yes
</details>
<details>
<summary>screenshotPage</summary>

**Description**:

```
Screenshots web page from URL.
    Executes *synchronously* and returns the content identifier.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | Web page URL. | Yes
</details>
<details>
<summary>describeImageUrl</summary>

**Description**:

```
Prompts vision LLM and returns completion. 
    Does *not* ingest image into Graphlit knowledge base.
    Accepts image URL as string.
    Returns Markdown text from LLM completion.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt | string | Prompt for image description. | Yes
| url | string | Image URL. | Yes
</details>
<details>
<summary>describeImageContent</summary>

**Description**:

```
Prompts vision LLM and returns description of image content. 
    Accepts content identifier as string, and optional prompt for image description.
    Returns Markdown text from LLM completion.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Content identifier. | Yes
| prompt | string | Prompt for image description, optional. | No
</details>
<details>
<summary>publishAudio</summary>

**Description**:

```
Publishes text as audio format, and ingests into Graphlit knowledge base.
    Accepts a name for the content object, the text itself, and an optional text type (Plain, Markdown, Html). Defaults to Markdown text type.
    Optionally accepts an ElevenLabs voice identifier.
    You *must* retrieve the content resource to get the downloadable audio URL for this published audio.
    Executes *synchronously* and returns the content identifiers.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name for the content object. | Yes
| text | string | Text content to publish. | Yes
| textType | string | Text type (Plain, Markdown, Html). Defaults to Markdown. | No
| voice | string | ElevenLabs voice identifier, optional. | No
</details>
<details>
<summary>publishImage</summary>

**Description**:

```
Publishes text as image format, and ingests into Graphlit knowledge base.
    Accepts a name for the content object.
    Also, accepts a prompt for image generation. For example, 'Create a cartoon image of a raccoon, saying "I Love Graphlit"'.
    You *must* retrieve the content resource to get the downloadable image URL for this published image.
    Executes *synchronously* and returns the content identifiers.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of images to generate, optional. Defaults to 1. | No
| name | string | Name for the content object. | Yes
| prompt | string | Prompt for image generation. | Yes
</details>
<details>
<summary>sendWebHookNotification</summary>

**Description**:

```
Sends a webhook notification to the provided URL.
    Accepts the webhook URL.
    Also accepts the text to be sent with the webhook, and an optional text type (Plain, Markdown, Html). Defaults to Markdown text type.
    Returns true if the notification was successfully sent, or false otherwise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| text | string | Text to send. | Yes
| textType | string | Text type (Plain, Markdown, Html). Defaults to Markdown. | No
| url | string | Webhook URL. | Yes
</details>
<details>
<summary>sendSlackNotification</summary>

**Description**:

```
Sends a Slack notification to the provided Slack channel.
    Accepts the Slack channel name.
    Also accepts the text for the Slack message, and an optional text type (Plain, Markdown, Html). Defaults to Markdown text type.
    Hint: In Slack Markdown, images are displayed by simply putting the URL in angle brackets like <https://example.com/image.jpg> instead of using the traditional Markdown image syntax ![alt text](url). 
    Requires environment variable to be configured: SLACK_BOT_TOKEN.
    Returns true if the notification was successfully sent, or false otherwise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channelName | string | Slack channel name. | Yes
| text | string | Text to send. | Yes
| textType | string | Text type (Plain, Markdown, Html). Defaults to Markdown. | No
</details>
<details>
<summary>sendTwitterNotification</summary>

**Description**:

```
Posts a tweet from the configured user account.
    Accepts the plain text for the tweet.
    Tweet text rules: allowed - plain text, @mentions, #hashtags, URLs (auto-shortened), line breaks (
).  
    Not allowed - markdown, HTML tags, rich text, or custom styles.
    Requires environment variables to be configured: TWITTER_CONSUMER_API_KEY, TWITTER_CONSUMER_API_SECRET, TWITTER_ACCESS_TOKEN_KEY, TWITTER_ACCESS_TOKEN_SECRET.
    Returns true if the notification was successfully sent, or false otherwise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| text | string | Text to send. | Yes
</details>
<details>
<summary>sendEmailNotification</summary>

**Description**:

```
Sends an email notification to the provided email address(es).
    Accepts the email subject and a list of email 'to' addresses.
    Email addresses should be in RFC 5322 format. i.e. Alice Wonderland <alice@wonderland.net>, or alice@wonderland.net
    Also accepts the text for the email, and an optional text type (Plain, Markdown, Html). Defaults to Markdown text type.
    Requires environment variable to be configured: FROM_EMAIL_ADDRESS.
    Returns true if the notification was successfully sent, or false otherwise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| subject | string | Email subject. | Yes
| text | string | Text to send. | Yes
| textType | string | Text type (Plain, Markdown, Html). Defaults to Markdown. | No
| to | array | Email address(es) to send the notification to. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | addContentsToCollection | description | e33b4f9868ff63a386ab0139f458aa1d32417d22dc01148c18f7dd0487a23e24 |
| tools | addContentsToCollection | contents | 0e981511c88d0994ad772601b08b7b35b92398dd71176bafade84164b33ee8df |
| tools | addContentsToCollection | id | a82d9f8c196801dbc8db82895e52a5a21a788cfbfdb81a128e65a85c76f8e861 |
| tools | askGraphlit | description | ba6ea3a51129ba5964908ae9678e13e897a509858c2b4863429530c99a6c3efc |
| tools | askGraphlit | prompt | 4e4578231789c6f8efabbb3995a9559ce7a6d0f4357a3f6cced38b977e79f4e5 |
| tools | configureProject | description | b5ba800a8561381966102a63498df22044ebe357fa1ec68f6829462e2dbae556 |
| tools | configureProject | configureConversationSpecification | 11011846504b88480d8fed47b66929740d7bb7150111039d671ac7f489d43e4d |
| tools | configureProject | configureExtractionSpecification | 4263cb589564952446f9a6cd219cea59e50afe5d62bfdca6fbee4de83c2a65cb |
| tools | configureProject | configurePreparationSpecification | 7a70674ca4e6887e9cc4bb39f7db43e3ba8da4ffbb8225b545a50ecf283de7df |
| tools | configureProject | modelServiceType | 0fe8bd34f7dec91a74e23d7c45c150df05c3eb48442b0066c632c63309c69523 |
| tools | createCollection | description | c5572a236f6b8510a1d7f782d761fd08bc50d202611aebbfa63728d9751f828e |
| tools | createCollection | contents | a4ec8e4be2643d86ccc877445307e70645a5ffd30f471ba7c305a5c77946d405 |
| tools | createCollection | name | cd274b8225c8f47659bd30bd1515ae94f3a45559c18c2e85ae347b16d090044f |
| tools | deleteCollection | description | 88ef716c828d4f8567def3d2cde0fc0c0cf29e5f5df06c2a7a5d891b70439529 |
| tools | deleteCollection | id | a82d9f8c196801dbc8db82895e52a5a21a788cfbfdb81a128e65a85c76f8e861 |
| tools | deleteCollections | description | 1dc7ce6d152fe88c867d29b92ff2afcd3cc1f37e8e091109a7199add65b3a0dd |
| tools | deleteCollections | limit | e710fcb53dfff39a8f5c81b860a29a5dc698cb11f8ce96b15492898687b97ad0 |
| tools | deleteContent | description | a998fa9d69080a924a33763983ac7636d2ffd2406864233af3e7bfd0fb90e8e7 |
| tools | deleteContent | id | dd8f0409a49357e5b9dff484884b770b5b8bb70751b25da5f540ef9e0c34b40c |
| tools | deleteContents | description | 06880e55f7a404eecd1f450e16a21bed70e638a0b7ddd4fbea13c893f3133029 |
| tools | deleteContents | contentType | d4ab74902f53a99a5136dd8eae836fc42c1f79ff26bc83235b0fd0b7ffd6182c |
| tools | deleteContents | fileType | 80c9decd868418c43303471e6d5509926b2453483930bd4e4e90b34539aa0e9c |
| tools | deleteContents | limit | 6af96543ea0921828c48c882975a322e5171419302ef4b271a9224be5e100cc3 |
| tools | deleteConversation | description | 4f77db02b6bbb604646191e2aff8b3a5aa8b3378804b3350895742e230e2cfd2 |
| tools | deleteConversation | id | 374073ffcd94a419e1e407fdbeeed64a0feaee1998c7c06d293a85c09169d97c |
| tools | deleteConversations | description | 254d58092965cc97c1d8dbdec850397f22fefc6d00cb44dbb2ba38dce59dfc29 |
| tools | deleteConversations | limit | 24718ad854a2a7b83e00cd041a76a63145293147eee870e9e27bf5445bb5977d |
| tools | deleteFeed | description | 9958aae29cb1ec5d63da2cb61a7b805020231492a3f49669f84518f82316e6c6 |
| tools | deleteFeed | id | 9555d03f0ff39b49742e4703b8296e0690809208f2d183548e7640bc61e1e349 |
| tools | deleteFeeds | description | 8db4c4ee441194a001ae936fff9b77dd6d2530b0e8e485567f8378f9a0f69206 |
| tools | deleteFeeds | feedType | 057a514825c2c1024fffb4aab8bdb4bcdfa3081225b22fa07db298c13bca94a9 |
| tools | deleteFeeds | limit | 2ab516833dffb87f3307ee21a403537279fb2ef7b5d3160d0455376d44aef74a |
| tools | describeImageContent | description | db40afd7d43dcb0ef61f8ac67eb90d881a8dc6b9cdd45f4166cd5eb3725959de |
| tools | describeImageContent | id | dd8f0409a49357e5b9dff484884b770b5b8bb70751b25da5f540ef9e0c34b40c |
| tools | describeImageContent | prompt | 35168a8fd6e647458517ae3e182adccb3931a41c48590d96c5d2a6501e02a2b4 |
| tools | describeImageUrl | description | 1b5090e8d7dcd37391d30317f3e0696740e9d68d75a3d92e0bce2508bca1e704 |
| tools | describeImageUrl | prompt | b802d667b19d548acacf43140366a868f4e23f41b7447d2affe0f8c844f890c8 |
| tools | describeImageUrl | url | 72615efbc52b67ee3cfb024b0ee70a69f27744a83979c061a0609252d62a6736 |
| tools | extractText | description | 56579f3d09ffdc793b873a8f499e7a71b5971977641c15555748cbc63733620e |
| tools | extractText | prompt | 6f09be606ce2d9c553b3ee149bb4a2e977bf9ad13d307a4a8709e97bebaf9b57 |
| tools | extractText | schema | b6c77d8fde9358f408c2253f52c689b324b3a2e87433971da144f06bf7eb016d |
| tools | extractText | text | 179a0f86ad3a9e9ac018a791544622733338cf4f86aa013b8012fecb4e647069 |
| tools | ingestBoxFiles | description | 04a072aafebaa76587ae086f6aeba9094e708339caaa42d847437658c04aa44e |
| tools | ingestBoxFiles | folderId | 094968dfbb0728c3ace97295f7c89dee55c8c2b07c2c1ee59d1943ef9d7c7d5c |
| tools | ingestBoxFiles | readLimit | 212f13a2013bf40f6409324f1cb6a7f08daeeb4c814f642d2e3360c3cc60506b |
| tools | ingestDiscordMessages | description | 61d997f24231b4ef42f91e4459121aa4f90f2c2e80d3bd0303400433bdb00adc |
| tools | ingestDiscordMessages | channelName | 2e4ae90c53c9b78d4cf62199d671232208ecbead8c22cf64752da9d5a1c1efde |
| tools | ingestDiscordMessages | readLimit | c52515d77ec305b6e04c55e0f415ba5b3cadc805247ab7597bfe67f5d5466858 |
| tools | ingestDropboxFiles | description | fe97c0807b2e162665e232f7cd38711bc5fdec08aa6aec893adbcd3a2bad731d |
| tools | ingestDropboxFiles | path | a885c25af1c8245b05e68ce70efc80b86f9d22ef71b0566e4b4ade5ec83e2d0b |
| tools | ingestDropboxFiles | readLimit | 212f13a2013bf40f6409324f1cb6a7f08daeeb4c814f642d2e3360c3cc60506b |
| tools | ingestFile | description | 5a093d19e4207dd7a15402e4eaf4124b871b8011144150753f2a8fe80c9daca7 |
| tools | ingestFile | filePath | c22e296edec032812a41e55fe0b3058661598c13a7f4f65e69fdc00224938b43 |
| tools | ingestGitHubFiles | description | 70bf7038e00c6ec12e79f4acd364c9c578151ff8c44368c872e6ae8f73e4ab6f |
| tools | ingestGitHubFiles | readLimit | 212f13a2013bf40f6409324f1cb6a7f08daeeb4c814f642d2e3360c3cc60506b |
| tools | ingestGitHubFiles | repositoryName | a934c12f952e18238e7a132199211f4f10ec03ff8ac0f83ce8b32c4ee17a15d1 |
| tools | ingestGitHubFiles | repositoryOwner | f6816683827a849aba02e792ace6351695c15d10ef7e6d806e305a652a289f66 |
| tools | ingestGitHubIssues | description | 5d3ecbd72f5f7c0c8c3904a9505e4569dadf09edc55ffbd2a62552e87b1b7bee |
| tools | ingestGitHubIssues | readLimit | 9159a1563d7f18209f3e6f5022aa1a8ec7175b80f8d5236fece099e060ec746c |
| tools | ingestGitHubIssues | repositoryName | a934c12f952e18238e7a132199211f4f10ec03ff8ac0f83ce8b32c4ee17a15d1 |
| tools | ingestGitHubIssues | repositoryOwner | f6816683827a849aba02e792ace6351695c15d10ef7e6d806e305a652a289f66 |
| tools | ingestGoogleDriveFiles | description | 1139c892a798c359a4234714ade94884278b5470ac9c8abbc6329972fb633120 |
| tools | ingestGoogleDriveFiles | folderId | b074bcf129d3cb0ad2970529929368e7193de9856ef6185124aec04c001ebc3e |
| tools | ingestGoogleDriveFiles | readLimit | 212f13a2013bf40f6409324f1cb6a7f08daeeb4c814f642d2e3360c3cc60506b |
| tools | ingestGoogleEmail | description | d3c17afcdaf7858b27c2b8f9d12c054171f70ad0820aff3adc43ebf67eeefd86 |
| tools | ingestGoogleEmail | readLimit | d6f01cc0227dfcc17c5179fe2b60cd5573ebbdaf5649d781e31ddbcf64ed3acf |
| tools | ingestJiraIssues | description | 0863869495cb718c570e3013c540c602ac91e71a8b9e043e6e8f9f33a5a1b99c |
| tools | ingestJiraIssues | projectName | 84e28cc9ba095a3a7177e4be058c154c7600457b3715958c6590ff089e4da0e7 |
| tools | ingestJiraIssues | readLimit | 9159a1563d7f18209f3e6f5022aa1a8ec7175b80f8d5236fece099e060ec746c |
| tools | ingestJiraIssues | url | 5e1bc05ca19b919e8735d316921ab4f507cc32c1fb5e7b81ab6769857e92e2c4 |
| tools | ingestLinearIssues | description | 0040f47486e85a3eb29b3a9edd268e46baab5f8f77fb4f402da3eff7272238e8 |
| tools | ingestLinearIssues | projectName | 7edc3c55082fa51a774c411519b258110537de47dd74b0b523efcaee79095b7c |
| tools | ingestLinearIssues | readLimit | 9159a1563d7f18209f3e6f5022aa1a8ec7175b80f8d5236fece099e060ec746c |
| tools | ingestMemory | description | f39379606fd104c90570706de13e41457103694d70bcc6793d382ed666fffd11 |
| tools | ingestMemory | name | 7c9768be17e7479cbc86ff420c17434fba47f3c8c6781e73b68a1b8a33030a93 |
| tools | ingestMemory | text | cee23ac3a13f2c412f8e095a1e045609bc1b983f757c54a0d0f5a5cbc60c5b4c |
| tools | ingestMemory | textType | 58c576074e5e76a8e7baaf89b6cec57d53d611ae9d98964d33ac2882fb673e17 |
| tools | ingestMemory | timeToLive | 636c3117cd6e0205c088c1041878c95d6f7d9ddcefab72b1d41796bae3dc7c3f |
| tools | ingestMicrosoftEmail | description | a3503340ad800660f664ee841ed8a3d46b328d1dc8e85a4a3377e8c63ac9ca7b |
| tools | ingestMicrosoftEmail | readLimit | d6f01cc0227dfcc17c5179fe2b60cd5573ebbdaf5649d781e31ddbcf64ed3acf |
| tools | ingestMicrosoftTeamsMessages | description | b91a8c97cc75b812c8bc307985a5f38e9393ad0bf7cd3604309650a60bdf2ac2 |
| tools | ingestMicrosoftTeamsMessages | channelId | 269d68b1f9fe0d38fde367010af0553809aad2f9032b6736f6a4d714a5a8134e |
| tools | ingestMicrosoftTeamsMessages | readLimit | c52515d77ec305b6e04c55e0f415ba5b3cadc805247ab7597bfe67f5d5466858 |
| tools | ingestMicrosoftTeamsMessages | teamId | 5cf3e0d26b014ac3c7451d605e71515169bc6c81820d43ee88f3e33834cef57a |
| tools | ingestNotionPages | description | 53a3a59440b7302b92aefdd3d1fe385e450aad0777b368f1a5b667fe71290365 |
| tools | ingestNotionPages | databaseId | d97fbd3fa68f2a7154d86fa9311ed0cc50291bc415192195eb8acfcf84537fd0 |
| tools | ingestNotionPages | readLimit | 784a368c768d1f58e255dee912025626746aca4c7f3ea001854a63bc44929965 |
| tools | ingestOneDriveFiles | description | 4bfcbd85d01b11c2bce54eca52d4c85d5da798e90d573b82eb1025fa401904a8 |
| tools | ingestOneDriveFiles | folderId | ea7d2ca57e1e79d7a6338f1e2fadacba08aea188fb8990dea7da7ba174668fc6 |
| tools | ingestOneDriveFiles | readLimit | 212f13a2013bf40f6409324f1cb6a7f08daeeb4c814f642d2e3360c3cc60506b |
| tools | ingestRSS | description | 24d70c1e706c74fa9f047cb5d9e564a3ae0fd80f8b49c89048d37fd1fda57b76 |
| tools | ingestRSS | readLimit | 3d08185f639a1790566b01cbbfd751a8c545e3eb4db72adb474ceb99bca50325 |
| tools | ingestRSS | url | 8a5f21d8bbefc35b1eebc7e9e8a0eb8d7727ab0942e281fabfda5d7c6af3730f |
| tools | ingestRedditPosts | description | d641adad7aa8b75a9f00a4f67881285e0913400ba7906992739ab20d545ccfb4 |
| tools | ingestRedditPosts | readLimit | 2206b8145edd5b96f8f4879e7183e82903f08bb6c7a575157517fd756c2f5f57 |
| tools | ingestRedditPosts | subredditName | 91758c227fd413ba25adb7f7f0f53549df40e8b2d9b1df0ebf8b0fd1fafa0deb |
| tools | ingestSharePointFiles | description | 63339052712ef662ce9842723ef807aa1bb5161a9420f5707da47765e984f351 |
| tools | ingestSharePointFiles | folderId | bcadca5c610952d9b658c1de40b6591be2692c7d3adc2bc688253a6e49f34632 |
| tools | ingestSharePointFiles | libraryId | d049f22aa3e44ff63b4f3566a6b69bde80bf75a7bb771eff5697967c1adc33cc |
| tools | ingestSharePointFiles | readLimit | 212f13a2013bf40f6409324f1cb6a7f08daeeb4c814f642d2e3360c3cc60506b |
| tools | ingestSlackMessages | description | 8d40117facef286225791fa1bf3aad22a32fcb91d00d6199b9a06e353561255b |
| tools | ingestSlackMessages | channelName | f4469cc35b6b1888cf692786953c82fe76a96fc1b28e272c9b361a1fda107f23 |
| tools | ingestSlackMessages | readLimit | c52515d77ec305b6e04c55e0f415ba5b3cadc805247ab7597bfe67f5d5466858 |
| tools | ingestText | description | 415b21307db54632195b66a43b470a68d9b7f8520ff1f2de70b3f07634dcd53f |
| tools | ingestText | id | d000871bd6049889c5322233c6587868dfa978327d8753dd99d5cb6993fd0b6a |
| tools | ingestText | name | ee62e733f4f067f6c5d8ac8e6acb309bc3a0412da22930f4e2bfdad9498a9b00 |
| tools | ingestText | text | 65bf0627fa5876d8b9abac94e8c53d785e885d45e7a42ef504e9abee2da73149 |
| tools | ingestText | textType | 58c576074e5e76a8e7baaf89b6cec57d53d611ae9d98964d33ac2882fb673e17 |
| tools | ingestTwitterPosts | description | d000b0b74a3c3181520b697b1f862cff06a0e9acfa6010ffd9c311c4f5781f77 |
| tools | ingestTwitterPosts | readLimit | 2206b8145edd5b96f8f4879e7183e82903f08bb6c7a575157517fd756c2f5f57 |
| tools | ingestTwitterPosts | userName | 41fb80535425e6f0c2caf359fa4811a2ba857c59b8267f6d2bda1ca7b61d0986 |
| tools | ingestTwitterSearch | description | a867b478c98a108cbb5e58b55cefe7a9c24dc533632f3d3dc94efc6919e6064b |
| tools | ingestTwitterSearch | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | ingestTwitterSearch | readLimit | 2206b8145edd5b96f8f4879e7183e82903f08bb6c7a575157517fd756c2f5f57 |
| tools | ingestUrl | description | 23801184d27b4e9aab1855c094aba5ae2f24d6b19b18c38b837f9b6bf0068216 |
| tools | ingestUrl | url | 7a32d04a6fc737e51a6eebdd4dc364b23cd11fb53ba378d35f1b4498f5960e82 |
| tools | isContentDone | description | b4ed97ed87460e87d5417392b2eab945d29b54eb18b5516f94110aa22f5a6f25 |
| tools | isContentDone | id | dd8f0409a49357e5b9dff484884b770b5b8bb70751b25da5f540ef9e0c34b40c |
| tools | isFeedDone | description | c3d51893b73427f18b40016526953d61540fe837d6ac0df68526dfe8cef7a2f0 |
| tools | isFeedDone | id | 9555d03f0ff39b49742e4703b8296e0690809208f2d183548e7640bc61e1e349 |
| tools | listLinearProjects | description | 9c244f71037d658a2cdf9a36d42c9ff66e576bcc31c9f32ca2175f6c21b1fc34 |
| tools | listNotionDatabases | description | c30d12285808cee27892b6623d2c40086e580a42b22811f90f44dce51b9ff9f9 |
| tools | listSharePointFolders | description | 10c091a25bcfc0365c53fdd12779d2384ea713bf3e5f71b7ef95ca4c5256b034 |
| tools | listSharePointFolders | libraryId | d049f22aa3e44ff63b4f3566a6b69bde80bf75a7bb771eff5697967c1adc33cc |
| tools | listSharePointLibraries | description | 7d6b081a1fa97c0382d22e1a415f640b4e2408cf1a66c7141c9096b6f1bd2e11 |
| tools | listSlackChannels | description | a3193c161d7e4d285b37c8ac7dda9c9bb408c8d92d712de14ab49ec764594691 |
| tools | promptConversation | description | b4d5d4fc0f3335f85835f68870dea10802859b9ad0ed0f8f07f232b8254ad5c8 |
| tools | promptConversation | conversationId | 5b5915fc136ba58e3750f24f040d2df1ef44cdf8ca561e33dacf12ad89aadd77 |
| tools | promptConversation | prompt | 7284adae5b474c7b90711bbb7991a012bfc49329f59e4b6439142cfb10d39c54 |
| tools | publishAudio | description | 826c89839cd649c714f5059fd4d3611170fc63c2c0db1acdd114196dbd1df90e |
| tools | publishAudio | name | 7c9768be17e7479cbc86ff420c17434fba47f3c8c6781e73b68a1b8a33030a93 |
| tools | publishAudio | text | fa16c6865a774807f55e24e2535249de087da5ab25721a88e601b777e1116183 |
| tools | publishAudio | textType | 58c576074e5e76a8e7baaf89b6cec57d53d611ae9d98964d33ac2882fb673e17 |
| tools | publishAudio | voice | cbe1a8250b265c2b5b99ac2c94fa02d2c6724217cb75998caab6b30560cea00f |
| tools | publishImage | description | b44c31b6c497a36b44974e1af9d8227ddeeef2eee379e546aa870d09bfb511c9 |
| tools | publishImage | count | 31c83dd46ea0adf18a755bdb76bfa11596fabf92be839372cf92d98bb2150865 |
| tools | publishImage | name | 7c9768be17e7479cbc86ff420c17434fba47f3c8c6781e73b68a1b8a33030a93 |
| tools | publishImage | prompt | 5ef83b5a6a3ab5f1a84ac68a4b6c147c6028e82db48cb12744b74b75b0eebd3b |
| tools | queryCollections | description | fc3ab4c3d183b2fa58923e7f5b0e95a90247a1700cee2137e9a32499b35ab03f |
| tools | queryCollections | limit | 92d2a9207e22fa5a26e753df63ef72509c301df25442109918c74071fa77e79a |
| tools | queryCollections | name | cc107237fdeb10a9f04ac5550be4af80145b2b0cd71ee9d259147d698bc64f89 |
| tools | queryContents | description | f2dbdc28a8aa5b3c656035282c7e3094e436e83256e426bfd8fba11a8db8a82c |
| tools | queryContents | collections | c23781254cb16c83e47d3961520e072eb21e5c0a889b13abca87837f4fb0ae4e |
| tools | queryContents | feeds | 1f9404a23ece82cf17d106a7079e4bb851ded1661245ef947022dc63e95bf4ec |
| tools | queryContents | fileType | 6396ed2b193782ce7e079c09c441fc9860bbef6b1dd043d395279c17afee93be |
| tools | queryContents | inLast | 57f4e2789b1ccbc06d8104e441718dc64e91b6d0c9928521dfd68f05fa4d5eb7 |
| tools | queryContents | limit | ad7c35ac33083e319b1a3066224aa62a0bc0974da4507706b2194075afcc5c92 |
| tools | queryContents | location | 3471e29b5c771c839540e1e70f5c49116528d073431956f05f790326d3af6176 |
| tools | queryContents | name | a3f01a58294613359f0c84a56b12fa7520b1ec5d40977abc041549c8ad5236c5 |
| tools | queryContents | query | b2d5e18f98e7168514f1b00d0c5d3e31b981afee7024b44d793a69eea54bcacf |
| tools | queryContents | type | 9d2a5df5fc328e9feae8d67ad30df2c7dcd1767ea5567e08c010e40f6dd80aa2 |
| tools | queryConversations | description | bbe2c22eb641be87575dbf44a6288ab18d4e6e5fd5cf34d7604256af9343db8e |
| tools | queryConversations | inLast | 4754dcc19ac799baa5bb827d64a721ba7c2980fabcdc8d10afb0812b59731d05 |
| tools | queryConversations | limit | 691a4bdedd0383c638e13f0b4c11eaed0f06f90a0ac0e88c5f387eee05a4c628 |
| tools | queryConversations | query | b2d5e18f98e7168514f1b00d0c5d3e31b981afee7024b44d793a69eea54bcacf |
| tools | queryFeeds | description | 7e5aeb5147e3c0eada111d9dec9868ff483a3158a37a1d8c10d2559b0d23a0fd |
| tools | queryFeeds | limit | a2ba3185d1469d57e659d8dffcf3b9ed31a7652afb08dcab5a261a50306415b4 |
| tools | queryFeeds | name | 7cfa59d98131e5c97b34a1971242f19e7b078c4c196915d92b601dcd6e78e36b |
| tools | queryFeeds | type | 219b229e6a49820057dcc9902f605ca86756d1846ed91bd50788239b64855ad8 |
| tools | queryProjectUsage | description | 40f59380a6793d898badd3e2bbea79c528994124605555006b9fca51faf69456 |
| tools | queryProjectUsage | inLast | 9f8e90230187333a0ea2858ac9ec83f9fa116fa92fd1dde230c35e6be33f502f |
| tools | removeContentsFromCollection | description | 256521c843e218eb74b219c269fe7fcf6085f83f5ba4f4c993e7f117c7797bb3 |
| tools | removeContentsFromCollection | contents | 93f3bafd7b9392d81f563c99f91fa1b1fc293cbfefd5b947fa2ef25953c07ff8 |
| tools | removeContentsFromCollection | id | a82d9f8c196801dbc8db82895e52a5a21a788cfbfdb81a128e65a85c76f8e861 |
| tools | retrieveImages | description | 113c2ed8913055c9ae7667699124d07de95152ea84b7c3a3701d2fb83f52a257 |
| tools | retrieveImages | collections | 496ca5b5f72d81bbfa556b360d8e61a09e090658d4519dd6bdff47bc4c1df296 |
| tools | retrieveImages | feeds | 5820a6f223af26a3367c91be822799fa005de8dc2c2f1b1ca5d08ee13b9c6091 |
| tools | retrieveImages | inLast | 16043484d2226bc07c8a6a221361d9a591a8971c05267bea13c78578d9288ad6 |
| tools | retrieveImages | limit | 8d66357f0ba6d5cb175f4c9ddb2cfcf66a556594b1f1ee37e5ca639e80f6b9b9 |
| tools | retrieveImages | location | 3471e29b5c771c839540e1e70f5c49116528d073431956f05f790326d3af6176 |
| tools | retrieveImages | url | 326034d459f27a2da5eec1d7b76ac93859eef1f7c7724f3ae87b113a039f66d3 |
| tools | retrieveSources | description | a33b2dbb4558b820d583a3a38718eb99a3f89e2367a4198ebb9f6b003d168776 |
| tools | retrieveSources | collections | 5082e01c6e67c2114dbb8a2a4d8747d9b65de52539900e1337c8b631262dfdbb |
| tools | retrieveSources | feeds | 9d54a77e0af708378eb5085e3003a2ae50f452ad403ef0ce91f9a94375ef698d |
| tools | retrieveSources | fileType | 80c9decd868418c43303471e6d5509926b2453483930bd4e4e90b34539aa0e9c |
| tools | retrieveSources | inLast | 57f4e2789b1ccbc06d8104e441718dc64e91b6d0c9928521dfd68f05fa4d5eb7 |
| tools | retrieveSources | prompt | 25b20e4ec5f4240c69336b7351a7b0d066a708205aebeabeb9fa48de45bf6e1a |
| tools | retrieveSources | type | d4ab74902f53a99a5136dd8eae836fc42c1f79ff26bc83235b0fd0b7ffd6182c |
| tools | screenshotPage | description | 2e621a1dd62db6fdec22d4730693035b00ed5cd807ccb15ff8b6f62f7e436a1e |
| tools | screenshotPage | url | a447285fe6a2ef840465c28c877b37cddfa9e0b7dcb78ffa1ffcf3efa0568179 |
| tools | sendEmailNotification | description | 2aec7d6ff64c4ffd5147a35e01346a6b8b6a302927f0a4686130b665ff22a075 |
| tools | sendEmailNotification | subject | 61b2ae8ab45fe142a633a8f2ec4216bd0dae2d28d0ff6d5caf501165f2e04816 |
| tools | sendEmailNotification | text | 58994a663390b125a0603abab3a174668916435d78a8ee4237fec325944ec631 |
| tools | sendEmailNotification | textType | 58c576074e5e76a8e7baaf89b6cec57d53d611ae9d98964d33ac2882fb673e17 |
| tools | sendEmailNotification | to | db1ba15a409b79b934b3cca58c35531c0be3d06cbab8c2c8be56aec19e0e4fa7 |
| tools | sendSlackNotification | description | e3b0497914d28a4af75a91ddbcc0a87840832985d16527ca27572ecd6ae48488 |
| tools | sendSlackNotification | channelName | f4469cc35b6b1888cf692786953c82fe76a96fc1b28e272c9b361a1fda107f23 |
| tools | sendSlackNotification | text | 58994a663390b125a0603abab3a174668916435d78a8ee4237fec325944ec631 |
| tools | sendSlackNotification | textType | 58c576074e5e76a8e7baaf89b6cec57d53d611ae9d98964d33ac2882fb673e17 |
| tools | sendTwitterNotification | description | e56fefc00cd317e7ba44c5cf95f072fe75738e0084dae2518d085c4dacea742a |
| tools | sendTwitterNotification | text | 58994a663390b125a0603abab3a174668916435d78a8ee4237fec325944ec631 |
| tools | sendWebHookNotification | description | 4252d34a72b6231aa23205afcab8208c463a75729549ad49fb48088577529261 |
| tools | sendWebHookNotification | text | 58994a663390b125a0603abab3a174668916435d78a8ee4237fec325944ec631 |
| tools | sendWebHookNotification | textType | 58c576074e5e76a8e7baaf89b6cec57d53d611ae9d98964d33ac2882fb673e17 |
| tools | sendWebHookNotification | url | 1f058130d701b83c622485416d52c88cace8a4fd618b917c057a90e7d32ff295 |
| tools | webCrawl | description | eea1cb7951355dd38c9568a2a89b80788ba97663acc255270b249cb473808e15 |
| tools | webCrawl | readLimit | c60a76969b312773ac25a22c406f550ed28f8ca588652d7de76b79e380a5b296 |
| tools | webCrawl | url | 82301c9879a2bd12c6a7e14d17902d8ede45bbb19abe38907cefb0be69c78c52 |
| tools | webMap | description | c4d940b54759c10cff5cc22375234c595cb2de9a786718c94139d51f33957f7a |
| tools | webMap | url | 82301c9879a2bd12c6a7e14d17902d8ede45bbb19abe38907cefb0be69c78c52 |
| tools | webSearch | description | 08fbd6292e1280c788b5f30929d74295b7a15bb471fccc3f1e19e5b6eaf144f2 |
| tools | webSearch | limit | 36e925df434ec2827ed9e5c43f8c6553c1e21103eda586e742c712b38b8a1caa |
| tools | webSearch | query | b2d5e18f98e7168514f1b00d0c5d3e31b981afee7024b44d793a69eea54bcacf |
| tools | webSearch | searchService | 09313f5cb737c5e7be7a7c6a023d0d143c626b4f1b570741dc2a0f0df91d50e1 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
