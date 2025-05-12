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


# What is mcp-server-slack?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-slack/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-slack/2025.4.25?logo=docker&logoColor=fff&label=2025.4.25)](https://hub.docker.com/r/acuvity/mcp-server-slack)
[![PyPI](https://img.shields.io/badge/2025.4.25-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-slack)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-slack&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22SLACK_BOT_TOKEN%22%2C%22-e%22%2C%22SLACK_TEAM_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-slack%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with Slack

Packaged by Acuvity from @modelcontextprotocol/server-slack original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-slack/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/charts/mcp-server-slack/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-slack run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/charts/mcp-server-slack#minibridge) for Helm charts).


# 📦 How to Install


> [!TIP]
> Given mcp-server-slack scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-slack&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22SLACK_BOT_TOKEN%22%2C%22-e%22%2C%22SLACK_TEAM_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-slack%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-slack": {
        "env": {
          "SLACK_BOT_TOKEN": "TO_BE_SET",
          "SLACK_TEAM_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "SLACK_BOT_TOKEN",
          "-e",
          "SLACK_TEAM_ID",
          "docker.io/acuvity/mcp-server-slack:2025.4.25"
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
    "acuvity-mcp-server-slack": {
      "env": {
        "SLACK_BOT_TOKEN": "TO_BE_SET",
        "SLACK_TEAM_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "SLACK_BOT_TOKEN",
        "-e",
        "SLACK_TEAM_ID",
        "docker.io/acuvity/mcp-server-slack:2025.4.25"
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
    "acuvity-mcp-server-slack": {
      "env": {
        "SLACK_BOT_TOKEN": "TO_BE_SET",
        "SLACK_TEAM_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "SLACK_BOT_TOKEN",
        "-e",
        "SLACK_TEAM_ID",
        "docker.io/acuvity/mcp-server-slack:2025.4.25"
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
    "acuvity-mcp-server-slack": {
      "env": {
        "SLACK_BOT_TOKEN": "TO_BE_SET",
        "SLACK_TEAM_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "SLACK_BOT_TOKEN",
        "-e",
        "SLACK_TEAM_ID",
        "docker.io/acuvity/mcp-server-slack:2025.4.25"
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
    "acuvity-mcp-server-slack": {
      "env": {
        "SLACK_BOT_TOKEN": "TO_BE_SET",
        "SLACK_TEAM_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "SLACK_BOT_TOKEN",
        "-e",
        "SLACK_TEAM_ID",
        "docker.io/acuvity/mcp-server-slack:2025.4.25"
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
        "env": {"SLACK_BOT_TOKEN":"TO_BE_SET","SLACK_TEAM_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","SLACK_BOT_TOKEN","-e","SLACK_TEAM_ID","docker.io/acuvity/mcp-server-slack:2025.4.25"]
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
  - `SLACK_BOT_TOKEN` required to be set
  - `SLACK_TEAM_ID` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e SLACK_BOT_TOKEN -e SLACK_TEAM_ID docker.io/acuvity/mcp-server-slack:2025.4.25`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e SLACK_BOT_TOKEN -e SLACK_TEAM_ID docker.io/acuvity/mcp-server-slack:2025.4.25
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-slack": {
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
    "acuvity-mcp-server-slack": {
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
  - `SLACK_BOT_TOKEN` secret to be set as secrets.SLACK_BOT_TOKEN either by `.value` or from existing with `.valueFrom`
  - `SLACK_TEAM_ID` secret to be set as secrets.SLACK_TEAM_ID either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-slack --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-slack --version 1.0.0
````

Install with helm

```console
helm install mcp-server-slack oci://docker.io/acuvity/mcp-server-slack --version 1.0.0
```

From there your MCP server mcp-server-slack will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-slack` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/charts/mcp-server-slack/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>slack_list_channels</summary>

**Description**:

```
List public or pre-defined channels in the workspace with pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Pagination cursor for next page of results | No
| limit | number | Maximum number of channels to return (default 100, max 200) | No
</details>
<details>
<summary>slack_post_message</summary>

**Description**:

```
Post a new message to a Slack channel
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel to post to | Yes
| text | string | The message text to post | Yes
</details>
<details>
<summary>slack_reply_to_thread</summary>

**Description**:

```
Reply to a specific message thread in Slack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel containing the thread | Yes
| text | string | The reply text | Yes
| thread_ts | string | The timestamp of the parent message in the format '1234567890.123456'. Timestamps in the format without the period can be converted by adding the period such that 6 numbers come after it. | Yes
</details>
<details>
<summary>slack_add_reaction</summary>

**Description**:

```
Add a reaction emoji to a message
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel containing the message | Yes
| reaction | string | The name of the emoji reaction (without ::) | Yes
| timestamp | string | The timestamp of the message to react to | Yes
</details>
<details>
<summary>slack_get_channel_history</summary>

**Description**:

```
Get recent messages from a channel
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel | Yes
| limit | number | Number of messages to retrieve (default 10) | No
</details>
<details>
<summary>slack_get_thread_replies</summary>

**Description**:

```
Get all replies in a message thread
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel containing the thread | Yes
| thread_ts | string | The timestamp of the parent message in the format '1234567890.123456'. Timestamps in the format without the period can be converted by adding the period such that 6 numbers come after it. | Yes
</details>
<details>
<summary>slack_get_users</summary>

**Description**:

```
Get a list of all users in the workspace with their basic profile information
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Pagination cursor for next page of results | No
| limit | number | Maximum number of users to return (default 100, max 200) | No
</details>
<details>
<summary>slack_get_user_profile</summary>

**Description**:

```
Get detailed profile information for a specific user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user_id | string | The ID of the user | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | slack_add_reaction | description | 1f62c0d2156feeea70ab2bb08899b0eea724921708ef1f842d5a3274b8a42242 |
| tools | slack_add_reaction | channel_id | 83651ca4b8296fa718d4acdfeb6cae2c112c95a79d72305e997bf788de804f4f |
| tools | slack_add_reaction | reaction | dde7c05968061cac6874c1977ced5368e35ef7faf132ecbe4581e793abf9ba7d |
| tools | slack_add_reaction | timestamp | 6bf125bd35ca506a4fcdde9d16cda3475862d295770c69c704fe5e21a62397de |
| tools | slack_get_channel_history | description | b43638ece46444f140ef4ee2bcc7361a2a2e45234c3bd1d02b08a2a6562d3bd8 |
| tools | slack_get_channel_history | channel_id | 73a4a19c15485e6ad000420b9a6f6520294a9f79e68febad4f62f408c5243e5b |
| tools | slack_get_channel_history | limit | 4054928c311253594c8a19a24c514c4a702aa5da1f8109f514e7340cd6c3a043 |
| tools | slack_get_thread_replies | description | f25a9302b989e9d86f701d431e0e5dfce1cf769429eea022e7f13e22888d93cf |
| tools | slack_get_thread_replies | channel_id | c8d1977d3c00d46ff3c2f206a9d17540dc173cf435ab4ad2a0fcbbaa53174b98 |
| tools | slack_get_thread_replies | thread_ts | e7d2dff0b6b5d4cb27ad3c927afc91e9bf54e44f67468519d23e81625423645f |
| tools | slack_get_user_profile | description | 24e26221d8494e92eee5dfd7c12e4ec57595f985c5873c89b2885cd5f1154b59 |
| tools | slack_get_user_profile | user_id | f0e13cca2694f31a174eb5bb798a4b5b187952d31bad9d14bcb1167d057e24f0 |
| tools | slack_get_users | description | 064d8ff96ee3ebc5262414bcf8d7a3569e50309fa1f47c86e8a504bd380a1bb9 |
| tools | slack_get_users | cursor | af663f140c35780ea36be96fa602b310c84c5373bd95d8f7e98e2fdb474d5061 |
| tools | slack_get_users | limit | a0f951f54f777c4126ec2111eeb7387dddd999ace45b68d2ba653a89f25d8db2 |
| tools | slack_list_channels | description | 20dcdc291e18a09e8ac35a4335082ec4394a452d18cfff2626d5a57158ef234b |
| tools | slack_list_channels | cursor | af663f140c35780ea36be96fa602b310c84c5373bd95d8f7e98e2fdb474d5061 |
| tools | slack_list_channels | limit | fa1df8a77e411a4caea75403c307b517794b232c64c461f5d72b2ba2aed7755e |
| tools | slack_post_message | description | d105b99a6bf981dd4dd7cde32c4b8d33778f41b55d598babca8eba58e0897708 |
| tools | slack_post_message | channel_id | 0160eabae43220452e6637867cbf32654460cdc34924d4c5181e600a08adc2c5 |
| tools | slack_post_message | text | c8aa0df1dbb20587482804936252b53a17db6330c1e42a8889aaeb687ca40a33 |
| tools | slack_reply_to_thread | description | a304e8edbaf0870a55d4d3c33ca6433ddd6ed10eae67ba538ce678da6a520c3a |
| tools | slack_reply_to_thread | channel_id | c8d1977d3c00d46ff3c2f206a9d17540dc173cf435ab4ad2a0fcbbaa53174b98 |
| tools | slack_reply_to_thread | text | 63318714e118e032285fa4f42f874e1b848ce97f3c96b0b429c88bcc3d68e4a3 |
| tools | slack_reply_to_thread | thread_ts | e7d2dff0b6b5d4cb27ad3c927afc91e9bf54e44f67468519d23e81625423645f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
