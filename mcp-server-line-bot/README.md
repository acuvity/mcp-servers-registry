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


# What is mcp-server-line-bot?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-line-bot/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-line-bot/0.3.0?logo=docker&logoColor=fff&label=0.3.0)](https://hub.docker.com/r/acuvity/mcp-server-line-bot)
[![PyPI](https://img.shields.io/badge/0.3.0-3775A9?logo=pypi&logoColor=fff&label=@line/line-bot-mcp-server)](https://github.com/line/line-bot-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-line-bot/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-line-bot&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHANNEL_ACCESS_TOKEN%22%2C%22-e%22%2C%22DESTINATION_USER_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-line-bot%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connects AI Agent to LINE for messaging interactions.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @line/line-bot-mcp-server original [sources](https://github.com/line/line-bot-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-line-bot/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/charts/mcp-server-line-bot/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @line/line-bot-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-line-bot scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `CHANNEL_ACCESS_TOKEN` required to be set
  - `DESTINATION_USER_ID` required to be set

For more information and extra configuration you can consult the [package](https://github.com/line/line-bot-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-line-bot&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHANNEL_ACCESS_TOKEN%22%2C%22-e%22%2C%22DESTINATION_USER_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-line-bot%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-line-bot": {
        "env": {
          "CHANNEL_ACCESS_TOKEN": "TO_BE_SET",
          "DESTINATION_USER_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "CHANNEL_ACCESS_TOKEN",
          "-e",
          "DESTINATION_USER_ID",
          "docker.io/acuvity/mcp-server-line-bot:0.3.0"
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
    "acuvity-mcp-server-line-bot": {
      "env": {
        "CHANNEL_ACCESS_TOKEN": "TO_BE_SET",
        "DESTINATION_USER_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHANNEL_ACCESS_TOKEN",
        "-e",
        "DESTINATION_USER_ID",
        "docker.io/acuvity/mcp-server-line-bot:0.3.0"
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
    "acuvity-mcp-server-line-bot": {
      "env": {
        "CHANNEL_ACCESS_TOKEN": "TO_BE_SET",
        "DESTINATION_USER_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHANNEL_ACCESS_TOKEN",
        "-e",
        "DESTINATION_USER_ID",
        "docker.io/acuvity/mcp-server-line-bot:0.3.0"
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
    "acuvity-mcp-server-line-bot": {
      "env": {
        "CHANNEL_ACCESS_TOKEN": "TO_BE_SET",
        "DESTINATION_USER_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHANNEL_ACCESS_TOKEN",
        "-e",
        "DESTINATION_USER_ID",
        "docker.io/acuvity/mcp-server-line-bot:0.3.0"
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
    "acuvity-mcp-server-line-bot": {
      "env": {
        "CHANNEL_ACCESS_TOKEN": "TO_BE_SET",
        "DESTINATION_USER_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHANNEL_ACCESS_TOKEN",
        "-e",
        "DESTINATION_USER_ID",
        "docker.io/acuvity/mcp-server-line-bot:0.3.0"
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
        "env": {"CHANNEL_ACCESS_TOKEN":"TO_BE_SET","DESTINATION_USER_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","CHANNEL_ACCESS_TOKEN","-e","DESTINATION_USER_ID","docker.io/acuvity/mcp-server-line-bot:0.3.0"]
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
- arguments: `run -i --rm --read-only -e CHANNEL_ACCESS_TOKEN -e DESTINATION_USER_ID docker.io/acuvity/mcp-server-line-bot:0.3.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e CHANNEL_ACCESS_TOKEN -e DESTINATION_USER_ID docker.io/acuvity/mcp-server-line-bot:0.3.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-line-bot": {
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
    "acuvity-mcp-server-line-bot": {
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
  - `CHANNEL_ACCESS_TOKEN` secret to be set as secrets.CHANNEL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`
  - `DESTINATION_USER_ID` secret to be set as secrets.DESTINATION_USER_ID either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
````

Install with helm

```console
helm install mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
```

From there your MCP server mcp-server-line-bot will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-line-bot` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/charts/mcp-server-line-bot/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>push_text_message</summary>

**Description**:

```
Push a simple text message to a user via LINE. Use this for sending plain text messages without formatting.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
| userId | string | The user ID to receive a message. Defaults to DESTINATION_USER_ID. | No
</details>
<details>
<summary>push_flex_message</summary>

**Description**:

```
Push a highly customizable flex message to a user via LINE. Supports both bubble (single container) and carousel (multiple swipeable bubbles) layouts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
| userId | string | The user ID to receive a message. Defaults to DESTINATION_USER_ID. | No
</details>
<details>
<summary>broadcast_text_message</summary>

**Description**:

```
Broadcast a simple text message via LINE to all users who have followed your LINE Official Account. Use this for sending plain text messages without formatting. Please be aware that this message will be sent to all users.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
</details>
<details>
<summary>broadcast_flex_message</summary>

**Description**:

```
Broadcast a highly customizable flex message via LINE to all users who have added your LINE Official Account. Supports both bubble (single container) and carousel (multiple swipeable bubbles) layouts. Please be aware that this message will be sent to all users.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
</details>
<details>
<summary>get_profile</summary>

**Description**:

```
Get detailed profile information of a LINE user including display name, profile picture URL, status message and language.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| userId | string | The user ID to get a profile. Defaults to DESTINATION_USER_ID. | No
</details>
<details>
<summary>get_message_quota</summary>

**Description**:

```
Get the message quota and consumption of the LINE Official Account. This shows the monthly message limit and current usage.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_rich_menu_list</summary>

**Description**:

```
Get the list of rich menus associated with your LINE Official Account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>delete_rich_menu</summary>

**Description**:

```
Delete a rich menu from your LINE Official Account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| richMenuId | string | The ID of the rich menu to delete. | Yes
</details>
<details>
<summary>set_rich_menu_default</summary>

**Description**:

```
Set a rich menu as the default rich menu.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| richMenuId | string | The ID of the rich menu to set as default. | Yes
</details>
<details>
<summary>cancel_rich_menu_default</summary>

**Description**:

```
Cancel the default rich menu.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | broadcast_flex_message | description | 375ffde87d672553fec772b66a897b10465d90cd26fa546489090ccc3ba88c74 |
| tools | broadcast_text_message | description | 6a7cee7032cbb044108c51358ff821abf09938c87a00c6f9ef9df70f848fdc91 |
| tools | cancel_rich_menu_default | description | 5665fffb4bd328740228f593ceaa04b8838575e8489c1b9db3eebf27eefa9993 |
| tools | delete_rich_menu | description | 9354a24cd221401fe051d2738db054192319efb3b6d293f348cf5e9a27a3e434 |
| tools | delete_rich_menu | richMenuId | 2d411290063b03c03efe1a704b011a2391040b3f116a1acde421819cb9327c8e |
| tools | get_message_quota | description | 9edfcab24cb244f0063332ca4117ffed55fb8de1b61c2735079b8bd5bfad0634 |
| tools | get_profile | description | 35f893ef7edcac5026b3bd2f7d5b9953827b7ad6484a2ec2d63e94dd5872625a |
| tools | get_profile | userId | ab51e75da45824d3fdaf17ed8b9a48dd5790587d762fafabfb91d93b7e28fb45 |
| tools | get_rich_menu_list | description | 615b67d830bc1ad3702a55c10fbf5317854b49be42b7dcf7d6ff0860bd8b950f |
| tools | push_flex_message | description | 3f7f8a97ee448ca4c7467dfb44ce2476225ae1d5e66dce76a1dd5e1591cc77ae |
| tools | push_flex_message | userId | ae3ba3776baad8eeb0f3eb9d13eaecf069294ebbff803dd13f7a7f1557cb04e4 |
| tools | push_text_message | description | 65e328795468a461ca52572caddd9320ef1afb238961594dcc04a122e73a5d1c |
| tools | push_text_message | userId | ae3ba3776baad8eeb0f3eb9d13eaecf069294ebbff803dd13f7a7f1557cb04e4 |
| tools | set_rich_menu_default | description | 0b133223247370c03fbd51ef4881660aa52ce6326e76bb2d689b123a12df36d5 |
| tools | set_rich_menu_default | richMenuId | f42e7823d6c9a7c04afafce460535cca4bbd2912680aefb43095a669105b99df |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
