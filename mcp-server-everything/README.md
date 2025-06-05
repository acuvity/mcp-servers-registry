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


# What is mcp-server-everything?
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-everything/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-everything/2025.5.12?logo=docker&logoColor=fff&label=2025.5.12)](https://hub.docker.com/r/acuvity/mcp-server-everything)
[![PyPI](https://img.shields.io/badge/2025.5.12-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-everything)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-everything/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-everything&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-everything%3A2025.5.12%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server that exercises all the features of the MCP protocol

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @modelcontextprotocol/server-everything original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-everything/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/charts/mcp-server-everything/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-everything run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-everything scope of operation it can be hosted anywhere.

For more information and extra configuration you can consult the [package](https://modelcontextprotocol.io) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-everything&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-everything%3A2025.5.12%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-everything": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-everything:2025.5.12"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2025.5.12"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2025.5.12"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2025.5.12"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2025.5.12"
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
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-everything:2025.5.12"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-everything:2025.5.12`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-everything:2025.5.12
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-everything": {
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
    "acuvity-mcp-server-everything": {
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

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
````

Install with helm

```console
helm install mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
```

From there your MCP server mcp-server-everything will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-everything` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/charts/mcp-server-everything/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>echo</summary>

**Description**:

```
Echoes back the input
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | Message to echo | Yes
</details>
<details>
<summary>add</summary>

**Description**:

```
Adds two numbers
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| a | number | First number | Yes
| b | number | Second number | Yes
</details>
<details>
<summary>printEnv</summary>

**Description**:

```
Prints all environment variables, helpful for debugging MCP server configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>longRunningOperation</summary>

**Description**:

```
Demonstrates a long running operation with progress updates
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration | number | Duration of the operation in seconds | No
| steps | number | Number of steps in the operation | No
</details>
<details>
<summary>sampleLLM</summary>

**Description**:

```
Samples from an LLM using MCP's sampling feature
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxTokens | number | Maximum number of tokens to generate | No
| prompt | string | The prompt to send to the LLM | Yes
</details>
<details>
<summary>getTinyImage</summary>

**Description**:

```
Returns the MCP_TINY_IMAGE
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>annotatedMessage</summary>

**Description**:

```
Demonstrates how annotations can be used to provide metadata about content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeImage | boolean | Whether to include an example image | No
| messageType | string | Type of message to demonstrate different annotation patterns | Yes
</details>
<details>
<summary>getResourceReference</summary>

**Description**:

```
Returns a resource reference that can be used by MCP clients
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resourceId | number | ID of the resource to reference (1-100) | Yes
</details>

## 📚 Resources (100)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Resource 1 | text/plain | test://static/resource/1 | - |
| Resource 2 | application/octet-stream | test://static/resource/2 | - |
| Resource 3 | text/plain | test://static/resource/3 | - |
| Resource 4 | application/octet-stream | test://static/resource/4 | - |
| Resource 5 | text/plain | test://static/resource/5 | - |
| Resource 6 | application/octet-stream | test://static/resource/6 | - |
| Resource 7 | text/plain | test://static/resource/7 | - |
| Resource 8 | application/octet-stream | test://static/resource/8 | - |
| Resource 9 | text/plain | test://static/resource/9 | - |
| Resource 10 | application/octet-stream | test://static/resource/10 | - |
| Resource 11 | text/plain | test://static/resource/11 | - |
| Resource 12 | application/octet-stream | test://static/resource/12 | - |
| Resource 13 | text/plain | test://static/resource/13 | - |
| Resource 14 | application/octet-stream | test://static/resource/14 | - |
| Resource 15 | text/plain | test://static/resource/15 | - |
| Resource 16 | application/octet-stream | test://static/resource/16 | - |
| Resource 17 | text/plain | test://static/resource/17 | - |
| Resource 18 | application/octet-stream | test://static/resource/18 | - |
| Resource 19 | text/plain | test://static/resource/19 | - |
| Resource 20 | application/octet-stream | test://static/resource/20 | - |
| Resource 21 | text/plain | test://static/resource/21 | - |
| Resource 22 | application/octet-stream | test://static/resource/22 | - |
| Resource 23 | text/plain | test://static/resource/23 | - |
| Resource 24 | application/octet-stream | test://static/resource/24 | - |
| Resource 25 | text/plain | test://static/resource/25 | - |
| Resource 26 | application/octet-stream | test://static/resource/26 | - |
| Resource 27 | text/plain | test://static/resource/27 | - |
| Resource 28 | application/octet-stream | test://static/resource/28 | - |
| Resource 29 | text/plain | test://static/resource/29 | - |
| Resource 30 | application/octet-stream | test://static/resource/30 | - |
| Resource 31 | text/plain | test://static/resource/31 | - |
| Resource 32 | application/octet-stream | test://static/resource/32 | - |
| Resource 33 | text/plain | test://static/resource/33 | - |
| Resource 34 | application/octet-stream | test://static/resource/34 | - |
| Resource 35 | text/plain | test://static/resource/35 | - |
| Resource 36 | application/octet-stream | test://static/resource/36 | - |
| Resource 37 | text/plain | test://static/resource/37 | - |
| Resource 38 | application/octet-stream | test://static/resource/38 | - |
| Resource 39 | text/plain | test://static/resource/39 | - |
| Resource 40 | application/octet-stream | test://static/resource/40 | - |
| Resource 41 | text/plain | test://static/resource/41 | - |
| Resource 42 | application/octet-stream | test://static/resource/42 | - |
| Resource 43 | text/plain | test://static/resource/43 | - |
| Resource 44 | application/octet-stream | test://static/resource/44 | - |
| Resource 45 | text/plain | test://static/resource/45 | - |
| Resource 46 | application/octet-stream | test://static/resource/46 | - |
| Resource 47 | text/plain | test://static/resource/47 | - |
| Resource 48 | application/octet-stream | test://static/resource/48 | - |
| Resource 49 | text/plain | test://static/resource/49 | - |
| Resource 50 | application/octet-stream | test://static/resource/50 | - |
| Resource 51 | text/plain | test://static/resource/51 | - |
| Resource 52 | application/octet-stream | test://static/resource/52 | - |
| Resource 53 | text/plain | test://static/resource/53 | - |
| Resource 54 | application/octet-stream | test://static/resource/54 | - |
| Resource 55 | text/plain | test://static/resource/55 | - |
| Resource 56 | application/octet-stream | test://static/resource/56 | - |
| Resource 57 | text/plain | test://static/resource/57 | - |
| Resource 58 | application/octet-stream | test://static/resource/58 | - |
| Resource 59 | text/plain | test://static/resource/59 | - |
| Resource 60 | application/octet-stream | test://static/resource/60 | - |
| Resource 61 | text/plain | test://static/resource/61 | - |
| Resource 62 | application/octet-stream | test://static/resource/62 | - |
| Resource 63 | text/plain | test://static/resource/63 | - |
| Resource 64 | application/octet-stream | test://static/resource/64 | - |
| Resource 65 | text/plain | test://static/resource/65 | - |
| Resource 66 | application/octet-stream | test://static/resource/66 | - |
| Resource 67 | text/plain | test://static/resource/67 | - |
| Resource 68 | application/octet-stream | test://static/resource/68 | - |
| Resource 69 | text/plain | test://static/resource/69 | - |
| Resource 70 | application/octet-stream | test://static/resource/70 | - |
| Resource 71 | text/plain | test://static/resource/71 | - |
| Resource 72 | application/octet-stream | test://static/resource/72 | - |
| Resource 73 | text/plain | test://static/resource/73 | - |
| Resource 74 | application/octet-stream | test://static/resource/74 | - |
| Resource 75 | text/plain | test://static/resource/75 | - |
| Resource 76 | application/octet-stream | test://static/resource/76 | - |
| Resource 77 | text/plain | test://static/resource/77 | - |
| Resource 78 | application/octet-stream | test://static/resource/78 | - |
| Resource 79 | text/plain | test://static/resource/79 | - |
| Resource 80 | application/octet-stream | test://static/resource/80 | - |
| Resource 81 | text/plain | test://static/resource/81 | - |
| Resource 82 | application/octet-stream | test://static/resource/82 | - |
| Resource 83 | text/plain | test://static/resource/83 | - |
| Resource 84 | application/octet-stream | test://static/resource/84 | - |
| Resource 85 | text/plain | test://static/resource/85 | - |
| Resource 86 | application/octet-stream | test://static/resource/86 | - |
| Resource 87 | text/plain | test://static/resource/87 | - |
| Resource 88 | application/octet-stream | test://static/resource/88 | - |
| Resource 89 | text/plain | test://static/resource/89 | - |
| Resource 90 | application/octet-stream | test://static/resource/90 | - |
| Resource 91 | text/plain | test://static/resource/91 | - |
| Resource 92 | application/octet-stream | test://static/resource/92 | - |
| Resource 93 | text/plain | test://static/resource/93 | - |
| Resource 94 | application/octet-stream | test://static/resource/94 | - |
| Resource 95 | text/plain | test://static/resource/95 | - |
| Resource 96 | application/octet-stream | test://static/resource/96 | - |
| Resource 97 | text/plain | test://static/resource/97 | - |
| Resource 98 | application/octet-stream | test://static/resource/98 | - |
| Resource 99 | text/plain | test://static/resource/99 | - |
| Resource 100 | application/octet-stream | test://static/resource/100 | - |

</details>

## 📝 Prompts (3)
<details>
<summary>simple_prompt</summary>

**Description**:

```
A prompt without arguments
```
<details>
<summary>complex_prompt</summary>

**Description**:

```
A prompt with arguments
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| temperature | Temperature setting |Yes |
| style | Output style |No |
<details>
<summary>resource_prompt</summary>

**Description**:

```
A prompt that includes an embedded resource reference
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| resourceId | Resource ID to include (1-100) |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | complex_prompt | description | 09b401289593b83e9904a308f5f25490bdf350b411a5c0704c2b809d0e1617ca |
| prompts | complex_prompt | style | f2e0e00a539e768a78c725148346c3b6c05beaa30157b103ce978e263381c4ba |
| prompts | complex_prompt | temperature | 15a255689d20cdae7535538cd0e874bba74ae5a398cda49bcd47b9301abf7b25 |
| prompts | resource_prompt | description | 485a9a963ffe2b74994e89a2ac741dc26ef7656974ba85d6e1a8fba8472adaca |
| prompts | resource_prompt | resourceId | 1c5b7ee8d6755c3d34e32b2f8ef08d51cf7270d762759795aa86e158a488a824 |
| prompts | simple_prompt | description | 388feeee3ff98cdb53b9fa774fe7e58b502a74241ccb5f4635160acf777ea5fb |
| tools | add | description | 1efcb1f3567517e507fe44f6853681a389c3ac9ec493ea45f8e0da09b2d6aaf8 |
| tools | add | a | 4d238256ad692183f3c2e945213eac5ae9e86bce06e6989360af210cae8751f4 |
| tools | add | b | c079e9787b04a05e7e4dd561a044bce326711ebc3f0c90160f33823530da93d3 |
| tools | annotatedMessage | description | c64e27024ec7adde221d1172fc30350a16cc89e948dee762bda74904f5bc9358 |
| tools | annotatedMessage | includeImage | 3f577041e74ad35132f1242ae17815ed70e39bad9533b717021987963f8abb27 |
| tools | annotatedMessage | messageType | 48ca223484fb0957dc6efa4920a79cc385ab419c7c3af0309e8acb4784c58d0d |
| tools | echo | description | befddbd2f7f4e08645d4777c5722d61db17d56a0115f5c9bdb19577e865a299b |
| tools | echo | message | 2aa7ac486933d92f1de28d4b527088a577a0fe0ad5d33c0c36c1d122fc8477ba |
| tools | getResourceReference | description | f65488ea8977f68a7680a0ba04efa98d742a3007664649c9e00899f43f1d89de |
| tools | getResourceReference | resourceId | babe671d40822849f662adcd0a04271ed201dc3849256f46bd5e721e0c752a69 |
| tools | getTinyImage | description | e05d66ca9c64728b0a6bb482363447a84c28caffab8df5c51e604876fd30b6fb |
| tools | longRunningOperation | description | 56b51dc5e58071626c7d2658ccc5f1e252cbc9cae02a03d228fbb82ca57d5562 |
| tools | longRunningOperation | duration | 611a5d1b6734296bafe76d21bca6f9c984b30ae9cf9921554c4440d26b7ea431 |
| tools | longRunningOperation | steps | 70c271e49e3c4217d398f502fda4be342f73aa5875a69b7f59fc749564181707 |
| tools | printEnv | description | 20b7f527310a05a74c119c317a418b8bb4d388fe182e2e4574758be98f06d06f |
| tools | sampleLLM | description | 585d6f5a9315c93685cfc6daa069743de7a0b05e1a055e593cb413d2dd466363 |
| tools | sampleLLM | maxTokens | 877bc91aff3481950f61058439e2f8d8e4a15e3cfa9d1f031c94e945ba2d516e |
| tools | sampleLLM | prompt | 472f849bc61d2fc5c70dac589c4cab3ee7ed1800fbc61dc1c78ba30546c40e95 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
