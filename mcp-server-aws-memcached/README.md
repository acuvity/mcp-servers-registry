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


# What is mcp-server-aws-memcached?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-memcached/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-memcached/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-aws-memcached)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=awslabs.memcached-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-memcached/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-memcached&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22MEMCACHED_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-memcached%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with Amazon ElastiCache Memcached through secure connections

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.memcached-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-memcached/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/charts/mcp-server-aws-memcached/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.memcached-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-aws-memcached scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `MEMCACHED_HOST` required to be set
  - `MEMCACHED_PORT` optional (11211)
  - `MEMCACHED_TIMEOUT` optional (1)
  - `MEMCACHED_CONNECT_TIMEOUT` optional (5)
  - `MEMCACHED_RETRY_TIMEOUT` optional (1)
  - `MEMCACHED_MAX_RETRIES` optional (3)
  - `MEMCACHED_USE_TLS` optional (not set)
  - `MEMCACHED_TLS_CERT_PATH` optional (not set)
  - `MEMCACHED_TLS_KEY_PATH` optional (not set)
  - `MEMCACHED_TLS_CA_CERT_PATH` optional (not set)
  - `MEMCACHED_TLS_VERIFY` optional (true)

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-memcached&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22MEMCACHED_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-memcached%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-memcached": {
        "env": {
          "MEMCACHED_HOST": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "MEMCACHED_HOST",
          "docker.io/acuvity/mcp-server-aws-memcached:1.0.2"
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
    "acuvity-mcp-server-aws-memcached": {
      "env": {
        "MEMCACHED_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MEMCACHED_HOST",
        "docker.io/acuvity/mcp-server-aws-memcached:1.0.2"
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
    "acuvity-mcp-server-aws-memcached": {
      "env": {
        "MEMCACHED_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MEMCACHED_HOST",
        "docker.io/acuvity/mcp-server-aws-memcached:1.0.2"
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
    "acuvity-mcp-server-aws-memcached": {
      "env": {
        "MEMCACHED_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MEMCACHED_HOST",
        "docker.io/acuvity/mcp-server-aws-memcached:1.0.2"
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
    "acuvity-mcp-server-aws-memcached": {
      "env": {
        "MEMCACHED_HOST": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "MEMCACHED_HOST",
        "docker.io/acuvity/mcp-server-aws-memcached:1.0.2"
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
        "env": {"MEMCACHED_HOST":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","MEMCACHED_HOST","docker.io/acuvity/mcp-server-aws-memcached:1.0.2"]
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
- arguments: `run -i --rm --read-only -e MEMCACHED_HOST docker.io/acuvity/mcp-server-aws-memcached:1.0.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e MEMCACHED_HOST docker.io/acuvity/mcp-server-aws-memcached:1.0.2
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-memcached": {
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
    "acuvity-mcp-server-aws-memcached": {
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

**Mandatory Environment variables**:
  - `MEMCACHED_HOST` environment variable to be set by env.MEMCACHED_HOST

**Optional Environment variables**:
  - `MEMCACHED_PORT="11211"` environment variable can be changed with env.MEMCACHED_PORT="11211"
  - `MEMCACHED_TIMEOUT="1"` environment variable can be changed with env.MEMCACHED_TIMEOUT="1"
  - `MEMCACHED_CONNECT_TIMEOUT="5"` environment variable can be changed with env.MEMCACHED_CONNECT_TIMEOUT="5"
  - `MEMCACHED_RETRY_TIMEOUT="1"` environment variable can be changed with env.MEMCACHED_RETRY_TIMEOUT="1"
  - `MEMCACHED_MAX_RETRIES="3"` environment variable can be changed with env.MEMCACHED_MAX_RETRIES="3"
  - `MEMCACHED_USE_TLS=""` environment variable can be changed with env.MEMCACHED_USE_TLS=""
  - `MEMCACHED_TLS_CERT_PATH=""` environment variable can be changed with env.MEMCACHED_TLS_CERT_PATH=""
  - `MEMCACHED_TLS_KEY_PATH=""` environment variable can be changed with env.MEMCACHED_TLS_KEY_PATH=""
  - `MEMCACHED_TLS_CA_CERT_PATH=""` environment variable can be changed with env.MEMCACHED_TLS_CA_CERT_PATH=""
  - `MEMCACHED_TLS_VERIFY="true"` environment variable can be changed with env.MEMCACHED_TLS_VERIFY="true"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
```

From there your MCP server mcp-server-aws-memcached will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-memcached` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/charts/mcp-server-aws-memcached/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (22)
<details>
<summary>cache_get</summary>

**Description**:

```
Get a value from the cache.

    Args:
        key: The key to retrieve

    Returns:
        Value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>cache_gets</summary>

**Description**:

```
Get a value and its CAS token from the cache.

    Args:
        key: The key to retrieve

    Returns:
        Value and CAS token or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>cache_get_many</summary>

**Description**:

```
Get multiple values from the cache.

    Args:
        keys: List of keys to retrieve

    Returns:
        Dictionary of key-value pairs or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_get_multi</summary>

**Description**:

```
Get multiple values from the cache (alias for get_many).

    Args:
        keys: List of keys to retrieve

    Returns:
        Dictionary of key-value pairs or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_set</summary>

**Description**:

```
Set a value in the cache.

    Args:
        key: The key to set
        value: The value to store
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_cas</summary>

**Description**:

```
Set a value using CAS (Check And Set).

    Args:
        key: The key to set
        value: The value to store
        cas: CAS token from gets()
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cas | integer | not set | Yes
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_set_many</summary>

**Description**:

```
Set multiple values in the cache.

    Args:
        mapping: Dictionary of key-value pairs
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| mapping | object | not set | Yes
</details>
<details>
<summary>cache_set_multi</summary>

**Description**:

```
Set multiple values in the cache (alias for set_many).

    Args:
        mapping: Dictionary of key-value pairs
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| mapping | object | not set | Yes
</details>
<details>
<summary>cache_add</summary>

**Description**:

```
Add a value to the cache only if the key doesn't exist.

    Args:
        key: The key to add
        value: The value to store
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_replace</summary>

**Description**:

```
Replace a value in the cache only if the key exists.

    Args:
        key: The key to replace
        value: The new value
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_append</summary>

**Description**:

```
Append a string to an existing value.

    Args:
        key: The key to append to
        value: String to append

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | string | not set | Yes
</details>
<details>
<summary>cache_prepend</summary>

**Description**:

```
Prepend a string to an existing value.

    Args:
        key: The key to prepend to
        value: String to prepend

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | string | not set | Yes
</details>
<details>
<summary>cache_delete</summary>

**Description**:

```
Delete a value from the cache.

    Args:
        key: The key to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>cache_delete_many</summary>

**Description**:

```
Delete multiple values from the cache.

    Args:
        keys: List of keys to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_delete_multi</summary>

**Description**:

```
Delete multiple values from the cache (alias for delete_many).

    Args:
        keys: List of keys to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_incr</summary>

**Description**:

```
Increment a counter in the cache.

    Args:
        key: The key to increment
        value: Amount to increment by (default 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | integer | not set | No
</details>
<details>
<summary>cache_decr</summary>

**Description**:

```
Decrement a counter in the cache.

    Args:
        key: The key to decrement
        value: Amount to decrement by (default 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | integer | not set | No
</details>
<details>
<summary>cache_touch</summary>

**Description**:

```
Update the expiration time for a key.

    Args:
        key: The key to update
        expire: New expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | integer | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>cache_stats</summary>

**Description**:

```
Get cache statistics.

    Args:
        args: Optional list of stats to retrieve

    Returns:
        Statistics or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| args | any | not set | No
</details>
<details>
<summary>cache_flush_all</summary>

**Description**:

```
Flush all cache entries.

    Args:
        delay: Optional delay in seconds before flushing

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| delay | integer | not set | No
</details>
<details>
<summary>cache_quit</summary>

**Description**:

```
Close the connection to the cache server.

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>cache_version</summary>

**Description**:

```
Get the version of the cache server.

    Returns:
        Version string or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | cache_add | description | 81f280f8d222199eeae9759dc3fcb5aed6efd7b697341d9e6d0502b6a5fe18da |
| tools | cache_append | description | 01631b0ad0ff6caf5dd7f2ed5d1e92940332e063ed9bf750d4dfa54bac41570f |
| tools | cache_cas | description | 59cf334eb2d467ffef7c22edf0529fea828a9c41a7e039021a6fae2b2a0727a9 |
| tools | cache_decr | description | fd784b4bd4dead1c91b4162f5d75e11b3769353765f0fa6901f275af61b4c0ef |
| tools | cache_delete | description | 01915385c6c89099c143c470bc11cd659576bac2741874813cc9cb98a7e11b2a |
| tools | cache_delete_many | description | 71746fd743c8b3e6114bba07f1eef689807859133b4b47b2f9294708f5324c5d |
| tools | cache_delete_multi | description | db1f86f259bab25a0ae690eaf72604f3cd52a444e0150e635ab586e5613a7f72 |
| tools | cache_flush_all | description | e894ed489862c6fde5cc7a1e449f49f67dd08cdf4f7f3f0a38ec65ba5520c81b |
| tools | cache_get | description | 07eb96e697fd6ca9ad6cd62d8b51814ba6d817e06957e29bc0618396d73af5e0 |
| tools | cache_get_many | description | fabbf6e51f142a1069fe132d889bce23ef46d3402b7cbbe744ca0a68b3d8d7ff |
| tools | cache_get_multi | description | 0462aecde4a078f2c360843feb113673c0480aec675c457c5ef0926ba32c771f |
| tools | cache_gets | description | d7be7ba2998a38b9bc95e79e7bc81fe75d2bcce37db6451e4f404e5a5461d65a |
| tools | cache_incr | description | 60382566a20be4d3ff7d314625b5683338965ea06905850defe055db5d971ec3 |
| tools | cache_prepend | description | a1455092720fd85777064b648ad1633e353c14bfc244b402ffe9dcde7d17cd88 |
| tools | cache_quit | description | 66d334197f33b112c62902ec5355b8b74cac9270930e88c7f802f9a2c04b4e66 |
| tools | cache_replace | description | 7009a3726e86bfc5c7d16ab52090377c1959fa37bced12ca50e7eb9d08be2faa |
| tools | cache_set | description | 51acc097b7eeb8807f285cfcf8b8f34436fdafd71bdbcd56dad327e2b7c25f2c |
| tools | cache_set_many | description | a297bba815d083cd47de6914d1c7d90ddf68aa39fb2d1320846603be238cec1b |
| tools | cache_set_multi | description | 9dec89dd2fed544cf87483b282eb15704f8abc6f1fdadb4294b80a46078dde7a |
| tools | cache_stats | description | 730cde3a76b996323740f2817b48638d5e33a37dbd07cd28090a1d1ed2768faa |
| tools | cache_touch | description | d8bec5113bebbbaf0bc6039929a7c6707f0579d636b8076ad3e7c69a81ec3f3b |
| tools | cache_version | description | eba7a88ca8724f8fb3a494e168b940672dd8e4edded6ba575738400d1a24e23b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
