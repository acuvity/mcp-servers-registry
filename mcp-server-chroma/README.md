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


# What is mcp-server-chroma?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chroma/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chroma/0.2.6?logo=docker&logoColor=fff&label=0.2.6)](https://hub.docker.com/r/acuvity/mcp-server-chroma)
[![PyPI](https://img.shields.io/badge/0.2.6-3775A9?logo=pypi&logoColor=fff&label=chroma-mcp)](https://github.com/chroma-core/chroma-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-chroma/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chroma&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHROMA_CLIENT_TYPE%22%2C%22-e%22%2C%22CHROMA_DATABASE%22%2C%22-e%22%2C%22CHROMA_HOST%22%2C%22-e%22%2C%22CHROMA_PORT%22%2C%22-e%22%2C%22CHROMA_TENANT%22%2C%22docker.io%2Facuvity%2Fmcp-server-chroma%3A0.2.6%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Embedding database for LLM applications with advanced search capabilities.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from chroma-mcp original [sources](https://github.com/chroma-core/chroma-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-chroma/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/charts/mcp-server-chroma/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure chroma-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-chroma scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `CHROMA_API_KEY` optional (not set)
  - `CHROMA_CLIENT_TYPE` required to be set
  - `CHROMA_CUSTOM_AUTH_CREDENTIALS` optional (not set)
  - `CHROMA_DATABASE` required to be set
  - `CHROMA_DATA_DIR` optional (not set)
  - `CHROMA_HOST` required to be set
  - `CHROMA_PORT` required to be set
  - `CHROMA_SSL` optional (not set)
  - `CHROMA_TENANT` required to be set

For more information and extra configuration you can consult the [package](https://github.com/chroma-core/chroma-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chroma&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHROMA_CLIENT_TYPE%22%2C%22-e%22%2C%22CHROMA_DATABASE%22%2C%22-e%22%2C%22CHROMA_HOST%22%2C%22-e%22%2C%22CHROMA_PORT%22%2C%22-e%22%2C%22CHROMA_TENANT%22%2C%22docker.io%2Facuvity%2Fmcp-server-chroma%3A0.2.6%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-chroma": {
        "env": {
          "CHROMA_CLIENT_TYPE": "TO_BE_SET",
          "CHROMA_DATABASE": "TO_BE_SET",
          "CHROMA_HOST": "TO_BE_SET",
          "CHROMA_PORT": "TO_BE_SET",
          "CHROMA_TENANT": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "CHROMA_CLIENT_TYPE",
          "-e",
          "CHROMA_DATABASE",
          "-e",
          "CHROMA_HOST",
          "-e",
          "CHROMA_PORT",
          "-e",
          "CHROMA_TENANT",
          "docker.io/acuvity/mcp-server-chroma:0.2.6"
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
    "acuvity-mcp-server-chroma": {
      "env": {
        "CHROMA_CLIENT_TYPE": "TO_BE_SET",
        "CHROMA_DATABASE": "TO_BE_SET",
        "CHROMA_HOST": "TO_BE_SET",
        "CHROMA_PORT": "TO_BE_SET",
        "CHROMA_TENANT": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHROMA_CLIENT_TYPE",
        "-e",
        "CHROMA_DATABASE",
        "-e",
        "CHROMA_HOST",
        "-e",
        "CHROMA_PORT",
        "-e",
        "CHROMA_TENANT",
        "docker.io/acuvity/mcp-server-chroma:0.2.6"
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
    "acuvity-mcp-server-chroma": {
      "env": {
        "CHROMA_CLIENT_TYPE": "TO_BE_SET",
        "CHROMA_DATABASE": "TO_BE_SET",
        "CHROMA_HOST": "TO_BE_SET",
        "CHROMA_PORT": "TO_BE_SET",
        "CHROMA_TENANT": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHROMA_CLIENT_TYPE",
        "-e",
        "CHROMA_DATABASE",
        "-e",
        "CHROMA_HOST",
        "-e",
        "CHROMA_PORT",
        "-e",
        "CHROMA_TENANT",
        "docker.io/acuvity/mcp-server-chroma:0.2.6"
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
    "acuvity-mcp-server-chroma": {
      "env": {
        "CHROMA_CLIENT_TYPE": "TO_BE_SET",
        "CHROMA_DATABASE": "TO_BE_SET",
        "CHROMA_HOST": "TO_BE_SET",
        "CHROMA_PORT": "TO_BE_SET",
        "CHROMA_TENANT": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHROMA_CLIENT_TYPE",
        "-e",
        "CHROMA_DATABASE",
        "-e",
        "CHROMA_HOST",
        "-e",
        "CHROMA_PORT",
        "-e",
        "CHROMA_TENANT",
        "docker.io/acuvity/mcp-server-chroma:0.2.6"
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
    "acuvity-mcp-server-chroma": {
      "env": {
        "CHROMA_CLIENT_TYPE": "TO_BE_SET",
        "CHROMA_DATABASE": "TO_BE_SET",
        "CHROMA_HOST": "TO_BE_SET",
        "CHROMA_PORT": "TO_BE_SET",
        "CHROMA_TENANT": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHROMA_CLIENT_TYPE",
        "-e",
        "CHROMA_DATABASE",
        "-e",
        "CHROMA_HOST",
        "-e",
        "CHROMA_PORT",
        "-e",
        "CHROMA_TENANT",
        "docker.io/acuvity/mcp-server-chroma:0.2.6"
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
        "env": {"CHROMA_CLIENT_TYPE":"TO_BE_SET","CHROMA_DATABASE":"TO_BE_SET","CHROMA_HOST":"TO_BE_SET","CHROMA_PORT":"TO_BE_SET","CHROMA_TENANT":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","CHROMA_CLIENT_TYPE","-e","CHROMA_DATABASE","-e","CHROMA_HOST","-e","CHROMA_PORT","-e","CHROMA_TENANT","docker.io/acuvity/mcp-server-chroma:0.2.6"]
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
- arguments: `run -i --rm --read-only -e CHROMA_CLIENT_TYPE -e CHROMA_DATABASE -e CHROMA_HOST -e CHROMA_PORT -e CHROMA_TENANT docker.io/acuvity/mcp-server-chroma:0.2.6`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e CHROMA_CLIENT_TYPE -e CHROMA_DATABASE -e CHROMA_HOST -e CHROMA_PORT -e CHROMA_TENANT docker.io/acuvity/mcp-server-chroma:0.2.6
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-chroma": {
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
    "acuvity-mcp-server-chroma": {
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

**Optional Secrets**:
  - `CHROMA_API_KEY` secret to be set as secrets.CHROMA_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `CHROMA_CLIENT_TYPE` environment variable to be set by env.CHROMA_CLIENT_TYPE
  - `CHROMA_DATABASE` environment variable to be set by env.CHROMA_DATABASE
  - `CHROMA_HOST` environment variable to be set by env.CHROMA_HOST
  - `CHROMA_PORT` environment variable to be set by env.CHROMA_PORT
  - `CHROMA_TENANT` environment variable to be set by env.CHROMA_TENANT

**Optional Environment variables**:
  - `CHROMA_CUSTOM_AUTH_CREDENTIALS=""` environment variable can be changed with env.CHROMA_CUSTOM_AUTH_CREDENTIALS=""
  - `CHROMA_DATA_DIR=""` environment variable can be changed with env.CHROMA_DATA_DIR=""
  - `CHROMA_SSL=""` environment variable can be changed with env.CHROMA_SSL=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
````

Install with helm

```console
helm install mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
```

From there your MCP server mcp-server-chroma will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-chroma` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/charts/mcp-server-chroma/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (13)
<details>
<summary>chroma_list_collections</summary>

**Description**:

```
List all collection names in the Chroma database with pagination support.
    
    Args:
        limit: Optional maximum number of collections to return
        offset: Optional number of collections to skip before returning results
    
    Returns:
        List of collection names or ["__NO_COLLECTIONS_FOUND__"] if database is empty
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
</details>
<details>
<summary>chroma_create_collection</summary>

**Description**:

```
Create a new Chroma collection with configurable HNSW parameters.
    
    Args:
        collection_name: Name of the collection to create
        embedding_function_name: Name of the embedding function to use. Options: 'default', 'cohere', 'openai', 'jina', 'voyageai', 'ollama', 'roboflow'
        metadata: Optional metadata dict to add to the collection
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| embedding_function_name | string | not set | No
| metadata | any | not set | No
</details>
<details>
<summary>chroma_peek_collection</summary>

**Description**:

```
Peek at documents in a Chroma collection.
    
    Args:
        collection_name: Name of the collection to peek into
        limit: Number of documents to peek at
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| limit | integer | not set | No
</details>
<details>
<summary>chroma_get_collection_info</summary>

**Description**:

```
Get information about a Chroma collection.
    
    Args:
        collection_name: Name of the collection to get info about
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_get_collection_count</summary>

**Description**:

```
Get the number of documents in a Chroma collection.
    
    Args:
        collection_name: Name of the collection to count
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_modify_collection</summary>

**Description**:

```
Modify a Chroma collection's name or metadata.
    
    Args:
        collection_name: Name of the collection to modify
        new_name: Optional new name for the collection
        new_metadata: Optional new metadata for the collection
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| new_metadata | any | not set | No
| new_name | any | not set | No
</details>
<details>
<summary>chroma_fork_collection</summary>

**Description**:

```
Fork a Chroma collection.
    
    Args:
        collection_name: Name of the collection to fork
        new_collection_name: Name of the new collection to create
        metadata: Optional metadata dict to add to the new collection
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| new_collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_delete_collection</summary>

**Description**:

```
Delete a Chroma collection.
    
    Args:
        collection_name: Name of the collection to delete
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_add_documents</summary>

**Description**:

```
Add documents to a Chroma collection.
    
    Args:
        collection_name: Name of the collection to add documents to
        documents: List of text documents to add
        ids: List of IDs for the documents (required)
        metadatas: Optional list of metadata dictionaries for each document
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| documents | array | not set | Yes
| ids | array | not set | Yes
| metadatas | any | not set | No
</details>
<details>
<summary>chroma_query_documents</summary>

**Description**:

```
Query documents from a Chroma collection with advanced filtering.
    
    Args:
        collection_name: Name of the collection to query
        query_texts: List of query texts to search for
        n_results: Number of results to return per query
        where: Optional metadata filters using Chroma's query operators
               Examples:
               - Simple equality: {"metadata_field": "value"}
               - Comparison: {"metadata_field": {"$gt": 5}}
               - Logical AND: {"$and": [{"field1": {"$eq": "value1"}}, {"field2": {"$gt": 5}}]}
               - Logical OR: {"$or": [{"field1": {"$eq": "value1"}}, {"field1": {"$eq": "value2"}}]}
        where_document: Optional document content filters
               Examples:
               - Contains: {"$contains": "value"}
               - Not contains: {"$not_contains": "value"}
               - Regex: {"$regex": "[a-z]+"}
               - Not regex: {"$not_regex": "[a-z]+"}
               - Logical AND: {"$and": [{"$contains": "value1"}, {"$not_regex": "[a-z]+"}]}
               - Logical OR: {"$or": [{"$regex": "[a-z]+"}, {"$not_contains": "value2"}]}
        include: List of what to include in response. By default, this will include documents, metadatas, and distances.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| include | array | not set | No
| n_results | integer | not set | No
| query_texts | array | not set | Yes
| where | any | not set | No
| where_document | any | not set | No
</details>
<details>
<summary>chroma_get_documents</summary>

**Description**:

```
Get documents from a Chroma collection with optional filtering.
    
    Args:
        collection_name: Name of the collection to get documents from
        ids: Optional list of document IDs to retrieve
        where: Optional metadata filters using Chroma's query operators
               Examples:
               - Simple equality: {"metadata_field": "value"}
               - Comparison: {"metadata_field": {"$gt": 5}}
               - Logical AND: {"$and": [{"field1": {"$eq": "value1"}}, {"field2": {"$gt": 5}}]}
               - Logical OR: {"$or": [{"field1": {"$eq": "value1"}}, {"field1": {"$eq": "value2"}}]}
        where_document: Optional document content filters
               Examples:
               - Contains: {"$contains": "value"}
               - Not contains: {"$not_contains": "value"}
               - Regex: {"$regex": "[a-z]+"}
               - Not regex: {"$not_regex": "[a-z]+"}
               - Logical AND: {"$and": [{"$contains": "value1"}, {"$not_regex": "[a-z]+"}]}
               - Logical OR: {"$or": [{"$regex": "[a-z]+"}, {"$not_contains": "value2"}]}
        include: List of what to include in response. By default, this will include documents, and metadatas.
        limit: Optional maximum number of documents to return
        offset: Optional number of documents to skip before returning results
    
    Returns:
        Dictionary containing the matching documents, their IDs, and requested includes
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| ids | any | not set | No
| include | array | not set | No
| limit | any | not set | No
| offset | any | not set | No
| where | any | not set | No
| where_document | any | not set | No
</details>
<details>
<summary>chroma_update_documents</summary>

**Description**:

```
Update documents in a Chroma collection.

    Args:
        collection_name: Name of the collection to update documents in
        ids: List of document IDs to update (required)
        embeddings: Optional list of new embeddings for the documents.
                    Must match length of ids if provided.
        metadatas: Optional list of new metadata dictionaries for the documents.
                   Must match length of ids if provided.
        documents: Optional list of new text documents.
                   Must match length of ids if provided.

    Returns:
        A confirmation message indicating the number of documents updated.

    Raises:
        ValueError: If 'ids' is empty or if none of 'embeddings', 'metadatas',
                    or 'documents' are provided, or if the length of provided
                    update lists does not match the length of 'ids'.
        Exception: If the collection does not exist or if the update operation fails.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| documents | any | not set | No
| embeddings | any | not set | No
| ids | array | not set | Yes
| metadatas | any | not set | No
</details>
<details>
<summary>chroma_delete_documents</summary>

**Description**:

```
Delete documents from a Chroma collection.

    Args:
        collection_name: Name of the collection to delete documents from
        ids: List of document IDs to delete

    Returns:
        A confirmation message indicating the number of documents deleted.

    Raises:
        ValueError: If 'ids' is empty
        Exception: If the collection does not exist or if the delete operation fails.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| ids | array | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | chroma_add_documents | description | c75391c9f0bd07200173f3d625933588e62236669cb02f3bcd52e8beead2f1e3 |
| tools | chroma_create_collection | description | a71c32e7d4434ec9ccba014543c74d1075f64de1640c7b1e801841e9e793d1fa |
| tools | chroma_delete_collection | description | a361003969b79e83a7d12f01a90673e38583b856951806d565b8d99a2b54c4ef |
| tools | chroma_delete_documents | description | 23ab4256014ccae612288d23ff8838af64c2f56391dc7851c570da81aade2987 |
| tools | chroma_fork_collection | description | 0e97debcb6b0a672bdaa3c6184c150bf96280adde5dca9b7bb92a8d1d866cc84 |
| tools | chroma_get_collection_count | description | 33047599d472f45af90fa29d9eacb603f25e1dbb6d1e1d4fad63dda4d868efe8 |
| tools | chroma_get_collection_info | description | bcde301a84c843b111bc751d56fc858b3dabd659be1336f7acf95522dcf81e1c |
| tools | chroma_get_documents | description | 052f63d293b9544924144c49ed816a4c67abe7e312e2eccaacfc9b18825aaf2c |
| tools | chroma_list_collections | description | 84eed66cb7c4265656325b0ec0ea43690c31e8a7d5bf312a478024908e56a2a8 |
| tools | chroma_modify_collection | description | babb12ff7b6907dcad1dcda4ecc3214fc029fe447cca257d4d088708b8925d12 |
| tools | chroma_peek_collection | description | 9f2ddf70df5250db4c74e7576cb64a067997c6cf5659401d00481d280135a9ca |
| tools | chroma_query_documents | description | 0151aa809c0a9720ab93d5d7f7a88592e699c169c3ab2fcb32de9052e6b24b20 |
| tools | chroma_update_documents | description | 038dbe7bb4d878805ac4552b9c62b8687e94954391a6ed95259b5029049de95d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
