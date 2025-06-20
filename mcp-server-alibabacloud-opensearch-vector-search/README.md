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


# What is mcp-server-alibabacloud-opensearch-vector-search?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-opensearch-vector-search/545d264?logo=docker&logoColor=fff&label=545d264)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search)
[![GitHUB](https://img.shields.io/badge/545d264-3775A9?logo=github&logoColor=fff&label=aliyun/alibabacloud-opensearch-mcp-server)](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-opensearch-vector-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_USERNAME%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_PASSWORD%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_INSTANCE_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-opensearch-vector-search%3A545d264%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Universal interface between AI Agents and OpenSearch Vector.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from aliyun/alibabacloud-opensearch-mcp-server original [sources](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-opensearch-vector-search/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure aliyun/alibabacloud-opensearch-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-alibabacloud-opensearch-vector-search scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `OPENSEARCH_VECTOR_USERNAME` required to be set
  - `OPENSEARCH_VECTOR_PASSWORD` required to be set
  - `OPENSEARCH_VECTOR_INSTANCE_ID` required to be set
  - `OPENSEARCH_VECTOR_INDEX_NAME` optional (not set)
  - `AISEARCH_API_KEY` optional (not set)
  - `AISEARCH_ENDPOINT` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-opensearch-vector-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_USERNAME%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_PASSWORD%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_INSTANCE_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-opensearch-vector-search%3A545d264%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
        "env": {
          "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
          "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
          "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "OPENSEARCH_VECTOR_USERNAME",
          "-e",
          "OPENSEARCH_VECTOR_PASSWORD",
          "-e",
          "OPENSEARCH_VECTOR_INSTANCE_ID",
          "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
      "env": {
        "OPENSEARCH_VECTOR_INSTANCE_ID": "TO_BE_SET",
        "OPENSEARCH_VECTOR_PASSWORD": "TO_BE_SET",
        "OPENSEARCH_VECTOR_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OPENSEARCH_VECTOR_USERNAME",
        "-e",
        "OPENSEARCH_VECTOR_PASSWORD",
        "-e",
        "OPENSEARCH_VECTOR_INSTANCE_ID",
        "docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"
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
        "env": {"OPENSEARCH_VECTOR_INSTANCE_ID":"TO_BE_SET","OPENSEARCH_VECTOR_PASSWORD":"TO_BE_SET","OPENSEARCH_VECTOR_USERNAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","OPENSEARCH_VECTOR_USERNAME","-e","OPENSEARCH_VECTOR_PASSWORD","-e","OPENSEARCH_VECTOR_INSTANCE_ID","docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264"]
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
- arguments: `run -i --rm --read-only -e OPENSEARCH_VECTOR_USERNAME -e OPENSEARCH_VECTOR_PASSWORD -e OPENSEARCH_VECTOR_INSTANCE_ID docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e OPENSEARCH_VECTOR_USERNAME -e OPENSEARCH_VECTOR_PASSWORD -e OPENSEARCH_VECTOR_INSTANCE_ID docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:545d264
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
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
    "acuvity-mcp-server-alibabacloud-opensearch-vector-search": {
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
  - `OPENSEARCH_VECTOR_PASSWORD` secret to be set as secrets.OPENSEARCH_VECTOR_PASSWORD either by `.value` or from existing with `.valueFrom`

**Optional Secrets**:
  - `AISEARCH_API_KEY` secret to be set as secrets.AISEARCH_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `OPENSEARCH_VECTOR_USERNAME` environment variable to be set by env.OPENSEARCH_VECTOR_USERNAME
  - `OPENSEARCH_VECTOR_INSTANCE_ID` environment variable to be set by env.OPENSEARCH_VECTOR_INSTANCE_ID

**Optional Environment variables**:
  - `OPENSEARCH_VECTOR_INDEX_NAME=""` environment variable can be changed with env.OPENSEARCH_VECTOR_INDEX_NAME=""
  - `AISEARCH_ENDPOINT=""` environment variable can be changed with env.AISEARCH_ENDPOINT=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
````

Install with helm

```console
helm install mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
```

From there your MCP server mcp-server-alibabacloud-opensearch-vector-search will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-opensearch-vector-search` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (6)
<details>
<summary>simple_search</summary>

**Description**:

```
Perform a similarity search based on either a text query or a vector. If the input is text, it will be converted into a vector using the specified embedding model.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| embedding_model | string | Embedding model for text queries. Supported: `ops-text-embedding-001`、`ops-text-embedding-zh-001`、`ops-text-embedding-en-001`、`ops-text-embedding-002` | No
| filter | any | Additional filtering criteria. | No
| namespace | any | Namespace for filtering results. | No
| need_sparse_vector | boolean | Whether to include sparse vector data in the search. | No
| query | any | Search query, can be either a text string or a list of floats representing a vector. | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
</details>
<details>
<summary>query_by_ids</summary>

**Description**:

```
Perform a simple search based on key ids.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ids | array | List of ids to query | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
</details>
<details>
<summary>inference_query</summary>

**Description**:

```
Perform a simple search based on text after configuring EmbeddingModel in OpenSearch Console.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The text to query | Yes
| namespace | any | The namespace of the target table in OpenSearch Vector. | No
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
</details>
<details>
<summary>multi_query</summary>

**Description**:

```
Perform a multi search based on vectors.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
| vector_list | array | A list of dense vectors to be used for the multi-vector similarity search. | Yes
</details>
<details>
<summary>mix_query_with_sparse_vector</summary>

**Description**:

```
Perform a complex search based on a single dense vector and a sparse vector.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sparse_ids | array | A list of token IDs representing the indices of the sparse vector. | Yes
| sparse_values | array | A list of corresponding weights for each token ID in sparse_ids, forming the sparse vector. | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
| vector | array | A dense vector used as the primary query vector for similarity search. | Yes
</details>
<details>
<summary>mix_query_with_text</summary>

**Description**:

```
Perform a complex search based on a single dense vector and a text.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | A text query for similarity search. | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
| vector | array | A dense vector for similarity search. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | inference_query | description | 46ec7dbe526f2f38d4f0be6e52d31e7b2088caff963b759de349dc04957087f1 |
| tools | inference_query | content | 3a9e67b7734e83063d056290633ca6d9f7d7bf6070fae6cbfb279a75fda5e099 |
| tools | inference_query | namespace | c5f3f8aeea4f98fedfdf82f13463d9a1a2fd9645a94baeabaa30b9c9b74f5609 |
| tools | inference_query | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | mix_query_with_sparse_vector | description | 90c71900bc568809689f449dcc3a8449fc3847d0e196ca237cf9dd5eaa465bc0 |
| tools | mix_query_with_sparse_vector | sparse_ids | 594a9f49a20a1647000229942298b16c09a49b1940c47377a8474a78dd77c022 |
| tools | mix_query_with_sparse_vector | sparse_values | 196cc8b6c9d410285838c3f480cfb363900e6011533dfe20b9bc76603df36938 |
| tools | mix_query_with_sparse_vector | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | mix_query_with_sparse_vector | vector | 9f4908a3cd51420bae5215d7be70280bc232f8de18a4c299bf9ae47595619dc1 |
| tools | mix_query_with_text | description | ecdc3576c1e7744051bee3604ca3c778a8150c4a9bc8f43a78c41ccb3bb231f9 |
| tools | mix_query_with_text | content | 7a662e4676b262d0e259a679a08b7fc35144f28ae8db9408d294ae5e7ae32ae4 |
| tools | mix_query_with_text | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | mix_query_with_text | vector | 02ceae19226395b6f4bddc8b96143a651c3a93b4e69e70bdd8c52c4fab7941e2 |
| tools | multi_query | description | 68186a60caa990bc5efb1987e03545258b5405983ca7e0f804ec31d9ab8bc6bb |
| tools | multi_query | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | multi_query | vector_list | c12b44c7640b8394d36b0f0a042d06b9500e5a9562796b45f4303ef43042325d |
| tools | query_by_ids | description | 64d3cd22f258ce2fd3fe7fb09213bbf61b79f100c12142dbab8ac496b3423cfc |
| tools | query_by_ids | ids | ee8044588b3879214257c2302e201c3a61b83f1401a4df9e8bc7d8d7375d03db |
| tools | query_by_ids | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | simple_search | description | 5107a7b75309bd2218d85484bf5ae384ba5127a09ddbb27cda056687d3ca8eff |
| tools | simple_search | embedding_model | 17cecb6e7d5767adb8025db25cc2be514b88e144654b7a7b643d7ca2be9e4e5c |
| tools | simple_search | filter | 699dbab22e9da5f117ac730b2bfb2aab3ce65c6e4a495b7d6adef3acbc2f631f |
| tools | simple_search | namespace | a2735052645d07d9e3daac15c818c027ed5c487789ad2eda55b83382a79f7890 |
| tools | simple_search | need_sparse_vector | ece41e6b7a00b1ddd535724f039408e9db21d57eacba26a37f720df3fcc38c8b |
| tools | simple_search | query | 7e0534f864ebd7b073fe3c37ea3b3f59daaf5ad7a9cd6cf3afc266bc4cd71983 |
| tools | simple_search | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
