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


# What is mcp-server-harness?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-harness/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-harness/v1.0.0-beta?logo=docker&logoColor=fff&label=v1.0.0-beta)](https://hub.docker.com/r/acuvity/mcp-server-harness)
[![GitHUB](https://img.shields.io/badge/v1.0.0-beta-3775A9?logo=github&logoColor=fff&label=harness/mcp-server)](https://github.com/harness/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-harness/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-harness&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HARNESS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-harness%3Av1.0.0-beta%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides seamless integration with Harness APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from harness/mcp-server original [sources](https://github.com/harness/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-harness/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/charts/mcp-server-harness/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure harness/mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-harness scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `HARNESS_API_KEY` required to be set
  - `HARNESS_DEFAULT_ORG_ID` optional (not set)
  - `HARNESS_DEFAULT_PROJECT_ID` optional (not set)
  - `HARNESS_BASE_URL` optional (not set)
  - `HARNESS_TOOLSETS` optional (not set)
  - `HARNESS_READ_ONLY` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/harness/mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-harness&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HARNESS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-harness%3Av1.0.0-beta%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-harness": {
        "env": {
          "HARNESS_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "HARNESS_API_KEY",
          "docker.io/acuvity/mcp-server-harness:v1.0.0-beta"
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
    "acuvity-mcp-server-harness": {
      "env": {
        "HARNESS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HARNESS_API_KEY",
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta"
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
    "acuvity-mcp-server-harness": {
      "env": {
        "HARNESS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HARNESS_API_KEY",
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta"
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
    "acuvity-mcp-server-harness": {
      "env": {
        "HARNESS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HARNESS_API_KEY",
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta"
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
    "acuvity-mcp-server-harness": {
      "env": {
        "HARNESS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HARNESS_API_KEY",
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta"
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
        "env": {"HARNESS_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","HARNESS_API_KEY","docker.io/acuvity/mcp-server-harness:v1.0.0-beta"]
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
- arguments: `run -i --rm --read-only -e HARNESS_API_KEY docker.io/acuvity/mcp-server-harness:v1.0.0-beta`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e HARNESS_API_KEY docker.io/acuvity/mcp-server-harness:v1.0.0-beta
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-harness": {
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
    "acuvity-mcp-server-harness": {
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
  - `HARNESS_API_KEY` secret to be set as secrets.HARNESS_API_KEY either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `HARNESS_DEFAULT_ORG_ID=""` environment variable can be changed with env.HARNESS_DEFAULT_ORG_ID=""
  - `HARNESS_DEFAULT_PROJECT_ID=""` environment variable can be changed with env.HARNESS_DEFAULT_PROJECT_ID=""
  - `HARNESS_BASE_URL=""` environment variable can be changed with env.HARNESS_BASE_URL=""
  - `HARNESS_TOOLSETS=""` environment variable can be changed with env.HARNESS_TOOLSETS=""
  - `HARNESS_READ_ONLY=""` environment variable can be changed with env.HARNESS_READ_ONLY=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
````

Install with helm

```console
helm install mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
```

From there your MCP server mcp-server-harness will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-harness` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/charts/mcp-server-harness/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (17)
<details>
<summary>create_pull_request</summary>

**Description**:

```
Create a new pull request in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | The description of the pull request | No
| is_draft | boolean | Whether the pull request should be created as a draft | No
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| repo_identifier | string | The identifier of the repository | Yes
| source_branch | string | The source branch for the pull request | Yes
| target_branch | string | The target branch for the pull request | No
| title | string | The title of the pull request | Yes
</details>
<details>
<summary>download_execution_logs</summary>

**Description**:

```
Downloads logs for an execution inside Harness
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| logs_directory | string | The absolute path to the directory where the logs should get downloaded | Yes
| org_id | string | Required ID of the organization. | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>fetch_execution_url</summary>

**Description**:

```
Fetch the execution URL for a pipeline execution in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pipeline_id | string | The ID of the pipeline | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>get_execution</summary>

**Description**:

```
Get details of a specific pipeline execution in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>get_pipeline</summary>

**Description**:

```
Get details of a specific pipeline in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pipeline_id | string | The ID of the pipeline | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>get_pull_request</summary>

**Description**:

```
Get details of a specific pull request in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pr_number | number | The number of the pull request | Yes
| project_id | string | Required ID of the project. | Yes
| repo_id | string | The ID of the repository | Yes
</details>
<details>
<summary>get_pull_request_checks</summary>

**Description**:

```
Get status checks for a specific pull request in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| pr_number | number | The number of the pull request | Yes
| project_id | string | Optional ID of the project. | No
| repo_identifier | string | The identifier of the repository | Yes
</details>
<details>
<summary>get_registry</summary>

**Description**:

```
Get details of a specific registry in Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
</details>
<details>
<summary>get_repository</summary>

**Description**:

```
Get details of a specific repository in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| repo_identifier | string | The identifier of the repository | Yes
</details>
<details>
<summary>list_artifact_files</summary>

**Description**:

```
List files for a specific artifact version in a Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| artifact | string | The name of the artifact | Yes
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
| size | number | Number of items per page | No
| sort_field | string | Optional field to sort by | No
| sort_order | string | Optional sort order | No
| version | string | The version of the artifact | Yes
</details>
<details>
<summary>list_artifact_versions</summary>

**Description**:

```
List artifact versions in a Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| artifact | string | The name of the artifact | Yes
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
| search | string | Optional search term to filter versions | No
| size | number | Number of items per page | No
</details>
<details>
<summary>list_artifacts</summary>

**Description**:

```
List artifacts in a Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
| search | string | Optional search term to filter artifacts | No
| size | number | Number of items per page | No
</details>
<details>
<summary>list_executions</summary>

**Description**:

```
List pipeline executions in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Optional branch to filter executions | No
| my_deployments | boolean | Optional flag to show only my deployments | No
| org_id | string | Required ID of the organization. | Yes
| page | number | Page number for pagination - page 0 is the first page | No
| pipeline_identifier | string | Optional pipeline identifier to filter executions | No
| project_id | string | Required ID of the project. | Yes
| search_term | string | Optional search term to filter executions | No
| size | number | Number of items per page | No
| status | string | Optional status to filter executions (e.g., Running, Success, Failed) | No
</details>
<details>
<summary>list_pipelines</summary>

**Description**:

```
List pipelines in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Required ID of the project. | Yes
| search_term | string | Optional search term to filter pipelines | No
| size | number | Number of items per page | No
</details>
<details>
<summary>list_pull_requests</summary>

**Description**:

```
List pull requests in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| include_checks | boolean | Optional flag to include CI check information for builds ran in the PR | No
| limit | number | Number of items per page | No
| org_id | string | Required ID of the organization. | Yes
| page | number | Page number for pagination | No
| project_id | string | Required ID of the project. | Yes
| query | string | Optional search query to filter pull requests | No
| repo_id | string | The ID of the repository | Yes
| source_branch | string | Optional source branch to filter pull requests | No
| state | string | Optional comma-separated states to filter pull requests (possible values: open,closed,merged) | No
| target_branch | string | Optional target branch to filter pull requests | No
</details>
<details>
<summary>list_registries</summary>

**Description**:

```
List registries in Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| package_type | string | Optional type to filter registries by package type | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| size | number | Number of items per page | No
| type | string | Optional type to filter registries | No
</details>
<details>
<summary>list_repositories</summary>

**Description**:

```
List repositories in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Number of items per page | No
| order | string | Optional sort order (asc or desc) | No
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination | No
| project_id | string | Optional ID of the project. | No
| query | string | Optional search term to filter repositories | No
| sort | string | Optional field to sort by (e.g., identifier) | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
