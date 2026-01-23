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


# What is mcp-server-harness?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-harness/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-harness/v1.0.0-beta.16?logo=docker&logoColor=fff&label=v1.0.0-beta.16)](https://hub.docker.com/r/acuvity/mcp-server-harness)
[![GitHUB](https://img.shields.io/badge/v1.0.0-beta.16-3775A9?logo=github&logoColor=fff&label=harness/mcp-server)](https://github.com/harness/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-harness/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-harness&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HARNESS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-harness%3Av1.0.0-beta.16%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-harness&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HARNESS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-harness%3Av1.0.0-beta.16%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16"
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
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16"
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
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16"
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
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16"
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
        "docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16"
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
        "args": ["run","-i","--rm","--read-only","-e","HARNESS_API_KEY","docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16"]
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
- arguments: `run -i --rm --read-only -e HARNESS_API_KEY docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e HARNESS_API_KEY docker.io/acuvity/mcp-server-harness:v1.0.0-beta.16
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

## 🧰 Tools (10)
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
<summary>get_connector_details</summary>

**Description**:

```
Get detailed information about a specific connector.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connector_identifier | string | The identifier of the connector | Yes
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
</details>
<details>
<summary>get_dashboard_data</summary>

**Description**:

```
Retrieves the data from a specific Harness dashboard
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dashboard_id | string | The ID of the dashboard to retrieve data from | Yes
| reporting_timeframe | number | Reporting timeframe in days | No
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
| child_stage_node_id | string | Optional ID of the child stage node to filter the execution details | No
| org_id | string | Required ID of the organization. | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
| stage_node_id | string | Optional ID of the stage node to filter the execution details | No
</details>
<details>
<summary>get_pipeline</summary>

**Description**:

```
Get details of a specific pipeline in a Harness repository. Use list_pipelines (if available) first to find the correct pipeline_id if you're unsure of the exact ID.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pipeline_id | string | The ID of the pipeline | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>list_connector_catalogue</summary>

**Description**:

```
List the Harness connector catalogue.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
</details>
<details>
<summary>list_connectors</summary>

**Description**:

```
List connectors with filtering options.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| categories | string | Comma-separated list of connector categories | No
| connectivity_statuses | string | Comma-separated list of connectivity statuses | No
| connector_connectivity_modes | string | Comma-separated list of connectivity modes | No
| connector_identifiers | string | Comma-separated list of connector identifiers to filter by | No
| connector_names | string | Comma-separated list of connector names to filter by | No
| description | string | Filter by connector description | No
| inheriting_credentials_from_delegate | boolean | Filter by whether connectors inherit credentials from delegate | No
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| tags | string | JSON object of tags to filter by (e.g., {"env":"prod"}) | No
| types | string | Comma-separated list of connector types | No
</details>
<details>
<summary>list_dashboards</summary>

**Description**:

```
Lists all available Harness dashboards
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for pagination - page 1 is the first page | No
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

## 📝 Prompts (5)
<details>
<summary>ask_confirmation_for_update_and_delete_operations</summary>

**Description**:

```
Ensure that Update or Delete operations are executed ONLY after user confirmation.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| mode | Selects the prompt mode: 'standard' or 'architect' |No |
<details>
<summary>ask_release_agent_prompt</summary>

**Description**:

```
Prompt for the Ask Release Agent tool
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| mode | Selects the prompt mode: 'standard' or 'architect' |No |
<details>
<summary>get_ccm_overview</summary>

**Description**:

```
Ensure parameters are provided correctly and in the right format. 
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| mode | Selects the prompt mode: 'standard' or 'architect' |No |
<details>
<summary>pipeline_error_analysis</summary>

**Description**:

```
Comprehensive error analysis for failed pipelines
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| mode | Selects the prompt mode: 'standard' or 'architect' |No |
<details>
<summary>pipeline_summarizer</summary>

**Description**:

```
Summarize a Harness pipeline's structure, purpose, and behavior.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| mode | Selects the prompt mode: 'standard' or 'architect' |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | ask_confirmation_for_update_and_delete_operations | description | 5ebf3bbc2ab5ada8722d5d3a3812d73b7768576c64077ffecbb74e7854b95d3d |
| prompts | ask_confirmation_for_update_and_delete_operations | mode | 4a1f6a4c26aa5af21d91edf6d2944b28be7acac3b8b37ca2e43aea8fba0fff05 |
| prompts | ask_release_agent_prompt | description | cb41cf88479a9a0fe9e3c8a639efebfcef0e653ec9a75d9bd66e7d1a2b61a5cb |
| prompts | ask_release_agent_prompt | mode | 4a1f6a4c26aa5af21d91edf6d2944b28be7acac3b8b37ca2e43aea8fba0fff05 |
| prompts | get_ccm_overview | description | 6ae6e3112b6126cc106fa401bdc9199e5510a3176aa521d2e1b7291d5ccb0964 |
| prompts | get_ccm_overview | mode | 4a1f6a4c26aa5af21d91edf6d2944b28be7acac3b8b37ca2e43aea8fba0fff05 |
| prompts | pipeline_error_analysis | description | 66b3866bce0909dd748682bcca045a725382f678663cf1bc91539b45012abf9a |
| prompts | pipeline_error_analysis | mode | 4a1f6a4c26aa5af21d91edf6d2944b28be7acac3b8b37ca2e43aea8fba0fff05 |
| prompts | pipeline_summarizer | description | f06a64cf79f69c86fb003f1c6dfdb8f3ff21df634f26c549e525b2ee370fb26c |
| prompts | pipeline_summarizer | mode | 4a1f6a4c26aa5af21d91edf6d2944b28be7acac3b8b37ca2e43aea8fba0fff05 |
| tools | fetch_execution_url | description | 1469e23ea5f5d25213828d61fff7594b96376297d7c66b48beec3ec08c00c0c5 |
| tools | fetch_execution_url | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | fetch_execution_url | pipeline_id | 50fc23224221dbf67c12e6ee33931b2c183b8e2cabd7a56da6c32e56ae238e0b |
| tools | fetch_execution_url | plan_execution_id | a300ba3e01c7428f5992ae07c929da21111bd7670e0b40888978c0901e84101d |
| tools | fetch_execution_url | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | get_connector_details | description | 8c5ddfc268db76b78ea0fca8c2db9d5562d60e8c478fcb8cdb3fd052e03ac3df |
| tools | get_connector_details | connector_identifier | 826392cc68b209aa18516dad2b71930b5c410e6619d88207d87e6d6ab2e39653 |
| tools | get_connector_details | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | get_connector_details | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | get_dashboard_data | description | 10c77c396b6f99f4f1f19f1cda386fd513029cdd5d4cac50b3a440cda1bb6e74 |
| tools | get_dashboard_data | dashboard_id | 86e16b3179d0f5b1deeedf6807a53cedde4b660f52a321cbe78cb5966c8e0b0a |
| tools | get_dashboard_data | reporting_timeframe | dd80093a054760a295d2d60e4bf0903177ac7d80c3a9fd2adc9c067cd7a3b1f9 |
| tools | get_execution | description | 3b3bbc6e056cfc8da6d02c6bd74e8bdf8365653e48c6cca6a52519adb75b9872 |
| tools | get_execution | child_stage_node_id | f6961caa69c059c7eba1452c419575295d89ade33d282c4f17fbc4ea685e9263 |
| tools | get_execution | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | get_execution | plan_execution_id | a300ba3e01c7428f5992ae07c929da21111bd7670e0b40888978c0901e84101d |
| tools | get_execution | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | get_execution | stage_node_id | d26afda8814479d12a8c539e20fe5e6da4afe62f2e2f749e21ca009adb416bbb |
| tools | get_pipeline | description | cfa125a010652461b7dcaa62f159663928b9d79eae437c95b838491abf1079ba |
| tools | get_pipeline | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | get_pipeline | pipeline_id | 50fc23224221dbf67c12e6ee33931b2c183b8e2cabd7a56da6c32e56ae238e0b |
| tools | get_pipeline | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | list_connector_catalogue | description | 70cc00497a581feeff7e59c215f8af203d1f73209740a3066ccaad47d348ae0d |
| tools | list_connector_catalogue | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_connector_catalogue | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_connectors | description | aa851eb542613b132df15049638a668b6286a390c88bfe91f81c9b5d291d3dff |
| tools | list_connectors | categories | b6c93909654f267671ce112f61703f6f43bf5425b13be02f726034e6213ed7bc |
| tools | list_connectors | connectivity_statuses | 1cdc9000af20b5b84aab006cfe52bfcbc9003e083c170e8fa9c08522d3d5a21b |
| tools | list_connectors | connector_connectivity_modes | 792b469eddde9c6642fb3b0261aea2e9c69e2480e2005532830ccdf27aae8181 |
| tools | list_connectors | connector_identifiers | 85497353b305bf627aebe613e2ad8b4ad2b480c21ea171b56cfeb14eb249472a |
| tools | list_connectors | connector_names | 6da5da3e1f214b817910137e8cae8c90c6b1621c01105a9a50b722afbd7bd74e |
| tools | list_connectors | description | 9662e2257a8bb3694bc52c96d80f0453fd471a0165070dbc50a1764a153e9c66 |
| tools | list_connectors | inheriting_credentials_from_delegate | 437c5039e7caec70e37b8e09bc204e69abe64167ba926a572b37f798b90f9ec4 |
| tools | list_connectors | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_connectors | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_connectors | tags | f5098c6a93c5c5a69c042b39b5b0afd8bf0e6172a8eb2d160fbddc6056408f16 |
| tools | list_connectors | types | ebd2b9e4f3efca85c855d7bec917ac0d72043ea752c56a64e28adb8c8851a809 |
| tools | list_dashboards | description | 3d6c84acaa262adbc5396ea7304bd9e96f4ef71629538ea5eb6636d734554c87 |
| tools | list_dashboards | page | 3b67bf7602d18880d7bcf11fdb15e7560ef6fc58fb8136f570b9e6da83d2b084 |
| tools | list_dashboards | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_executions | description | 639d87a9fc8c56b9da15de96fe1d69f2e6ddfd83f213f72498005f7dc931d025 |
| tools | list_executions | branch | 33b16f813d79b5b0a0e5c5cb8c36260f23491303a4dc312b40585e68210ac5a1 |
| tools | list_executions | my_deployments | f6e15331fb4a9d878510fdcb6e0e71e0fe9536766dcb9bf93286f2e80d0443ee |
| tools | list_executions | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | list_executions | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_executions | pipeline_identifier | ea32bdb79e8c29d407c287993c9e078ad539e607ba8271648d3fb69dcd645054 |
| tools | list_executions | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | list_executions | search_term | a31863dbe6950a21ba780b23fadc50767cf84f1df1b74894ce32fb479d35c36d |
| tools | list_executions | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_executions | status | cd4cfdb5b7e3bd9b0dac5b737705047da58c5c1d338879715e357995b7c531df |
| tools | list_pipelines | description | b4106dda0c4f300945d433b87ffaaaed53a36422ff2c8a23ad6d2f557bdf4ab4 |
| tools | list_pipelines | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | list_pipelines | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_pipelines | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | list_pipelines | search_term | cd148af67bed8f4944b2971b11e88a1b87c244c7efd418adf5379a116e86afaa |
| tools | list_pipelines | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
