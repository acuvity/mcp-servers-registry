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


# What is mcp-server-neo4j-aura?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-aura/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-neo4j-aura/0.4.7?logo=docker&logoColor=fff&label=0.4.7)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-aura)
[![PyPI](https://img.shields.io/badge/0.4.7-3775A9?logo=pypi&logoColor=fff&label=mcp-neo4j-aura-manager)](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-cloud-aura-api)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-aura/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-aura&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_ID%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-aura%3A0.4.7%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Managing Neo4j Aura database instances through the Neo4j Aura API.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-neo4j-aura-manager original [sources](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-cloud-aura-api).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-neo4j-aura/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/charts/mcp-server-neo4j-aura/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-neo4j-aura-manager run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-neo4j-aura scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `NEO4J_AURA_CLIENT_ID` required to be set
  - `NEO4J_AURA_CLIENT_SECRET` required to be set

For more information and extra configuration you can consult the [package](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-cloud-aura-api) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-aura&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_ID%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-aura%3A0.4.7%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-neo4j-aura": {
        "env": {
          "NEO4J_AURA_CLIENT_ID": "TO_BE_SET",
          "NEO4J_AURA_CLIENT_SECRET": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "NEO4J_AURA_CLIENT_ID",
          "-e",
          "NEO4J_AURA_CLIENT_SECRET",
          "docker.io/acuvity/mcp-server-neo4j-aura:0.4.7"
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
    "acuvity-mcp-server-neo4j-aura": {
      "env": {
        "NEO4J_AURA_CLIENT_ID": "TO_BE_SET",
        "NEO4J_AURA_CLIENT_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_AURA_CLIENT_ID",
        "-e",
        "NEO4J_AURA_CLIENT_SECRET",
        "docker.io/acuvity/mcp-server-neo4j-aura:0.4.7"
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
    "acuvity-mcp-server-neo4j-aura": {
      "env": {
        "NEO4J_AURA_CLIENT_ID": "TO_BE_SET",
        "NEO4J_AURA_CLIENT_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_AURA_CLIENT_ID",
        "-e",
        "NEO4J_AURA_CLIENT_SECRET",
        "docker.io/acuvity/mcp-server-neo4j-aura:0.4.7"
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
    "acuvity-mcp-server-neo4j-aura": {
      "env": {
        "NEO4J_AURA_CLIENT_ID": "TO_BE_SET",
        "NEO4J_AURA_CLIENT_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_AURA_CLIENT_ID",
        "-e",
        "NEO4J_AURA_CLIENT_SECRET",
        "docker.io/acuvity/mcp-server-neo4j-aura:0.4.7"
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
    "acuvity-mcp-server-neo4j-aura": {
      "env": {
        "NEO4J_AURA_CLIENT_ID": "TO_BE_SET",
        "NEO4J_AURA_CLIENT_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_AURA_CLIENT_ID",
        "-e",
        "NEO4J_AURA_CLIENT_SECRET",
        "docker.io/acuvity/mcp-server-neo4j-aura:0.4.7"
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
        "env": {"NEO4J_AURA_CLIENT_ID":"TO_BE_SET","NEO4J_AURA_CLIENT_SECRET":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","NEO4J_AURA_CLIENT_ID","-e","NEO4J_AURA_CLIENT_SECRET","docker.io/acuvity/mcp-server-neo4j-aura:0.4.7"]
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
- arguments: `run -i --rm --read-only -e NEO4J_AURA_CLIENT_ID -e NEO4J_AURA_CLIENT_SECRET docker.io/acuvity/mcp-server-neo4j-aura:0.4.7`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e NEO4J_AURA_CLIENT_ID -e NEO4J_AURA_CLIENT_SECRET docker.io/acuvity/mcp-server-neo4j-aura:0.4.7
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-neo4j-aura": {
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
    "acuvity-mcp-server-neo4j-aura": {
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
  - `NEO4J_AURA_CLIENT_ID` secret to be set as secrets.NEO4J_AURA_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `NEO4J_AURA_CLIENT_SECRET` secret to be set as secrets.NEO4J_AURA_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-neo4j-aura --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-neo4j-aura --version 1.0.0
````

Install with helm

```console
helm install mcp-server-neo4j-aura oci://docker.io/acuvity/mcp-server-neo4j-aura --version 1.0.0
```

From there your MCP server mcp-server-neo4j-aura will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-neo4j-aura` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/charts/mcp-server-neo4j-aura/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>list_instances</summary>

**Description**:

```
List all Neo4j Aura database instances.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_instance_details</summary>

**Description**:

```
Get details for one or more Neo4j Aura instances by ID.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_ids | array | not set | Yes
</details>
<details>
<summary>get_instance_by_name</summary>

**Description**:

```
Find a Neo4j Aura instance by name and returns the details including the id.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
</details>
<details>
<summary>create_instance</summary>

**Description**:

```
Create a new Neo4j Aura database instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cloud_provider | string | Cloud provider (gcp, aws, azure) | No
| graph_analytics_plugin | boolean | Whether to enable the graph analytics plugin | No
| memory | integer | Memory allocation in GB | No
| name | string | Name for the new instance | Yes
| region | string | Region for the instance (e.g., 'us-central1') | No
| source_instance_id | any | ID of the source instance to clone from | No
| tenant_id | string | ID of the tenant/project where the instance will be created | Yes
| type | string | Instance type (free-db, professional-db, enterprise-db, or business-critical) | No
| vector_optimized | boolean | Whether the instance is optimized for vector operations | No
</details>
<details>
<summary>update_instance_name</summary>

**Description**:

```
Update the name of a Neo4j Aura instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | not set | Yes
| name | string | not set | Yes
</details>
<details>
<summary>update_instance_memory</summary>

**Description**:

```
Update the memory allocation of a Neo4j Aura instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | not set | Yes
| memory | integer | not set | Yes
</details>
<details>
<summary>update_instance_vector_optimization</summary>

**Description**:

```
Update the vector optimization setting of a Neo4j Aura instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | not set | Yes
| vector_optimized | boolean | not set | Yes
</details>
<details>
<summary>pause_instance</summary>

**Description**:

```
Pause a Neo4j Aura database instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | not set | Yes
</details>
<details>
<summary>resume_instance</summary>

**Description**:

```
Resume a paused Neo4j Aura database instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | not set | Yes
</details>
<details>
<summary>list_tenants</summary>

**Description**:

```
List all Neo4j Aura tenants/projects.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_tenant_details</summary>

**Description**:

```
Get details for a specific Neo4j Aura tenant/project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tenant_id | string | not set | Yes
</details>
<details>
<summary>delete_instance</summary>

**Description**:

```
Delete a Neo4j Aura database instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_instance | description | cda7c1db08aa20e8065f9cb6edfe5ba9eaa8e5dec2f39c26f7158732779a4ba7 |
| tools | create_instance | cloud_provider | 00d1bc80b1bfd822ea5c1f8841ba1bc8c11cb3872f4bc3a7089d58e2ebec92cd |
| tools | create_instance | graph_analytics_plugin | 8def195900bd8092ba29750fa754825d8732135258bef2f61da505919f012f7c |
| tools | create_instance | memory | 5b2ea7b2a454958e52b4bb1513010c83ff79c6eccc9180221ee33571caffafe5 |
| tools | create_instance | name | 54081da08d575df2e4d41e44cee48e790231cd11f98d222f82bafe8e09408d8b |
| tools | create_instance | region | fbdce11591760c8dd8f61f28d9342201ff2228bdf4258b81711683dac1ddff60 |
| tools | create_instance | source_instance_id | f3e0124f0c937e4c98a388af9b5578b60c05488096b130ca4f80ac0a1dcd5d95 |
| tools | create_instance | tenant_id | dfa994e46732ff6b54143e71270f8b57753caa63cd48764b7c7b4037f4212d61 |
| tools | create_instance | type | 795b104c7fb6dc0e1bcba17197d90b30ca29a58da40b7dd18f6b154bddf15560 |
| tools | create_instance | vector_optimized | 3fc45809b575c486bc3816eaf08c01eb575c90b1ed9bb48514debb6e8be74c47 |
| tools | delete_instance | description | 97312116025a9aad672154ec5641828d515cf6b1cdb93c0ab8810fb51bdf4adb |
| tools | get_instance_by_name | description | a8c21e30e2dfb21c1596aeaf6e7a19f0a2fcc6b8a78174cabb30ce5d38f027d3 |
| tools | get_instance_details | description | cfe0a42a37e33393f55e7854e7ba6fb675d878937e02fe24bdc131fe18d91112 |
| tools | get_tenant_details | description | b8aac80a67aafacbf96819d1be08504b1e7f9de9460ab4e3c4b3cf014c1682a3 |
| tools | list_instances | description | 8e118ef6cac809436f7d9a2fb46b92c66a66a15867f91d847c80f6b0de54a3cd |
| tools | list_tenants | description | 2a7ff617d01646cd4080734f845d20b4aeee8f879929f3333e353149e9a305e9 |
| tools | pause_instance | description | 6deb01357b18992b3027b651661322805baae9f9a064f7cb4855e3c6002f8661 |
| tools | resume_instance | description | 34ec063622a3610186af0601775073e77ed11d2025a0b8f5bfb33de709694dce |
| tools | update_instance_memory | description | cc62468bbf38c961a02efb30e62b8983eba7b4f7bb2aa6abe6c4f2cbc4fdbbdc |
| tools | update_instance_name | description | 791bde7b4211e7b15fbcc0aafb99e0db332e88924ed3a2359350e32d103ceb22 |
| tools | update_instance_vector_optimization | description | 45a6bd0ff6bbb4c77ba821cac8276692efff7a98d53b7775ffe5e8629d94a7d0 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
