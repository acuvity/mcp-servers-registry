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


# What is mcp-server-neo4j-aura?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-aura/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-neo4j-aura/0.2.2?logo=docker&logoColor=fff&label=0.2.2)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-aura)
[![PyPI](https://img.shields.io/badge/0.2.2-3775A9?logo=pypi&logoColor=fff&label=mcp-neo4j-aura-manager)](https://github.com/neo4j-contrib/mcp-neo4j)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-aura&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_ID%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-aura%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Managing Neo4j Aura database instances through the Neo4j Aura API.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-neo4j-aura-manager original [sources](https://github.com/neo4j-contrib/mcp-neo4j).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-neo4j-aura/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/charts/mcp-server-neo4j-aura/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-neo4j-aura-manager run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-aura/charts/mcp-server-neo4j-aura#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-neo4j-aura scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-aura&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_ID%22%2C%22-e%22%2C%22NEO4J_AURA_CLIENT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-aura%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-neo4j-aura:0.2.2"
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
        "docker.io/acuvity/mcp-server-neo4j-aura:0.2.2"
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
        "docker.io/acuvity/mcp-server-neo4j-aura:0.2.2"
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
        "docker.io/acuvity/mcp-server-neo4j-aura:0.2.2"
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
        "docker.io/acuvity/mcp-server-neo4j-aura:0.2.2"
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
        "args": ["run","-i","--rm","--read-only","-e","NEO4J_AURA_CLIENT_ID","-e","NEO4J_AURA_CLIENT_SECRET","docker.io/acuvity/mcp-server-neo4j-aura:0.2.2"]
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
  - `NEO4J_AURA_CLIENT_ID` required to be set
  - `NEO4J_AURA_CLIENT_SECRET` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e NEO4J_AURA_CLIENT_ID -e NEO4J_AURA_CLIENT_SECRET docker.io/acuvity/mcp-server-neo4j-aura:0.2.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e NEO4J_AURA_CLIENT_ID -e NEO4J_AURA_CLIENT_SECRET docker.io/acuvity/mcp-server-neo4j-aura:0.2.2
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

## 🛡️ Runtime security

**Guardrails:**

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.

**Basic Authentication:**

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

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
List all Neo4j Aura database instances
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_instance_details</summary>

**Description**:

```
Get details for one or more Neo4j Aura instances by ID, including status, region, memory, storage
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_ids | array | List of instance IDs to retrieve | Yes
</details>
<details>
<summary>get_instance_by_name</summary>

**Description**:

```
Find a Neo4j Aura instance by name and returns the details including the id
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the instance to find | Yes
</details>
<details>
<summary>create_instance</summary>

**Description**:

```
Create a new Neo4j Aura database instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cloud_provider | string | Cloud provider (gcp, aws, azure) | No
| graph_analytics_plugin | boolean | Whether to enable the graph analytics plugin | No
| memory | integer | Memory allocation in GB | No
| name | string | Name for the new instance | Yes
| region | string | Region for the instance (e.g., 'us-central1') | No
| source_instance_id | string | ID of the source instance to clone from (for professional/enterprise instances) | No
| tenant_id | string | ID of the tenant/project where the instance will be created | Yes
| type | string | Instance type (free-db, professional-db, enterprise-db, or business-critical) | No
| vector_optimized | boolean | Whether the instance is optimized for vector operations. Only allowed for instance with more than 4GB memory. | No
</details>
<details>
<summary>update_instance_name</summary>

**Description**:

```
Update the name of a Neo4j Aura instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | ID of the instance to update | Yes
| name | string | New name for the instance | Yes
</details>
<details>
<summary>update_instance_memory</summary>

**Description**:

```
Update the memory allocation of a Neo4j Aura instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | ID of the instance to update | Yes
| memory | integer | New memory allocation in GB | Yes
</details>
<details>
<summary>update_instance_vector_optimization</summary>

**Description**:

```
Update the vector optimization setting of a Neo4j Aura instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | ID of the instance to update | Yes
| vector_optimized | boolean | Whether the instance should be optimized for vector operations | Yes
</details>
<details>
<summary>pause_instance</summary>

**Description**:

```
Pause a Neo4j Aura database instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | ID of the instance to pause | Yes
</details>
<details>
<summary>resume_instance</summary>

**Description**:

```
Resume a paused Neo4j Aura database instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | ID of the instance to resume | Yes
</details>
<details>
<summary>list_tenants</summary>

**Description**:

```
List all Neo4j Aura tenants/projects
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_tenant_details</summary>

**Description**:

```
Get details for a specific Neo4j Aura tenant/project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tenant_id | string | ID of the tenant/project to retrieve | Yes
</details>
<details>
<summary>delete_instance</summary>

**Description**:

```
Delete a Neo4j Aura database instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| instance_id | string | ID of the instance to delete | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_instance | description | 80baa44396ebd55ced1067aedbe903b272b25cf774e4b8522abfffaa28e2c55a |
| tools | create_instance | cloud_provider | 00d1bc80b1bfd822ea5c1f8841ba1bc8c11cb3872f4bc3a7089d58e2ebec92cd |
| tools | create_instance | graph_analytics_plugin | 8def195900bd8092ba29750fa754825d8732135258bef2f61da505919f012f7c |
| tools | create_instance | memory | 5b2ea7b2a454958e52b4bb1513010c83ff79c6eccc9180221ee33571caffafe5 |
| tools | create_instance | name | 54081da08d575df2e4d41e44cee48e790231cd11f98d222f82bafe8e09408d8b |
| tools | create_instance | region | fbdce11591760c8dd8f61f28d9342201ff2228bdf4258b81711683dac1ddff60 |
| tools | create_instance | source_instance_id | 85223e99df4b3a9f2a230a517160a7be5c18f56032404876608554944507f8ca |
| tools | create_instance | tenant_id | dfa994e46732ff6b54143e71270f8b57753caa63cd48764b7c7b4037f4212d61 |
| tools | create_instance | type | 795b104c7fb6dc0e1bcba17197d90b30ca29a58da40b7dd18f6b154bddf15560 |
| tools | create_instance | vector_optimized | fb3d968e2e38bf593a1a0e1f1fb3371636a54c40e73ce27e76940c150bc82f88 |
| tools | delete_instance | description | 3cba481e98eebe78fd76d167f88545b184dd1b4587c03cf6aa8baaa47bc23c48 |
| tools | delete_instance | instance_id | 0a25da80c5a471e9002a0867d66b6a2621f0002680dff72739dc2ef142edb2fd |
| tools | get_instance_by_name | description | 7a7156771d31815248f8b0b7c3c68fceaab6ee42ebd83de066e2b48c5956915a |
| tools | get_instance_by_name | name | 839fdf3f92f8f921b27c78e40b7fdfeef0d50d0939c7fc024c480735c5d9f847 |
| tools | get_instance_details | description | d1a9b3bb0746ae9983034431321f4dd6180d1539eb8f863fc7efd0c81c8a0440 |
| tools | get_instance_details | instance_ids | dbed060556c31b6f6e11bca2713196252d25097e68ccd2213d3ea9781caa859e |
| tools | get_tenant_details | description | c745e698b82622715bde20ba647ddcac1456a74562752256a1a48526e8bb5574 |
| tools | get_tenant_details | tenant_id | 36fe884d113dbf24331cf2f9ab13a5c67cc9b2d48368c6c65d87f9ed790b39dc |
| tools | list_instances | description | b5655f2bb53e2587f4d42e912b1d2a3665c8fccef971f85a1a11bfb33299f160 |
| tools | list_tenants | description | 2084e35eb28a90a1441cc16f8a7f26acc1dfacc2420f49057cbf761bfa0374af |
| tools | pause_instance | description | b201aabbdc3e9a711a967284c466b5a8ccc9fa6309eb315ad0b915fe6ff4a2be |
| tools | pause_instance | instance_id | 58e86331f004440a0318f214a1845953886336fd4cad8482b1e1d0aebe999749 |
| tools | resume_instance | description | 35faffdd67b31d1072e17bdf868a59c8e429f46fc9b48bb39735fbbc45c7377c |
| tools | resume_instance | instance_id | 16b1860694e1aa570f5c17cf9868ad9d75edd91db8ca8aa5a115e439077a164a |
| tools | update_instance_memory | description | 0bed1112f1e4df8c5c45be867471ced8048d2b5b106e3d238cb719c28e6509c1 |
| tools | update_instance_memory | instance_id | 03223ffbb84e345ef189a829eb628b38c4d8a3db1c4b80cb0dfe3edc79848b7a |
| tools | update_instance_memory | memory | 0825a63f725396cae160b6955d5b5b8eb1cf1bd50b9404b0c1d0cb2b0b9dbb84 |
| tools | update_instance_name | description | 11861fe155ebba028e5cdf44d3d5a834d9fe5c6b3b76fcc783fcb4cba78ea4e5 |
| tools | update_instance_name | instance_id | 03223ffbb84e345ef189a829eb628b38c4d8a3db1c4b80cb0dfe3edc79848b7a |
| tools | update_instance_name | name | 5af44d472513df51f72e4a2519e1c9edbcd6d9f83e9b3b8d93efa34c671684b5 |
| tools | update_instance_vector_optimization | description | 5160aacb993f5adf974cb1301ff7519234e82bbe0517e497db02f1b3431f0045 |
| tools | update_instance_vector_optimization | instance_id | 03223ffbb84e345ef189a829eb628b38c4d8a3db1c4b80cb0dfe3edc79848b7a |
| tools | update_instance_vector_optimization | vector_optimized | f1073ddf891723d499365366da70e89d16a6b7b6bd000a9e7c24eb49600e25fd |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
