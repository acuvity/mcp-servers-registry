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


# What is mcp-server-mongodb?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-mongodb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-mongodb/0.1.1?logo=docker&logoColor=fff&label=0.1.1)](https://hub.docker.com/r/acuvity/mcp-server-mongodb)
[![PyPI](https://img.shields.io/badge/0.1.1-3775A9?logo=pypi&logoColor=fff&label=mongodb-mcp-server)](https://github.com/mongodb-js/mongodb-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-mongodb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-mongodb%3A0.1.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with MongoDB and MongoDB Atlas.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mongodb-mcp-server original [sources](https://github.com/mongodb-js/mongodb-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-mongodb/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/charts/mcp-server-mongodb/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mongodb-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/charts/mcp-server-mongodb#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-mongodb scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-mongodb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-mongodb%3A0.1.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-mongodb": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "docker.io/acuvity/mcp-server-mongodb:0.1.1"
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
    "acuvity-mcp-server-mongodb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-mongodb:0.1.1"
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
    "acuvity-mcp-server-mongodb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-mongodb:0.1.1"
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
    "acuvity-mcp-server-mongodb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-mongodb:0.1.1"
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
    "acuvity-mcp-server-mongodb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-mongodb:0.1.1"
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
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","docker.io/acuvity/mcp-server-mongodb:0.1.1"]
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
  - `MDB_MCP_API_CLIENT_ID` optional (not set)
  - `MDB_MCP_API_CLIENT_SECRET` optional (not set)
  - `MDB_MCP_CONNECTION_STRING` optional (not set)
  - `MDB_MCP_LOG_PATH` optional (/tmp)


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-mongodb:0.1.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-mongodb:0.1.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-mongodb": {
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
    "acuvity-mcp-server-mongodb": {
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

**Optional Secrets**:
  - `MDB_MCP_API_CLIENT_ID` secret to be set as secrets.MDB_MCP_API_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `MDB_MCP_API_CLIENT_SECRET` secret to be set as secrets.MDB_MCP_API_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `MDB_MCP_CONNECTION_STRING=""` environment variable can be changed with env.MDB_MCP_CONNECTION_STRING=""
  - `MDB_MCP_LOG_PATH="/tmp"` environment variable can be changed with env.MDB_MCP_LOG_PATH="/tmp"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-mongodb --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-mongodb --version 1.0.0
````

Install with helm

```console
helm install mcp-server-mongodb oci://docker.io/acuvity/mcp-server-mongodb --version 1.0.0
```

From there your MCP server mcp-server-mongodb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-mongodb` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mongodb/charts/mcp-server-mongodb/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (31)
<details>
<summary>atlas-list-clusters</summary>

**Description**:

```
List MongoDB Atlas clusters
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectId | string | Atlas project ID to filter clusters | No
</details>
<details>
<summary>atlas-list-projects</summary>

**Description**:

```
List MongoDB Atlas projects
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| orgId | string | Atlas organization ID to filter projects | No
</details>
<details>
<summary>atlas-inspect-cluster</summary>

**Description**:

```
Inspect MongoDB Atlas cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| clusterName | string | Atlas cluster name | Yes
| projectId | string | Atlas project ID | Yes
</details>
<details>
<summary>atlas-create-free-cluster</summary>

**Description**:

```
Create a free MongoDB Atlas cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the cluster | Yes
| projectId | string | Atlas project ID to create the cluster in | Yes
| region | string | Region of the cluster | No
</details>
<details>
<summary>atlas-create-access-list</summary>

**Description**:

```
Allow Ip/CIDR ranges to access your MongoDB Atlas clusters.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cidrBlocks | array | CIDR blocks to allow access from | No
| comment | string | Comment for the access list entries | No
| currentIpAddress | boolean | Add the current IP address | No
| ipAddresses | array | IP addresses to allow access from | No
| projectId | string | Atlas project ID | Yes
</details>
<details>
<summary>atlas-inspect-access-list</summary>

**Description**:

```
Inspect Ip/CIDR ranges with access to your MongoDB Atlas clusters.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectId | string | Atlas project ID | Yes
</details>
<details>
<summary>atlas-list-db-users</summary>

**Description**:

```
List MongoDB Atlas database users
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectId | string | Atlas project ID to filter DB users | Yes
</details>
<details>
<summary>atlas-create-db-user</summary>

**Description**:

```
Create an MongoDB Atlas database user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| clusters | array | Clusters to assign the user to, leave empty for access to all clusters | No
| password | any | Password for the new user. If the user hasn't supplied an explicit password, leave it unset and under no circumstances try to generate a random one. A secure password will be generated by the MCP server if necessary. | No
| projectId | string | Atlas project ID | Yes
| roles | array | Roles for the new user | Yes
| username | string | Username for the new user | Yes
</details>
<details>
<summary>atlas-create-project</summary>

**Description**:

```
Create a MongoDB Atlas project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | Organization ID for the new project | No
| projectName | string | Name for the new project | No
</details>
<details>
<summary>atlas-list-orgs</summary>

**Description**:

```
List MongoDB Atlas organizations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>atlas-connect-cluster</summary>

**Description**:

```
Connect to MongoDB Atlas cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| clusterName | string | Atlas cluster name | Yes
| projectId | string | Atlas project ID | Yes
</details>
<details>
<summary>connect</summary>

**Description**:

```
Connect to a MongoDB instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connectionString | string | MongoDB connection string (in the mongodb:// or mongodb+srv:// format) | Yes
</details>
<details>
<summary>list-collections</summary>

**Description**:

```
List all collections for a given database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Database name | Yes
</details>
<details>
<summary>list-databases</summary>

**Description**:

```
List all databases for a MongoDB connection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>collection-indexes</summary>

**Description**:

```
Describe the indexes for a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
</details>
<details>
<summary>create-index</summary>

**Description**:

```
Create an index for a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| keys | object | The index definition | Yes
| name | string | The name of the index | No
</details>
<details>
<summary>collection-schema</summary>

**Description**:

```
Describe the schema for a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
</details>
<details>
<summary>find</summary>

**Description**:

```
Run a find query against a MongoDB collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| filter | object | The query filter, matching the syntax of the query argument of db.collection.find() | No
| limit | number | The maximum number of documents to return | No
| projection | object | The projection, matching the syntax of the projection argument of db.collection.find() | No
| sort | object | A document, describing the sort order, matching the syntax of the sort argument of cursor.sort() | No
</details>
<details>
<summary>insert-many</summary>

**Description**:

```
Insert an array of documents into a MongoDB collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| documents | array | The array of documents to insert, matching the syntax of the document argument of db.collection.insertMany() | Yes
</details>
<details>
<summary>delete-many</summary>

**Description**:

```
Removes all documents that match the filter from a MongoDB collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| filter | object | The query filter, specifying the deletion criteria. Matches the syntax of the filter argument of db.collection.deleteMany() | No
</details>
<details>
<summary>collection-storage-size</summary>

**Description**:

```
Gets the size of the collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
</details>
<details>
<summary>count</summary>

**Description**:

```
Gets the number of documents in a MongoDB collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| query | object | The query filter to count documents. Matches the syntax of the filter argument of db.collection.count() | No
</details>
<details>
<summary>db-stats</summary>

**Description**:

```
Returns statistics that reflect the use state of a single database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Database name | Yes
</details>
<details>
<summary>aggregate</summary>

**Description**:

```
Run an aggregation against a MongoDB collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| pipeline | array | An array of aggregation stages to execute | Yes
</details>
<details>
<summary>update-many</summary>

**Description**:

```
Updates all documents that match the specified filter for a collection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| filter | object | The selection criteria for the update, matching the syntax of the filter argument of db.collection.updateOne() | No
| update | object | An update document describing the modifications to apply using update operator expressions | Yes
| upsert | boolean | Controls whether to insert a new document if no documents match the filter | No
</details>
<details>
<summary>rename-collection</summary>

**Description**:

```
Renames a collection in a MongoDB database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| dropTarget | boolean | If true, drops the target collection if it exists | No
| newName | string | The new name for the collection | Yes
</details>
<details>
<summary>drop-database</summary>

**Description**:

```
Removes the specified database, deleting the associated data files
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Database name | Yes
</details>
<details>
<summary>drop-collection</summary>

**Description**:

```
Removes a collection or view from the database. The method also removes any indexes associated with the dropped collection.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
</details>
<details>
<summary>explain</summary>

**Description**:

```
Returns statistics describing the execution of the winning plan chosen by the query optimizer for the evaluated method
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
| method | array | The method and its arguments to run | Yes
</details>
<details>
<summary>create-collection</summary>

**Description**:

```
Creates a new collection in a database. If the database doesn't exist, it will be created automatically.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Collection name | Yes
| database | string | Database name | Yes
</details>
<details>
<summary>mongodb-logs</summary>

**Description**:

```
Returns the most recent logged mongod events
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | The maximum number of log entries to return. | No
| type | string | The type of logs to return. Global returns all recent log entries, while startupWarnings returns only warnings and errors from when the process started. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | aggregate | description | 7c33e35f8e93a28e3f0fe43806a3ef8b3c7e954e45a9b503629949058b58da6d |
| tools | aggregate | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | aggregate | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | aggregate | pipeline | 27ad7ca763e787f6fec26d3a8787378ab6e2e07d35f578ec442d1fc97e05e79c |
| tools | atlas-connect-cluster | description | 73c911a3523663e40a7dd95287334349ff06c0d5d6281aeea2f51c573bdd1c4a |
| tools | atlas-connect-cluster | clusterName | 84401bb0fee8476905c5b8abdedaec47d8b71fba3a2f51586359f529387ba1d6 |
| tools | atlas-connect-cluster | projectId | 673b73641c1cc83069b5085bc0958432a2135e1d2046f08fafaabfdb6f5d8be7 |
| tools | atlas-create-access-list | description | 1bb37ff96e17d2a063634d9078ddd9f94a649f02d8f1fc80e0423aa8b7d1f775 |
| tools | atlas-create-access-list | cidrBlocks | 8c412a072a815f33e22120f904b0bdbc3d60a28d056c38599e11923f2869e6a0 |
| tools | atlas-create-access-list | comment | df60393120daf122802df69e5121fbae4321ee2f772e3a306a612ab24cd8f35d |
| tools | atlas-create-access-list | currentIpAddress | 010eabb4ddcf1e557fcc5688b94030be1c61ce58d0881a653efb97a719008f32 |
| tools | atlas-create-access-list | ipAddresses | 8e341a4438c2fa630a28c2c9db263785d910c81f51c806e19d2da7dc5c96793a |
| tools | atlas-create-access-list | projectId | 673b73641c1cc83069b5085bc0958432a2135e1d2046f08fafaabfdb6f5d8be7 |
| tools | atlas-create-db-user | description | 63e925d7d1af974b29a0a1859c040563cda048e78b4a022d360847b1954a9b2a |
| tools | atlas-create-db-user | clusters | 3e672f3305d216843193b9eca68b22281e82f95da0b546d055b3a42c1c6e751c |
| tools | atlas-create-db-user | password | 59e7d907efee9ec1ff073c92e4aaaf84e14d57cda478f3417dba03c9bee9d516 |
| tools | atlas-create-db-user | projectId | 673b73641c1cc83069b5085bc0958432a2135e1d2046f08fafaabfdb6f5d8be7 |
| tools | atlas-create-db-user | roles | 5ecd49e3395921332d584a2014095d61b19cc6b1d1efd1e4dab57cccb1b0f758 |
| tools | atlas-create-db-user | username | 749f2783331f8f8b1ed47ca2efafb9f95fbf8e7cea1c6bbe7ddfb001b99b6ae1 |
| tools | atlas-create-free-cluster | description | 96099ef302a60116026045630690331fb73d8e48dbcba63222593b7e2a35e1d5 |
| tools | atlas-create-free-cluster | name | e9cbbfe81ae8be7629ca2f2f0c24f6e8287cc32bb16190d7574fcfcea073b362 |
| tools | atlas-create-free-cluster | projectId | 3f511b8d632f34fcd87f2bf8ecc7e172f2f076c57a10c9a0130b60e204aa248f |
| tools | atlas-create-free-cluster | region | b445c439a972b11f49241cbe21832a2c049ca7ed2bf3f9c31a2204d15a01ce58 |
| tools | atlas-create-project | description | 651632a71133e3763871452451d31ed072a84541b767990d8ec57e053db6ed77 |
| tools | atlas-create-project | organizationId | 6a49f322852d78f290228ab041298c33e8576c5104ee1a293f5431477b51a104 |
| tools | atlas-create-project | projectName | e3be152a7ce0095661fba852aa1cf0beaae95afc517a7fa6b370e6d08adde4bf |
| tools | atlas-inspect-access-list | description | e0ba493bdd0e65272159df9d2658d5a07db54174cafb33ce77eed7265772e4d9 |
| tools | atlas-inspect-access-list | projectId | 673b73641c1cc83069b5085bc0958432a2135e1d2046f08fafaabfdb6f5d8be7 |
| tools | atlas-inspect-cluster | description | 96bf62bb54a98763c2cc9ff89dc1adf6b2606e61740d17443e3077c209e5bc4a |
| tools | atlas-inspect-cluster | clusterName | 84401bb0fee8476905c5b8abdedaec47d8b71fba3a2f51586359f529387ba1d6 |
| tools | atlas-inspect-cluster | projectId | 673b73641c1cc83069b5085bc0958432a2135e1d2046f08fafaabfdb6f5d8be7 |
| tools | atlas-list-clusters | description | 933e808f45921106ae79ae39a7d14b271ceb9f17b1ee146bd6a157e3210e5a4e |
| tools | atlas-list-clusters | projectId | 4e0d80300fa127a05d4756f43b01c95d670686917640c9bd356ac706761d2aa0 |
| tools | atlas-list-db-users | description | a87af628f8b9dd78c39e782b9c0b329789fd5b8c40ead37293ac56435c6e7b9f |
| tools | atlas-list-db-users | projectId | 9d22c31d2fd1b62f7a29503999b9008babec4c5b650f93ca014ab7b91cfab9b2 |
| tools | atlas-list-orgs | description | 2875dc9dc072ede4309236358ee1157b56d7844697f6fb0c97f47e901a4d3350 |
| tools | atlas-list-projects | description | 2aade686db4b68c563d4d92fd3ebbdec6182872d7cba0b2240b59499a76b6d0c |
| tools | atlas-list-projects | orgId | 94334eae10c86525ac572b4a85af34234a8c6c8464f5ef679723e167f5984450 |
| tools | collection-indexes | description | e34678b2f5b471acef7d7a01c928ab5d845e62286b43d5e47cee658cd6458e50 |
| tools | collection-indexes | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | collection-indexes | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | collection-schema | description | 4344ff2ecc4cc69c2d08beb2e2122c9ad2d3d2d97b42e94781bd0d556022dd19 |
| tools | collection-schema | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | collection-schema | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | collection-storage-size | description | 04d5d714e34265b918b4e90d310c25bc8683772027386d46e3f60e6f6ed52c76 |
| tools | collection-storage-size | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | collection-storage-size | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | connect | description | c0302f33ba275defdb23f2ed6f0d7942191fac240321b74f72432ee5a3ffa38e |
| tools | connect | connectionString | fd7eb15e287b7ff1b7aba3cf0ce4d3c9dfa9148c550733abe061f6bda209d664 |
| tools | count | description | aec7af22beb8e177a4f065486874a8ef89f07c2c2a432886198c552592fb1331 |
| tools | count | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | count | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | count | query | a2b23da54046b968f4a2f3f415c951c53306174788f60490324a31d865b38d62 |
| tools | create-collection | description | 0b220de070e59dc89b5d6993189ff7ba37b80752979af5577d28a879a6c8a253 |
| tools | create-collection | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | create-collection | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | create-index | description | 4dc4db5b4986bf794405ca28f87a156e8151da9580190a7f0ce9490225198088 |
| tools | create-index | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | create-index | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | create-index | keys | 9ea95393019f15541c12d92ae971ac8e77df2f306370ba8054ee544e07d33e9f |
| tools | create-index | name | e409895d5cae55916d29baf634d8914c4d798bdc0636f5b35ca143006a4e3611 |
| tools | db-stats | description | f31d0d52286936349c4e1a2933b15bd1a913f452fe954d3950d1c13cb6d95bd2 |
| tools | db-stats | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | delete-many | description | e56c0e98fe5d20c30ad5a63569227e74098e66275c8ae9d388ecf53cf0bb8084 |
| tools | delete-many | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | delete-many | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | delete-many | filter | 98e24907fa4a4a21da97a19bb4bf3fee4b14f64383acb00deae2cfbcceacfe6c |
| tools | drop-collection | description | e7ca8d90dfc95bfaf23a5ded7dd316bfce5165f92adbb7d29ba6ec5c5cdfb686 |
| tools | drop-collection | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | drop-collection | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | drop-database | description | 54ce8023061b52d7f0b1d74eb6a8e8387d331978a8d7f27a131fb3e68814c677 |
| tools | drop-database | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | explain | description | b60101adbc07e7ba014cc046f6b35b145b5de53b886dfc0a4ce91bf65788ef9a |
| tools | explain | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | explain | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | explain | method | 700e30906f13235c995bc893d7096f03c11cbe235e06882ef3607d151da58a8d |
| tools | find | description | 1b1bfb95a87932ced499cd96d5774c0e5658fab3e71663a8ba28a2995e38a68e |
| tools | find | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | find | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | find | filter | 4d7299ad9c6c13ba6874010101017ce04ea8722513cbb1757f5e09596110df7b |
| tools | find | limit | 795258ccedc518ceb955d76cc21fe131da9668379b8aa5ce5e5b9f4a002a49fd |
| tools | find | projection | 2a1cb62a18517e56d059a18cf5553b27fa1adc38b8fe553b57d8e95556c22445 |
| tools | find | sort | 82431ec7a4424a135fa564ec0a8c65677f037e501f43e415dd20d29e45f66783 |
| tools | insert-many | description | 3998ae6353c8f21ae8ad473d68c48fa45e979b10e83a2e65e409c24ab58e0024 |
| tools | insert-many | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | insert-many | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | insert-many | documents | 0de35e2bbb702fd1ce22806dfa1a3801d51278fd3d6f8f8c392785591fabaf81 |
| tools | list-collections | description | 657eee50274204a7d197a0c94585ccf6efbedbba35b6d56345d4e5df2a6c9e92 |
| tools | list-collections | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | list-databases | description | d71fe372bc4b696845ebfb882f555593b7812582ce3d208e34c2abd68d1fddc8 |
| tools | mongodb-logs | description | 29da3b950d5f996c194287c87584aa72792605fb40ffe5598e4ae61809882c99 |
| tools | mongodb-logs | limit | c305174839ef8cc4ea03686bffe0010efcb67eba07cc84b64243671c47454947 |
| tools | mongodb-logs | type | 056b0738b88d46afc836af1a70177092adbcb044248c83dfe0ed210f265096df |
| tools | rename-collection | description | eab70bf037ca73372d72442f176699a1084c5526b22ce2ce0058ab66d70e222a |
| tools | rename-collection | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | rename-collection | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | rename-collection | dropTarget | 8c087c00650afe15fe38a1ea3e67b50caf73be0f1fe5e58d1795152a29ca893a |
| tools | rename-collection | newName | 485aef2a149cb6edb4fc24296f0251655ee0159c11e40e8578feac45ac57a0c3 |
| tools | update-many | description | 13dac4d056cdbf7e1bee7293950e8b8f3748e883e0ad609a8375581ca89df3ed |
| tools | update-many | collection | 922214922b48f09e732a98c94e2f91391f0e4782749b280d909ee4d726492883 |
| tools | update-many | database | e97a0773fb7b656c174155270bd9ded70bc82caa0fc5d65b3ba24871577a5b08 |
| tools | update-many | filter | d2f2d3c206e3228942c2e8a532376af1d3301ed846f2e108efb28c9b11743b79 |
| tools | update-many | update | 50076f98d33cd1eee87157e40977786a349cf0834a58835f24d73b4d5e752fe0 |
| tools | update-many | upsert | 7c14ab6919eb180bb8ed1cb54db41179c42433cd0c5e9e864d7e68a2bc21670f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
