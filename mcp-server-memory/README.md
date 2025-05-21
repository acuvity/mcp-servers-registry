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


# What is mcp-server-memory?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-memory/2025.4.25?logo=docker&logoColor=fff&label=2025.4.25)](https://hub.docker.com/r/acuvity/mcp-server-memory)
[![PyPI](https://img.shields.io/badge/2025.4.25-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-memory)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-memory/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22memory%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-memory%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for enabling memory for Claude through a knowledge graph

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @modelcontextprotocol/server-memory original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-memory/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-memory/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-memory/charts/mcp-server-memory/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-memory run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-memory/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-memory scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

**Environment variables and secrets:**
  - `MEMORY_FILE_PATH` optional (/data/default.json)
**Required volumes or mountPaths:**
  - data to be mounted on `/data`

For more information and extra configuration you can consult the [package](https://modelcontextprotocol.io) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22memory%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-memory%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-memory": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-v",
          "memory:/data",
          "docker.io/acuvity/mcp-server-memory:2025.4.25"
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-memory:2025.4.25"
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-memory:2025.4.25"
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-memory:2025.4.25"
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
    "acuvity-mcp-server-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-memory:2025.4.25"
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
        "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-memory:2025.4.25"]
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
- arguments: `run -i --rm --read-only -v memory:/data docker.io/acuvity/mcp-server-memory:2025.4.25`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -v memory:/data docker.io/acuvity/mcp-server-memory:2025.4.25
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-memory": {
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
    "acuvity-mcp-server-memory": {
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

### Chart storage requirement

This chart will be deployed as a `StatefulSet` as the server requires access to persistent storage.

You will have to configure the storage settings for:
  - `storage.memory.class` with a proper storage class
  - `storage.memory.size` with a proper storage size

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Optional Environment variables**:
  - `MEMORY_FILE_PATH="/data/default.json"` environment variable can be changed with env.MEMORY_FILE_PATH="/data/default.json"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-memory --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-memory --version 1.0.0
````

Install with helm

```console
helm install mcp-server-memory oci://docker.io/acuvity/mcp-server-memory --version 1.0.0
```

From there your MCP server mcp-server-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-memory` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-memory/charts/mcp-server-memory/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>create_entities</summary>

**Description**:

```
Create multiple new entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entities | array | not set | Yes
</details>
<details>
<summary>create_relations</summary>

**Description**:

```
Create multiple new relations between entities in the knowledge graph. Relations should be in active voice
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | not set | Yes
</details>
<details>
<summary>add_observations</summary>

**Description**:

```
Add new observations to existing entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| observations | array | not set | Yes
</details>
<details>
<summary>delete_entities</summary>

**Description**:

```
Delete multiple entities and their associated relations from the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entityNames | array | An array of entity names to delete | Yes
</details>
<details>
<summary>delete_observations</summary>

**Description**:

```
Delete specific observations from entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| deletions | array | not set | Yes
</details>
<details>
<summary>delete_relations</summary>

**Description**:

```
Delete multiple relations from the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | An array of relations to delete | Yes
</details>
<details>
<summary>read_graph</summary>

**Description**:

```
Read the entire knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>search_nodes</summary>

**Description**:

```
Search for nodes in the knowledge graph based on a query
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The search query to match against entity names, types, and observation content | Yes
</details>
<details>
<summary>open_nodes</summary>

**Description**:

```
Open specific nodes in the knowledge graph by their names
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| names | array | An array of entity names to retrieve | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_observations | description | f66d1982a935c25deae16641b447a894687858da5f4e56a4ffd5eded9f15287b |
| tools | create_entities | description | 5d2cd1d3e5d4ea6fd952e9568d41dd54e18c1c5a611daffe1c0399ebc57444e1 |
| tools | create_relations | description | eeb160c5595ea67cee737ea4d34dcf3d22b3d316e107d1edcf02d1dc71727f37 |
| tools | delete_entities | description | 4e8ad2271cd9cfd21a213070f051534e2fb5c6723d7f5d2eed86c9a2f41b05c2 |
| tools | delete_entities | entityNames | a927153ab95010896fc74cf8f26a9c7bc3e840e7aaf9fc7f15866c3525873ab2 |
| tools | delete_observations | description | bae5684867bc99aa4c62c3cb29dccb386983e7575a910a8be7d13ea023aafd80 |
| tools | delete_relations | description | 1b07436348ac9732db58c69ed4db4dbebed012fd263851e1ee4e35e86fe0968e |
| tools | delete_relations | relations | 16642cf152c4f981edf60e0064e4fa10410158457a438a63b60c21c1c4beb5c9 |
| tools | open_nodes | description | 0a799b2e13cab0744fe6b8dd3dbacf7e04753376fdf0adb9d9b6821ad853eded |
| tools | open_nodes | names | 7275b2ac1cb2f632b23e78c872c589a8489cda3a5306f3b399dce23ca813e3ca |
| tools | read_graph | description | 1dfb0bb4dcfe39f92a8a0464153263a3d836524a3c8fd9ff3f73be5ecb2a098c |
| tools | search_nodes | description | cdd54c52fcef34587fc903df13b58b02371a9fb2390cab93d0eeabd229c479f3 |
| tools | search_nodes | query | 2be985b738ac91d8f1e6039cc46c99b96b49b912c19eefccf337c0fc89173cff |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
