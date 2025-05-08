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


# What is mcp-server-gitlab?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-gitlab/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-gitlab/2025.4.25?logo=docker&logoColor=fff&label=2025.4.25)](https://hub.docker.com/r/acuvity/mcp-server-gitlab)
[![PyPI](https://img.shields.io/badge/2025.4.25-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-gitlab)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-gitlab&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GITLAB_PERSONAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-gitlab%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for using the GitLab API

> [!NOTE]
> `mcp-server-gitlab` has been packaged by Acuvity from @modelcontextprotocol/server-gitlab original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-gitlab run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a built-in Rego policy that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

</details>

> [!NOTE]
> All guardrails start disabled. You can switch each one on or off individually, so you only activate the protections your environment requires.


# 📦 How to Use


> [!NOTE]
> Given mcp-server-gitlab scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-gitlab&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GITLAB_PERSONAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-gitlab%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-gitlab": {
        "env": {
          "GITLAB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "GITLAB_PERSONAL_ACCESS_TOKEN",
          "docker.io/acuvity/mcp-server-gitlab:2025.4.25"
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
    "acuvity-mcp-server-gitlab": {
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITLAB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-gitlab:2025.4.25"
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
    "acuvity-mcp-server-gitlab": {
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITLAB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-gitlab:2025.4.25"
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
    "acuvity-mcp-server-gitlab": {
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITLAB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-gitlab:2025.4.25"
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
    "acuvity-mcp-server-gitlab": {
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITLAB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-gitlab:2025.4.25"
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
        "env": {"GITLAB_PERSONAL_ACCESS_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","GITLAB_PERSONAL_ACCESS_TOKEN","docker.io/acuvity/mcp-server-gitlab:2025.4.25"]
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
  - `GITLAB_API_URL` optional (not set)
  - `GITLAB_PERSONAL_ACCESS_TOKEN` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e GITLAB_PERSONAL_ACCESS_TOKEN docker.io/acuvity/mcp-server-gitlab:2025.4.25`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e GITLAB_PERSONAL_ACCESS_TOKEN docker.io/acuvity/mcp-server-gitlab:2025.4.25
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-gitlab": {
      "url": "http://localhost:<localport>/sse",
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
    "acuvity-mcp-server-gitlab": {
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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

for example, `-e GUARDRAILS="secrets-redaction covert-instruction-detection"` will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


To turn on Basic Authentication, set BASIC_AUTH_SECRET like `- e BASIC_AUTH_SECRET="supersecret`

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
  - `GITLAB_PERSONAL_ACCESS_TOKEN` secret to be set as secrets.GITLAB_PERSONAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `GITLAB_API_URL=""` environment variable can be changed with env.GITLAB_API_URL=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
````

Install with helm

```console
helm install mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
```

From there your MCP server mcp-server-gitlab will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-gitlab` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/charts/mcp-server-gitlab/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>create_or_update_file</summary>

**Description**:

```
Create or update a single file in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to create/update the file in | Yes
| commit_message | string | Commit message | Yes
| content | string | Content of the file | Yes
| file_path | string | Path where to create/update the file | Yes
| previous_path | string | Path of the file to move/rename | No
| project_id | string | Project ID or URL-encoded path | Yes
</details>
<details>
<summary>search_repositories</summary>

**Description**:

```
Search for GitLab projects
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for pagination (default: 1) | No
| per_page | number | Number of results per page (default: 20) | No
| search | string | Search query | Yes
</details>
<details>
<summary>create_repository</summary>

**Description**:

```
Create a new GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | Repository description | No
| initialize_with_readme | boolean | Initialize with README.md | No
| name | string | Repository name | Yes
| visibility | string | Repository visibility level | No
</details>
<details>
<summary>get_file_contents</summary>

**Description**:

```
Get the contents of a file or directory from a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | Path to the file or directory | Yes
| project_id | string | Project ID or URL-encoded path | Yes
| ref | string | Branch/tag/commit to get contents from | No
</details>
<details>
<summary>push_files</summary>

**Description**:

```
Push multiple files to a GitLab project in a single commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to push to | Yes
| commit_message | string | Commit message | Yes
| files | array | Array of files to push | Yes
| project_id | string | Project ID or URL-encoded path | Yes
</details>
<details>
<summary>create_issue</summary>

**Description**:

```
Create a new issue in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee_ids | array | Array of user IDs to assign | No
| description | string | Issue description | No
| labels | array | Array of label names | No
| milestone_id | number | Milestone ID to assign | No
| project_id | string | Project ID or URL-encoded path | Yes
| title | string | Issue title | Yes
</details>
<details>
<summary>create_merge_request</summary>

**Description**:

```
Create a new merge request in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allow_collaboration | boolean | Allow commits from upstream members | No
| description | string | Merge request description | No
| draft | boolean | Create as draft merge request | No
| project_id | string | Project ID or URL-encoded path | Yes
| source_branch | string | Branch containing changes | Yes
| target_branch | string | Branch to merge into | Yes
| title | string | Merge request title | Yes
</details>
<details>
<summary>fork_repository</summary>

**Description**:

```
Fork a GitLab project to your account or specified namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| namespace | string | Namespace to fork to (full path) | No
| project_id | string | Project ID or URL-encoded path | Yes
</details>
<details>
<summary>create_branch</summary>

**Description**:

```
Create a new branch in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Name for the new branch | Yes
| project_id | string | Project ID or URL-encoded path | Yes
| ref | string | Source branch/commit for new branch | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_branch | description | 370c8fdea4b4ed2c01e13aa6c698e1e547b27bc86998317a904dfe007c640d3b |
| tools | create_branch | branch | 4c318264c967c58971b8a1e0f74375753c460aafb016099268c365625e14b475 |
| tools | create_branch | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_branch | ref | 5fe6a4648ba2c040d592f76e6a1e3b06e058613def274087239e5477e963a651 |
| tools | create_issue | description | 67bd8b1d40a0d879f02ae6df3e7a032e9f67d8185ff96a946b6407a8da74676d |
| tools | create_issue | assignee_ids | b1e95a9a21177c02ec9b67f5619cdf261c9226a4b06fc7ccc1baaaa0ff179af3 |
| tools | create_issue | description | 6fdf4c7fb5a19e122d009b8deed663a56034d8170be9300906c4368c423da250 |
| tools | create_issue | labels | 73e3d3cb50073e91dd598b8c1c00a632d01907f339ed5228197a3d82bd0e1bfd |
| tools | create_issue | milestone_id | 0d1caf40d22dd8764da4abbb92bc5c803236c1b08b4844722a165ce185ea75ea |
| tools | create_issue | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_issue | title | baebb0f722db7150e454ecfb2d432205f6331d57837328637d25ac8413f84644 |
| tools | create_merge_request | description | 2c412a96dcbe413da1ec4527c917ada4201af860c44f3db3a3f0fdf7d5b6846a |
| tools | create_merge_request | allow_collaboration | 79eebf7e7bdf597f123e7d7ce6f7638205f5e21c1d0b62dadbe27b9c4ed68beb |
| tools | create_merge_request | description | 6ee8d87260dcfc89cd9f7aefb2c9309137a659c7bcff8f6f101326b0061218aa |
| tools | create_merge_request | draft | b5890bf1f6c20cd8a358d093142e2d69c59507b4bbdad8c01917649070c5daf6 |
| tools | create_merge_request | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_merge_request | source_branch | f30a2f6fcdb7af894b1cd42fd17f7651a3e9de4c432a615fe383235d8822d669 |
| tools | create_merge_request | target_branch | 68d3d352a8e9b1b21daef0144ddbd5ebbfdfafa1c150afd9184f2889aeba0f54 |
| tools | create_merge_request | title | 009fb5b5349f3ea12220e3d5a8d86edd8c975c1be01feba848bb14d4823ac9e4 |
| tools | create_or_update_file | description | 5a9d17ef2e130c8ce70a42df7f712b4ae8858b25754dd52c2a5f7a26c14cb9c3 |
| tools | create_or_update_file | branch | d6a5e87fe732d76cc378c1d1f1210e9b2deb75c9a0dc93b4e453bd5681e9ebe9 |
| tools | create_or_update_file | commit_message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | create_or_update_file | content | 651936dc46e2fa051b60ccb3cbfe9f87f0f58f41773e79b4839a814525a7d688 |
| tools | create_or_update_file | file_path | c57e5f48646295c4493f5d052c3ce4d46f88f8c963d162f44c187ff5defa6791 |
| tools | create_or_update_file | previous_path | cf397a18416cb0b87c38f5dfff95b3ba924af348310612cb5cce0bd3a472bfc4 |
| tools | create_or_update_file | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_repository | description | 1d98765246028af2aabc6e3d9257883b4b744bb9b352cd8396c5466306c468f9 |
| tools | create_repository | description | 2b96b72a003b28027236e3a9d7b66958233d752e92381122915202c3c00f6058 |
| tools | create_repository | initialize_with_readme | 7e2901b2f7514bf8332f7e21b39c372da2839884a4f6f497fc38ba9783044538 |
| tools | create_repository | name | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_repository | visibility | c184fe837e436f41e9f8c51f845c35976bc65dcb9ee55c21dccbda312d38410b |
| tools | fork_repository | description | a12e1d457b0dddd2646db05db4abc33f10d2d9e7d85108510a70effce2175e63 |
| tools | fork_repository | namespace | 1745a33a34c4b0df0dff3502345eb24b9df73588ec9c93253a72a38e29264f88 |
| tools | fork_repository | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | get_file_contents | description | ff1b95763ce6d2fc775ed4fe3f8e654b9d2f12d80fa2ccad22f5ae9186ba2310 |
| tools | get_file_contents | file_path | 52efab3f41db809584fb319e63956f45cdcc3a67736a23ea06daaa495c975658 |
| tools | get_file_contents | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | get_file_contents | ref | d437b023475af49fe4753ed5eeb9f0f4331f914caa7cb9e61224c77758da1541 |
| tools | push_files | description | bd07cf006dbb6be775064074a39533c7494f70a2e56eea1b4f530e4feee038ba |
| tools | push_files | branch | 903fd236be715d2d2dabe8871e567bebdb55a876b1f9b4db0c49400e3b944e01 |
| tools | push_files | commit_message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | push_files | files | a9c47d470281bded4c57e1c0278bbc153c1d133c163a1cf7d5da6b9920ccbe3f |
| tools | push_files | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | search_repositories | description | 7fab15409bf7d2f9911d7cde2a71fdbba5449c8e39f032f37d86feb8b2f33755 |
| tools | search_repositories | page | 72a453385ec021aacde1c9dedd043203bf0244b3414156f8e9455eca78907d8b |
| tools | search_repositories | per_page | 7ab4ede2b5836fe3c170dedd1d2cc91073be26a72af9f1590c05b35f0447ed18 |
| tools | search_repositories | search | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
