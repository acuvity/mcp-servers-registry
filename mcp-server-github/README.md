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


# What is mcp-server-github?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-github/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-github/v0.29.0?logo=docker&logoColor=fff&label=v0.29.0)](https://hub.docker.com/r/acuvity/mcp-server-github)
[![GitHUB](https://img.shields.io/badge/v0.29.0-3775A9?logo=github&logoColor=fff&label=github/github-mcp-server)](https://github.com/github/github-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-github/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-github&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GITHUB_PERSONAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-github%3Av0.29.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** GitHub's official MCP Server

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from github/github-mcp-server original [sources](https://github.com/github/github-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-github/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/charts/mcp-server-github/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure github/github-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-github scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `GITHUB_PERSONAL_ACCESS_TOKEN` required to be set
  - `GITHUB_HOST` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/github/github-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-github&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GITHUB_PERSONAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-github%3Av0.29.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-github": {
        "env": {
          "GITHUB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "GITHUB_PERSONAL_ACCESS_TOKEN",
          "docker.io/acuvity/mcp-server-github:v0.29.0"
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
    "acuvity-mcp-server-github": {
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-github:v0.29.0"
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
    "acuvity-mcp-server-github": {
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-github:v0.29.0"
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
    "acuvity-mcp-server-github": {
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-github:v0.29.0"
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
    "acuvity-mcp-server-github": {
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-github:v0.29.0"
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
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","GITHUB_PERSONAL_ACCESS_TOKEN","docker.io/acuvity/mcp-server-github:v0.29.0"]
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
- arguments: `run -i --rm --read-only -e GITHUB_PERSONAL_ACCESS_TOKEN docker.io/acuvity/mcp-server-github:v0.29.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e GITHUB_PERSONAL_ACCESS_TOKEN docker.io/acuvity/mcp-server-github:v0.29.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-github": {
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
    "acuvity-mcp-server-github": {
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
  - `GITHUB_PERSONAL_ACCESS_TOKEN` secret to be set as secrets.GITHUB_PERSONAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `GITHUB_HOST=""` environment variable can be changed with env.GITHUB_HOST=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-github --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-github --version 1.0.0
````

Install with helm

```console
helm install mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0
```

From there your MCP server mcp-server-github will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-github` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/charts/mcp-server-github/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (40)
<details>
<summary>add_comment_to_pending_review</summary>

**Description**:

```
Add review comment to the requester's latest pending pull request review. A pending review needs to already exist to call this (check with the user if not sure).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | The text of the review comment | Yes
| line | number | The line of the blob in the pull request diff that the comment applies to. For multi-line comments, the last line of the range | No
| owner | string | Repository owner | Yes
| path | string | The relative path to the file that necessitates a comment | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
| side | string | The side of the diff to comment on. LEFT indicates the previous state, RIGHT indicates the new state | No
| startLine | number | For multi-line comments, the first line of the range that the comment applies to | No
| startSide | string | For multi-line comments, the starting side of the diff that the comment applies to. LEFT indicates the previous state, RIGHT indicates the new state | No
| subjectType | string | The level at which the comment is targeted | Yes
</details>
<details>
<summary>add_issue_comment</summary>

**Description**:

```
Add a comment to a specific issue in a GitHub repository. Use this tool to add comments to pull requests as well (in this case pass pull request number as issue_number), but only if user is not asking specifically to add review comments.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | Comment content | Yes
| issue_number | number | Issue number to comment on | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>assign_copilot_to_issue</summary>

**Description**:

```
Assign Copilot to a specific issue in a GitHub repository.

This tool can help with the following outcomes:
- a Pull Request created with source code changes to resolve the issue


More information can be found at:
- https://docs.github.com/en/copilot/using-github-copilot/using-copilot-coding-agent-to-work-on-tasks/about-assigning-tasks-to-copilot

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base_ref | string | Git reference (e.g., branch) that the agent will start its work from. If not specified, defaults to the repository's default branch | No
| custom_instructions | string | Optional custom instructions to guide the agent beyond the issue body. Use this to provide additional context, constraints, or guidance that is not captured in the issue description | No
| issue_number | number | Issue number | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_branch</summary>

**Description**:

```
Create a new branch in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Name for new branch | Yes
| from_branch | string | Source branch (defaults to repo default) | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_or_update_file</summary>

**Description**:

```
Create or update a single file in a GitHub repository. 
If updating, you should provide the SHA of the file you want to update. Use this tool to create or update a file in a GitHub repository remotely; do not use it for local file operations.

In order to obtain the SHA of original file version before updating, use the following git command:
git ls-tree HEAD <path to file>

If the SHA is not provided, the tool will attempt to acquire it by fetching the current file contents from the repository, which may lead to rewriting latest committed changes if the file has changed since last retrieval.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to create/update the file in | Yes
| content | string | Content of the file | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path where to create/update the file | Yes
| repo | string | Repository name | Yes
| sha | string | The blob SHA of the file being replaced. | No
</details>
<details>
<summary>create_pull_request</summary>

**Description**:

```
Create a new pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | Branch to merge into | Yes
| body | string | PR description | No
| draft | boolean | Create as draft PR | No
| head | string | Branch containing changes | Yes
| maintainer_can_modify | boolean | Allow maintainer edits | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| title | string | PR title | Yes
</details>
<details>
<summary>create_repository</summary>

**Description**:

```
Create a new GitHub repository in your account or specified organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| autoInit | boolean | Initialize with README | No
| description | string | Repository description | No
| name | string | Repository name | Yes
| organization | string | Organization to create the repository in (omit to create in your personal account) | No
| private | boolean | Whether repo should be private | No
</details>
<details>
<summary>delete_file</summary>

**Description**:

```
Delete a file from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to delete the file from | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path to the file to delete | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>fork_repository</summary>

**Description**:

```
Fork a GitHub repository to your account or specified organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organization | string | Organization to fork to | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_commit</summary>

**Description**:

```
Get details for a commit from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| include_diff | boolean | Whether to include file diffs and stats in the response. Default is true. | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sha | string | Commit SHA, branch name, or tag name | Yes
</details>
<details>
<summary>get_file_contents</summary>

**Description**:

```
Get the contents of a file or directory from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path to file/directory | No
| ref | string | Accepts optional git refs such as `refs/tags/{tag}`, `refs/heads/{branch}` or `refs/pull/{pr_number}/head` | No
| repo | string | Repository name | Yes
| sha | string | Accepts optional commit SHA. If specified, it will be used instead of ref | No
</details>
<details>
<summary>get_label</summary>

**Description**:

```
Get a specific label from a repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Label name. | Yes
| owner | string | Repository owner (username or organization name) | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_latest_release</summary>

**Description**:

```
Get the latest release in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_me</summary>

**Description**:

```
Get details of the authenticated GitHub user. Use this when a request is about the user's own profile for GitHub. Or when information is missing to build other tool calls.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_release_by_tag</summary>

**Description**:

```
Get a specific release by its tag name in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| tag | string | Tag name (e.g., 'v1.0.0') | Yes
</details>
<details>
<summary>get_tag</summary>

**Description**:

```
Get details about a specific git tag in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| tag | string | Tag name | Yes
</details>
<details>
<summary>get_team_members</summary>

**Description**:

```
Get member usernames of a specific team in an organization. Limited to organizations accessible with current credentials
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org | string | Organization login (owner) that contains the team. | Yes
| team_slug | string | Team slug | Yes
</details>
<details>
<summary>get_teams</summary>

**Description**:

```
Get details of the teams the user is a member of. Limited to organizations accessible with current credentials
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | string | Username to get teams for. If not provided, uses the authenticated user. | No
</details>
<details>
<summary>issue_read</summary>

**Description**:

```
Get information about a specific issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_number | number | The number of the issue | Yes
| method | string | The read operation to perform on a single issue.
Options are:
1. get - Get details of a specific issue.
2. get_comments - Get issue comments.
3. get_sub_issues - Get sub-issues of the issue.
4. get_labels - Get labels assigned to the issue.
 | Yes
| owner | string | The owner of the repository | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | The name of the repository | Yes
</details>
<details>
<summary>issue_write</summary>

**Description**:

```
Create a new or update an existing issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignees | array | Usernames to assign to this issue | No
| body | string | Issue body content | No
| duplicate_of | number | Issue number that this issue is a duplicate of. Only used when state_reason is 'duplicate'. | No
| issue_number | number | Issue number to update | No
| labels | array | Labels to apply to this issue | No
| method | string | Write operation to perform on a single issue.
Options are:
- 'create' - creates a new issue.
- 'update' - updates an existing issue.
 | Yes
| milestone | number | Milestone number | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| state | string | New state | No
| state_reason | string | Reason for the state change. Ignored unless state is changed. | No
| title | string | Issue title | No
| type | string | Type of this issue. Only use if the repository has issue types configured. Use list_issue_types tool to get valid type values for the organization. If the repository doesn't support issue types, omit this parameter. | No
</details>
<details>
<summary>list_branches</summary>

**Description**:

```
List branches in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>list_commits</summary>

**Description**:

```
Get list of commits of a branch in a GitHub repository. Returns at least 30 results per page by default, but can return more if specified using the perPage parameter (up to 100).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| author | string | Author username or email address to filter commits by | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sha | string | Commit SHA, branch or tag name to list commits of. If not provided, uses the default branch of the repository. If a commit SHA is provided, will list commits up to that SHA. | No
</details>
<details>
<summary>list_issue_types</summary>

**Description**:

```
List supported issue types for repository owner (organization).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | The organization owner of the repository | Yes
</details>
<details>
<summary>list_issues</summary>

**Description**:

```
List issues in a GitHub repository. For pagination, use the 'endCursor' from the previous response's 'pageInfo' in the 'after' parameter.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | Cursor for pagination. Use the endCursor from the previous page's PageInfo for GraphQL APIs. | No
| direction | string | Order direction. If provided, the 'orderBy' also needs to be provided. | No
| labels | array | Filter by labels | No
| orderBy | string | Order issues by field. If provided, the 'direction' also needs to be provided. | No
| owner | string | Repository owner | Yes
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| since | string | Filter by date (ISO 8601 timestamp) | No
| state | string | Filter by state, by default both open and closed issues are returned when not provided | No
</details>
<details>
<summary>list_pull_requests</summary>

**Description**:

```
List pull requests in a GitHub repository. If the user specifies an author, then DO NOT use this tool and use the search_pull_requests tool instead.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | Filter by base branch | No
| direction | string | Sort direction | No
| head | string | Filter by head user/org and branch | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sort | string | Sort by | No
| state | string | Filter by state | No
</details>
<details>
<summary>list_releases</summary>

**Description**:

```
List releases in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>list_tags</summary>

**Description**:

```
List git tags in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>merge_pull_request</summary>

**Description**:

```
Merge a pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| commit_message | string | Extra detail for merge commit | No
| commit_title | string | Title for merge commit | No
| merge_method | string | Merge method | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>pull_request_read</summary>

**Description**:

```
Get information on a specific pull request in GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| method | string | Action to specify what pull request data needs to be retrieved from GitHub. 
Possible options: 
 1. get - Get details of a specific pull request.
 2. get_diff - Get the diff of a pull request.
 3. get_status - Get status of a head commit in a pull request. This reflects status of builds and checks.
 4. get_files - Get the list of files changed in a pull request. Use with pagination parameters to control the number of results returned.
 5. get_review_comments - Get review threads on a pull request. Each thread contains logically grouped review comments made on the same code location during pull request reviews. Returns threads with metadata (isResolved, isOutdated, isCollapsed) and their associated comments. Use cursor-based pagination (perPage, after) to control results.
 6. get_reviews - Get the reviews on a pull request. When asked for review comments, use get_review_comments method.
 7. get_comments - Get comments on a pull request. Use this if user doesn't specifically want review comments. Use with pagination parameters to control the number of results returned.
 | Yes
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>pull_request_review_write</summary>

**Description**:

```
Create and/or submit, delete review of a pull request.

Available methods:
- create: Create a new review of a pull request. If "event" parameter is provided, the review is submitted. If "event" is omitted, a pending review is created.
- submit_pending: Submit an existing pending review of a pull request. This requires that a pending review exists for the current user on the specified pull request. The "body" and "event" parameters are used when submitting the review.
- delete_pending: Delete an existing pending review of a pull request. This requires that a pending review exists for the current user on the specified pull request.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | Review comment text | No
| commitID | string | SHA of commit to review | No
| event | string | Review action to perform. | No
| method | string | The write operation to perform on pull request review. | Yes
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>push_files</summary>

**Description**:

```
Push multiple files to a GitHub repository in a single commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to push to | Yes
| files | array | Array of file objects to push, each object with path (string) and content (string) | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>request_copilot_review</summary>

**Description**:

```
Request a GitHub Copilot code review for a pull request. Use this for automated feedback on pull requests, usually before requesting a human reviewer.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>search_code</summary>

**Description**:

```
Fast and precise code search across ALL GitHub repositories using GitHub's native search engine. Best for finding exact symbols, functions, classes, or specific code patterns.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order for results | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | Search query using GitHub's powerful code search syntax. Examples: 'content:Skill language:Java org:github', 'NOT is:archived language:Python OR language:go', 'repo:github/github-mcp-server'. Supports exact matching, language filters, path filters, and more. | Yes
| sort | string | Sort field ('indexed' only) | No
</details>
<details>
<summary>search_issues</summary>

**Description**:

```
Search for issues in GitHub repositories using issues search syntax already scoped to is:issue
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| owner | string | Optional repository owner. If provided with repo, only issues for this repository are listed. | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | Search query using GitHub issues search syntax | Yes
| repo | string | Optional repository name. If provided with owner, only issues for this repository are listed. | No
| sort | string | Sort field by number of matches of categories, defaults to best match | No
</details>
<details>
<summary>search_pull_requests</summary>

**Description**:

```
Search for pull requests in GitHub repositories using issues search syntax already scoped to is:pr
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| owner | string | Optional repository owner. If provided with repo, only pull requests for this repository are listed. | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | Search query using GitHub pull request search syntax | Yes
| repo | string | Optional repository name. If provided with owner, only pull requests for this repository are listed. | No
| sort | string | Sort field by number of matches of categories, defaults to best match | No
</details>
<details>
<summary>search_repositories</summary>

**Description**:

```
Find GitHub repositories by name, description, readme, topics, or other metadata. Perfect for discovering projects, finding examples, or locating specific repositories across GitHub.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| minimal_output | boolean | Return minimal repository information (default: true). When false, returns full GitHub API repository objects. | No
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | Repository search query. Examples: 'machine learning in:name stars:>1000 language:python', 'topic:react', 'user:facebook'. Supports advanced search syntax for precise filtering. | Yes
| sort | string | Sort repositories by field, defaults to best match | No
</details>
<details>
<summary>search_users</summary>

**Description**:

```
Find GitHub users by username, real name, or other profile information. Useful for locating developers, contributors, or team members.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | User search query. Examples: 'john smith', 'location:seattle', 'followers:>100'. Search is automatically scoped to type:user. | Yes
| sort | string | Sort users by number of followers or repositories, or when the person joined GitHub. | No
</details>
<details>
<summary>sub_issue_write</summary>

**Description**:

```
Add a sub-issue to a parent issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after_id | number | The ID of the sub-issue to be prioritized after (either after_id OR before_id should be specified) | No
| before_id | number | The ID of the sub-issue to be prioritized before (either after_id OR before_id should be specified) | No
| issue_number | number | The number of the parent issue | Yes
| method | string | The action to perform on a single sub-issue
Options are:
- 'add' - add a sub-issue to a parent issue in a GitHub repository.
- 'remove' - remove a sub-issue from a parent issue in a GitHub repository.
- 'reprioritize' - change the order of sub-issues within a parent issue in a GitHub repository. Use either 'after_id' or 'before_id' to specify the new position.
				 | Yes
| owner | string | Repository owner | Yes
| replace_parent | boolean | When true, replaces the sub-issue's current parent issue. Use with 'add' method only. | No
| repo | string | Repository name | Yes
| sub_issue_id | number | The ID of the sub-issue to add. ID is not the same as issue number | Yes
</details>
<details>
<summary>update_pull_request</summary>

**Description**:

```
Update an existing pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | New base branch name | No
| body | string | New description | No
| draft | boolean | Mark pull request as draft (true) or ready for review (false) | No
| maintainer_can_modify | boolean | Allow maintainer edits | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number to update | Yes
| repo | string | Repository name | Yes
| reviewers | array | GitHub usernames to request reviews from | No
| state | string | New state | No
| title | string | New title | No
</details>
<details>
<summary>update_pull_request_branch</summary>

**Description**:

```
Update the branch of a pull request with the latest changes from the base branch.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expectedHeadSha | string | The expected SHA of the pull request's HEAD ref | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>

## 📝 Prompts (2)
<details>
<summary>AssignCodingAgent</summary>

**Description**:

```
Assign GitHub Coding Agent to multiple tasks in a GitHub repository.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| repo | The repository to assign tasks in (owner/repo). |Yes |
<details>
<summary>issue_to_fix_workflow</summary>

**Description**:

```
Create an issue for a problem and then generate a pull request to fix it
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| owner | Repository owner |Yes |
| repo | Repository name |Yes |
| title | Issue title |Yes |
| description | Issue description |Yes |
| labels | Comma-separated list of labels to apply (optional) |No |
| assignees | Comma-separated list of assignees (optional) |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | AssignCodingAgent | description | 4f9fe34b7c7e89aa96df3550d613d28352ad4e354c8450d3057a533d96a490c7 |
| prompts | AssignCodingAgent | repo | c830ac58c90245c73c3a1f0ecd7c8722be8cb955ec08d2b1d4b74b00db1ddba4 |
| prompts | issue_to_fix_workflow | description | fcf1ae23cc8ef26b35816db215df7336e943b45831868a6f37cebb64472df034 |
| prompts | issue_to_fix_workflow | assignees | 2f70679e444e867cf3f5883993e4a91b0ea45a17b6685dfc7983d0554dd8fa9e |
| prompts | issue_to_fix_workflow | description | 6fdf4c7fb5a19e122d009b8deed663a56034d8170be9300906c4368c423da250 |
| prompts | issue_to_fix_workflow | labels | 03560bc948abee46f4a1d9d7d330447aec5d17fd21a8770d6d2c8da43d9d99f6 |
| prompts | issue_to_fix_workflow | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| prompts | issue_to_fix_workflow | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| prompts | issue_to_fix_workflow | title | baebb0f722db7150e454ecfb2d432205f6331d57837328637d25ac8413f84644 |
| tools | add_comment_to_pending_review | description | c01d9b539761ed349fdefe576e822b51e45119bb65ec58bae048f32d545a4a59 |
| tools | add_comment_to_pending_review | body | 150bf72e1256c35c56d58cce6912ae25bb0a02e2a048a422297a7eead2024635 |
| tools | add_comment_to_pending_review | line | 819e79a56ebb1ecd61715def06ef3dda6306d32677da2d9c797a17ea0c2fe4bc |
| tools | add_comment_to_pending_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | add_comment_to_pending_review | path | ad65a27b6cdd3e833939b5c162ff0e5e105a2a0d8120a83907c1c286c6ce1c6b |
| tools | add_comment_to_pending_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | add_comment_to_pending_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | add_comment_to_pending_review | side | a8c682b21f75d5200a487c37af5d312ed2fe67abca69116aa93eb2a7ae228b5c |
| tools | add_comment_to_pending_review | startLine | 19184c9e73d4d7fbb9661702c5af2054059047e4b6cfc56b0e66f31fe3c2ba16 |
| tools | add_comment_to_pending_review | startSide | 6a4676ef00a54ce3692d9292bdd8dea138dceffd9d3a2bd7af22f2b776395448 |
| tools | add_comment_to_pending_review | subjectType | 12fc508ce13c1c2a9607f35cb7add1b0335cddf96c243530df7db80cab254182 |
| tools | add_issue_comment | description | 560688ce52ed72988fcfec72f46d01941035c9a05d96fdd8c4d10e8cf243d753 |
| tools | add_issue_comment | body | 76196e088940dc7627854dccef8d659636b54a66ba71c85512d65beb0131a5a8 |
| tools | add_issue_comment | issue_number | 55508553706f381501225c1367bc7f12548ab08da5ce677d10875fb316ee3ce4 |
| tools | add_issue_comment | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | add_issue_comment | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | assign_copilot_to_issue | description | d9f189d6cd4dc4e14f648c16825a32209ecb55bc1528e8d7a5c5d47a936312f3 |
| tools | assign_copilot_to_issue | base_ref | 2b3bf8d14e1139ed7306f537db4d88e9a781961f457ddcea7b6772c0e3c163b2 |
| tools | assign_copilot_to_issue | custom_instructions | 2646811ef631ffb8e9a63917c0e13f5bac4b8838839b7599d92f09e0fdf34916 |
| tools | assign_copilot_to_issue | issue_number | b90458b6339c0e14f5cea20207035c8a316ca33c0fda5d372ab8c4fc51fdb075 |
| tools | assign_copilot_to_issue | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | assign_copilot_to_issue | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_branch | description | 178c4aa2cad9c4dec2d6883eb0913ba5385f367e681e9d97cb751a2eb0983645 |
| tools | create_branch | branch | 23431660a4982622d8107024b732941aab6327a832c6715c57299e716e175d88 |
| tools | create_branch | from_branch | 5fa655e2e4b9da16f3de9e22d4d842abb6226464a2e91758242eacc4fec42dc9 |
| tools | create_branch | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_branch | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_or_update_file | description | 375ff78dd0fe9fbcf11a65d2225a5942e529b7ea6f69cea3eeb2080f4427da77 |
| tools | create_or_update_file | branch | d6a5e87fe732d76cc378c1d1f1210e9b2deb75c9a0dc93b4e453bd5681e9ebe9 |
| tools | create_or_update_file | content | 651936dc46e2fa051b60ccb3cbfe9f87f0f58f41773e79b4839a814525a7d688 |
| tools | create_or_update_file | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | create_or_update_file | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | create_or_update_file | path | c57e5f48646295c4493f5d052c3ce4d46f88f8c963d162f44c187ff5defa6791 |
| tools | create_or_update_file | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_or_update_file | sha | c6038773152de7f9db6ccc4b3b22f1b9af307f1c1cb5ae99a1837017e68e1728 |
| tools | create_pull_request | description | b3ce1a8e1c8396e567b2df7957109ec2298ca873d8084f9a9c033f39657f3572 |
| tools | create_pull_request | base | 68d3d352a8e9b1b21daef0144ddbd5ebbfdfafa1c150afd9184f2889aeba0f54 |
| tools | create_pull_request | body | 6b20fc28a2739e184ca6e00b2e894ed90a2213780fe67c05664a6917b26e1010 |
| tools | create_pull_request | draft | 13570f145a780449c8841dec203e2f3b37b7ced1b53e0a675553880b30b743db |
| tools | create_pull_request | head | f30a2f6fcdb7af894b1cd42fd17f7651a3e9de4c432a615fe383235d8822d669 |
| tools | create_pull_request | maintainer_can_modify | 4c61cb2daa11e76d1bd1483894ba1f0c8d8430cf9011793815d3cbd017f341ad |
| tools | create_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_pull_request | title | 878bfb1640ec1cecdf8cab8f3c62f5413e6b4084e0e1a4494df8f65a5a5eebf7 |
| tools | create_repository | description | 4b58d95b681b9e48375400e581666ae89d51cbad25412a2f5de964da9ce8bf80 |
| tools | create_repository | autoInit | fb659aaef50b97ff2f1d0518139663caef0d38424fc1107a8bf1a0cd7d7a637b |
| tools | create_repository | description | 2b96b72a003b28027236e3a9d7b66958233d752e92381122915202c3c00f6058 |
| tools | create_repository | name | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_repository | organization | 27408283fd33350e994962c641a90ca1a628ab59da48eb8e50e98f95cf7e4745 |
| tools | create_repository | private | d2180d4e67c48806764e44a9533344b63b6c05db56d6974818cb393c38e666e1 |
| tools | delete_file | description | a6706184f6656f1e0a1d8b6322d2c1c18bb3672a97cd2ac5bf71b0daf99e8900 |
| tools | delete_file | branch | eed2c3cf92bd302596d7dd8c0d052f667e6d9d3e5debc46913ff50de8c370a59 |
| tools | delete_file | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | delete_file | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | delete_file | path | d4e57b1045d6bdf511b312f8574c99772b8c03cc0528da2604ebc5f7d6daa335 |
| tools | delete_file | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | fork_repository | description | b9c81712c56e48175df559052b73f7e28646208f961b6b61c3ac3f3545eef86f |
| tools | fork_repository | organization | 715d8a3a0d64573efa8d492a5ac06ccf88e4ecb1db7a7b6cb0d30ee9369e6ccb |
| tools | fork_repository | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | fork_repository | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_commit | description | a27095bf05dc570a18bf4f6db26662c8dd39f2997f914127c59e8ecf906bf30f |
| tools | get_commit | include_diff | f532a5fbbbb36f8afb93d9f4c4f3194b3c3b3c7a07c6f77e4286ca33e9097fcf |
| tools | get_commit | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_commit | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | get_commit | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | get_commit | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_commit | sha | dcf39de8e2207559c31e5f4576561e8e569c991a889b697d8db7a3460924b445 |
| tools | get_file_contents | description | 54de6216aa12cd8da08e335b6955e2261b4241359f184959829407d0e40dcdc0 |
| tools | get_file_contents | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | get_file_contents | path | 2957637372ff4e19e270a582b546db31597054befcac8ee9aa597018697273be |
| tools | get_file_contents | ref | 875f572a6b88be55fa675b365b115cebba9c3fed283430959254d3aaefd96da0 |
| tools | get_file_contents | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_file_contents | sha | fda0ee26c9410debd8f92f8574994f92fc3f7f32c3c0110e5e038f72b245e40c |
| tools | get_label | description | bc5e986298d736683f2928e24dd080fa0735fbcb3d1529aa2573a84570568b44 |
| tools | get_label | name | 5f8530e3693ee4b5319375c6cb7b1aa2333dae312613974bca3551c13fca72e3 |
| tools | get_label | owner | c7969e651591ec1fd11228666bf4b809fe9ea930cd86f42c4fa75dc7db62f664 |
| tools | get_label | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_latest_release | description | 57a49eb576b15e088997f3906897973907a872ac7532593fa48826e0b3d0d09a |
| tools | get_latest_release | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_latest_release | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_me | description | bc34f566cc782d563dbfb6035ec4b94c7c7d46f34ef84c61cd7b02729ba281ce |
| tools | get_release_by_tag | description | 370170693dc5177b119f9aadd27bb305c23eec6de6050e5accbee27acd764a7f |
| tools | get_release_by_tag | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_release_by_tag | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_release_by_tag | tag | 5c5b50c5122e0628cc4cbf1692e097ea01b0f84cde76562125f4d0fc52ff1791 |
| tools | get_tag | description | e6d557e07eb01ac88760ac5a62bc68d3b795b61d4d7fa4be36758c0f7ce61eae |
| tools | get_tag | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_tag | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_tag | tag | 1ace926bc7cdee5323e297d439d2d268286749252b1c7f5e332d5003681d092d |
| tools | get_team_members | description | e86ce60eeea8d7fcc9a5e50ae24c13b083aed10d254af864402ec8167502bbc4 |
| tools | get_team_members | org | 8f82b1e1d8e55b252e1e32296aab20a519ec407a92f986379d8fc2b3e905ccf9 |
| tools | get_team_members | team_slug | 80b01119e50dfe735a6881fe673751b4e5ea652b3060fd46cfbabb9a32c94202 |
| tools | get_teams | description | 99380d708092b4760246658a3e9bc5f7991d7bcecc75c3dea03e13fcff6aa27b |
| tools | get_teams | user | e7014fc86ff0dc1234683bd328e76b2d368abb424043c57b75e86007b281b4fc |
| tools | issue_read | description | e3ccc7984b309935391ec33b448056c6177cd97383005727831d46e8c73213dc |
| tools | issue_read | issue_number | 792880d24307a7c2e3ccb34d164888a960335024892f6faa8729fe06657409fe |
| tools | issue_read | method | 8fc24ff5c235579b50c9495070de7e897a2d006321c4cb11d0cd277392c80521 |
| tools | issue_read | owner | ee38b59dccfd5b3c8d391330a1f61654141c77f7a3bfcd3da617d6f32f3fba55 |
| tools | issue_read | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | issue_read | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | issue_read | repo | 707cdfc2a1225dbd1d0ab3c3e9c69aa50df8556f176cfcb822744bef5cee4481 |
| tools | issue_write | description | 8fe78ac80b6a1295e9149d41aab56393236e2c6155abf09a5b56a23b09ef587c |
| tools | issue_write | assignees | 4b3bd4c85313c2684d6dcf769e368485947d08818835207a231a61700dc3552b |
| tools | issue_write | body | 16e4f6813850b28daf1d698946455b18a587988665d95175da2e415938a906f7 |
| tools | issue_write | duplicate_of | 53698074a89edce07b87d2fee16e63accc21cdea6e50f4058a028e85da3ef427 |
| tools | issue_write | issue_number | 45f54a035e52ddd24bd931710aed635cc2d5a202ba687d0708c618fe76095437 |
| tools | issue_write | labels | 14ab87d13af5cc4d90c937d8c30258158c0afe9d6cedfb89b4a10d0d057d0397 |
| tools | issue_write | method | 52170d190606d783c3383db65d6b72a6f4e6e9598ef831aa9f442874816bac38 |
| tools | issue_write | milestone | 87dbe6860309e747c0fc0fc44621cdc1b20e79faaccdd485a4b74c5daa8e333d |
| tools | issue_write | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | issue_write | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | issue_write | state | 73d2abfb99c5146711a52488e33aa097ebd94cc1f1d14a0e21e9a6ed88709818 |
| tools | issue_write | state_reason | 9cea5f38007ac5ff5923758f8747775d5c14bf17a46336e52c159b26ef467128 |
| tools | issue_write | title | baebb0f722db7150e454ecfb2d432205f6331d57837328637d25ac8413f84644 |
| tools | issue_write | type | 4cdfe6d81ac007f40e6ffe451a7e4b3154c8a20af966032818941ef3d6588bd2 |
| tools | list_branches | description | 8ce903bf8c1572fd527fd93f38d7d2ccb9b8d463ffe947100aeb1b8187363840 |
| tools | list_branches | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_branches | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_branches | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_branches | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_commits | description | dd2e7a438ec8ef9f8c31a41ce203325fc971ad1dc601c7647f5a9a39ca372df9 |
| tools | list_commits | author | 1f1de9b0a4f304b5c277397fc0f2ccfa560bd738a0629c1dfbea414c3b0d5525 |
| tools | list_commits | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_commits | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_commits | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_commits | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_commits | sha | 32370fb2be08709a082e75aad76c4ea68131ea14e7c7d5397589551b4c578590 |
| tools | list_issue_types | description | aad76d81c64bef558b289deaa559d6df71f073175296d652177fa5269ff75b46 |
| tools | list_issue_types | owner | a52c8fb1e603a20184e28ac2617bf3691d25622e5c59b880455382e0b2992169 |
| tools | list_issues | description | c41469eaf78f99580e51ff1bbbadc2922bdec37e47f0e5d142e1e576f3390c87 |
| tools | list_issues | after | 08dda1d80d90e055580fd030062b62012b8ea50c39e1c4c8cb3224c35ab4c326 |
| tools | list_issues | direction | fee43777658d13fc2a11ea0f8b5b82f03a410bef3ef26750efe89d8818d62951 |
| tools | list_issues | labels | cd8837d9c837a6e1991502a822f57a44fc95a741eeece870f890f82c275c16a3 |
| tools | list_issues | orderBy | f275807f86362c1b5c51261dd4081b2fd8997a5fc1c80b85fb7d6a9c40762cf5 |
| tools | list_issues | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_issues | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_issues | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_issues | since | ea0dd87c74f5845692af7bc86972f1f210d984342fb26602fe35c0c04a3a49cd |
| tools | list_issues | state | da8480769e2cb1db597453b840eba06b9528d242e2ff2e0c4a3f6f5be675559b |
| tools | list_pull_requests | description | c249adc3491b598845fda74d1b7f815b368107b47786634fc6e44ef0ea5f1a06 |
| tools | list_pull_requests | base | 3915eefd074b833c42fa1a78466ff3667210bb7cd9e867bce531f6d69b6b25f1 |
| tools | list_pull_requests | direction | 29c8371d927b118d8d71544c8c8d336f340b0fe893a48faa5a746880f578f373 |
| tools | list_pull_requests | head | dc15fecf43097ca55e53fff94ae252ac6f7a0325fa37efb0ba854276c2eea920 |
| tools | list_pull_requests | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_pull_requests | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_pull_requests | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_pull_requests | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_pull_requests | sort | c9129025bd3ff6522a7eeebc1abf1481f36e4ac9d74524a473ac1c3be1c6fc2f |
| tools | list_pull_requests | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | list_releases | description | 16c40a2d80141352b60b845be6bb163ab868e1dc3b7edbdbe14ca7b2d664e411 |
| tools | list_releases | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_releases | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_releases | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_releases | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_tags | description | b45b57651e9a56b5d03befc9edb790d1c1d92742cc6e1cd9d56f6b41fc3dca92 |
| tools | list_tags | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_tags | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_tags | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_tags | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | merge_pull_request | description | 124cd641ce348386107609b1831084962d2198fa82fe58f7a040dd7e1cebb6b4 |
| tools | merge_pull_request | commit_message | 8b3fd7f52419bc6922db1546614fcd15e214033be38066ff4cd1cbb841ba27ce |
| tools | merge_pull_request | commit_title | df303c95cc0cb2a4ceb92b29c47c9b965ec484d53b5fee6add5c9189e2f96342 |
| tools | merge_pull_request | merge_method | 889b19c3b7a37b0d3249fd662f04c6cdc914c42bfc45d642c5d74946ca8837db |
| tools | merge_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | merge_pull_request | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | merge_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | pull_request_read | description | 2d2b3f1fbb088bc1a5eef4fd77b7c8abdfd2753e2356abce8401dba5236cae5b |
| tools | pull_request_read | method | 37b490bb771936c01b0ae2f765733376b218f25e74770b1f4f1af20fd4d9bc98 |
| tools | pull_request_read | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | pull_request_read | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | pull_request_read | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | pull_request_read | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | pull_request_read | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | pull_request_review_write | description | 4395e0a7f82f40a8dd040d9b8a7a4711f37b4eda463858ccb989eecf00d33090 |
| tools | pull_request_review_write | body | 305435be37ca49348dd59f76ed78d1d3db653263c87268f19e38edd8e9903f8a |
| tools | pull_request_review_write | commitID | 8edaee0cc39481736353ab6b261838e08ea25f5a48ff2235247349671fd2d092 |
| tools | pull_request_review_write | event | 00abd179b03232fbd602ad69bd7c4e4eec497999929b7b10ebc5b45cf762fd8e |
| tools | pull_request_review_write | method | 6c9da86826c33d7875ac0f6c7a8a9f9c2f75507258df8b9e23f9bc152b71bc2a |
| tools | pull_request_review_write | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | pull_request_review_write | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | pull_request_review_write | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | push_files | description | 0ea99ad23e44e739ed503658bdaab5ee2dc239246cb00e715d8fff3d80fe544f |
| tools | push_files | branch | 903fd236be715d2d2dabe8871e567bebdb55a876b1f9b4db0c49400e3b944e01 |
| tools | push_files | files | 1c55ce034da38092a4c35795368bf7da13897eb6ab576f0539b22e02cda877a0 |
| tools | push_files | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | push_files | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | push_files | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | request_copilot_review | description | 0a31c498daefdb4310ae1335e16496ed8d238d01ebf12c04d45a1b215e4c7de3 |
| tools | request_copilot_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | request_copilot_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | request_copilot_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | search_code | description | 80d70342e3a3eb8b9ad5df5eb159840c6a363b7ef54bc757e541990984e2b2ad |
| tools | search_code | order | 459d5b91cd6d44d4d449ac7ea47b374b8a64f41347ea88c26ff60293e91a5410 |
| tools | search_code | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_code | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_code | query | 4195e12d52f49f89827d3e4e20190f0b9246a116802728e6714b4fdc247f90ac |
| tools | search_code | sort | 5a8b728c15aab0284ebfeb9dfb94debf67e55d178d8bf7c3b660fe36ef92855f |
| tools | search_issues | description | 43486d364155338655b54fc20c59d4b770504ecad84b4878c826745c01a3e39e |
| tools | search_issues | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_issues | owner | 2b0b674feebefdb92c2ae156a0d69926ea5c9b5bb7488dd0ee8dc69a6b475ff4 |
| tools | search_issues | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_issues | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_issues | query | ba2ce5263245f1c7beda19f750b937dee26e69df9b0773c5ee3902142e81e3ee |
| tools | search_issues | repo | 1123ae7af5aa2a436f142f42ac4e8a8ec6c5242d90711eb443f60ca51bec7fd1 |
| tools | search_issues | sort | 45f652334776f448a204bdd17cb144e1d6a7b0bf6e6746e677874ad01432470d |
| tools | search_pull_requests | description | d8a220faae6baa7cd5dfad6e2acd46e0949ef79854cd1d98baa8c6a5e15b1cea |
| tools | search_pull_requests | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_pull_requests | owner | b4630553300033a3784143bef3cd6eaaf07fa13ac3ece89ad63b5af747263e59 |
| tools | search_pull_requests | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_pull_requests | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_pull_requests | query | 2eb3b226fb8c4d8de76cb2cafa5f133b8ad6d117590eb9eda9a79f0b7445b47d |
| tools | search_pull_requests | repo | 689f726331c0f078fde7f7a94e4d9af223b58df8dd79d309a2a1d3fd5c4f59a3 |
| tools | search_pull_requests | sort | 45f652334776f448a204bdd17cb144e1d6a7b0bf6e6746e677874ad01432470d |
| tools | search_repositories | description | 7b9c5ffba195b04b1c4d835eca98ea84c999b254239740dd5a38e89d6f46ab02 |
| tools | search_repositories | minimal_output | 4af9b88e9893e72033a60d84efb0087f44790e176b455f738cc15b7f6db7f3ab |
| tools | search_repositories | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_repositories | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_repositories | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_repositories | query | 1c6a82bc7504d47ba45d87b94e4c35cab4392381291e88647e4215798d36bb3b |
| tools | search_repositories | sort | 5bee5ee03cb669d6152c8059a10341aa6efdd05dbc76fc10a8d089556052867a |
| tools | search_users | description | e2c14890a74e50c883b5ba65dd1ae521152ef8e7ffe67aab5336091fcefe0807 |
| tools | search_users | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_users | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_users | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_users | query | 2bdd0f05eb601997f555c602d81a9a9fe3edde63d396cad58aea855fa094e00e |
| tools | search_users | sort | 70aa5854fb750b213cbc0d4e95a3a50ced65335a521cd617c62673fb00894df3 |
| tools | sub_issue_write | description | 0e8fa66b77f7ec60fa9ee3a6402d1aa53a8b4ee45621b52dea19a7777b9692c9 |
| tools | sub_issue_write | after_id | b8451ca1764a44349b69eebff232b4a8eae441e4bf69e17632bb1798bb56cfb4 |
| tools | sub_issue_write | before_id | c7b4548a5c32f2c45c00bdc0623fcbe84709343305e28c2d0f19f859e3ba5c04 |
| tools | sub_issue_write | issue_number | 0ec2e63e1a2a883d952d2a60cec7f5c1cf7aa6af1da3e8477bfb3d3f825a374f |
| tools | sub_issue_write | method | 70c3e687e87f43455200f2166483a85fb7a1d0ce1f6ad4bed7da4de0022a6d20 |
| tools | sub_issue_write | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | sub_issue_write | replace_parent | ee0549613454cbb10045f6efc25cc6d31b1a29de3daab4aceb13f1c7c3abc2bc |
| tools | sub_issue_write | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | sub_issue_write | sub_issue_id | 7016cafc44f9fd8fa96bec3e4c8f108772df7aec76cf899e1a6471fa8abcc6b3 |
| tools | update_pull_request | description | bed4d74cfd86d23ab02749d6b4fffa5ba43c3290bfa7c9810514cf821e0563eb |
| tools | update_pull_request | base | 33cd739abf299499afc569d0b3bf88e53d9833841bb0af1c9e7c3a61c827991a |
| tools | update_pull_request | body | 23b7ce65508de7bbfb013fd25a384491f896e839f62116c96813ec6f53945e98 |
| tools | update_pull_request | draft | 2348581419a41833f3019df10f6c1508524410025f4f0054b6995e508227a03f |
| tools | update_pull_request | maintainer_can_modify | 4c61cb2daa11e76d1bd1483894ba1f0c8d8430cf9011793815d3cbd017f341ad |
| tools | update_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_pull_request | pullNumber | 4f4b068a5c13d2a2547b7a13655111963fd97b583156f8cea0fd62c4a16f7375 |
| tools | update_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | update_pull_request | reviewers | 9b88c448f5064122e6adde819b4b684e78631a4f6915b1bc5f4e67d29fef3c77 |
| tools | update_pull_request | state | 73d2abfb99c5146711a52488e33aa097ebd94cc1f1d14a0e21e9a6ed88709818 |
| tools | update_pull_request | title | 522156b9b0af7eb99063569c92036931a3c9f027728ac6de8a70bcd0a1d3721c |
| tools | update_pull_request_branch | description | bb1dacdad1b56b12c6b26f7833d5b189a7827f66ea3d04917632eed63277d80d |
| tools | update_pull_request_branch | expectedHeadSha | 86e4137627e7ef4e6244395428104ab03f903b5c98f1a4be25279deb54f96c00 |
| tools | update_pull_request_branch | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_pull_request_branch | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | update_pull_request_branch | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
