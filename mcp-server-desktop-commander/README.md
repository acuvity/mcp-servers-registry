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


# What is mcp-server-desktop-commander?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-desktop-commander/0.1.39?logo=docker&logoColor=fff&label=0.1.39)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander)
[![PyPI](https://img.shields.io/badge/0.1.39-3775A9?logo=pypi&logoColor=fff&label=@wonderwhy-er/desktop-commander)](https://github.com/wonderwhy-er/DesktopCommanderMCP)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.1.39%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** A swiss-army-knife that can manage/execute programs and read/write/search/edit code and text files.

Packaged by Acuvity from @wonderwhy-er/desktop-commander original [sources](https://github.com/wonderwhy-er/DesktopCommanderMCP).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-desktop-commander/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/charts/mcp-server-desktop-commander/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @wonderwhy-er/desktop-commander run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/charts/mcp-server-desktop-commander#minibridge) for Helm charts).


# 📦 How to Install


> [!TIP]
> Given mcp-server-desktop-commander scope of operation the intended usage is to run natively on the targeted machine to access local resources.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.1.39%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-desktop-commander": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-desktop-commander:0.1.39"
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
    "acuvity-mcp-server-desktop-commander": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-desktop-commander:0.1.39"
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
    "acuvity-mcp-server-desktop-commander": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-desktop-commander:0.1.39"
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
    "acuvity-mcp-server-desktop-commander": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-desktop-commander:0.1.39"
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
    "acuvity-mcp-server-desktop-commander": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-desktop-commander:0.1.39"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-desktop-commander:0.1.39"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-desktop-commander:0.1.39`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-desktop-commander:0.1.39
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-desktop-commander": {
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
    "acuvity-mcp-server-desktop-commander": {
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

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
````

Install with helm

```console
helm install mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
```

From there your MCP server mcp-server-desktop-commander will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-desktop-commander` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/charts/mcp-server-desktop-commander/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (18)
<details>
<summary>get_config</summary>

**Description**:

```
Get the complete server configuration as JSON. Config includes fields for: blockedCommands (array of blocked shell commands), defaultShell (shell to use for commands), allowedDirectories (paths the server can access).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>set_config_value</summary>

**Description**:

```
Set a specific configuration value by key. WARNING: Should be used in a separate chat from file operations and command execution to prevent security issues. Config keys include: blockedCommands (array), defaultShell (string), allowedDirectories (array of paths). IMPORTANT: Setting allowedDirectories to an empty array ([]) allows full access to the entire file system, regardless of the operating system.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | any | not set | No
</details>
<details>
<summary>read_file</summary>

**Description**:

```
Read the complete contents of a file from the file system or a URL. Prefer this over 'execute_command' with cat/type for viewing files. When reading from the file system, only works within allowed directories. Can fetch content from URLs when isUrl parameter is set to true. Handles text files normally and image files are returned as viewable images. Recognized image types: PNG, JPEG, GIF, WebP. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| isUrl | boolean | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>read_multiple_files</summary>

**Description**:

```
Read the contents of multiple files simultaneously. Each file's content is returned with its path as a reference. Handles text files normally and renders images as viewable content. Recognized image types: PNG, JPEG, GIF, WebP. Failed reads for individual files won't stop the entire operation. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| paths | array | not set | Yes
</details>
<details>
<summary>write_file</summary>

**Description**:

```
Completely replace file contents. Best for large changes (>20% of file) or when edit_block fails. Use with caution as it will overwrite existing files. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>create_directory</summary>

**Description**:

```
Create a new directory or ensure a directory exists. Can create multiple nested directories in one operation. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>list_directory</summary>

**Description**:

```
Get a detailed listing of all files and directories in a specified path. Use this instead of 'execute_command' with ls/dir commands. Results distinguish between files and directories with [FILE] and [DIR] prefixes. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>move_file</summary>

**Description**:

```
Move or rename files and directories. 
                        Can move files between directories and rename them in a single operation. 
                        Both source and destination must be within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | not set | Yes
| source | string | not set | Yes
</details>
<details>
<summary>search_files</summary>

**Description**:

```
Finds files by name using a case-insensitive substring matching. 
                        Use this instead of 'execute_command' with find/dir/ls for locating files.
                        Searches through all subdirectories from the starting path. 
                        Has a default timeout of 30 seconds which can be customized using the timeoutMs parameter. 
                        Only searches within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
| pattern | string | not set | Yes
| timeoutMs | number | not set | No
</details>
<details>
<summary>search_code</summary>

**Description**:

```
Search for text/code patterns within file contents using ripgrep. 
                        Use this instead of 'execute_command' with grep/find for searching code content.
                        Fast and powerful search similar to VS Code search functionality. 
                        Supports regular expressions, file pattern filtering, and context lines. 
                        Has a default timeout of 30 seconds which can be customized. 
                        Only searches within allowed directories. 
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contextLines | number | not set | No
| filePattern | string | not set | No
| ignoreCase | boolean | not set | No
| includeHidden | boolean | not set | No
| maxResults | number | not set | No
| path | string | not set | Yes
| pattern | string | not set | Yes
| timeoutMs | number | not set | No
</details>
<details>
<summary>get_file_info</summary>

**Description**:

```
Retrieve detailed metadata about a file or directory including size, creation time, last modified time, 
                        permissions, and type. 
                        Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>edit_block</summary>

**Description**:

```
Apply surgical text replacements to files. 
                        BEST PRACTICE: Make multiple small, focused edits rather than one large edit. 
                        Each edit_block call should change only what needs to be changed - include just enough context to uniquely identify the text being modified. 
                        Takes file_path, old_string (text to replace), new_string (replacement text), and optional expected_replacements parameter. 
                        By default, replaces only ONE occurrence of the search text. 
                        To replace multiple occurrences, provide the expected_replacements parameter with the exact number of matches expected. 
                        UNIQUENESS REQUIREMENT: When expected_replacements=1 (default), include the minimal amount of context necessary (typically 1-3 lines) before and after the change point, with exact whitespace and indentation. 
                        When editing multiple sections, make separate edit_block calls for each distinct change rather than one large replacement. 
                        When a close but non-exact match is found, a character-level diff is shown in the format: common_prefix{-removed-}{+added+}common_suffix to help you identify what's different. 
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expected_replacements | number | not set | No
| file_path | string | not set | Yes
| new_string | string | not set | Yes
| old_string | string | not set | Yes
</details>
<details>
<summary>execute_command</summary>

**Description**:

```
Execute a terminal command with timeout. 
                        Command will continue running in background if it doesn't complete within timeout. 
                        NOTE: For file operations, prefer specialized tools like read_file, search_code, list_directory instead of cat, grep, or ls commands.
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | not set | Yes
| shell | string | not set | No
| timeout_ms | number | not set | No
</details>
<details>
<summary>read_output</summary>

**Description**:

```
Read new output from a running terminal session.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
</details>
<details>
<summary>force_terminate</summary>

**Description**:

```
Force terminate a running terminal session.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
</details>
<details>
<summary>list_sessions</summary>

**Description**:

```
List all active terminal sessions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_processes</summary>

**Description**:

```
List all running processes. Returns process information including PID, command name, CPU usage, and memory usage.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>kill_process</summary>

**Description**:

```
Terminate a running process by PID. Use with caution as this will forcefully terminate the specified process.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_directory | description | c7fefb3d795ec75837bc8a78cf8d59dc49fc09f1631bacf34d98ce2c4f0cea49 |
| tools | edit_block | description | fc4ff2e1c0f8a5f49897b25b30e6ff6190edff025c91ce8c47682abe11c88f24 |
| tools | execute_command | description | d56794a362c464d21a02e9ae15ab43f532827ba29755d7fb84f259d245d0bdfc |
| tools | force_terminate | description | 1e2f2a73d35cecb07c924ca4e581fd4bf11d022ee20a7cc489dfdef93516f59e |
| tools | get_config | description | be3f650cba9e9f1a3076d93efd139c936bdaeed69ec3a549147584d771fed347 |
| tools | get_file_info | description | ac0976d058642e602ed54addfed78827b853e009a26b54fe7ac58ab38fa9832b |
| tools | kill_process | description | 72fcd002619ed594586a2999eee8203440a2813155a22fc68e56b400a913ce94 |
| tools | list_directory | description | 2cd494ea838c57996713e2d9ea6493b425842b59b0149bcbf07ae9f5d9ff1735 |
| tools | list_processes | description | f256bced396b792c6d64e288112c70f27644d22a4de48ee77c169f6b7bc67f29 |
| tools | list_sessions | description | da9a1e7281fbd5e4cfb27aa59046a142f50b5bcd5c42a243aaee64f8b09f5db5 |
| tools | move_file | description | 0a27c32339f4e1623326c0980888cfab884e9d5c3d6a4f18c6cd43b23e219269 |
| tools | read_file | description | 9b2a0a3bcaf09cb4713f96d723a0b61f8a0776efcf4b2cf3539a2f0d6915acb9 |
| tools | read_multiple_files | description | 56b4f4a9d2b662c03e96fa83c21868d6e35155284048f20f6f3fe422d4ae49e6 |
| tools | read_output | description | c59565a21c11ed4034b8d6546d5019913d0e761929dad7b28bd94796d824d033 |
| tools | search_code | description | 89ccd3f91bed92e6a4dcecd8a8723bf31cac3861c3ddaac11617afb981d8eb18 |
| tools | search_files | description | ea128f04fcc0c50080a3197c2555889ebdaf21365325faebb0cee9fa7488ca97 |
| tools | set_config_value | description | ec588a0b568b74e751a8b9095c288eee93d9ce7b434e6c46ed3142493b94feb9 |
| tools | write_file | description | f5427c57d36f7846673f67fc80427bd76589e8b68fa44abb87732f7cfdcaff78 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
