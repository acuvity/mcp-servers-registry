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
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-desktop-commander/0.2.3?logo=docker&logoColor=fff&label=0.2.3)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander)
[![PyPI](https://img.shields.io/badge/0.2.3-3775A9?logo=pypi&logoColor=fff&label=@wonderwhy-er/desktop-commander)](https://github.com/wonderwhy-er/DesktopCommanderMCP)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.2.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** A swiss-army-knife that can manage/execute programs and read/write/search/edit code and text files.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @wonderwhy-er/desktop-commander original [sources](https://github.com/wonderwhy-er/DesktopCommanderMCP).

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
> Given mcp-server-desktop-commander scope of operation the intended usage is to run natively on the targeted machine to access local resources.

**Environment variables and secrets:**
  - `HOME` optional (/tmp)

For more information and extra configuration you can consult the [package](https://github.com/wonderwhy-er/DesktopCommanderMCP) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.2.3%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "docker.io/acuvity/mcp-server-desktop-commander:0.2.3"
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
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.3"
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
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.3"
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
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.3"
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
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.3"
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
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","docker.io/acuvity/mcp-server-desktop-commander:0.2.3"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-desktop-commander:0.2.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-desktop-commander:0.2.3
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-desktop-commander": {
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

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Optional Environment variables**:
  - `HOME="/tmp"` environment variable can be changed with env.HOME="/tmp"

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

                        Get the complete server configuration as JSON. Config includes fields for:
                        - blockedCommands (array of blocked shell commands)
                        - defaultShell (shell to use for commands)
                        - allowedDirectories (paths the server can access)
                        - fileReadLineLimit (max lines for read_file, default 1000)
                        - fileWriteLineLimit (max lines per write_file call, default 50)
                        - telemetryEnabled (boolean for telemetry opt-in/out)
                        -  version (version of the DesktopCommander)
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>set_config_value</summary>

**Description**:

```

                        Set a specific configuration value by key.
                        
                        WARNING: Should be used in a separate chat from file operations and 
                        command execution to prevent security issues.
                        
                        Config keys include:
                        - blockedCommands (array)
                        - defaultShell (string)
                        - allowedDirectories (array of paths)
                        - fileReadLineLimit (number, max lines for read_file)
                        - fileWriteLineLimit (number, max lines per write_file call)
                        - telemetryEnabled (boolean)
                        
                        IMPORTANT: Setting allowedDirectories to an empty array ([]) allows full access 
                        to the entire file system, regardless of the operating system.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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

                        Read the contents of a file from the file system or a URL with optional offset and length parameters.
                        
                        Prefer this over 'execute_command' with cat/type for viewing files.
                        
                        Supports partial file reading with:
                        - 'offset' (start line, default: 0)
                          * Positive: Start from line N (0-based indexing)
                          * Negative: Read last N lines from end (tail behavior)
                        - 'length' (max lines to read, default: configurable via 'fileReadLineLimit' setting, initially 1000)
                          * Used with positive offsets for range reading
                          * Ignored when offset is negative (reads all requested tail lines)
                        
                        Examples:
                        - offset: 0, length: 10     → First 10 lines
                        - offset: 100, length: 5    → Lines 100-104
                        - offset: -20               → Last 20 lines  
                        - offset: -5, length: 10    → Last 5 lines (length ignored)
                        
                        Performance optimizations:
                        - Large files with negative offsets use reverse reading for efficiency
                        - Large files with deep positive offsets use byte estimation
                        - Small files use fast readline streaming
                        
                        When reading from the file system, only works within allowed directories.
                        Can fetch content from URLs when isUrl parameter is set to true
                        (URLs are always read in full regardless of offset/length).
                        
                        Handles text files normally and image files are returned as viewable images.
                        Recognized image types: PNG, JPEG, GIF, WebP.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| isUrl | boolean | not set | No
| length | number | not set | No
| offset | number | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>read_multiple_files</summary>

**Description**:

```

                        Read the contents of multiple files simultaneously.
                        
                        Each file's content is returned with its path as a reference.
                        Handles text files normally and renders images as viewable content.
                        Recognized image types: PNG, JPEG, GIF, WebP.
                        
                        Failed reads for individual files won't stop the entire operation.
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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

                        Write or append to file contents. 

                        🎯 CHUNKING IS STANDARD PRACTICE: Always write files in chunks of 25-30 lines maximum.
                        This is the normal, recommended way to write files - not an emergency measure.

                        STANDARD PROCESS FOR ANY FILE:
                        1. FIRST → write_file(filePath, firstChunk, {mode: 'rewrite'})  [≤30 lines]
                        2. THEN → write_file(filePath, secondChunk, {mode: 'append'})   [≤30 lines]
                        3. CONTINUE → write_file(filePath, nextChunk, {mode: 'append'}) [≤30 lines]

                        ⚠️ ALWAYS CHUNK PROACTIVELY - don't wait for performance warnings!

                        WHEN TO CHUNK (always be proactive):
                        1. Any file expected to be longer than 25-30 lines
                        2. When writing multiple files in sequence
                        3. When creating documentation, code files, or configuration files
                        
                        HANDLING CONTINUATION ("Continue" prompts):
                        If user asks to "Continue" after an incomplete operation:
                        1. Read the file to see what was successfully written
                        2. Continue writing ONLY the remaining content using {mode: 'append'}
                        3. Keep chunks to 25-30 lines each
                        
                        Files over 50 lines will generate performance notes but are still written successfully.
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| mode | string | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>create_directory</summary>

**Description**:

```

                        Create a new directory or ensure a directory exists.
                        
                        Can create multiple nested directories in one operation.
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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

                        Get a detailed listing of all files and directories in a specified path.
                        
                        Use this instead of 'execute_command' with ls/dir commands.
                        Results distinguish between files and directories with [FILE] and [DIR] prefixes.
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
                        Both source and destination must be within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
                        Only searches within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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

                        Retrieve detailed metadata about a file or directory including:
                        - size
                        - creation time
                        - last modified time 
                        - permissions
                        - type
                        - lineCount (for text files)
                        - lastLine (zero-indexed number of last line, for text files)
                        - appendPosition (line number for appending, for text files)
                        
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
                        Each edit_block call should change only what needs to be changed - include just enough 
                        context to uniquely identify the text being modified.
                        
                        Takes:
                        - file_path: Path to the file to edit
                        - old_string: Text to replace
                        - new_string: Replacement text
                        - expected_replacements: Optional parameter for number of replacements
                        
                        By default, replaces only ONE occurrence of the search text.
                        To replace multiple occurrences, provide the expected_replacements parameter with
                        the exact number of matches expected.
                        
                        UNIQUENESS REQUIREMENT: When expected_replacements=1 (default), include the minimal
                        amount of context necessary (typically 1-3 lines) before and after the change point,
                        with exact whitespace and indentation.
                        
                        When editing multiple sections, make separate edit_block calls for each distinct change
                        rather than one large replacement.
                        
                        When a close but non-exact match is found, a character-level diff is shown in the format:
                        common_prefix{-removed-}{+added+}common_suffix to help you identify what's different.
                        
                        Similar to write_file, there is a configurable line limit (fileWriteLineLimit) that warns
                        if the edited file exceeds this limit. If this happens, consider breaking your edits into
                        smaller, more focused changes.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
                        
                        NOTE: For file operations, prefer specialized tools like read_file, search_code, 
                        list_directory instead of cat, grep, or ls commands.
                        
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | not set | Yes
| shell | string | not set | No
| timeout_ms | number | not set | Yes
</details>
<details>
<summary>read_output</summary>

**Description**:

```

                        Read new output from a running terminal session.
                        Set timeout_ms for long running commands.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
| timeout_ms | number | not set | No
</details>
<details>
<summary>force_terminate</summary>

**Description**:

```

                        Force terminate a running terminal session.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_processes</summary>

**Description**:

```

                        List all running processes.
                        
                        Returns process information including PID, command name, CPU usage, and memory usage.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>kill_process</summary>

**Description**:

```

                        Terminate a running process by PID.
                        
                        Use with caution as this will forcefully terminate the specified process.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
| tools | create_directory | description | 3e16e56ccad14565f3bc65b56938c6b68cbd32fc6d551eb7a7e550e5b7b304af |
| tools | edit_block | description | 3ce36fcdbf191892c7c747905054a5d07f099e937cfd6b4d7febc5e1f32301bf |
| tools | execute_command | description | fc8b9e33ff1e44d77b6a4f4cda7f299d389898e094badc55308392875ef38ea2 |
| tools | force_terminate | description | 9109012600d4a9a370367c4479fcae7092b5aaae0fb55f074e8eab0afb9c8306 |
| tools | get_config | description | 04f640303aa42b7852a6a2ac6ccebc0149b2a2f776b7993a32fc05f601e36ecb |
| tools | get_file_info | description | 496b04e9d6d766a7057babf6517dde178fc82d321fb0381f9f092493748ee5a3 |
| tools | kill_process | description | 5e7eb30c182e5f57a93094478b83e066868eb3cb8d331487071226c952092835 |
| tools | list_directory | description | 96ce5a41302a1f01a26196645e2f93035630720958b21ef14a9f6d495b3e10c0 |
| tools | list_processes | description | bccaf3bd87272c75e038e50077bca491355236be9fb99d131463c34553df9a2a |
| tools | list_sessions | description | efa60b39dc2cdcc845f5053cf2debd9e5c15b33dae15ce4001f2a8e1dffa2a16 |
| tools | move_file | description | ed4294c075e3f891f9980b6e3b458cb72967ae77d7b78b4fc2bc8330702b81ac |
| tools | read_file | description | 96dcf541bed39a4887900164f1c62acbf87a1c112ce425db3c5904fef971af08 |
| tools | read_multiple_files | description | a565fd247993616d89e9cd247c024346f76fd65d2a21c994a0128b335b1b8752 |
| tools | read_output | description | 01171776821f6acb671fd54c2e0b6d223c5f1a4765f2b9b7bba7f76e9fda79d2 |
| tools | search_code | description | 9e69a945172aebff5fc61dbe9522e0e285ef1e581ec74e02c63e07d114821f75 |
| tools | search_files | description | f41652d2fd0f701958c382769c9a1dca4989b0f1eeb8fc83b32b7ef051e8aff5 |
| tools | set_config_value | description | 155afe1d85ebd07ac64f76703797548c8b48a1e2a3d63b14c2369633527df389 |
| tools | write_file | description | 1c329b37aecef0e273658fe15b59ad432a182c904d9a14d8d8a6e2101e843a85 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
