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


# What is mcp-server-desktop-commander?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-desktop-commander/0.2.30?logo=docker&logoColor=fff&label=0.2.30)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander)
[![PyPI](https://img.shields.io/badge/0.2.30-3775A9?logo=pypi&logoColor=fff&label=@wonderwhy-er/desktop-commander)](https://github.com/wonderwhy-er/DesktopCommanderMCP)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.2.30%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.2.30%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-desktop-commander:0.2.30"
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
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.30"
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
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.30"
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
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.30"
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
        "docker.io/acuvity/mcp-server-desktop-commander:0.2.30"
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
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","docker.io/acuvity/mcp-server-desktop-commander:0.2.30"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-desktop-commander:0.2.30`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-desktop-commander:0.2.30
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

## 🧰 Tools (26)
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
                        - currentClient (information about the currently connected MCP client)
                        - clientHistory (history of all clients that have connected)
                        - version (version of the DesktopCommander)
                        - systemInfo (operating system and environment details)
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
| value | any | not set | Yes
</details>
<details>
<summary>read_file</summary>

**Description**:

```

                        Read contents from files and URLs.
                        Read PDF files and extract content as markdown and images.
                        
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
                        
                        FORMAT HANDLING (by extension):
                        - Text: Uses offset/length for line-based pagination
                        - Excel (.xlsx, .xls, .xlsm): Returns JSON 2D array
                          * sheet: "Sheet1" (name) or "0" (index as string, 0-based)
                          * range: ALWAYS use FROM:TO format (e.g., "A1:D100", "C1:C1", "B2:B50")
                          * offset/length work as row pagination (optional fallback)
                        - Images (PNG, JPEG, GIF, WebP): Base64 encoded viewable content
                        - PDF: Extracts text content as markdown with page structure
                          * offset/length work as page pagination (0-based)
                          * Includes embedded images when available

                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| isUrl | boolean | not set | No
| length | number | not set | No
| offset | number | not set | No
| options | object | not set | No
| path | string | not set | Yes
| range | string | not set | No
| sheet | string | not set | No
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
                        
                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
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

                        IMPORTANT: DO NOT use this tool to create PDF files. Use 'write_pdf' for all PDF creation tasks.

                        CHUNKING IS STANDARD PRACTICE: Always write files in chunks of 25-30 lines maximum.
                        This is the normal, recommended way to write files - not an emergency measure.

                        STANDARD PROCESS FOR ANY FILE:
                        1. FIRST → write_file(filePath, firstChunk, {mode: 'rewrite'})  [≤30 lines]
                        2. THEN → write_file(filePath, secondChunk, {mode: 'append'})   [≤30 lines]
                        3. CONTINUE → write_file(filePath, nextChunk, {mode: 'append'}) [≤30 lines]

                        ALWAYS CHUNK PROACTIVELY - don't wait for performance warnings!

                        WHEN TO CHUNK (always be proactive):
                        1. Any file expected to be longer than 25-30 lines
                        2. When writing multiple files in sequence
                        3. When creating documentation, code files, or configuration files

                        HANDLING CONTINUATION ("Continue" prompts):
                        If user asks to "Continue" after an incomplete operation:
                        1. Read the file to see what was successfully written
                        2. Continue writing ONLY the remaining content using {mode: 'append'}
                        3. Keep chunks to 25-30 lines each

                        FORMAT HANDLING (by extension):
                        - Text files: String content
                        - Excel (.xlsx, .xls, .xlsm): JSON 2D array or {"SheetName": [[...]]}
                          Example: '[["Name","Age"],["Alice",30]]'

                        Files over 50 lines will generate performance notes but are still written successfully.
                        Only works within allowed directories.

                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
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
<summary>write_pdf</summary>

**Description**:

```

                        Create a new PDF file or modify an existing one.

                        THIS IS THE ONLY TOOL FOR CREATING AND MODIFYING PDF FILES.

                        RULES ABOUT FILENAMES:
                        - When creating a new PDF, 'outputPath' MUST be provided and MUST use a new unique filename (e.g., "result_01.pdf", "analysis_2025_01.pdf", etc.).

                        MODES:
                        1. CREATE NEW PDF:
                           - Pass a markdown string as 'content'.
                           write_pdf(path="doc.pdf", content="# Title\n\nBody text...")

                        2. MODIFY EXISTING PDF:
                           - Pass array of operations as 'content'.
                           - NEVER overwrite the original file.
                           - ALWAYS provide a new filename in 'outputPath'.
                           - After modifying, show original file path and new file path to user.

                           write_pdf(path="doc.pdf", content=[
                               { type: "delete", pageIndexes: [0, 2] },
                               { type: "insert", pageIndex: 1, markdown: "# New Page" }
                           ])

                        OPERATIONS:
                        - delete: Remove pages by 0-based index.
                          { type: "delete", pageIndexes: [0, 1, 5] }

                        - insert: Add pages at a specific 0-based index.
                          { type: "insert", pageIndex: 0, markdown: "..." }
                          { type: "insert", pageIndex: 5, sourcePdfPath: "/path/to/source.pdf" }

                        PAGE BREAKS:
                        To force a page break, use this HTML element:
                        <div style="page-break-before: always;"></div>
                        
                        Example:
                        "# Page 1\n\n<div style=\"page-break-before: always;\"></div>\n\n# Page 2"

                        ADVANCED STYLING:
                        HTML/CSS and inline SVG are supported for:
                        - Text styling: colors, sizes, alignment, highlights
                        - Boxes: borders, backgrounds, padding, rounded corners
                        - SVG graphics: charts, diagrams, icons, shapes
                        - Images: <img src="/absolute/path/image.jpg" width="300" /> or ![alt](/path/image.jpg)

                        Supports standard markdown features including headers, lists, code blocks, tables, and basic formatting.

                        Only works within allowed directories.

                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | any | not set | Yes
| options | object | not set | No
| outputPath | string | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>create_directory</summary>

**Description**:

```

                        Create a new directory or ensure a directory exists.
                        
                        Can create multiple nested directories in one operation.
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
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
                        
                        Supports recursive listing with the 'depth' parameter (default: 2):
                        - depth=1: Only direct contents of the directory
                        - depth=2: Contents plus one level of subdirectories
                        - depth=3+: Multiple levels deep
                        
                        CONTEXT OVERFLOW PROTECTION:
                        - Top-level directory shows ALL items
                        - Nested directories are limited to 100 items maximum per directory
                        - When a nested directory has more than 100 items, you'll see a warning like:
                          [WARNING] node_modules: 500 items hidden (showing first 100 of 600 total)
                        - This prevents overwhelming the context with large directories like node_modules
                        
                        Results show full relative paths from the root directory being listed.
                        Example output with depth=2:
                        [DIR] src
                        [FILE] src/index.ts
                        [DIR] src/tools
                        [FILE] src/tools/filesystem.ts
                        
                        If a directory cannot be accessed, it will show [DENIED] instead.
                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | number | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>move_file</summary>

**Description**:

```

                        Move or rename files and directories.
                        
                        Can move files between directories and rename them in a single operation.
                        Both source and destination must be within allowed directories.
                        
                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | not set | Yes
| source | string | not set | Yes
</details>
<details>
<summary>start_search</summary>

**Description**:

```

                        Start a streaming search that can return results progressively.
                        
                        SEARCH STRATEGY GUIDE:
                        Choose the right search type based on what the user is looking for:
                        
                        USE searchType="files" WHEN:
                        - User asks for specific files: "find package.json", "locate config files"
                        - Pattern looks like a filename: "*.js", "README.md", "test-*.tsx" 
                        - User wants to find files by name/extension: "all TypeScript files", "Python scripts"
                        - Looking for configuration/setup files: ".env", "dockerfile", "tsconfig.json"
                        
                        USE searchType="content" WHEN:
                        - User asks about code/logic: "authentication logic", "error handling", "API calls"
                        - Looking for functions/variables: "getUserData function", "useState hook"
                        - Searching for text/comments: "TODO items", "FIXME comments", "documentation"
                        - Finding patterns in code: "console.log statements", "import statements"
                        - User describes functionality: "components that handle login", "files with database queries"
                        
                        WHEN UNSURE OR USER REQUEST IS AMBIGUOUS:
                        Run TWO searches in parallel - one for files and one for content:
                        
                        Example approach for ambiguous queries like "find authentication stuff":
                        1. Start file search: searchType="files", pattern="auth"
                        2. Simultaneously start content search: searchType="content", pattern="authentication"  
                        3. Present combined results: "Found 3 auth-related files and 8 files containing authentication code"
                        
                        SEARCH TYPES:
                        - searchType="files": Find files by name (pattern matches file names)
                        - searchType="content": Search inside files for text patterns
                        
                        PATTERN MATCHING MODES:
                        - Default (literalSearch=false): Patterns are treated as regular expressions
                        - Literal (literalSearch=true): Patterns are treated as exact strings
                        
                        WHEN TO USE literalSearch=true:
                        Use literal search when searching for code patterns with special characters:
                        - Function calls with parentheses and quotes
                        - Array access with brackets
                        - Object methods with dots and parentheses
                        - File paths with backslashes
                        - Any pattern containing: . * + ? ^ $ { } [ ] | \ ( )
                        
                        IMPORTANT PARAMETERS:
                        - pattern: What to search for (file names OR content text)
                        - literalSearch: Use exact string matching instead of regex (default: false)
                        - filePattern: Optional filter to limit search to specific file types (e.g., "*.js", "package.json")
                        - ignoreCase: Case-insensitive search (default: true). Works for both file names and content.
                        - earlyTermination: Stop search early when exact filename match is found (optional: defaults to true for file searches, false for content searches)
                        
                        DECISION EXAMPLES:
                        - "find package.json" → searchType="files", pattern="package.json" (specific file)
                        - "find authentication components" → searchType="content", pattern="authentication" (looking for functionality)
                        - "locate all React components" → searchType="files", pattern="*.tsx" or "*.jsx" (file pattern)
                        - "find TODO comments" → searchType="content", pattern="TODO" (text in files)
                        - "show me login files" → AMBIGUOUS → run both: files with "login" AND content with "login"
                        - "find config" → AMBIGUOUS → run both: config files AND files containing config code
                        
                        COMPREHENSIVE SEARCH EXAMPLES:
                        - Find package.json files: searchType="files", pattern="package.json"
                        - Find all JS files: searchType="files", pattern="*.js"
                        - Search for TODO in code: searchType="content", pattern="TODO", filePattern="*.js|*.ts"
                        - Search for exact code: searchType="content", pattern="toast.error('test')", literalSearch=true
                        - Ambiguous request "find auth stuff": Run two searches:
                          1. searchType="files", pattern="auth"
                          2. searchType="content", pattern="authentication"
                        
                        PRO TIP: When user requests are ambiguous about whether they want files or content,
                        run both searches concurrently and combine results for comprehensive coverage.
                        
                        Unlike regular search tools, this starts a background search process and returns
                        immediately with a session ID. Use get_more_search_results to get results as they
                        come in, and stop_search to stop the search early if needed.
                        
                        Perfect for large directories where you want to see results immediately and
                        have the option to cancel if the search takes too long or you find what you need.
                        
                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contextLines | number | not set | No
| earlyTermination | boolean | not set | No
| filePattern | string | not set | No
| ignoreCase | boolean | not set | No
| includeHidden | boolean | not set | No
| literalSearch | boolean | not set | No
| maxResults | number | not set | No
| path | string | not set | Yes
| pattern | string | not set | Yes
| searchType | string | not set | No
| timeout_ms | number | not set | No
</details>
<details>
<summary>get_more_search_results</summary>

**Description**:

```

                        Get more results from an active search with offset-based pagination.
                        
                        Supports partial result reading with:
                        - 'offset' (start result index, default: 0)
                          * Positive: Start from result N (0-based indexing)
                          * Negative: Read last N results from end (tail behavior)
                        - 'length' (max results to read, default: 100)
                          * Used with positive offsets for range reading
                          * Ignored when offset is negative (reads all requested tail results)
                        
                        Examples:
                        - offset: 0, length: 100     → First 100 results
                        - offset: 200, length: 50    → Results 200-249
                        - offset: -20                → Last 20 results
                        - offset: -5, length: 10     → Last 5 results (length ignored)
                        
                        Returns only results in the specified range, along with search status.
                        Works like read_process_output - call this repeatedly to get progressive
                        results from a search started with start_search.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| length | number | not set | No
| offset | number | not set | No
| sessionId | string | not set | Yes
</details>
<details>
<summary>stop_search</summary>

**Description**:

```

                        Stop an active search.
                        
                        Stops the background search process gracefully. Use this when you've found
                        what you need or if a search is taking too long. Similar to force_terminate
                        for terminal processes.
                        
                        The search will still be available for reading final results until it's
                        automatically cleaned up after 5 minutes.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | not set | Yes
</details>
<details>
<summary>list_searches</summary>

**Description**:

```

                        List all active searches.
                        
                        Shows search IDs, search types, patterns, status, and runtime.
                        Similar to list_sessions for terminal processes. Useful for managing
                        multiple concurrent searches.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
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
                        - sheets (for Excel files - array of {name, rowCount, colCount})

                        Only works within allowed directories.
                        
                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
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

                        Apply surgical edits to files.

                        BEST PRACTICE: Make multiple small, focused edits rather than one large edit.
                        Each edit_block call should change only what needs to be changed - include just enough
                        context to uniquely identify the text being modified.

                        FORMAT HANDLING (by extension):

                        EXCEL FILES (.xlsx, .xls, .xlsm) - Range Update mode:
                        Takes:
                        - file_path: Path to the Excel file
                        - range: ALWAYS use FROM:TO format - "SheetName!A1:C10" or "SheetName!C1:C1"
                        - content: 2D array, e.g., [["H1","H2"],["R1","R2"]]

                        TEXT FILES - Find/Replace mode:
                        Takes:
                        - file_path: Path to the file to edit
                        - old_string: Text to replace
                        - new_string: Replacement text
                        - expected_replacements: Optional number of replacements (default: 1)

                        By default, replaces only ONE occurrence of the search text.
                        To replace multiple occurrences, provide expected_replacements with
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

                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | any | not set | No
| expected_replacements | number | not set | No
| file_path | string | not set | Yes
| new_string | string | not set | No
| old_string | string | not set | No
| options | object | not set | No
| range | string | not set | No
</details>
<details>
<summary>start_process</summary>

**Description**:

```

                        Start a new terminal process with intelligent state detection.
                        
                        PRIMARY TOOL FOR FILE ANALYSIS AND DATA PROCESSING
                        This is the ONLY correct tool for analyzing local files (CSV, JSON, logs, etc.).
                        The analysis tool CANNOT access local files and WILL FAIL - always use processes for file-based work.
                        
                        CRITICAL RULE: For ANY local file work, ALWAYS use this tool + interact_with_process, NEVER use analysis/REPL tool.
                        
                        Running on Linux (Docker). Default shell: bash.

🐳 DOCKER CONTAINER ENVIRONMENT DETECTED:
This Desktop Commander instance is running inside a Docker container.

AVAILABLE MOUNTED DIRECTORIES:
- /home/appuser (read-write) - Host folder: appuser

IMPORTANT: When users ask about files, FIRST check mounted directories above.
Files outside these paths will be lost when the container stops.
Always suggest using mounted directories for file operations.

PATH TRANSLATION IN DOCKER:
When users provide host paths, translate to container paths:

Windows: "C:\projects\data\file.txt" → "/home/projects/data/file.txt"
Linux/Mac: "/Users/john/projects/data/file.txt" → "/home/projects/data/file.txt"

Rules: Remove drive letter/user prefix, keep full folder structure, mount to /home/

NOTE: Desktop Commander Docker installer mounts host folders to /home/[folder-name].
Container: 369c696c356f
        
LINUX-SPECIFIC NOTES:
- Package managers vary by distro: apt, yum, dnf, pacman, zypper
- Python 3 might be 'python3' command, not 'python'
- Standard Unix shell tools available (grep, awk, sed, etc.)
- File permissions and ownership important for many operations
- Systemd services common on modern distributions
                        
                        REQUIRED WORKFLOW FOR LOCAL FILES:
                        1. start_process("python3 -i") - Start Python REPL for data analysis
                        2. interact_with_process(pid, "import pandas as pd, numpy as np")
                        3. interact_with_process(pid, "df = pd.read_csv('/absolute/path/file.csv')")
                        4. interact_with_process(pid, "print(df.describe())")
                        5. Continue analysis with pandas, matplotlib, seaborn, etc.
                        
                        COMMON FILE ANALYSIS PATTERNS:
                        • start_process("python3 -i") → Python REPL for data analysis (RECOMMENDED)
                        • start_process("node -i") → Node.js REPL for JSON processing
                        • start_process("node:local") → Node.js on MCP server (stateless, ES imports, all code in one call)
                        • start_process("cut -d',' -f1 file.csv | sort | uniq -c") → Quick CSV analysis
                        • start_process("wc -l /path/file.csv") → Line counting
                        • start_process("head -10 /path/file.csv") → File preview
                        
                        BINARY FILE SUPPORT:
                        For PDF, Excel, Word, archives, databases, and other binary formats, use process tools with appropriate libraries or command-line utilities.
                        
                        INTERACTIVE PROCESSES FOR DATA ANALYSIS:
                        For code/calculations, use in this priority order:
                        1. start_process("python3 -i") - Python REPL (preferred)
                        2. start_process("node -i") - Node.js REPL (when Python unavailable)
                        3. start_process("node:local") - Node.js fallback (when node -i fails)
                        4. Use interact_with_process() to send commands
                        5. Use read_process_output() to get responses
                        When Python is unavailable, prefer Node.js over shell for calculations.
                        Node.js: Always use ES import syntax (import x from 'y'), not require().

                        SMART DETECTION:
                        - Detects REPL prompts (>>>, >, $, etc.)
                        - Identifies when process is waiting for input
                        - Recognizes process completion vs timeout
                        - Early exit prevents unnecessary waiting
                        
                        STATES DETECTED:
                        Process waiting for input (shows prompt)
                        Process finished execution
                        Process running (use read_process_output)

                        PERFORMANCE DEBUGGING (verbose_timing parameter):
                        Set verbose_timing: true to get detailed timing information including:
                        - Exit reason (early_exit_quick_pattern, early_exit_periodic_check, process_exit, timeout)
                        - Total duration and time to first output
                        - Complete timeline of all output events with timestamps
                        - Which detection mechanism triggered early exit
                        Use this to identify missed optimization opportunities and improve detection patterns.

                        ALWAYS USE FOR: Local file analysis, CSV processing, data exploration, system commands
                        NEVER USE ANALYSIS TOOL FOR: Local file access (analysis tool is browser-only and WILL FAIL)

                        IMPORTANT: Always use absolute paths for reliability. Paths are automatically normalized regardless of slash direction. 

🐳 DOCKER: Prefer paths within mounted directories: /home/appuser.
When users ask about file locations, check these mounted paths first. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths.
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | not set | Yes
| shell | string | not set | No
| timeout_ms | number | not set | Yes
| verbose_timing | boolean | not set | No
</details>
<details>
<summary>read_process_output</summary>

**Description**:

```

                        Read output from a running process with file-like pagination support.
                        
                        Supports partial output reading with offset and length parameters (like read_file):
                        - 'offset' (start line, default: 0)
                          * offset=0: Read NEW output since last read (default, like old behavior)
                          * Positive: Read from absolute line position
                          * Negative: Read last N lines from end (tail behavior)
                        - 'length' (max lines to read, default: configurable via 'fileReadLineLimit' setting)
                        
                        Examples:
                        - offset: 0, length: 100     → First 100 NEW lines since last read
                        - offset: 0                  → All new lines (respects config limit)
                        - offset: 500, length: 50    → Lines 500-549 (absolute position)
                        - offset: -20                → Last 20 lines (tail)
                        - offset: -50, length: 10    → Start 50 from end, read 10 lines
                        
                        OUTPUT PROTECTION:
                        - Uses same fileReadLineLimit as read_file (default: 1000 lines)
                        - Returns status like: [Reading 100 lines from line 0 (total: 5000 lines, 4900 remaining)]
                        - Prevents context overflow from verbose processes
                        
                        SMART FEATURES:
                        - For offset=0, waits up to timeout_ms for new output to arrive
                        - Detects REPL prompts and process completion
                        - Shows process state (waiting for input, finished, etc.)
                        
                        DETECTION STATES:
                        Process waiting for input (ready for interact_with_process)
                        Process finished execution
                        Timeout reached (may still be running)

                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| length | number | not set | No
| offset | number | not set | No
| pid | number | not set | Yes
| timeout_ms | number | not set | No
| verbose_timing | boolean | not set | No
</details>
<details>
<summary>interact_with_process</summary>

**Description**:

```

                        Send input to a running process and automatically receive the response.
                        
                        CRITICAL: THIS IS THE PRIMARY TOOL FOR ALL LOCAL FILE ANALYSIS
                        For ANY local file analysis (CSV, JSON, data processing), ALWAYS use this instead of the analysis tool.
                        The analysis tool CANNOT access local files and WILL FAIL - use processes for ALL file-based work.
                        
                        FILE ANALYSIS PRIORITY ORDER (MANDATORY):
                        1. ALWAYS FIRST: Use this tool (start_process + interact_with_process) for local data analysis
                        2. ALTERNATIVE: Use command-line tools (cut, awk, grep) for quick processing  
                        3. NEVER EVER: Use analysis tool for local file access (IT WILL FAIL)
                        
                        REQUIRED INTERACTIVE WORKFLOW FOR FILE ANALYSIS:
                        1. Start REPL: start_process("python3 -i")
                        2. Load libraries: interact_with_process(pid, "import pandas as pd, numpy as np")
                        3. Read file: interact_with_process(pid, "df = pd.read_csv('/absolute/path/file.csv')")
                        4. Analyze: interact_with_process(pid, "print(df.describe())")
                        5. Continue: interact_with_process(pid, "df.groupby('column').size()")
                        
                        BINARY FILE PROCESSING WORKFLOWS:
                        Use appropriate Python libraries (PyPDF2, pandas, docx2txt, etc.) or command-line tools for binary file analysis.
                        
                        SMART DETECTION:
                        - Automatically waits for REPL prompt (>>>, >, etc.)
                        - Detects errors and completion states
                        - Early exit prevents timeout delays
                        - Clean output formatting (removes prompts)
                        
                        SUPPORTED REPLs:
                        - Python: python3 -i (RECOMMENDED for data analysis)
                        - Node.js: node -i
                        - R: R
                        - Julia: julia
                        - Shell: bash, zsh
                        - Database: mysql, postgres
                        
                        PARAMETERS:
                        - pid: Process ID from start_process
                        - input: Code/command to execute
                        - timeout_ms: Max wait (default: 8000ms)
                        - wait_for_prompt: Auto-wait for response (default: true)
                        - verbose_timing: Enable detailed performance telemetry (default: false)

                        Returns execution result with status indicators.

                        PERFORMANCE DEBUGGING (verbose_timing parameter):
                        Set verbose_timing: true to get detailed timing information including:
                        - Exit reason (early_exit_quick_pattern, early_exit_periodic_check, process_finished, timeout, no_wait)
                        - Total duration and time to first output
                        - Complete timeline of all output events with timestamps
                        - Which detection mechanism triggered early exit
                        Use this to identify slow interactions and optimize detection patterns.

                        ALWAYS USE FOR: CSV analysis, JSON processing, file statistics, data visualization prep, ANY local file work
                        NEVER USE ANALYSIS TOOL FOR: Local file access (it cannot read files from disk and WILL FAIL)

                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| input | string | not set | Yes
| pid | number | not set | Yes
| timeout_ms | number | not set | No
| verbose_timing | boolean | not set | No
| wait_for_prompt | boolean | not set | No
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
                        
                        Shows session status including:
                        - PID: Process identifier  
                        - Blocked: Whether session is waiting for input
                        - Runtime: How long the session has been running
                        
                        DEBUGGING REPLs:
                        - "Blocked: true" often means REPL is waiting for input
                        - Use this to verify sessions are running before sending input
                        - Long runtime with blocked status may indicate stuck process
                        
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
<details>
<summary>get_usage_stats</summary>

**Description**:

```

                        Get usage statistics for debugging and analysis.
                        
                        Returns summary of tool usage, success/failure rates, and performance metrics.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_recent_tool_calls</summary>

**Description**:

```

                        Get recent tool call history with their arguments and outputs.
                        Returns chronological list of tool calls made during this session.
                        
                        Useful for:
                        - Onboarding new chats about work already done
                        - Recovering context after chat history loss
                        - Debugging tool call sequences
                        
                        Note: Does not track its own calls or other meta/query tools.
                        History kept in memory (last 1000 calls, lost on restart).
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxResults | number | not set | No
| since | string | not set | No
| toolName | string | not set | No
</details>
<details>
<summary>give_feedback_to_desktop_commander</summary>

**Description**:

```

                        Open feedback form in browser to provide feedback about Desktop Commander.
                        
                        IMPORTANT: This tool simply opens the feedback form - no pre-filling available.
                        The user will fill out the form manually in their browser.
                        
                        WORKFLOW:
                        1. When user agrees to give feedback, just call this tool immediately
                        2. No need to ask questions or collect information
                        3. Tool opens form with only usage statistics pre-filled automatically:
                           - tool_call_count: Number of commands they've made
                           - days_using: How many days they've used Desktop Commander
                           - platform: Their operating system (Mac/Windows/Linux)
                           - client_id: Analytics identifier
                        
                        All survey questions will be answered directly in the form:
                        - Job title and technical comfort level
                        - Company URL for industry context
                        - Other AI tools they use
                        - Desktop Commander's biggest advantage
                        - How they typically use it
                        - Recommendation likelihood (0-10)
                        - User study participation interest
                        - Email and any additional feedback
                        
                        EXAMPLE INTERACTION:
                        User: "sure, I'll give feedback"
                        Claude: "Perfect! Let me open the feedback form for you."
                        [calls tool immediately]
                        
                        No parameters are needed - just call the tool to open the form.
                        
                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_prompts</summary>

**Description**:

```

                        Retrieve a specific Desktop Commander onboarding prompt by ID and execute it.
                        
                        SIMPLIFIED ONBOARDING V2: This tool only supports direct prompt retrieval.
                        The onboarding system presents 5 options as a simple numbered list:
                        
                        1. Organize my Downloads folder (promptId: 'onb2_01')
                        2. Explain a codebase or repository (promptId: 'onb2_02')
                        3. Create organized knowledge base (promptId: 'onb2_03')
                        4. Analyze a data file (promptId: 'onb2_04')
                        5. Check system health and resources (promptId: 'onb2_05')
                        
                        USAGE:
                        When user says "1", "2", "3", "4", or "5" from onboarding:
                        - "1" → get_prompts(action='get_prompt', promptId='onb2_01')
                        - "2" → get_prompts(action='get_prompt', promptId='onb2_02')
                        - "3" → get_prompts(action='get_prompt', promptId='onb2_03')
                        - "4" → get_prompts(action='get_prompt', promptId='onb2_04')
                        - "5" → get_prompts(action='get_prompt', promptId='onb2_05')
                        
                        The prompt content will be injected and execution begins immediately.

                        This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | not set | Yes
| promptId | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_directory | description | 35929f2a1500f142cedea08b105d64ae5803cc08f5137f1ef948d64580490642 |
| tools | edit_block | description | a33681e0290593b4c30b329831e1743ccf0963c0cdbb5a4a5539f4f231c18b44 |
| tools | force_terminate | description | 9109012600d4a9a370367c4479fcae7092b5aaae0fb55f074e8eab0afb9c8306 |
| tools | get_config | description | 23d2cf43fb5ae48251a88b2d2424a987031323838dbba337a7de4cf5367039a1 |
| tools | get_file_info | description | b5558228c7e033811be7888767773426b542700dbe19ccd488dd04a84d03ff99 |
| tools | get_more_search_results | description | f336b2bfa716bf6ef6b2f07c3dfc9a4a156c5b93416f80218e2b2d1d3daa9f66 |
| tools | get_prompts | description | 1f8f70533ab74fe7a2cfaa96f3be413888af11481f6c250603c9261f3f766e2b |
| tools | get_recent_tool_calls | description | da806ef6ab0286b4fbf5bcb8a25789a3696ca449688b41421ad7c5cb35a7596f |
| tools | get_usage_stats | description | 25b118cb6c54a7f596fa6745c1682647b494553a61f5ec2c3585d0e2691d3544 |
| tools | give_feedback_to_desktop_commander | description | 71f2b9f5565a3ea8f5cdf00c055b7495f0c4158a2155f4e240030a864db81dc5 |
| tools | interact_with_process | description | cd80cc97b6638f9165e31f0e2d5b9d84164df7bd9ecc91a64d6f3199df1df3c2 |
| tools | kill_process | description | e0f11a540a85bc7e384344d499958d6135cdb5335d2fdb9d048bf21cf3c8df4e |
| tools | list_directory | description | 73bf9d202fdf067a0fdc65c2afc3b49429a32c0301d09d55730489f9fcd6af54 |
| tools | list_processes | description | bccaf3bd87272c75e038e50077bca491355236be9fb99d131463c34553df9a2a |
| tools | list_searches | description | 5f5e9de424d71de978b335ac89d6c52668903813c07643beff95c53663d873ff |
| tools | list_sessions | description | 7a355d8b85348a78e976ed84445a1246ddff6d4b3a1b2aff8f4cd2d9c9dc8fc7 |
| tools | move_file | description | c7f6a7015717a302e2ce7502045fb05cc9f29522c9c70bfa9de8b1a0e8dde96d |
| tools | read_file | description | 00a18b4f97cb9f9b86d86636eea3d43bc9e7e7b8da6d2ee3f1b2f392522086be |
| tools | read_multiple_files | description | bc0b5749147ce71c98529bc186f900af1414333f95f0f8dd0257d985a0bb4144 |
| tools | read_process_output | description | 441069f97a9cc09c43e8f2ec0c28530b362dd8de35793acfa25370c0631d7d1f |
| tools | set_config_value | description | 155afe1d85ebd07ac64f76703797548c8b48a1e2a3d63b14c2369633527df389 |
| tools | start_process | description | 77c8203a6f530d830ddf82b206582bc10f0916dc6b62f014fcf30bfa527518cd |
| tools | start_search | description | 98be6d33259e5a29f48a48501c40d8691f9a07b794a409121ceb8c54f849ced6 |
| tools | stop_search | description | b883c2ef066c772135bfa92d22654e4eedbe71b6afe10b4fb144d647cd063d44 |
| tools | write_file | description | 1be2fa72e631cd018f7f831e7622a118a9ffa13986d57d09ae3d66c0981e336b |
| tools | write_pdf | description | ec46c51f5cd9030eec0c2af23fd0b0ad18c7d39c88a6557e6ff930ea786e672a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
