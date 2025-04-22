
<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://mma.prnewswire.com/media/2544052/Acuvity__Logo.jpg" height="90" alt="Acuvity logo"/>
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://discord.gg/BkU7fBkrNk">
    <img src="https://img.shields.io/badge/Acuvity-Join-7289DA?logo=discord&logoColor=fff)](https://discord.gg/BkU7fBkrNk" alt="Join Acuvity community" /></a>
<a href="https://www.linkedin.com/company/acuvity/">
    <img src="https://img.shields.io/badge/LinkedIn-follow-0a66c2" alt="Follow us on LinkedIn" />
  </a>
</p>


# What is mcp-server-filesystem?

[![Helm](https://img.shields.io/badge/v1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-filesystem/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/2025.3.28?logo=docker&logoColor=fff&label=2025.3.28)](https://hub.docker.com/r/acuvity/mcp-server-filesystem/tags/2025.3.28)
[![PyPI](https://img.shields.io/badge/2025.3.28-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-filesystem)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for filesystem access

> [!NOTE]
> `@modelcontextprotocol/server-filesystem` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-filesystem run reliably and safely.

## 🔐 Key Security Features

<details>
<summary>📦 Isolated Immutable Sandbox </summary>

- **Isolated Execution**: All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.
- **Non-root by Default**: Enforces least-privilege principles, minimizing the impact of potential security breaches.
- **Read-only Filesystem**: Ensures runtime immutability, preventing unauthorized modification.
- **Version Pinning**: Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.
- **CVE Scanning**: Continuously monitors for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation.
- **SBOM & Provenance**: Provides full supply chain transparency with embedded metadata and traceable build information.
</details>

<details>
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails to protect MCP server integrity and detect suspicious behavior:

- **Integrity via Hashing**: Verifies the authenticity and integrity of tool descriptors and runtime components.
- **Threat Detection**:
  - Detects hidden or covert instruction patterns.
  - Monitors for schema parameter misuse as potential exfiltration channels.
  - Flags unauthorized access to sensitive files or credentials.
  - Identifies tool shadowing and override attempts.
  - Enforces cross-origin and server-mismatch protection policies.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# 📦 How to Use


> [!NOTE]
> Given mcp-server-filesystem scope of operation the intended usage is to run natively on the targeted machine to access local resources.

## 🐳 With Docker
**Required volumes or mountPaths:**
  - data to be mounted on `/data`


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -v path:/data docker.io/acuvity/mcp-server-filesystem:2025.3.28`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -v path:/data docker.io/acuvity/mcp-server-filesystem:2025.3.28
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-filesystem": {
      "url": "http://localhost:<localport>/sse",
    }
  }
}
```

You might have to use different ports for different tools.

</details>

<details>
<summary>Remotely with Websocket tunneling and MTLS </summary>

> This section assume you are familar with TLS and certificates and will require:
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
    "acuvity-mcp-server-filesystem": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Of course there is plenty of other option that minibridge can provide.

Don't be shy to ask question either.

</details>

## ☁️ On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-filesystem/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-filesystem --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-filesystem --version <version>
````

Install with helm

```console
helm install mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version <version>
```

From there your MCP server mcp-server-filesystem will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-filesystem` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/mcp-server-filesystem/charts/mcp-server-filesystem/README.md) for more details about settings.

</details>

# 🧰 Integrations

> [!NOTE]
> All the integrations below should work natively for all run mode.
> Only the `docker` local run is described to keep it concise.

<details>
<summary>Visual Studio Code</summary>

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-filesystem": {
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-v","path:/data","docker.io/acuvity/mcp-server-filesystem:2025.3.28"]
      }
    }
  }
}
```

## Workspace scope

In your workspace createa file called `.vscode/mcp.json` and add the following section:

```json
{
  "servers": {
    "acuvity-mcp-server-filesystem": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","path:/data","docker.io/acuvity/mcp-server-filesystem:2025.3.28"]
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
    "acuvity-mcp-server-filesystem": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","path:/data","docker.io/acuvity/mcp-server-filesystem:2025.3.28"]
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
    "acuvity-mcp-server-filesystem": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","path:/data","docker.io/acuvity/mcp-server-filesystem:2025.3.28"]
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
    "acuvity-mcp-server-filesystem": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-v","path:/data","docker.io/acuvity/mcp-server-filesystem:2025.3.28"]
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
        "args": ["run","-i","--rm","--read-only","-v","path:/data","docker.io/acuvity/mcp-server-filesystem:2025.3.28"]
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

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>read_file</summary>

**Description**:

```
Read the complete contents of a file from the file system. Handles various text encodings and provides detailed error messages if the file cannot be read. Use this tool when you need to examine the contents of a single file. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | <no value> | Yes
</details>
<details>
<summary>read_multiple_files</summary>

**Description**:

```
Read the contents of multiple files simultaneously. This is more efficient than reading files one by one when you need to analyze or compare multiple files. Each file's content is returned with its path as a reference. Failed reads for individual files won't stop the entire operation. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| paths | array | <no value> | Yes
</details>
<details>
<summary>write_file</summary>

**Description**:

```
Create a new file or completely overwrite an existing file with new content. Use with caution as it will overwrite existing files without warning. Handles text content with proper encoding. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | <no value> | Yes
| path | string | <no value> | Yes
</details>
<details>
<summary>edit_file</summary>

**Description**:

```
Make line-based edits to a text file. Each edit replaces exact line sequences with new content. Returns a git-style diff showing the changes made. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dryRun | boolean | Preview changes using git-style diff format | No
| edits | array | <no value> | Yes
| path | string | <no value> | Yes
</details>
<details>
<summary>create_directory</summary>

**Description**:

```
Create a new directory or ensure a directory exists. Can create multiple nested directories in one operation. If the directory already exists, this operation will succeed silently. Perfect for setting up directory structures for projects or ensuring required paths exist. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | <no value> | Yes
</details>
<details>
<summary>list_directory</summary>

**Description**:

```
Get a detailed listing of all files and directories in a specified path. Results clearly distinguish between files and directories with [FILE] and [DIR] prefixes. This tool is essential for understanding directory structure and finding specific files within a directory. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | <no value> | Yes
</details>
<details>
<summary>directory_tree</summary>

**Description**:

```
Get a recursive tree view of files and directories as a JSON structure. Each entry includes 'name', 'type' (file/directory), and 'children' for directories. Files have no children array, while directories always have a children array (which may be empty). The output is formatted with 2-space indentation for readability. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | <no value> | Yes
</details>
<details>
<summary>move_file</summary>

**Description**:

```
Move or rename files and directories. Can move files between directories and rename them in a single operation. If the destination exists, the operation will fail. Works across different directories and can be used for simple renaming within the same directory. Both source and destination must be within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | <no value> | Yes
| source | string | <no value> | Yes
</details>
<details>
<summary>search_files</summary>

**Description**:

```
Recursively search for files and directories matching a pattern. Searches through all subdirectories from the starting path. The search is case-insensitive and matches partial names. Returns full paths to all matching items. Great for finding files when you don't know their exact location. Only searches within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| excludePatterns | array | <no value> | No
| path | string | <no value> | Yes
| pattern | string | <no value> | Yes
</details>
<details>
<summary>get_file_info</summary>

**Description**:

```
Retrieve detailed metadata about a file or directory. Returns comprehensive information including size, creation time, last modified time, permissions, and type. This tool is perfect for understanding file characteristics without reading the actual content. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | <no value> | Yes
</details>
<details>
<summary>list_allowed_directories</summary>

**Description**:

```
Returns the list of directories that this server is allowed to access. Use this to understand which directories are available before trying to access files.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_directory | description | 7e243b9bddbea4a901f0807ae14535972587b896eecde076b03dd4fbd3a9b5bd |
| tools | directory_tree | description | a51dfb91799e4e8ff62aad67e4b3665360cc62a328efe43a541e66e0fb78ff01 |
| tools | edit_file | description | 1349a91ad62c6a43363a6af7995e3f29f44bf5e9c5310dadd8c278aec75e3969 |
| tools | edit_file | dryRun | 3dd869be68e1ef354dda1870b0ed00f8ae2c79ba1604a672b42b054fca958bfc |
| tools | get_file_info | description | e4cae83266b5e75a423ffb34bd21b66c22d0b9d6b673fb4cc45ea02e7298f7f3 |
| tools | list_allowed_directories | description | 6ab054bcfc2f3cbbd833f8a3cb59ede6daae3b43f9939e58524e1d5b29458975 |
| tools | list_directory | description | 2a89821007a4702b0f7e7cd13107b335d1c49baba8ffc4d38fe8d1cfbe3ac789 |
| tools | move_file | description | 0a86f8ce8d46144ec865434db66cd5c5f90f16123206b3334d7196477526b2a1 |
| tools | read_file | description | fcd11b5a6da30a56f0fb021421897c152c7a6cd1bf77a7a2fd420524064a000e |
| tools | read_multiple_files | description | d5a30eac51a3257ccd4b0acf3b70788f2b180fe1b9807c02644fa3389ebcbcb0 |
| tools | search_files | description | 5a9ec8c0901b2ccf519cf939cdcd3a7fe262be2df9e6ab81605a7e04836b4788 |
| tools | write_file | description | 182c8895da7eacc6f301ba5895d779aca5c0a29cf622fa14f34f728657f79688 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
