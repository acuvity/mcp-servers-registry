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
</p>


# What is mcp-server-basic-memory?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-basic-memory/0.12.3?logo=docker&logoColor=fff&label=0.12.3)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory)
[![PyPI](https://img.shields.io/badge/0.12.3-3775A9?logo=pypi&logoColor=fff&label=basic-memory)](https://pypi.org/project/basic-memory/)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-basic-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22memory%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-basic-memory%3A0.12.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Local-first knowledge management combining Zettelkasten with knowledge graphs

> [!NOTE]
> `basic-memory` has been repackaged by Acuvity from Basic Machines <hello@basic-machines.co> original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure basic-memory run reliably and safely.

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
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails that protect MCP server integrity and detect suspicious behaviors in real-time.:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions - or call arguments - reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognised tokens formats with `[REDACTED]` in outbound content.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# 📦 How to Use


> [!NOTE]
> Given mcp-server-basic-memory scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-basic-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22memory%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-basic-memory%3A0.12.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-basic-memory": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-v",
          "memory:/data",
          "docker.io/acuvity/mcp-server-basic-memory:0.12.3"
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
    "acuvity-mcp-server-basic-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-basic-memory:0.12.3"
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
    "acuvity-mcp-server-basic-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-basic-memory:0.12.3"
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
    "acuvity-mcp-server-basic-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-basic-memory:0.12.3"
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
    "acuvity-mcp-server-basic-memory": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "memory:/data",
        "docker.io/acuvity/mcp-server-basic-memory:0.12.3"
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
        "args": ["run","-i","--rm","--read-only","-v","memory:/data","docker.io/acuvity/mcp-server-basic-memory:0.12.3"]
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
**Environment variables:**
  - `HOME` optional (/data)
  - `BASIC_MEMORY_HOME` optional (/data)
**Required volumes or mountPaths:**
  - data to be mounted on `/data`


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -v memory:/data docker.io/acuvity/mcp-server-basic-memory:0.12.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -v memory:/data docker.io/acuvity/mcp-server-basic-memory:0.12.3
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-basic-memory": {
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
    "acuvity-mcp-server-basic-memory": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Of course there are plenty of other options that minibridge can provide.

Don't be shy to ask question either.

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
  - `HOME="/data"` environment variable can be changed with env.HOME="/data"
  - `BASIC_MEMORY_HOME="/data"` environment variable can be changed with env.BASIC_MEMORY_HOME="/data"

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0
````

Install with helm

```console
helm install mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0
```

From there your MCP server mcp-server-basic-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-basic-memory` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/charts/mcp-server-basic-memory/README.md) for more details about settings.

</details>


# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>delete_note</summary>

**Description**:

```
Delete a note by title or permalink
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | <no value> | Yes
</details>
<details>
<summary>read_content</summary>

**Description**:

```
Read a file's raw content by path or permalink
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | <no value> | Yes
</details>
<details>
<summary>build_context</summary>

**Description**:

```
Build context from a memory:// URI to continue conversations naturally.
    
    Use this to follow up on previous discussions or explore related topics.
    Timeframes support natural language like:
    - "2 days ago"
    - "last week" 
    - "today"
    - "3 months ago"
    Or standard formats like "7d", "24h"
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | <no value> | <no value> | No
| max_related | integer | <no value> | No
| page | integer | <no value> | No
| page_size | integer | <no value> | No
| timeframe | <no value> | <no value> | No
| url | string | <no value> | Yes
</details>
<details>
<summary>recent_activity</summary>

**Description**:

```
Get recent activity from across the knowledge base.

    Timeframe supports natural language formats like:
    - "2 days ago"  
    - "last week"
    - "yesterday" 
    - "today"
    - "3 weeks ago"
    Or standard formats like "7d"
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | integer | <no value> | No
| max_related | integer | <no value> | No
| page | integer | <no value> | No
| page_size | integer | <no value> | No
| timeframe | string | <no value> | No
| type | <no value> | <no value> | No
</details>
<details>
<summary>search_notes</summary>

**Description**:

```
Search across all content in the knowledge base.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after_date | <no value> | <no value> | No
| entity_types | <no value> | <no value> | No
| page | integer | <no value> | No
| page_size | integer | <no value> | No
| query | string | <no value> | Yes
| search_type | string | <no value> | No
| types | <no value> | <no value> | No
</details>
<details>
<summary>read_note</summary>

**Description**:

```
Read a markdown note by title or permalink.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | <no value> | Yes
| page | integer | <no value> | No
| page_size | integer | <no value> | No
</details>
<details>
<summary>write_note</summary>

**Description**:

```
Create or update a markdown note. Returns a markdown formatted summary of the semantic content.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | <no value> | Yes
| folder | string | <no value> | Yes
| tags | string | <no value> | No
| title | string | <no value> | Yes
</details>
<details>
<summary>canvas</summary>

**Description**:

```
Create an Obsidian canvas file to visualize concepts and connections.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| edges | array | <no value> | Yes
| folder | string | <no value> | Yes
| nodes | array | <no value> | Yes
| title | string | <no value> | Yes
</details>
<details>
<summary>project_info</summary>

**Description**:

```
Get information and statistics about the current Basic Memory project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| ai assistant guide | text/plain | memory://ai_assistant_guide | <no value> |

</details>

## 📝 Prompts (3)
<details>
<summary>Continue Conversation</summary>

**Description**:

```
Continue a previous conversation
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| topic | Topic or keyword to search for | <no value> |
| timeframe | How far back to look for activity (e.g. '1d', '1 week') | <no value> |
<details>
<summary>Share Recent Activity</summary>

**Description**:

```
Get recent activity from across the knowledge base
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| timeframe | How far back to look for activity (e.g. '1d', '1 week') | <no value> |
<details>
<summary>Search Knowledge Base</summary>

**Description**:

```
Search across all content in basic-memory
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| query | <no value> | true |
| timeframe | How far back to search (e.g. '1d', '1 week') | <no value> |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | Continue Conversation | description | 08f57034421ff1f069d1c1f6dd0dd640b9982a6ba21a5b2442953cb1b5dd6efa |
| prompts | Continue Conversation | timeframe | cd9af00423b977d8f501edaeef3d43f42a323778bbbcc0900c4d88b6a4f9354e |
| prompts | Continue Conversation | topic | d8cb6ba6d70a65d763ba5f3f38b7f24ffee35f1f32c0fb1d5bfe095ba9f2d327 |
| prompts | Search Knowledge Base | description | dcd0e4296554bc417239afd10b686e82c4879c842c3a7c60a2288ad0152513e3 |
| prompts | Search Knowledge Base | query | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Search Knowledge Base | timeframe | ac891e951bb4167b6fafdd14fdac08a1dcf761aacef7f3add86de2000a8223fb |
| prompts | Share Recent Activity | description | acaf99888843d7d2c0243f8bf67259929179ab71579a4af5a16571f3485475f7 |
| prompts | Share Recent Activity | timeframe | cd9af00423b977d8f501edaeef3d43f42a323778bbbcc0900c4d88b6a4f9354e |
| tools | build_context | description | 5e8820de852b3082413d3bd44c6d0b5764cea766cadfcac66876f4b49e604614 |
| tools | canvas | description | c739f799c4f54a0beebbbba387862e5370f4e715f36b65d0e523b3fe664d759c |
| tools | delete_note | description | b92bd108ffa7b65b4ac92c9f75167080771a08e3e9a78dd6ec3fabde085802b7 |
| tools | project_info | description | 80e50af2790edd8a0228a515f76a18d540cb04542b3f5fa91037917a6ae13847 |
| tools | read_content | description | 5b184094eabd23821254f0608ad35de1570fd776906e9ff822020cd68d129921 |
| tools | read_note | description | 5d503b64dafb1601312dd1780eb5fbdb5d7988f7d1ce090545c3fb033c0bec77 |
| tools | recent_activity | description | 8b43acabdd7bc9e4ab6398f1f27b28203fb5df0314d7f0888946136d40f548d5 |
| tools | search_notes | description | fcaec1323a397ec1b89c8d50efb4cf4af054f0574d569452599c927231594adc |
| tools | write_note | description | 3fb632ad40400235da2eae016e76b13f699cd2206aca615729e8ee85653ec98f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
