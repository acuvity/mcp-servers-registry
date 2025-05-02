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


# What is mcp-server-21st-dev-magic?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-21st-dev-magic/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-21st-dev-magic/0.0.47?logo=docker&logoColor=fff&label=0.0.47)](https://hub.docker.com/r/acuvity/mcp-server-21st-dev-magic)
[![PyPI](https://img.shields.io/badge/0.0.47-3775A9?logo=pypi&logoColor=fff&label=@21st-dev/magic)](https://github.com/21st-dev/magic-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-21st-dev-magic&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22TWENTY_FIRST_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-21st-dev-magic%3A0.0.47%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Create crafted UI components inspired by the best 21st.dev design engineers.

> [!NOTE]
> `@21st-dev/magic` has been repackaged by Acuvity from serafim@21st.dev original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @21st-dev/magic run reliably and safely.

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
> Given mcp-server-21st-dev-magic scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-21st-dev-magic&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22TWENTY_FIRST_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-21st-dev-magic%3A0.0.47%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-21st-dev-magic": {
        "env": {
          "TWENTY_FIRST_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "TWENTY_FIRST_API_KEY",
          "docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47"
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
    "acuvity-mcp-server-21st-dev-magic": {
      "env": {
        "TWENTY_FIRST_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TWENTY_FIRST_API_KEY",
        "docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47"
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
    "acuvity-mcp-server-21st-dev-magic": {
      "env": {
        "TWENTY_FIRST_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TWENTY_FIRST_API_KEY",
        "docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47"
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
    "acuvity-mcp-server-21st-dev-magic": {
      "env": {
        "TWENTY_FIRST_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TWENTY_FIRST_API_KEY",
        "docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47"
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
    "acuvity-mcp-server-21st-dev-magic": {
      "env": {
        "TWENTY_FIRST_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TWENTY_FIRST_API_KEY",
        "docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47"
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
        "env": {"TWENTY_FIRST_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","TWENTY_FIRST_API_KEY","docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47"]
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
  - `TWENTY_FIRST_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e TWENTY_FIRST_API_KEY docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e TWENTY_FIRST_API_KEY docker.io/acuvity/mcp-server-21st-dev-magic:0.0.47
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-21st-dev-magic": {
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
    "acuvity-mcp-server-21st-dev-magic": {
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

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `TWENTY_FIRST_API_KEY` secret to be set as secrets.TWENTY_FIRST_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0
````

Install with helm

```console
helm install mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0
```

From there your MCP server mcp-server-21st-dev-magic will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-21st-dev-magic` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/charts/mcp-server-21st-dev-magic/README.md) for more details about settings.

</details>

# 🧠 Server features

## 🧰 Tools (4)
<details>
<summary>21st_magic_component_builder</summary>

**Description**:

```

"Use this tool when the user requests a new UI component—e.g., mentions /ui, /21 /21st, or asks for a button, input, dialog, table, form, banner, card, or other React component.
This tool ONLY returns the text snippet for that UI component. 
After calling this tool, you must edit or add files to integrate the snippet into the codebase."

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| absolutePathToCurrentFile | string | Absolute path to the current file to which we want to apply changes | Yes
| absolutePathToProjectDirectory | string | Absolute path to the project root directory | Yes
| context | string | Extract additional context about what should be done to create a ui component/page based on the user's message, search query, and conversation history, files. Don't halucinate and be on point. | Yes
| message | string | Full users message | Yes
| searchQuery | string | Generate a search query for 21st.dev (library for searching UI components) to find a UI component that matches the user's message. Must be a two-four words max or phrase | Yes
</details>
<details>
<summary>logo_search</summary>

**Description**:

```

Search and return logos in specified format (JSX, TSX, SVG).
Supports single and multiple logo searches with category filtering.
Can return logos in different themes (light/dark) if available.

When to use this tool:
1. When user types "/logo" command (e.g., "/logo GitHub")
2. When user asks to add a company logo that's not in the local project

Example queries:
- Single company: ["discord"]
- Multiple companies: ["discord", "github", "slack"]
- Specific brand: ["microsoft office"]
- Command style: "/logo GitHub" -> ["github"]
- Request style: "Add Discord logo to the project" -> ["discord"]

Format options:
- TSX: Returns TypeScript React component
- JSX: Returns JavaScript React component
- SVG: Returns raw SVG markup

Each result includes:
- Component name (e.g., DiscordIcon)
- Component code
- Import instructions

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Output format | Yes
| queries | array | List of company names to search for logos | Yes
</details>
<details>
<summary>21st_magic_component_inspiration</summary>

**Description**:

```

"Use this tool when the user wants to see component, get inspiration, or /21st fetch data and previews from 21st.dev. This tool returns the JSON data of matching components without generating new code. This tool ONLY returns the text snippet for that UI component. 
After calling this tool, you must edit or add files to integrate the snippet into the codebase."

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | Full users message | Yes
| searchQuery | string | Search query for 21st.dev (library for searching UI components) to find a UI component that matches the user's message. Must be a two-four words max or phrase | Yes
</details>
<details>
<summary>21st_magic_component_refiner</summary>

**Description**:

```

"Use this tool when the user requests to re-design/refine/improve current UI component with /ui or /21 commands, 
or when context is about improving, or refining UI for a React component or molecule (NOT for big pages).
This tool improves UI of components and returns redesigned version of the component and instructions on how to implement it."

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| absolutePathToRefiningFile | string | Absolute path to the file that needs to be refined | Yes
| context | string | Extract the specific UI elements and aspects that need improvement based on user messages, code, and conversation history. Identify exactly which components (buttons, forms, modals, etc.) the user is referring to and what aspects (styling, layout, responsiveness, etc.) they want to enhance. Do not include generic improvements - focus only on what the user explicitly mentions or what can be reasonably inferred from the available context. If nothing specific is mentioned or you cannot determine what needs improvement, return an empty string. | Yes
| userMessage | string | Full user's message about UI refinement | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | 21st_magic_component_builder | description | 011e0e5db60e77a06a3fd5063614b7b2b93ced2925663e8168cac8b0c6d7ae66 |
| tools | 21st_magic_component_builder | absolutePathToCurrentFile | 450130593147c19a97f2a5f0ed209a5f0b84dd8e70b7b27b62400d4ef9957a91 |
| tools | 21st_magic_component_builder | absolutePathToProjectDirectory | 6303e9e4a0b12ff5e2a097fe5f9abcbdb1ed49ec8ef42ad6fb24134ed64dc822 |
| tools | 21st_magic_component_builder | context | 512f11c1d32d3e983da308c65118d7b61486c0c73385701d20c8249f8b0cb47f |
| tools | 21st_magic_component_builder | message | 48cb03af6caea4c4c7719fdf6a43a50db0542485c3ba341a28532ef756da1652 |
| tools | 21st_magic_component_builder | searchQuery | eb695e76137317ae4778f099cfa2f0940f955b1f6fb88c5b3043e782d826b9e3 |
| tools | 21st_magic_component_inspiration | description | 3226eb3548d20e699204369a805c8e1181d3b51002d6539c0236998ec2aff33e |
| tools | 21st_magic_component_inspiration | message | 48cb03af6caea4c4c7719fdf6a43a50db0542485c3ba341a28532ef756da1652 |
| tools | 21st_magic_component_inspiration | searchQuery | fbc79e6c9c705ce4f5b8022da56323f221687b2af5d4b29478cfb72c10e0e597 |
| tools | 21st_magic_component_refiner | description | d7cd82ff345c5062c305ce6152af693a5a934c66cc7a30e0e3051d95dec2452b |
| tools | 21st_magic_component_refiner | absolutePathToRefiningFile | 35ad0e28bb9a3f39b6ef4e75caa8205ac8d06fd0d3ed51c563b5748863ec1868 |
| tools | 21st_magic_component_refiner | context | c2d8d152ce6971bcd011ba571ca71577c33831002a0cd7a05ff97b02befffab4 |
| tools | 21st_magic_component_refiner | userMessage | e6d673475625348fc2c01a43379d8688a94ad59bf976643844a160f78aaf92f6 |
| tools | logo_search | description | 4b660e35f86c0c855f48e7ec46c370e9d07f43f9908672506816aa795dd3f5c1 |
| tools | logo_search | format | 93c53d3745136c4e4e142811cdff560c8dfb4b9c4c875b7a8687dda559f688e1 |
| tools | logo_search | queries | 09c2780a768a860722317a6121664d0c3efbde797a7bf492acec147afb8b89e0 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
