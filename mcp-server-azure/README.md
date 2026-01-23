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


# What is mcp-server-azure?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-azure/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-azure/2.0.0-beta.12?logo=docker&logoColor=fff&label=2.0.0-beta.12)](https://hub.docker.com/r/acuvity/mcp-server-azure)
[![PyPI](https://img.shields.io/badge/2.0.0-beta.12-3775A9?logo=pypi&logoColor=fff&label=@azure/mcp)](https://github.com/Azure/azure-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-azure/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-azure&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22-e%22%2C%22AZURE_CLIENT_ID%22%2C%22-e%22%2C%22AZURE_CLIENT_SECRET%22%2C%22-e%22%2C%22AZURE_TENANT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-azure%3A2.0.0-beta.12%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates AI agents with Azure services for enhanced functionality.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @azure/mcp original [sources](https://github.com/Azure/azure-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-azure/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/charts/mcp-server-azure/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @azure/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-azure scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `AZURE_CLIENT_ID` required to be set
  - `AZURE_CLIENT_SECRET` required to be set
  - `AZURE_TENANT_ID` required to be set
  - `DOTNET_BUNDLE_EXTRACT_BASE_DIR` optional (/tmp)

For more information and extra configuration you can consult the [package](https://github.com/Azure/azure-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-azure&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22-e%22%2C%22AZURE_CLIENT_ID%22%2C%22-e%22%2C%22AZURE_CLIENT_SECRET%22%2C%22-e%22%2C%22AZURE_TENANT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-azure%3A2.0.0-beta.12%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-azure": {
        "env": {
          "AZURE_CLIENT_ID": "TO_BE_SET",
          "AZURE_CLIENT_SECRET": "TO_BE_SET",
          "AZURE_TENANT_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "-e",
          "AZURE_CLIENT_ID",
          "-e",
          "AZURE_CLIENT_SECRET",
          "-e",
          "AZURE_TENANT_ID",
          "docker.io/acuvity/mcp-server-azure:2.0.0-beta.12"
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
    "acuvity-mcp-server-azure": {
      "env": {
        "AZURE_CLIENT_ID": "TO_BE_SET",
        "AZURE_CLIENT_SECRET": "TO_BE_SET",
        "AZURE_TENANT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "AZURE_CLIENT_ID",
        "-e",
        "AZURE_CLIENT_SECRET",
        "-e",
        "AZURE_TENANT_ID",
        "docker.io/acuvity/mcp-server-azure:2.0.0-beta.12"
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
    "acuvity-mcp-server-azure": {
      "env": {
        "AZURE_CLIENT_ID": "TO_BE_SET",
        "AZURE_CLIENT_SECRET": "TO_BE_SET",
        "AZURE_TENANT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "AZURE_CLIENT_ID",
        "-e",
        "AZURE_CLIENT_SECRET",
        "-e",
        "AZURE_TENANT_ID",
        "docker.io/acuvity/mcp-server-azure:2.0.0-beta.12"
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
    "acuvity-mcp-server-azure": {
      "env": {
        "AZURE_CLIENT_ID": "TO_BE_SET",
        "AZURE_CLIENT_SECRET": "TO_BE_SET",
        "AZURE_TENANT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "AZURE_CLIENT_ID",
        "-e",
        "AZURE_CLIENT_SECRET",
        "-e",
        "AZURE_TENANT_ID",
        "docker.io/acuvity/mcp-server-azure:2.0.0-beta.12"
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
    "acuvity-mcp-server-azure": {
      "env": {
        "AZURE_CLIENT_ID": "TO_BE_SET",
        "AZURE_CLIENT_SECRET": "TO_BE_SET",
        "AZURE_TENANT_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "-e",
        "AZURE_CLIENT_ID",
        "-e",
        "AZURE_CLIENT_SECRET",
        "-e",
        "AZURE_TENANT_ID",
        "docker.io/acuvity/mcp-server-azure:2.0.0-beta.12"
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
        "env": {"AZURE_CLIENT_ID":"TO_BE_SET","AZURE_CLIENT_SECRET":"TO_BE_SET","AZURE_TENANT_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","-e","AZURE_CLIENT_ID","-e","AZURE_CLIENT_SECRET","-e","AZURE_TENANT_ID","docker.io/acuvity/mcp-server-azure:2.0.0-beta.12"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e AZURE_TENANT_ID docker.io/acuvity/mcp-server-azure:2.0.0-beta.12`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e AZURE_TENANT_ID docker.io/acuvity/mcp-server-azure:2.0.0-beta.12
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-azure": {
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
    "acuvity-mcp-server-azure": {
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
  - `AZURE_CLIENT_ID` secret to be set as secrets.AZURE_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `AZURE_CLIENT_SECRET` secret to be set as secrets.AZURE_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`
  - `AZURE_TENANT_ID` secret to be set as secrets.AZURE_TENANT_ID either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `DOTNET_BUNDLE_EXTRACT_BASE_DIR="/tmp"` environment variable can be changed with env.DOTNET_BUNDLE_EXTRACT_BASE_DIR="/tmp"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
````

Install with helm

```console
helm install mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
```

From there your MCP server mcp-server-azure will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-azure` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/charts/mcp-server-azure/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (50)
<details>
<summary>documentation</summary>

**Description**:

```
Search official Microsoft/Azure documentation to find the most relevant and trustworthy content for a user's query. This tool returns up to 10 high-quality content chunks (each max 500 tokens), extracted from Microsoft Learn and other official sources. Each result includes the article title, URL, and a self-contained content excerpt optimized for fast retrieval and reasoning. Always use this tool to quickly ground your answers in accurate, first-party Microsoft/Azure knowledge.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>azd</summary>

**Description**:

```
Azure Developer CLI (azd) includes a suite of tools to help build, modernize, and manage applications on Azure. It simplifies the process of developing cloud applications by providing commands for project initialization, resource provisioning, deployment, and monitoring. Use this tool to streamline your Azure development workflow and manage your cloud resources efficiently.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>get_azure_bestpractices</summary>

**Description**:

```
Azure best practices - Commands return a list of best practices for code generation, operations and deployment 
            when working with Azure services. 
            It should be called for any code generation, deployment or 
            operations involving Azure, Azure Functions, Azure Kubernetes Service (AKS), Azure Container 
            Apps (ACA), Bicep, Terraform, Azure Cache, Redis, CosmosDB, Entra, Azure Active Directory, 
            Azure App Services, or any other Azure technology or programming language. 
            This command set also includes the command to get AI application best practices, which provides specialized guidance
            for building AI applications, offering recommendations for agents, chatbots, workflows, and other 
            AI-powered features leveraging Microsoft Foundry. 
            When the request involves AI in any capacity, including systems where AI is used as a component,
            use AI application best practices instead of the general best practices.
            Call this tool first before creating any plans, todos or code.
            Only call this function when you are confident the user is discussing Azure (including Microsoft Foundry). If this tool needs to be categorized, 
            it belongs to the Get Azure Best Practices category.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>aks</summary>

**Description**:

```
Azure Kubernetes Service operations - Manage and query Azure Kubernetes Service (AKS) resources across subscriptions. Use when you need subscription-scoped visibility into AKS cluster and node pool metadata—including Azure resource IDs, networking endpoints, identity configuration, and provisioning state—for governance or automation. Requires Azure subscription context. Not for kubectl execution, pod lifecycle changes, or in-cluster application deployments—use Kubernetes-native tooling for those tasks.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>appconfig</summary>

**Description**:

```
App Configuration operations - Commands for managing Azure App Configuration stores and key-value settings. Includes operations for listing configuration stores, managing key-value pairs, setting labels, locking/unlocking settings, and retrieving configuration data.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>applens</summary>

**Description**:

```
AppLens diagnostic operations - **Primary tool for diagnosing Azure resource issues and troubleshooting problems**. Use this tool when users ask to:
- Diagnose issues, problems, or errors with Azure resources
- Troubleshoot performance, availability, or reliability problems
- Investigate resource health concerns or unexpected behavior
- Find root causes of application slowness, downtime, or failures
- Get recommendations for fixing Azure resource issues
- Analyze resource problems and get actionable solutions

Always use this tool if user asks to use App Lens in regards to their resource.

This tool provides conversational AI-powered diagnostics that automatically detect issues, identify root causes, and suggest specific remediation steps. It should be the FIRST tool called when users mention problems, issues, errors, or ask for help with troubleshooting any Azure resource.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>appservice</summary>

**Description**:

```
App Service operations - Commands for managing Azure App Service resources including web apps, databases, and configurations.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>role</summary>

**Description**:

```
Authorization operations - Commands for managing Azure Role-Based Access Control (RBAC) resources. Includes operations for listing role assignments, managing permissions, and working with Azure security and access management at various scopes.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>datadog</summary>

**Description**:

```
Datadog operations - Commands for managing and monitoring Azure resources through Datadog integration. Includes operations for listing Datadog monitors and retrieving information about monitored Azure resources and their health status.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>managedlustre</summary>

**Description**:

```
Azure Managed Lustre operations - Commands for creating, updating, listing and inspecting Azure Managed Lustre file systems (AMLFS) used for high-performance computing workloads. The tool focuses on managing all the aspects related to Azure Managed Lustre file system instances.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>azureterraformbestpractices</summary>

**Description**:

```
Returns Terraform best practices for Azure. Call this before generating Terraform code for Azure Providers. 
            If this tool needs to be categorized, it belongs to the Azure Best Practices category.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>deploy</summary>

**Description**:

```
Deploy commands for deploying applications to Azure, including sub commands: - plan get: generates a deployment plan to construct the infrastructure and deploy the application on Azure. Agent should read its output and generate a deploy plan in '.azure/plan.copilotmd' for execution steps, recommended azure services based on the information agent detected from project. Before calling this tool, please scan this workspace to detect the services to deploy and their dependent services; - iac rules get: offers guidelines for creating Bicep/Terraform files to deploy applications on Azure; - app logs get: fetch logs from log analytics workspace for Container Apps, App Services, function apps that were deployed through azd; - pipeline guidance get: guidance to create a CI/CD pipeline which provision Azure resources and build and deploy applications to Azure; - architecture diagram generate: generates an azure service architecture diagram for the application based on the provided app topology; This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>eventgrid</summary>

**Description**:

```
Event Grid operations - Commands for managing and accessing Event Grid topics, domains, and event subscriptions.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>acr</summary>

**Description**:

```
Azure Container Registry operations - Commands for managing Azure Container Registry resources. Includes operations for listing container registries and managing registry configurations.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>bicepschema</summary>

**Description**:

```
Bicep schema operations - Commands for working with Azure Bicep Infrastructure as Code (IaC) generation and schema management. Includes operations for retrieving Bicep schemas, templates, and resource definitions to support infrastructure deployment automation.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>cosmos</summary>

**Description**:

```
Cosmos DB operations - Commands for managing and querying Azure Cosmos DB resources. Includes operations for databases, containers, and document queries.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>cloudarchitect</summary>

**Description**:

```
Cloud Architecture operations - Commands for generating Azure architecture designs and recommendations based on requirements.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>confidentialledger</summary>

**Description**:

```
Azure Confidential Ledger operations - Commands for appending and querying tamper-proof ledger entries backed by TEEs and blockchain-style integrity guarantees. Use these commands to write immutable audit records.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>eventhubs</summary>

**Description**:

```
Azure Event Hubs operations - Commands for managing Azure Event Hubs namespaces and event hubs. Includes CRUD operations Event Hubs service resources.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>fileshares</summary>

**Description**:

```
File Shares operations - Commands for managing Azure File Shares.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>foundry</summary>

**Description**:

```
Foundry service operations - Commands for listing and managing services and resources in Microsoft Foundry.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>functionapp</summary>

**Description**:

```
Function App operations - Commands for managing and accessing Azure Function App resources.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>grafana</summary>

**Description**:

```
Grafana workspace operations - Commands for managing and accessing Azure Managed Grafana resources and monitoring dashboards. Includes operations for listing Grafana workspaces and managing data visualization and monitoring capabilities.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>keyvault</summary>

**Description**:

```
Key Vault operations - Commands for managing and accessing Azure Key Vault resources.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>kusto</summary>

**Description**:

```
Kusto operations - Commands for managing and querying Azure Data Explorer (Kusto) resources. Includes operations for listing clusters and databases, executing KQL queries, retrieving table schemas, and working with Kusto data analytics workloads.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>loadtesting</summary>

**Description**:

```
Load Testing operations - Commands for managing Azure Load Testing resources, test configurations, and test runs. Includes operations for creating and managing load test resources, configuring test scripts, executing performance tests, and monitoring test results.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>marketplace</summary>

**Description**:

```
Marketplace operations - Commands for managing and accessing Azure Marketplace products and offers.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>quota</summary>

**Description**:

```
Quota commands for getting the available regions of specific Azure resource types or checking Azure resource quota and usageThis tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>monitor</summary>

**Description**:

```
Azure Monitor operations - Commands for querying and analyzing Azure Monitor logs and metrics.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>applicationinsights</summary>

**Description**:

```
Application Insights operations - Commands for listing and managing Application Insights components. 
These commands do not support querying metrics or logs. Use Azure Monitor querying tools for that purpose.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>mysql</summary>

**Description**:

```
MySQL operations - Commands for managing Azure Database for MySQL Flexible Server resources. Includes operations for listing servers and databases, executing SQL queries, managing table schemas, and configuring server parameters.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>policy</summary>

**Description**:

```
Manage Azure Policy assignments and definitions using Azure CLI. Retrieve policy assignments, view enforcement modes, and analyze policy compliance across subscriptions.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>postgres</summary>

**Description**:

```
PostgreSQL operations - Commands for managing Azure Database for PostgreSQL Flexible Server resources. Includes operations for listing servers and databases, executing SQL queries, managing table schemas, and configuring server parameters.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>redis</summary>

**Description**:

```
Redis operations - Commands for managing Azure Redis resources. Includes operations for listing Redis resources, databases, and data access policies, in both the Azure Managed Redis and legacy Azure Cache for Redis services, as well as for creating Azure Managed Redis resources.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>communication</summary>

**Description**:

```
Communication services operations - Commands for managing Azure Communication Services - supports sending SMSThis tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>resourcehealth</summary>

**Description**:

```
Resource Health operations - Commands for monitoring and diagnosing Azure resource health status.
Use this tool to check the current availability status of Azure resources and identify potential issues.
This tool provides access to Azure Resource Health data including availability state, detailed status,
historical health information, and service health events for troubleshooting and monitoring purposes.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>search</summary>

**Description**:

```
Search operations - Commands for Azure AI Search (formerly known as \"Azure Cognitive Search\") services,
search indexes, knowledge sources and knowledge bases. Use this tool when you need to retrieve knowledge,
search indexes, or introspect search services and their components. This tool supports enterprise search,
document search, and knowledge mining. Do not use this tool for database queries or Azure Monitor
logs, this tool is specifically designed for Azure AI Search. This tool is a hierarchical MCP command
router where sub-commands are routed to MCP servers that require specific fields inside the \"parameters\"
object. To invoke a command, set \"command\" and wrap its arguments in \"parameters\". Set \"learn=true\"
to discover available sub-commands for different search service and index operations. Note that this tool
requires appropriate Azure AI Search permissions and will only access search resources accessible to the
authenticated user.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>speech</summary>

**Description**:

```
Speech operations - Commands for Azure AI Services Speech functionality including speech-to-text (STT) 
recognition, text-to-speech (TTS) synthesis, audio processing, and language detection. Use this tool when you need to convert spoken 
audio to text, convert text to spoken audio, process audio files, or work with speech recognition services. This tool supports 
multiple audio formats, configurable recognition languages, profanity filtering options, and both 
simple and detailed output formats. This tool is a hierarchical MCP command router where sub-commands 
are routed to MCP servers that require specific fields inside the "parameters" object. To invoke a 
command, set "command" and wrap its arguments in "parameters". Set "learn=true" to discover available 
sub-commands for different Azure AI Services Speech operations. Note that this tool requires Azure AI 
Services Speech endpoints and will only access speech resources accessible to the authenticated user.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>servicebus</summary>

**Description**:

```
Service Bus operations - Commands for managing Azure Service Bus messaging infrastructure including queues, topics, and subscriptions for reliable asynchronous communication and enterprise integration. Use this tool to manage message queues for point-to-point communication, configure topics and subscriptions for publish-subscribe patterns, monitor message processing, or set up messaging for decoupled architectures. Supports reliable messaging, dead letter handling, and enterprise integration patterns. Do not use for real-time communication, direct API calls, or database operations - Service Bus is for asynchronous messaging between distributed applications. This is a hierarchical MCP command router where sub-commands are routed to servers requiring specific "parameters" fields. To invoke: set "command" and wrap arguments in "parameters". Set "learn=true" to discover sub-commands. Requires appropriate Service Bus permissions.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>signalr</summary>

**Description**:

```
Azure SignalR operations - Commands for managing Azure SignalR Service resources. Includes operations for listing SignalR services.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>sql</summary>

**Description**:

```
Azure SQL operations - Commands for managing Azure SQL databases, servers, and elastic pools. Includes operations for listing databases, configuring server settings, managing firewall rules, Entra ID administrators, and elastic pool resources.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>storage</summary>

**Description**:

```
Storage operations - Commands for managing and accessing Azure Storage accounts and their data services
including Blobs and Tables service for scalable cloud storage solutions. Use this tool when you need to
list storage accounts, work with blob containers and blobs, and list tables. This tool focuses on object
storage scenarios. This tool is a hierarchical MCP command router where sub-commands are routed to MCP
servers that require specific fields inside the "parameters" object. To invoke a command, set "command" and
wrap its arguments in "parameters". Set "learn=true" to discover available sub-commands for different Azure
Storage service operations including blobs. Note that this tool requires appropriate Storage account
permissions and will only access storage resources accessible to the authenticated user.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>storagesync</summary>

**Description**:

```
Azure Storage Sync operations - Commands for managing Azure File Sync services, sync groups, cloud endpoints,
server endpoints, and registered servers. Use this tool to deploy, configure, and manage File Sync infrastructure
for hybrid cloud file synchronization scenarios. The tool supports listing, creating, updating, and deleting
resources across the Storage Sync service hierarchy. Each command requires appropriate Azure permissions and
subscription access.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>virtualdesktop</summary>

**Description**:

```
Azure Virtual Desktop operations - Commands for managing and accessing Azure Virtual Desktop resources. Includes operations for hostpools, session hosts, and user sessions.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>workbooks</summary>

**Description**:

```
Workbooks operations - Commands for managing Azure Workbooks resources and interactive data visualization dashboards. Includes operations for listing, creating, updating, and deleting workbooks, as well as managing workbook configurations and content.This tool is a hierarchical MCP command router.
Sub commands are routed to MCP servers that require specific fields inside the "parameters" object.
To invoke a command, set "command" and wrap its args in "parameters".
Set "learn=true" to discover available sub commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | The command to execute against the specified tool. | No
| intent | string | The intent of the azure operation to perform. | Yes
| learn | boolean | To learn about the tool and its supported child tools and parameters. | No
| parameters | object | The parameters to pass to the tool command. | No
</details>
<details>
<summary>group_list</summary>

**Description**:

```
List all resource groups in a subscription. This command retrieves all resource groups available
in the specified subscription. Results include resource group names and IDs,
returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | Specifies the Azure subscription to use. Accepts either a subscription ID (GUID) or display name. If not specified, the AZURE_SUBSCRIPTION_ID environment variable will be used instead. | No
| tenant | string | The Microsoft Entra ID tenant ID or name. This can be either the GUID identifier or the display name of your Entra ID tenant. | No
</details>
<details>
<summary>subscription_list</summary>

**Description**:

```
List all or current subscriptions for an account in Azure; returns subscriptionId, displayName, state, tenantId, and isDefault. Use for scope selection in governance, policy, access, cost management, or deployment.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| tenant | string | The Microsoft Entra ID tenant ID or name. This can be either the GUID identifier or the display name of your Entra ID tenant. | No
</details>
<details>
<summary>extension_azqr</summary>

**Description**:

```
Runs Azure Quick Review CLI (azqr) commands to generate compliance/security reports for Azure resources.
This tool should be used when the user wants to identify any non-compliant configurations or areas for improvement in their Azure resources.
Requires a subscription id and optionally a resource group name. Returns the generated report file's path.
Note that Azure Quick Review CLI (azqr) is different from Azure CLI (az).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | Specifies the Azure subscription to use. Accepts either a subscription ID (GUID) or display name. If not specified, the AZURE_SUBSCRIPTION_ID environment variable will be used instead. | No
| tenant | string | The Microsoft Entra ID tenant ID or name. This can be either the GUID identifier or the display name of your Entra ID tenant. | No
</details>
<details>
<summary>extension_cli_generate</summary>

**Description**:

```
This tool can generate Azure CLI commands to be used with the corresponding CLI tool to accomplish a goal described by the user. This tool incorporates knowledge of the CLI tool beyond what the LLM knows. Always use this tool to generate the CLI command when the user asks for such CLI commands or wants to use the CLI tool to accomplish something.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cli-type | string | The type of CLI tool to use. Supported values are 'az' for Azure CLI. | Yes
| intent | string | The user intent of the task to be solved by using the CLI tool. This user intent will be used to generate the appropriate CLI command to accomplish the desirable goal. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| tenant | string | The Microsoft Entra ID tenant ID or name. This can be either the GUID identifier or the display name of your Entra ID tenant. | No
</details>
<details>
<summary>extension_cli_install</summary>

**Description**:

```
This tool can provide installation instructions for the specified CLI tool among Azure CLI (az), Azure Developer CLI (azd) and Azure Functions Core Tools CLI (func). It incorporates knowledge of the CLI tool beyond what the LLM knows. Use this tool to get installation instructions if you attempt to use the CLI tool but it isn't installed.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cli-type | string | The type of CLI tool to use. Supported values are 'az' for Azure CLI, 'azd' for Azure Developer CLI, and 'func' for Azure Functions Core Tools CLI. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| tenant | string | The Microsoft Entra ID tenant ID or name. This can be either the GUID identifier or the display name of your Entra ID tenant. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | acr | description | 940d25da8ab8b08bcf62ebb31f5d20e6c2ff8fa8cf54a935251a79f5ed3cc774 |
| tools | acr | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | acr | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | acr | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | acr | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | aks | description | 1ac62b9f75fcbc0160bf7d84cd6a21d16d7b761f8d33ea78130df701b925dfeb |
| tools | aks | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | aks | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | aks | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | aks | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | appconfig | description | 1692d30e4d78ab3aace16d435c68d0baed6fc6051948a4686f90a0a797344d5a |
| tools | appconfig | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | appconfig | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | appconfig | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | appconfig | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | applens | description | b1e37177eb3756a71168edb901485ffd21eed2a71531ad2e5dcab336ecc94767 |
| tools | applens | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | applens | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | applens | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | applens | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | applicationinsights | description | 55aa71ab41d8b3e99753328e74027b11e1dd8e19b730a29a215ec1f333124f49 |
| tools | applicationinsights | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | applicationinsights | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | applicationinsights | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | applicationinsights | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | appservice | description | 6dede9afea87ddc70a05f3e748ccb40f7a9d9754098eddced554aa0376984362 |
| tools | appservice | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | appservice | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | appservice | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | appservice | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | azd | description | 5612dd312976bd74293f0c4fe9472100a6d92b38c90cf0ea7b0a1e0d69cc4fb4 |
| tools | azd | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | azd | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | azd | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | azd | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | azureterraformbestpractices | description | b3a883e5dc777c641887bf792b1f15e309969be95466e8b86a0b7d30f0841ba5 |
| tools | azureterraformbestpractices | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | azureterraformbestpractices | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | azureterraformbestpractices | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | azureterraformbestpractices | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | bicepschema | description | 5d9366518b8805c310120759e1e82620090d729f2fb5825013d486b1bf41c26d |
| tools | bicepschema | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | bicepschema | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | bicepschema | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | bicepschema | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | cloudarchitect | description | fdc4fdbee8f2a19b643dffb9a6f3ecda24a81e99b8940d2a4736e08fb07849bd |
| tools | cloudarchitect | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | cloudarchitect | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | cloudarchitect | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | cloudarchitect | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | communication | description | c49f0b7fc59f9dd5b998a1e141ca47e94975999266cfac227a1b4a08779ac182 |
| tools | communication | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | communication | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | communication | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | communication | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | confidentialledger | description | e487d5c625b420d5fcdc377d664f29fb999aca3aff7ef39e105c2acaca218ce5 |
| tools | confidentialledger | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | confidentialledger | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | confidentialledger | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | confidentialledger | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | cosmos | description | fa5ccc43772800bd27ab78e335e6dff42b9c8a15068cae28a2089efc823ca1ce |
| tools | cosmos | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | cosmos | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | cosmos | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | cosmos | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | datadog | description | c9a629088faf7ebbe68cfaba636e30e8fda2fa0998ac8b9f8b62cd639422d8b6 |
| tools | datadog | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | datadog | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | datadog | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | datadog | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | deploy | description | e4cdf3c1592321b157d6f6110a61ef7ac03c8e34de4e50ebf9dde70fb17aee79 |
| tools | deploy | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | deploy | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | deploy | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | deploy | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | documentation | description | 46c84dcfccc1263573c16ad2b95b01a647c9460cf9f362c71eb3cf7cdfcf6d3c |
| tools | documentation | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | documentation | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | documentation | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | documentation | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | eventgrid | description | 722e8e2bce801c0991cb5b8442215197fb5aec161606fd22ed2cd931b9a5bcb2 |
| tools | eventgrid | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | eventgrid | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | eventgrid | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | eventgrid | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | eventhubs | description | c700bb99062ea1f3e3626a67994040540dfeb47ac895adb98ea75097f08bf60e |
| tools | eventhubs | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | eventhubs | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | eventhubs | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | eventhubs | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | extension_azqr | description | 56a66f132ddb20c8ed7b39fbc06f709e75ec2aac634cdadca5f839be54482500 |
| tools | extension_azqr | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | extension_azqr | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | extension_azqr | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | extension_azqr | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | extension_azqr | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | extension_azqr | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | extension_azqr | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | extension_azqr | subscription | d3b1e34ab22a54c9af612e5d236cc5da296dcf468e248606977bf31ae2409931 |
| tools | extension_azqr | tenant | fe2eb37ac52d78332fb0e15753de299f143a6513fc6ad98c46510d0f6586625a |
| tools | extension_cli_generate | description | 90ad5a3731a543e75c1adba119676dde89ef5a833c0644aa1248f1eba9b9ac31 |
| tools | extension_cli_generate | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | extension_cli_generate | cli-type | 974988ed7761964a3c5e2f0d240cd696230441b531787bc8eae7c377b216e41d |
| tools | extension_cli_generate | intent | 59240e8f13defb01c0416febe68d75abf1dfcd6c93c32504ec4c40dc597c0c1a |
| tools | extension_cli_generate | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | extension_cli_generate | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | extension_cli_generate | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | extension_cli_generate | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | extension_cli_generate | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | extension_cli_generate | tenant | fe2eb37ac52d78332fb0e15753de299f143a6513fc6ad98c46510d0f6586625a |
| tools | extension_cli_install | description | 401e5765db1f385a6c9f9d6b3c7c7c932e56687dafe04f1b68c14cca540e689c |
| tools | extension_cli_install | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | extension_cli_install | cli-type | bdf06a2a135ea94387e021ba6afa1471880b7cfcd1b2f116a744f18f57a4dc8d |
| tools | extension_cli_install | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | extension_cli_install | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | extension_cli_install | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | extension_cli_install | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | extension_cli_install | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | extension_cli_install | tenant | fe2eb37ac52d78332fb0e15753de299f143a6513fc6ad98c46510d0f6586625a |
| tools | fileshares | description | 8e2707d73d364349c50fc7046aaf9185ae300d80dc710ec7f5805b63dc5a875e |
| tools | fileshares | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | fileshares | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | fileshares | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | fileshares | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | foundry | description | 71898addc10e91b003209675ffde6ce578775df6d505b769df1541d4b2663765 |
| tools | foundry | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | foundry | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | foundry | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | foundry | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | functionapp | description | 5c462b6d9e9ea957d5e4f84d4c3b8da6de3fcd58364ed771226b8464892c5d87 |
| tools | functionapp | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | functionapp | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | functionapp | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | functionapp | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | get_azure_bestpractices | description | c110096e3ae7fa7a05f0c915e3a251fb2fcfddbc6d2ff000701c1ad1a1bb6026 |
| tools | get_azure_bestpractices | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | get_azure_bestpractices | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | get_azure_bestpractices | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | get_azure_bestpractices | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | grafana | description | e3bdcfc4f8823256f8d5533a8180af7e74abf374512069a8498ab4c8a1090526 |
| tools | grafana | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | grafana | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | grafana | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | grafana | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | group_list | description | fb9dff1fafd90c64e21ae7271a59d3180b6a62957b28bbd32b1afb9500789336 |
| tools | group_list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | group_list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | group_list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | group_list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | group_list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | group_list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | group_list | subscription | d3b1e34ab22a54c9af612e5d236cc5da296dcf468e248606977bf31ae2409931 |
| tools | group_list | tenant | fe2eb37ac52d78332fb0e15753de299f143a6513fc6ad98c46510d0f6586625a |
| tools | keyvault | description | f591a23ccfdd9dff42147aab2cfa9878a75c982e0c028753d0994ef4d3d30727 |
| tools | keyvault | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | keyvault | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | keyvault | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | keyvault | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | kusto | description | b7b68b72ac36a273ac681565af6771ea16b3889ca3668ec0662420c61e3010d0 |
| tools | kusto | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | kusto | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | kusto | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | kusto | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | loadtesting | description | 54d5406da3f41a85cc81f6f48f95e84c1dcb0d10932f51350d3b61f46f6675fb |
| tools | loadtesting | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | loadtesting | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | loadtesting | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | loadtesting | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | managedlustre | description | e6a25c9decf027137fbc42f2e6141390fa756aee38e854b606eb6801da970665 |
| tools | managedlustre | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | managedlustre | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | managedlustre | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | managedlustre | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | marketplace | description | 75c15676ec947054bc84fbea5ed854f2ed7584845e88a8b8d53e70911aa6106a |
| tools | marketplace | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | marketplace | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | marketplace | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | marketplace | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | monitor | description | a00545faadef85fab791b3aead22ef11cd220bbbede498ad59fb7f4533f64b7e |
| tools | monitor | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | monitor | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | monitor | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | monitor | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | mysql | description | 5c865ac6b47731359465d78a3a3b66206d0698fa8d57d25c92098c845c2833c6 |
| tools | mysql | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | mysql | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | mysql | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | mysql | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | policy | description | 7809ae8d15dcb41e4da555f58474a4bdde0f294f842a887ddb0c1cf27b62dd46 |
| tools | policy | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | policy | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | policy | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | policy | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | postgres | description | e68df42cff9c766ed104bc309c1bfbde24c1241bf0c8b1d77c275c3a2aa67a78 |
| tools | postgres | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | postgres | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | postgres | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | postgres | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | quota | description | 748dd06b144442f2fb7d096f139d6a097ec60fd0640443a2133f5b78a0155a7e |
| tools | quota | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | quota | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | quota | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | quota | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | redis | description | 556a75f397f54f7ccf5a24644f33e6e825e8ccd46fbcdc512579be3273ea76db |
| tools | redis | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | redis | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | redis | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | redis | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | resourcehealth | description | c06fa5ef399b84e553098effe8d844cb8196b4c2944ec7f662d38289d40b8091 |
| tools | resourcehealth | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | resourcehealth | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | resourcehealth | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | resourcehealth | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | role | description | 1429580b890c18ab9150939b17fb917ea0b2a6d77b13be363f2858e4377eb453 |
| tools | role | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | role | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | role | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | role | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | search | description | 1e1d397120b2ca22af1f86446ae905a9564e412ad8fe2f1592c9fd74b32a66c5 |
| tools | search | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | search | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | search | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | search | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | servicebus | description | dea4ade3bee0468d57085ec2017580d2cac1a81e235bbbc368ad1d903c182121 |
| tools | servicebus | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | servicebus | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | servicebus | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | servicebus | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | signalr | description | 5e2b419b9f209b0712c7db796af0d07181807ca35070c6c5d8d1056d88ec01d8 |
| tools | signalr | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | signalr | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | signalr | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | signalr | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | speech | description | f028caab5dac73067a6a0e1203e02564100a7b8c98c460e32e71e1a0364172b8 |
| tools | speech | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | speech | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | speech | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | speech | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | sql | description | 88cadb502dd8ac0512fb5d757c69f22dc8b50eacded6cd8502c43d91e75d5531 |
| tools | sql | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | sql | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | sql | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | sql | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | storage | description | 372f18aa83398ba475d3070765943035ab72cdae4728777b5e747641a1586709 |
| tools | storage | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | storage | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | storage | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | storage | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | storagesync | description | ed25c362ff9d0c500e8d7f891ba2fc570c564676bb01b8e955db82b00c7bfb15 |
| tools | storagesync | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | storagesync | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | storagesync | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | storagesync | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | subscription_list | description | f455eeaf6fa9a842c43ad99d13bddfe7962fa380a08ce907990c86a5e6b0e6b6 |
| tools | subscription_list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | subscription_list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | subscription_list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | subscription_list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | subscription_list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | subscription_list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | subscription_list | tenant | fe2eb37ac52d78332fb0e15753de299f143a6513fc6ad98c46510d0f6586625a |
| tools | virtualdesktop | description | 359df24f105391d03c88409b77e6d53ad969d3fd45cfcb18e3f541d0451c6289 |
| tools | virtualdesktop | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | virtualdesktop | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | virtualdesktop | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | virtualdesktop | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |
| tools | workbooks | description | f7ffbd27b6b2f88afb46af7c8c8ebf1e049dcef72ac734bb23182ec8e3a15ca8 |
| tools | workbooks | command | 6c4235c61af20fa535cda65547eece77a48250ae0ef3847dceb2974e89781f0c |
| tools | workbooks | intent | 49f4d1366d83477e25c6fb30bd8d94d91d004d98fa16b971225ac39503eda363 |
| tools | workbooks | learn | a102ae2d7521e2647c797819b9eb4f015681b7fb22632040ddb9ec384b77964e |
| tools | workbooks | parameters | 3cbc8396fbdb6cc4c65e115c63482428cd7dad59a9f971184b58fb2f6f4277af |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
