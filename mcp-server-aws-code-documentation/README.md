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


# What is mcp-server-aws-code-documentation?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-code-documentation/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-code-documentation/1.0.1?logo=docker&logoColor=fff&label=1.0.1)](https://hub.docker.com/r/acuvity/mcp-server-aws-code-documentation)
[![PyPI](https://img.shields.io/badge/1.0.1-3775A9?logo=pypi&logoColor=fff&label=awslabs.code-doc-gen-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/code-doc-gen-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-code-documentation/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-code-documentation&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22data%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-code-documentation%3A1.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Analyzes repository structure and generates comprehensive documentation for code projects

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.code-doc-gen-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/code-doc-gen-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-code-documentation/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-code-documentation/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-code-documentation/charts/mcp-server-aws-code-documentation/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.code-doc-gen-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-code-documentation/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-aws-code-documentation scope of operation the intended usage is to run natively on the targeted machine to access local resources.
**Required volumes or mountPaths:**
  - data to be mounted on `/data`

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/code-doc-gen-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-code-documentation&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22data%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-code-documentation%3A1.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-code-documentation": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-v",
          "data:/data",
          "docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1"
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
    "acuvity-mcp-server-aws-code-documentation": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "data:/data",
        "docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1"
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
    "acuvity-mcp-server-aws-code-documentation": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "data:/data",
        "docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1"
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
    "acuvity-mcp-server-aws-code-documentation": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "data:/data",
        "docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1"
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
    "acuvity-mcp-server-aws-code-documentation": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "data:/data",
        "docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1"
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
        "args": ["run","-i","--rm","--read-only","-v","data:/data","docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1"]
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
- arguments: `run -i --rm --read-only -v data:/data docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -v data:/data docker.io/acuvity/mcp-server-aws-code-documentation:1.0.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-code-documentation": {
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
    "acuvity-mcp-server-aws-code-documentation": {
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

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-code-documentation --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-code-documentation --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-code-documentation oci://docker.io/acuvity/mcp-server-aws-code-documentation --version 1.0.0
```

From there your MCP server mcp-server-aws-code-documentation will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-code-documentation` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-code-documentation/charts/mcp-server-aws-code-documentation/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (4)
<details>
<summary>prepare_repository</summary>

**Description**:

```
Prepare repository for the MCP client's analysis.

This tool:
1. Extracts directory structure from the repository
2. Returns an EMPTY ProjectAnalysis for you to fill out
3. Provides directory structure in file_structure["directory_structure"]
4. Provides repository statistics in file_structure["statistics"] (file count, character count, etc.)

You should:
1. Review the directory structure in file_structure["directory_structure"]
2. Use read_file to examine key files you identify from the structure
3. Fill out the empty fields in ProjectAnalysis based on your analysis
4. Set has_infrastructure_as_code=True if you detect CDK, Terraform, or other infrastructure as code
5. Use create_context to create a DocumentationContext from your analysis
6. Use the DocumentationContext with plan_documentation

NOTE: This tool does NOT analyze the code - that's your job!
The tool only extracts the directory structure and statistics to help you identify important files.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ctx | any | not set | No
| project_root | string | Path to the code repository | Yes
</details>
<details>
<summary>create_context</summary>

**Description**:

```
Create a DocumentationContext from a ProjectAnalysis.

This tool simplifies the creation of a DocumentationContext for use with
plan_documentation and generate_documentation tools.

Args:
    project_root: Path to the code repository
    analysis: Completed ProjectAnalysis from prepare_repository
    ctx: Optional MCP context for logging and progress reporting

Returns:
    A DocumentationContext ready for use with other tools

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| analysis | any | Completed ProjectAnalysis from prepare_repository | Yes
| ctx | any | not set | No
| project_root | string | Path to the code repository | Yes
</details>
<details>
<summary>plan_documentation</summary>

**Description**:

```
Third step: Create documentation plan using analysis.

Using your analysis from prepare_repository and the DocumentationContext from create_context:
1. Review the ProjectAnalysis in doc_context containing:
   - Project type and purpose
   - Key features and capabilities
   - Programming languages and dependencies
   - APIs and interfaces
2. Determine what documentation types are needed
3. Create appropriate documentation structure
4. Return documentation plan

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ctx | any | not set | No
| doc_context | any | not set | Yes
</details>
<details>
<summary>generate_documentation</summary>

**Description**:

```
Final step: Generate documentation content.

Using your analysis and documentation plan:
1. Generate document structures with empty sections
2. YOU (MCP Client) MUST then:
   - Write detailed content for each section
   - Include relevant code examples and explanations
   - Fill in ALL empty sections with comprehensive content
   - Cover all aspects:
     * Project setup and installation
     * Architecture and design
     * Features and capabilities
     * APIs and interfaces (if any)
     * Dependencies and requirements
3. Return document structures for you to fill with content

IMPORTANT: When you receive the generated documents, it is YOUR responsibility
to write comprehensive content for each section. Do not leave sections empty
or wait for further instructions - YOU must fill them in!

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ctx | any | not set | No
| doc_context | any | not set | Yes
| plan | any | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
