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


# What is mcp-server-aws-cdk?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-cdk/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-cdk/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-aws-cdk)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=awslabs.cdk-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/cdk-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-cdk/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cdk&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cdk%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AWS CDK best practices, infrastructure patterns, and security compliance with CDK Nag

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.cdk-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/cdk-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-cdk/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cdk/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cdk/charts/mcp-server-aws-cdk/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.cdk-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cdk/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-aws-cdk scope of operation it can be hosted anywhere.

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/cdk-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cdk&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cdk%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-cdk": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-aws-cdk:1.0.2"
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
    "acuvity-mcp-server-aws-cdk": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cdk:1.0.2"
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
    "acuvity-mcp-server-aws-cdk": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cdk:1.0.2"
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
    "acuvity-mcp-server-aws-cdk": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cdk:1.0.2"
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
    "acuvity-mcp-server-aws-cdk": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cdk:1.0.2"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-aws-cdk:1.0.2"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-aws-cdk:1.0.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-aws-cdk:1.0.2
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-cdk": {
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
    "acuvity-mcp-server-aws-cdk": {
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
helm show readme oci://docker.io/acuvity/mcp-server-aws-cdk --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-cdk --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-cdk oci://docker.io/acuvity/mcp-server-aws-cdk --version 1.0.0
```

From there your MCP server mcp-server-aws-cdk will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-cdk` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cdk/charts/mcp-server-aws-cdk/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>CDKGeneralGuidance</summary>

**Description**:

```
Use this tool to get prescriptive CDK advice for building applications on AWS.

    Args:
        ctx: MCP context
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>ExplainCDKNagRule</summary>

**Description**:

```
Explain a specific CDK Nag rule with AWS Well-Architected guidance.

    CDK Nag is a crucial tool for ensuring your CDK applications follow AWS security best practices.

    Basic implementation:
    ```typescript
    import { App } from 'aws-cdk-lib';
    import { AwsSolutionsChecks } from 'cdk-nag';

    const app = new App();
    // Create your stack
    const stack = new MyStack(app, 'MyStack');
    // Apply CDK Nag
    AwsSolutionsChecks.check(app);
    ```

    Optional integration patterns:

    1. Using environment variables:
    ```typescript
    if (process.env.ENABLE_CDK_NAG === 'true') {
      AwsSolutionsChecks.check(app);
    }
    ```

    2. Using CDK context parameters:
    ```typescript
    3. Environment-specific application:
    ```typescript
    const environment = app.node.tryGetContext('environment') || 'development';
    if (['production', 'staging'].includes(environment)) {
      AwsSolutionsChecks.check(stack);
    }
    ```

    For more information on specific rule packs:
    - Use resource `cdk-nag://rules/{rule_pack}` to get all rules for a specific pack
    - Use resource `cdk-nag://warnings/{rule_pack}` to get warnings for a specific pack
    - Use resource `cdk-nag://errors/{rule_pack}` to get errors for a specific pack

    Args:
        ctx: MCP context
        rule_id: The CDK Nag rule ID (e.g., 'AwsSolutions-IAM4')

    Returns:
        Dictionary with detailed explanation and remediation steps
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| rule_id | string | not set | Yes
</details>
<details>
<summary>CheckCDKNagSuppressions</summary>

**Description**:

```
Check if CDK code contains Nag suppressions that require human review.

    Scans TypeScript/JavaScript code for NagSuppressions usage to ensure security
    suppressions receive proper human oversight and justification.

    Args:
        ctx: MCP context
        code: CDK code to analyze (TypeScript/JavaScript)
        file_path: Path to a file containing CDK code to analyze

    Returns:
        Analysis results with suppression details and security guidance
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| code | any | not set | No
| file_path | any | not set | No
</details>
<details>
<summary>GenerateBedrockAgentSchema</summary>

**Description**:

```
Generate OpenAPI schema for Bedrock Agent Action Groups from a file.

    This tool converts a Lambda file with BedrockAgentResolver into a Bedrock-compatible
    OpenAPI schema. It uses a progressive approach to handle common issues:
    1. Direct import of the Lambda file
    2. Simplified version with problematic imports commented out
    3. Fallback script generation if needed

    Args:
        ctx: MCP context
        lambda_code_path: Path to Python file containing BedrockAgentResolver app
        output_path: Where to save the generated schema

    Returns:
        Dictionary with schema generation results, including status, path to generated schema,
        and diagnostic information if errors occurred
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| lambda_code_path | string | not set | Yes
| output_path | string | not set | Yes
</details>
<details>
<summary>GetAwsSolutionsConstructPattern</summary>

**Description**:

```
Search and discover AWS Solutions Constructs patterns.

    AWS Solutions Constructs are vetted architecture patterns that combine multiple
    AWS services to solve common use cases following AWS Well-Architected best practices.

    Key benefits:
    - Accelerated Development: Implement common patterns without boilerplate code
    - Best Practices Built-in: Security, reliability, and performance best practices
    - Reduced Complexity: Simplified interfaces for multi-service architectures
    - Well-Architected: Patterns follow AWS Well-Architected Framework principles

    When to use Solutions Constructs:
    - Implementing common architecture patterns (e.g., API + Lambda + DynamoDB)
    - You want secure defaults and best practices applied automatically
    - You need to quickly prototype or build production-ready infrastructure

    This tool provides metadata about patterns. For complete documentation,
    use the resource URI returned in the 'documentation_uri' field.

    Args:
        ctx: MCP context
        pattern_name: Optional name of the specific pattern (e.g., 'aws-lambda-dynamodb')
        services: Optional list of AWS services to search for patterns that use them
                 (e.g., ['lambda', 'dynamodb'])

    Returns:
        Dictionary with pattern metadata including description, services, and documentation URI
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pattern_name | any | not set | No
| services | any | not set | No
</details>
<details>
<summary>SearchGenAICDKConstructs</summary>

**Description**:

```
Search for GenAI CDK constructs by name or type.

    The search is flexible and will match any of your search terms (OR logic).
    It handles common variations like singular/plural forms and terms with/without spaces.
    Content is fetched dynamically from GitHub to ensure the most up-to-date documentation.

    Examples:
    - "bedrock agent" - Returns all agent-related constructs
    - "knowledgebase vector" - Returns knowledge base constructs related to vector stores
    - "agent actiongroups" - Returns action groups for agents
    - "opensearch vector" - Returns OpenSearch vector constructs

    The search supports subdirectory content (like knowledge bases and their sections)
    and will find matches across all available content.

    Args:
        ctx: MCP context
        query: Search term(s) to find constructs by name or description
        construct_type: Optional filter by construct type ('bedrock', 'opensearchserverless', etc.)

    Returns:
        Dictionary with matching constructs and resource URIs
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| construct_type | any | not set | No
| query | any | not set | No
</details>
<details>
<summary>LambdaLayerDocumentationProvider</summary>

**Description**:

```
Provide documentation sources for Lambda layers.

    This tool returns information about where to find documentation for Lambda layers
    and instructs the MCP Client to fetch and process this documentation.

    Args:
        ctx: MCP context
        layer_type: Type of layer ("generic" or "python")

    Returns:
        Dictionary with documentation source information
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| layer_type | string | not set | Yes
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| get_lambda_powertools_index | text/plain | lambda-powertools:// | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | CDKGeneralGuidance | description | 296d68dc031855415c3f88fa0655a8e38cf8d7730eb8334f037488257f918f46 |
| tools | CheckCDKNagSuppressions | description | c22fe68fc7d09f9cb2dd6db410b6b395a6729ca74d1ae02ecbe331d946c8ace9 |
| tools | ExplainCDKNagRule | description | f922da8f15e69c0f7092d921043be40015ac8a986ebad4b5645ab88a4e6c6501 |
| tools | GenerateBedrockAgentSchema | description | 0e16e1a2af06ca18f7920f2b1274458b596811116c206bddebf7f09afbe98924 |
| tools | GetAwsSolutionsConstructPattern | description | 8eb5f6bdde17b9da9a11be5934228c9eba5e895402c3a43e63b92b900eb2cf1f |
| tools | LambdaLayerDocumentationProvider | description | ce273de51ab6ae533993e38592a458ba42ea1bc7c29e5a1e3ac01989d8be2240 |
| tools | SearchGenAICDKConstructs | description | d3c3f86e49dc4bd73f5d3cde2a9a4c37f04f1a300f238aa1bdd513866e9964b0 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
