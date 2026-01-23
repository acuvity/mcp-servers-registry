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


# What is mcp-server-pulumi?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-pulumi/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-pulumi/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-pulumi)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=@pulumi/mcp-server)](https://github.com/pulumi/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-pulumi/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-pulumi&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22cache%3A%2Fapp%2Fnode_modules%2F%40pulumi%2Fmcp-server%2Fdist%2F.cache%22%2C%22docker.io%2Facuvity%2Fmcp-server-pulumi%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Server for programmatic Pulumi operations via Model Context Protocol.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @pulumi/mcp-server original [sources](https://github.com/pulumi/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-pulumi/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/charts/mcp-server-pulumi/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @pulumi/mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-pulumi scope of operation it can be hosted anywhere.
**Required volumes or mountPaths:**
  - data to be mounted on `/app/node_modules/@pulumi/mcp-server/dist/.cache`

For more information and extra configuration you can consult the [package](https://github.com/pulumi/mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-pulumi&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22cache%3A%2Fapp%2Fnode_modules%2F%40pulumi%2Fmcp-server%2Fdist%2F.cache%22%2C%22docker.io%2Facuvity%2Fmcp-server-pulumi%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-pulumi": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-v",
          "cache:/app/node_modules/@pulumi/mcp-server/dist/.cache",
          "docker.io/acuvity/mcp-server-pulumi:0.2.0"
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
    "acuvity-mcp-server-pulumi": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "cache:/app/node_modules/@pulumi/mcp-server/dist/.cache",
        "docker.io/acuvity/mcp-server-pulumi:0.2.0"
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
    "acuvity-mcp-server-pulumi": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "cache:/app/node_modules/@pulumi/mcp-server/dist/.cache",
        "docker.io/acuvity/mcp-server-pulumi:0.2.0"
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
    "acuvity-mcp-server-pulumi": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "cache:/app/node_modules/@pulumi/mcp-server/dist/.cache",
        "docker.io/acuvity/mcp-server-pulumi:0.2.0"
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
    "acuvity-mcp-server-pulumi": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "cache:/app/node_modules/@pulumi/mcp-server/dist/.cache",
        "docker.io/acuvity/mcp-server-pulumi:0.2.0"
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
        "args": ["run","-i","--rm","--read-only","-v","cache:/app/node_modules/@pulumi/mcp-server/dist/.cache","docker.io/acuvity/mcp-server-pulumi:0.2.0"]
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
- arguments: `run -i --rm --read-only -v cache:/app/node_modules/@pulumi/mcp-server/dist/.cache docker.io/acuvity/mcp-server-pulumi:0.2.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -v cache:/app/node_modules/@pulumi/mcp-server/dist/.cache docker.io/acuvity/mcp-server-pulumi:0.2.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-pulumi": {
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
    "acuvity-mcp-server-pulumi": {
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
helm show readme oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
````

Install with helm

```console
helm install mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
```

From there your MCP server mcp-server-pulumi will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-pulumi` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/charts/mcp-server-pulumi/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>pulumi-registry-get-type</summary>

**Description**:

```
Get the JSON schema for a specific JSON schema type reference
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | The module to query (e.g., 's3', 'ec2', 'lambda'). Optional for smaller providers, will be 'index by default. | No
| name | string | The name of the type to query (e.g., 'BucketGrant', 'FunctionEnvironment', 'InstanceCpuOptions') | Yes
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-get-resource</summary>

**Description**:

```
Returns information about a Pulumi Registry resource
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | The module to query (e.g., 's3', 'ec2', 'lambda'). If not specified it will match resources with the given name in any module. | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| resource | string | The resource type to query (e.g., 'Bucket', 'Function', 'Instance') | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-get-function</summary>

**Description**:

```
Returns information about a Pulumi Registry function
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| function | string | The function type to query (e.g., 'getBucket', 'getFunction', 'getInstance') | Yes
| module | string | The module to query (e.g., 's3', 'ec2', 'lambda'). If not specified it will match functions with the given name in any module. | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-list-resources</summary>

**Description**:

```
List all resource types for a given provider and module
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | Optional module to filter by (e.g., 's3', 'ec2', 'lambda') | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-list-functions</summary>

**Description**:

```
List all function types for a given provider and module
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | Optional module to filter by (e.g., 's3', 'ec2', 'lambda') | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-cli-preview</summary>

**Description**:

```
Run pulumi preview for a given project and stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>pulumi-cli-up</summary>

**Description**:

```
Run pulumi up for a given project and stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>pulumi-cli-stack-output</summary>

**Description**:

```
Get the output value(s) of a given stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| outputName | string | The specific stack output name to retrieve. | No
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>pulumi-cli-refresh</summary>

**Description**:

```
Run pulumi refresh for a given project and stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>deploy-to-aws</summary>

**Description**:

```
Deploy application code to AWS by generating Pulumi infrastructure. This tool automatically analyzes your application files and provisions the appropriate AWS resources (S3, Lambda, EC2, etc.) based on what it finds. No prior analysis needed -  just invoke directly.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>pulumi-resource-search</summary>

**Description**:

```
Search and analyze Pulumi-managed cloud resources using a strict subset of Lucene query syntax.

QUERY SYNTAX RULES:
- The search query syntax is a strict subset of Lucene query syntax
- The documents being searched are Pulumi resources
- The implicit operator is AND
- Parentheses and OR are supported between fields but not within fields
- All resources are returned by default (use empty query "" to get all)
- Wildcard queries are NOT supported (no * allowed)
- Fuzzy queries are NOT supported
- Boosting is NOT supported
- Field grouping is NOT supported
- Whitespace is NOT supported
- field:value produces a match_phrase query
- field:"value" produces a term query
- -field:value produces a bool must_not match_phrase query
- -field:"value" produces a bool must_not term query
- field: produces an existence query
- Resource properties can be queried with leading dot: .property.path:value or .property.path: (existence)
- You absolutely must not produce queries that use fields other than: type, name, id, stack, project, package, modified, provider, provider_urn, team and protected, unless the field is the name of a property.
- You absolutely must not produce queries that use wildcards (e.g., *).
- You absolutely must not produce queries that use field grouping (e.g., type:(a OR b))

AVAILABLE FIELDS:
- type: Pulumi types used for pulumi import operations (e.g., aws:s3/bucket:Bucket)
- name: logical Pulumi resource names
- id: physical Pulumi resource names
- stack: name of the stack the resource belongs to
- project: name of the project the resource belongs to
- created: when the resource was first created (absolute dates only)
- modified: when the resource was last modified (absolute dates only)
- package: package of the resource (e.g., aws, gcp)
- provider: alias for the "package" field
- provider_urn: full URN of the resource's provider
- protected: boolean representing whether a resource is protected
- team: name of a team with access to the resource

IMPORTANT QUERY PATTERNS:
For AWS resources, do not use specific provider prefixes (aws: or aws-native:) in type filters. Instead:
WRONG: type:aws:s3/bucket:Bucket
WRONG: type:aws-native:s3:Bucket
CORRECT: type:"Bucket" (searches across both aws and aws-native providers)
For package filtering, use the generic package name:
CORRECT: package:aws (matches both aws and aws-native packages)
For finding resources by service, prefer the module field when possible:
PREFERRED: module:s3 (finds all S3 resources regardless of provider)
For property existence queries, always use the dot notation:
CORRECT: .tags: (checks if tags property exists)
For property negation queries (finding resources WITHOUT a property):
CORRECT: -.tags: or NOT .tags: (finds resources without tags)
COMMON TRANSLATIONS:
- "untagged resources" → -.tags: or NOT .tags:
- "resources without tags" → -.tags: or NOT .tags:

Supports field filters, boolean operators (AND, OR, NOT), exact matches with quotes, and property searches. The top parameter controls the maximum number of results to return (defaults to 20).

Resources may not have a repository url. This means that there is no available information about the repository that the resource is associated with.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org | string | Pulumi organization name (optional, defaults to current default org) | No
| properties | boolean | Whether to include resource properties in the response (defaults to false). WARNING: Setting this to true produces significantly more tokens and can cause response size limits to be exceeded. Only set to true when: (1) user explicitly requests properties/details, (2) querying a very small number of specific resources, or (3) user needs property-based analysis. NOT recommended for loose queries (empty query, broad type searches, etc.) that return many resources. | No
| query | string | Lucene query string using strict subset syntax (see tool description for full rules). NO WILDCARDS (*) allowed. | Yes
| top | number | Maximum number of top results to return (defaults to 20) | No
</details>
<details>
<summary>neo-task-launcher</summary>

**Description**:

```
Launch a Neo task when user asks Neo to perform a task. Pulumi Neo is a purpose-built cloud infrastructure automation agent.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| context | string | Optional conversation context with details of work done so far. Include: 1) Summary of what the user has been working on, 2) For any files modified, provide git diff format showing the changes, 3) Textual explanation of what was changed and why. Example: "The user has been working on authentication. Files modified: src/auth.ts - Added token support: ```diff\n- function login(user) {\n+ function login(user, token) {\n```\nThis change adds token-based auth for better security." | No
| query | string | The task query to send to Neo (what the user wants Neo to do) | Yes
</details>

## 📝 Prompts (2)
<details>
<summary>deploy-to-aws</summary>

**Description**:

```
Deploy application code to AWS by generating Pulumi infrastructure
```
<details>
<summary>convert-terraform-to-typescript</summary>

**Description**:

```
Converts a Terraform file to TypeScript
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| outputDir | The directory to output the TypeScript code to |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | convert-terraform-to-typescript | description | 46721b1af46ad5dc9f006d54a92682b4651a280fcc5ed1eb8c0c16508cf3676a |
| prompts | convert-terraform-to-typescript | outputDir | 79fb78573933eef422e5c6cfe8967a19bd80a3087dfb49427c7af29b9256c027 |
| prompts | deploy-to-aws | description | 84b5819f8a04f39f97b66ee3b302729d18ef812bec8446af245d45b485d4f216 |
| tools | deploy-to-aws | description | 0a24c7371bb30010e043be7eba2ec686194bf50cd5668be3c4fbee2bc48cb539 |
| tools | neo-task-launcher | description | a7d7f5ffe9094b383d72e88104f5e2b5d6670f6c344e41371f0a42704abcb477 |
| tools | neo-task-launcher | context | 05ae8e4b48f5db2ba701750fc2396c0fae821c9afc1f4ae91400ccd8dcb15eb0 |
| tools | neo-task-launcher | query | f48f47ff5fa0476e249b322261995d7bbeded518bb5f84efe3fef21baddb2573 |
| tools | pulumi-cli-preview | description | 77eebbe43ea5f25cc6c6afba4493876241cb4553c3c800fefa38414777f9001a |
| tools | pulumi-cli-preview | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-preview | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-cli-refresh | description | 2051576b742f677f54e34cc7073cd22f5d8a115bab0ff1a7379edb686020caab |
| tools | pulumi-cli-refresh | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-refresh | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-cli-stack-output | description | 4b26ee5e37a27ae0158d38c55fe154141fe0068d75f5ef35a60f78ffab49ffd0 |
| tools | pulumi-cli-stack-output | outputName | af5e3b5255274599dd681b448adaa308c2c9aa54bb3203fecb449b2fd2a4db2a |
| tools | pulumi-cli-stack-output | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-stack-output | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-cli-up | description | 76e44523dd1858cf57baa3a7014a59eac6a8b8d352f0cfbb530c18ddbddf3336 |
| tools | pulumi-cli-up | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-up | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-registry-get-function | description | deca77a2cd724e1e6347de7f3cd46f0bef35629a208c7afbe3b9f1f3d411d745 |
| tools | pulumi-registry-get-function | function | 41781d7673ae216d861a74916a1d1140b37b9d23ac78e7f3365a770bca14ab80 |
| tools | pulumi-registry-get-function | module | 863b6f97dae28a9dfe55e288a125140172423942393113c8f56af5fac089b5bb |
| tools | pulumi-registry-get-function | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-get-function | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-get-resource | description | 187e34cb220dab47370d558de593b9157264cbae9bf52d1ff54ab6dba5783991 |
| tools | pulumi-registry-get-resource | module | c6939148bd48eb3acc755f0bb65d2ef94c5ee91c265b948ffc9d10cb26848b85 |
| tools | pulumi-registry-get-resource | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-get-resource | resource | bd4be36001049fe09082abdb3eecc5b2a427e0d1fb0b0873bb28a897be45263b |
| tools | pulumi-registry-get-resource | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-get-type | description | c86705d3607c12cc3050e20ea36461dd7f58b32850e2e378295a19776ff440e7 |
| tools | pulumi-registry-get-type | module | 912e142e135630c83cb0e36edc94b26ef20354d5b8e38f3ec948dccfac468bca |
| tools | pulumi-registry-get-type | name | ff0e769d54e1fdb895b7bd957584af333e5204c04050bbe34c91e7570c22f5aa |
| tools | pulumi-registry-get-type | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-get-type | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-list-functions | description | a7693331d1d6b2de628d279a752dbd8e1baebb00b9cc7210973def3639728716 |
| tools | pulumi-registry-list-functions | module | de9a6844786d8547d8e984bdb7c39b73da5ac3917ae7761d956471cc31160d18 |
| tools | pulumi-registry-list-functions | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-list-functions | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-list-resources | description | c020cf469c10b34c06eed648d7a647881a1b5b2ee1cd482b605f74afed6cce82 |
| tools | pulumi-registry-list-resources | module | de9a6844786d8547d8e984bdb7c39b73da5ac3917ae7761d956471cc31160d18 |
| tools | pulumi-registry-list-resources | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-list-resources | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-resource-search | description | 32a16c5be45c3dbb6d30530060f7d7330cd1db7778a7612d9f725668fa77adc2 |
| tools | pulumi-resource-search | org | c7136e5ee12fab855f78fbad9925612fcd3db02f6702871de9ca37ff7331484f |
| tools | pulumi-resource-search | properties | 29e8397d40408a28c654f7e9ea1c76ff3b3b0d1c024ac280a267dbaf2bab9059 |
| tools | pulumi-resource-search | query | 7ccf6bcba87c263358dd3d49be6c27167d2bb13b940e592bf1eb71f03cfb836c |
| tools | pulumi-resource-search | top | 347f9266497294660354199156e84cbe89f03552f9d449fcfd0f7439e675cc41 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
