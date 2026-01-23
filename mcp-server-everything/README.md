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


# What is mcp-server-everything?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-everything/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-everything/2026.1.14?logo=docker&logoColor=fff&label=2026.1.14)](https://hub.docker.com/r/acuvity/mcp-server-everything)
[![PyPI](https://img.shields.io/badge/2026.1.14-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-everything)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-everything/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-everything&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-everything%3A2026.1.14%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server that exercises all the features of the MCP protocol

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @modelcontextprotocol/server-everything original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-everything/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/charts/mcp-server-everything/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-everything run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-everything scope of operation it can be hosted anywhere.

For more information and extra configuration you can consult the [package](https://modelcontextprotocol.io) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-everything&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-everything%3A2026.1.14%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-everything": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-everything:2026.1.14"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2026.1.14"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2026.1.14"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2026.1.14"
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
    "acuvity-mcp-server-everything": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-everything:2026.1.14"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-everything:2026.1.14"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-everything:2026.1.14`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-everything:2026.1.14
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-everything": {
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
    "acuvity-mcp-server-everything": {
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
helm show readme oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
````

Install with helm

```console
helm install mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
```

From there your MCP server mcp-server-everything will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-everything` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/charts/mcp-server-everything/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>echo</summary>

**Description**:

```
Echoes back the input string
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | Message to echo | Yes
</details>
<details>
<summary>get-annotated-message</summary>

**Description**:

```
Demonstrates how annotations can be used to provide metadata about content.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeImage | boolean | Whether to include an example image | No
| messageType | string | Type of message to demonstrate different annotation patterns | Yes
</details>
<details>
<summary>get-env</summary>

**Description**:

```
Returns all environment variables, helpful for debugging MCP server configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get-resource-links</summary>

**Description**:

```
Returns up to ten resource links that reference different types of resources
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of resource links to return (1-10) | No
</details>
<details>
<summary>get-resource-reference</summary>

**Description**:

```
Returns a resource reference that can be used by MCP clients
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resourceId | number | ID of the text resource to fetch | No
| resourceType | string | not set | No
</details>
<details>
<summary>get-structured-content</summary>

**Description**:

```
Returns structured content along with an output schema for client data validation
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| location | string | Choose city | Yes
</details>
<details>
<summary>get-sum</summary>

**Description**:

```
Returns the sum of two numbers
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| a | number | First number | Yes
| b | number | Second number | Yes
</details>
<details>
<summary>get-tiny-image</summary>

**Description**:

```
Returns a tiny MCP logo image.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>gzip-file-as-resource</summary>

**Description**:

```
Compresses a single file using gzip compression. Depending upon the selected output type, returns either the compressed data as a gzipped resource or a resource link, allowing it to be downloaded in a subsequent request during the current session.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | string | URL or data URI of the file content to compress | No
| name | string | Name of the output file | No
| outputType | string | How the resulting gzipped file should be returned. 'resourceLink' returns a link to a resource that can be read later, 'resource' returns a full resource object. | No
</details>
<details>
<summary>toggle-simulated-logging</summary>

**Description**:

```
Toggles simulated, random-leveled logging on or off.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>toggle-subscriber-updates</summary>

**Description**:

```
Toggles simulated resource subscription updates on or off.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>trigger-long-running-operation</summary>

**Description**:

```
Demonstrates a long running operation with progress updates.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration | number | Duration of the operation in seconds | No
| steps | number | Number of steps in the operation | No
</details>
<details>
<summary>get-roots-list</summary>

**Description**:

```
Lists the current MCP roots provided by the client. Demonstrates the roots protocol capability even though this server doesn't access files.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>trigger-sampling-request</summary>

**Description**:

```
Trigger a Request from the Server for LLM Sampling
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxTokens | number | Maximum number of tokens to generate | No
| prompt | string | The prompt to send to the LLM | Yes
</details>

## 📚 Resources (7)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| architecture.md | text/markdown | demo://resource/static/document/architecture.md | - |
| extension.md | text/markdown | demo://resource/static/document/extension.md | - |
| features.md | text/markdown | demo://resource/static/document/features.md | - |
| how-it-works.md | text/markdown | demo://resource/static/document/how-it-works.md | - |
| instructions.md | text/markdown | demo://resource/static/document/instructions.md | - |
| startup.md | text/markdown | demo://resource/static/document/startup.md | - |
| structure.md | text/markdown | demo://resource/static/document/structure.md | - |

</details>

## 📝 Prompts (4)
<details>
<summary>simple-prompt</summary>

**Description**:

```
A prompt with no arguments
```
<details>
<summary>args-prompt</summary>

**Description**:

```
A prompt with two arguments, one required and one optional
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| city | Name of the city |Yes |
| state | Name of the state |No |
<details>
<summary>completable-prompt</summary>

**Description**:

```
First argument choice narrows values for second argument.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| department | Choose the department. |Yes |
| name | Choose a team member to lead the selected department. |Yes |
<details>
<summary>resource-prompt</summary>

**Description**:

```
A prompt that includes an embedded resource reference
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| resourceType | Type of resource to fetch |Yes |
| resourceId | ID of the text resource to fetch |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | args-prompt | description | 6bf9e87694814907d18376c10df390d1d026ab22dd25dc2f90c7f54fe3e872f2 |
| prompts | args-prompt | city | 6e7972358d7f0ec8764bf526b14781a42654304776ea3ad233f60bf922899155 |
| prompts | args-prompt | state | 9a5f7119fb7e49fe59783d064d75904aadf8acf32e7e60bdd5c5ace03c81df39 |
| prompts | completable-prompt | description | 440077b1101c42fe4de7f359ffe44f5428ea005d4d3003be8a7b008e4e657931 |
| prompts | completable-prompt | department | 6c1697a1528ebdd17c722c8df0be4ebc7908e0932ab9c07a29a22ea3965b11a2 |
| prompts | completable-prompt | name | 8d9a952b1921cc303f93f852d16c1975a52c1296c869e9e062fd08a3ff6b7b30 |
| prompts | resource-prompt | description | 485a9a963ffe2b74994e89a2ac741dc26ef7656974ba85d6e1a8fba8472adaca |
| prompts | resource-prompt | resourceId | 747c611eadb757cc695479ba71ad7ad30123383782d50dcae9cc923c5ff6c7f4 |
| prompts | resource-prompt | resourceType | 54b6b2f551a23a9e4909208c06a589a3fca85a290fc1cb3cfdb626346eeeaacb |
| prompts | simple-prompt | description | bd5b0cf66fbff61626808db1d4285c51cda3d933d3d05a4ad7bd7500d0ab86ba |
| tools | echo | description | 4d00e170dfb2475b38d7c595d6b83ddc873f4119814d8c3e96321a53aaf18fca |
| tools | echo | message | 2aa7ac486933d92f1de28d4b527088a577a0fe0ad5d33c0c36c1d122fc8477ba |
| tools | get-annotated-message | description | 6050c40378a145a00c1912f5904b37edb1266ce1c43fa430b6655a6f302d5222 |
| tools | get-annotated-message | includeImage | 3f577041e74ad35132f1242ae17815ed70e39bad9533b717021987963f8abb27 |
| tools | get-annotated-message | messageType | 48ca223484fb0957dc6efa4920a79cc385ab419c7c3af0309e8acb4784c58d0d |
| tools | get-env | description | 41cecdc4e2e1e3ab2be769fefe6cb155289da5ade9c381a1578bda7948111c26 |
| tools | get-resource-links | description | 0574c9e3571c77380de27d3927dbac8133e68c558150b8f0b95d2e884403613c |
| tools | get-resource-links | count | 710b4aa7c24cb2e02f1dfaaa05449a98f92d7ee2252f0da40c0685b614d00783 |
| tools | get-resource-reference | description | f65488ea8977f68a7680a0ba04efa98d742a3007664649c9e00899f43f1d89de |
| tools | get-resource-reference | resourceId | 747c611eadb757cc695479ba71ad7ad30123383782d50dcae9cc923c5ff6c7f4 |
| tools | get-roots-list | description | 3b7b19f4e04c4ca99d1475992f4b95915e7415d4261cf4cebc291b7b3def7c8d |
| tools | get-structured-content | description | 276d76ef534072c914d17df7855f06d6c44a8c5be3ee2b8eb686afdeb357d88c |
| tools | get-structured-content | location | 43ae23322301a2f94c6b19a84e30a7d2681359513b6cea1000cffeafd8ee2920 |
| tools | get-sum | description | 98b4e89d761c05f63a8acce7100a3950f49ca67537dea3716c0ba2a9431316f9 |
| tools | get-sum | a | 4d238256ad692183f3c2e945213eac5ae9e86bce06e6989360af210cae8751f4 |
| tools | get-sum | b | c079e9787b04a05e7e4dd561a044bce326711ebc3f0c90160f33823530da93d3 |
| tools | get-tiny-image | description | 7eba2275ba1ae93a58102c84bcd8f1fb29126fb998d3cbd2947457cdbe685bde |
| tools | gzip-file-as-resource | description | e74512860ba0e5a1d47699b6bc8099970a510674295e14a861287882ed715243 |
| tools | gzip-file-as-resource | data | fe50d774f0f3d2c53621ed9187fb8110a675cc16644da0368e3a94d3011f16e5 |
| tools | gzip-file-as-resource | name | fe91c771dbfa72cbd6dbd6404fb3eeb4aac574ebcbc8e111cd28b86cf882db5d |
| tools | gzip-file-as-resource | outputType | 216a80a9e4dce55bb3cf355f09d764bc7e399daa474b3aff4dc5c13da7e915f5 |
| tools | toggle-simulated-logging | description | 4ece88d0dc82c58f375c0df4229b4fad8a4ee98398486f5d3e64f8b5d1f2219d |
| tools | toggle-subscriber-updates | description | 8d2608e7a48902396a0c7b08e56cfdcf93667ecd09de825d71a6c47b207f22c8 |
| tools | trigger-long-running-operation | description | d047c3fcbcb25a9255d0bd7584d019509a8aa5a181ce7e3c6109d76ea820d125 |
| tools | trigger-long-running-operation | duration | 611a5d1b6734296bafe76d21bca6f9c984b30ae9cf9921554c4440d26b7ea431 |
| tools | trigger-long-running-operation | steps | 70c271e49e3c4217d398f502fda4be342f73aa5875a69b7f59fc749564181707 |
| tools | trigger-sampling-request | description | 807babf5b7ff34397dda42ab6ad339d82f992dc120ddb6c92165c8ee0a217a14 |
| tools | trigger-sampling-request | maxTokens | 877bc91aff3481950f61058439e2f8d8e4a15e3cfa9d1f031c94e945ba2d516e |
| tools | trigger-sampling-request | prompt | 472f849bc61d2fc5c70dac589c4cab3ee7ed1800fbc61dc1c78ba30546c40e95 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
