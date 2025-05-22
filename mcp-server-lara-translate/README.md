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


# What is mcp-server-lara-translate?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-lara-translate/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-lara-translate/0.0.10?logo=docker&logoColor=fff&label=0.0.10)](https://hub.docker.com/r/acuvity/mcp-server-lara-translate)
[![PyPI](https://img.shields.io/badge/0.0.10-3775A9?logo=pypi&logoColor=fff&label=@translated/lara-mcp)](https://github.com/translated/lara-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-lara-translate/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-lara-translate&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22LARA_ACCESS_KEY_ID%22%2C%22-e%22%2C%22LARA_ACCESS_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-lara-translate%3A0.0.10%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server enabling powerful language translation capabilities.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @translated/lara-mcp original [sources](https://github.com/translated/lara-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-lara-translate/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-lara-translate/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-lara-translate/charts/mcp-server-lara-translate/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @translated/lara-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-lara-translate/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-lara-translate scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `LARA_ACCESS_KEY_ID` required to be set
  - `LARA_ACCESS_KEY_SECRET` required to be set

For more information and extra configuration you can consult the [package](https://github.com/translated/lara-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-lara-translate&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22LARA_ACCESS_KEY_ID%22%2C%22-e%22%2C%22LARA_ACCESS_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-lara-translate%3A0.0.10%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-lara-translate": {
        "env": {
          "LARA_ACCESS_KEY_ID": "TO_BE_SET",
          "LARA_ACCESS_KEY_SECRET": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "LARA_ACCESS_KEY_ID",
          "-e",
          "LARA_ACCESS_KEY_SECRET",
          "docker.io/acuvity/mcp-server-lara-translate:0.0.10"
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
    "acuvity-mcp-server-lara-translate": {
      "env": {
        "LARA_ACCESS_KEY_ID": "TO_BE_SET",
        "LARA_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "LARA_ACCESS_KEY_ID",
        "-e",
        "LARA_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-lara-translate:0.0.10"
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
    "acuvity-mcp-server-lara-translate": {
      "env": {
        "LARA_ACCESS_KEY_ID": "TO_BE_SET",
        "LARA_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "LARA_ACCESS_KEY_ID",
        "-e",
        "LARA_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-lara-translate:0.0.10"
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
    "acuvity-mcp-server-lara-translate": {
      "env": {
        "LARA_ACCESS_KEY_ID": "TO_BE_SET",
        "LARA_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "LARA_ACCESS_KEY_ID",
        "-e",
        "LARA_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-lara-translate:0.0.10"
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
    "acuvity-mcp-server-lara-translate": {
      "env": {
        "LARA_ACCESS_KEY_ID": "TO_BE_SET",
        "LARA_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "LARA_ACCESS_KEY_ID",
        "-e",
        "LARA_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-lara-translate:0.0.10"
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
        "env": {"LARA_ACCESS_KEY_ID":"TO_BE_SET","LARA_ACCESS_KEY_SECRET":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","LARA_ACCESS_KEY_ID","-e","LARA_ACCESS_KEY_SECRET","docker.io/acuvity/mcp-server-lara-translate:0.0.10"]
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
- arguments: `run -i --rm --read-only -e LARA_ACCESS_KEY_ID -e LARA_ACCESS_KEY_SECRET docker.io/acuvity/mcp-server-lara-translate:0.0.10`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e LARA_ACCESS_KEY_ID -e LARA_ACCESS_KEY_SECRET docker.io/acuvity/mcp-server-lara-translate:0.0.10
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-lara-translate": {
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
    "acuvity-mcp-server-lara-translate": {
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
  - `LARA_ACCESS_KEY_ID` secret to be set as secrets.LARA_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `LARA_ACCESS_KEY_SECRET` secret to be set as secrets.LARA_ACCESS_KEY_SECRET either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-lara-translate --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-lara-translate --version 1.0.0
````

Install with helm

```console
helm install mcp-server-lara-translate oci://docker.io/acuvity/mcp-server-lara-translate --version 1.0.0
```

From there your MCP server mcp-server-lara-translate will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-lara-translate` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-lara-translate/charts/mcp-server-lara-translate/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>translate</summary>

**Description**:

```
Translate text between languages with support for language detection, context-aware translations and translation memories using Lara Translate.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| adapt_to | array | A list of translation memory IDs for adapting the translation. | No
| context | string | Additional context string to improve translation quality (e.g., 'This is a legal document' or 'Im talking with a doctor'). This helps the translation system better understand the domain. | No
| instructions | array | A list of instructions to adjust the network’s behavior regarding the output (e.g., 'Use a formal tone'). | No
| source | string | The source language code (e.g., 'en-EN' for English). If not specified, the system will attempt to detect it automatically. If you have a hint about the source language, you should specify it in the source_hint field. | No
| source_hint | string | Used to guide language detection. Specify this when the source language is uncertain to improve detection accuracy. | No
| target | string | The target language code (e.g., 'it-IT' for Italian). This specifies the language you want the text translated into. | Yes
| text | array | An array of text blocks to translate. Each block contains a text string and a boolean indicating whether it should be translated. This allows for selective translation where some text blocks can be preserved in their original form while others are translated. | Yes
</details>
<details>
<summary>create_memory</summary>

**Description**:

```
Create a translation memory with a custom name in your Lara Translate account. Translation memories store pairs of source and target text segments (translation units) for reuse in future translations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| external_id | string | The ID of the memory to be imported from MyMemory. Use this to initialize the memory with external content. Format: ext_my_[MyMemory ID] | No
| name | string | The name of the new memory, it should be short and generic, like 'catch_phrases' or 'brand_names' | Yes
</details>
<details>
<summary>delete_memory</summary>

**Description**:

```
Deletes a translation memory from your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The unique identifier of the memory to update. Format: mem_xyz123 | Yes
</details>
<details>
<summary>update_memory</summary>

**Description**:

```
Updates a translation memory in your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The unique identifier of the memory to update. Format: mem_xyz123 | Yes
| name | string | The new name for the memory | Yes
</details>
<details>
<summary>add_translation</summary>

**Description**:

```
Adds a translation to a translation memory in your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | array | The ID or list of IDs where to save the translation unit. Format: mem_xyz123 | Yes
| sentence | string | The source sentence | Yes
| sentence_after | string | The sentence after the source sentence to specify the context of the translation unit | No
| sentence_before | string | The sentence before the source sentence to specify the context of the translation unit | No
| source | string | The source language code of the sentence, it MUST be a language supported by the system, use the list_languages tool to get a list of all the supported languages | Yes
| target | string | The target language code of the translation, it MUST be a language supported by the system, use the list_languages tool to get a list of all the supported languages | Yes
| translation | string | The translated sentence | Yes
| tuid | string | Translation Unit unique identifier | No
</details>
<details>
<summary>delete_translation</summary>

**Description**:

```
Deletes a translation from a translation memory from your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | array | The ID or list of IDs where to delete the translation unit from. Format: mem_xyz123 | Yes
| sentence | string | The source sentence | Yes
| sentence_after | string | The sentence after the source sentence to specify the context of the translation unit | No
| sentence_before | string | The sentence before the source sentence to specify the context of the translation unit | No
| source | string | The source language code of the sentence | Yes
| target | string | The target language code of the translation | Yes
| translation | string | The translated sentence | Yes
| tuid | string | Translation Unit unique identifier | No
</details>
<details>
<summary>import_tmx</summary>

**Description**:

```
Imports a TMX file into a translation memory in your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| gzip | boolean | Indicates if the file is a compressed .gz file | No
| id | string | The ID of the memory to update. Format: mem_xyz123. | Yes
| tmx_content | string | The content of the tmx file to upload. Don't provide this if you choose to use tmx_url. | No
| tmx_url | string | A URL to the tmx file to upload. Don't provide this if you choose to use tmx_content. | No
</details>
<details>
<summary>check_import_status</summary>

**Description**:

```
Checks the status of a TMX file import job in your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The ID of the import job | Yes
</details>
<details>
<summary>list_memories</summary>

**Description**:

```
Lists all translation memories in your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_languages</summary>

**Description**:

```
Lists all supported languages in your Lara Translate account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>

## 📚 Resources (2)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Translation Memories | <no value> | memories://list | - |
| Supported Languages | <no value> | languages://list | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_translation | description | 2387171a256ac905ea9e959885ef7f3e461e8e6720205ad8006b76568312ad7e |
| tools | add_translation | id | 41678a84a664297c91ac16514d6808b7eeb84d4b471acf73b94b7c6d6175607c |
| tools | add_translation | sentence | 8256317c90bc9c1584a05dad6f4e60c31b8dba5dc72480e5dd8475e42557889b |
| tools | add_translation | sentence_after | 87b1e5e35ca28a8aec8b0cd1de06eebe813ab81f8b1fde8ff5cb1d6cb90251b5 |
| tools | add_translation | sentence_before | 5e8e3e37e6c98c9d78accc695c8b8200e30e7ec3135c2e4ba2ffa4d918368ee5 |
| tools | add_translation | source | 74cac3b198877e76b01abac107c96b973331acb30f52c570bde49de47f339487 |
| tools | add_translation | target | 7c24b1ef7e6f72fa55023940c041d18db61ebc0489d84247405c0b33ce91a184 |
| tools | add_translation | translation | 4261fceaa98a52c89d6f04b34e1f023747f71849581ed9b8e47edd60290c75ef |
| tools | add_translation | tuid | a04149f24d09a0a9724e2f452464b1f717237bc824d7dd1e484b1bed8154bde0 |
| tools | check_import_status | description | 66c05830c1288b8a2340a79ce44586fe86c4543826b83f1f3bc65acfa9b71360 |
| tools | check_import_status | id | a6bac8140fc9463accb2718fc48c17cb93ca0ab9fceb417dd0f270ae5fb00240 |
| tools | create_memory | description | 7a570a22fa815d92c8524683eb44d533583a5c8a7707f1453184cc29ec020253 |
| tools | create_memory | external_id | 941422d45e8e6f71ed842799d1643aba334bde277f7e147fe1f17c29c0c4e057 |
| tools | create_memory | name | 15aa1f35f480fa69592891769346f7aa4021e5cb9551384e05732a8f08a6c46e |
| tools | delete_memory | description | 55a01ed697a6a2e2e6815aefd612bd3c7fd8f4cf8a7dc3450f33f6475090e7af |
| tools | delete_memory | id | ffd44fc743d295ffac3258171d24997bd7ae32a235d85a7e656d8dd6db0943de |
| tools | delete_translation | description | c960e0d50b8b4d1b655bb0e2f8596473d21f9cf0699e048a6689771335c14428 |
| tools | delete_translation | id | 0cc8980895d3b837011933d4aa118599b7f40b2ff8c35c8da7e8cd87ce5a0b91 |
| tools | delete_translation | sentence | 8256317c90bc9c1584a05dad6f4e60c31b8dba5dc72480e5dd8475e42557889b |
| tools | delete_translation | sentence_after | 87b1e5e35ca28a8aec8b0cd1de06eebe813ab81f8b1fde8ff5cb1d6cb90251b5 |
| tools | delete_translation | sentence_before | 5e8e3e37e6c98c9d78accc695c8b8200e30e7ec3135c2e4ba2ffa4d918368ee5 |
| tools | delete_translation | source | 488c5779de1629a6a66fab9531dfc9b7287711ff364797c0048e8af5bf4386b4 |
| tools | delete_translation | target | e32961c10e6e3d15aea70d4512947afbaa5c3a2928b146a3534c07571bcc389c |
| tools | delete_translation | translation | 4261fceaa98a52c89d6f04b34e1f023747f71849581ed9b8e47edd60290c75ef |
| tools | delete_translation | tuid | a04149f24d09a0a9724e2f452464b1f717237bc824d7dd1e484b1bed8154bde0 |
| tools | import_tmx | description | bc53fefa95defccc0371caf9426a14beba5a75a6ec6420a0f7067e827109f393 |
| tools | import_tmx | gzip | 8b5335bd86641e96ebaa9dbe572bd79715b5489594fe49de99de4ea979bcbd70 |
| tools | import_tmx | id | e6a3fe5204d2ae3d03d7e4bfc45a0bde4837fc3799ea1856ceda4c2555fa45c0 |
| tools | import_tmx | tmx_content | c949bc1eda4b7a196edb4bd60c9615cbb9213da254c4e5a9e69fa5a385e608d8 |
| tools | import_tmx | tmx_url | cd4c23aef7ecb0edbeebb2add30a44688999337dc85635f6dc5bfea57402b6de |
| tools | list_languages | description | 2ddf95e12cd539a3dee9872c4e5054d61dbd826e4ea7c2124226165dfe7ef64c |
| tools | list_memories | description | 5928b92abea4b638a532de1c1a4698cf5874021e6570842a0917bd17e19b256a |
| tools | translate | description | 49c7008373a693f08f6f234e69ca6a28e9f6dc9e4413a1f970422f49a69a3143 |
| tools | translate | adapt_to | 7effe21b9feea169e92b3b7d3728e68f4727a42128ad7c667953a485f05b9ab8 |
| tools | translate | context | 4bac4c2dbcb9b9a5ad582df595d6899f8f7a20f817b49066be163113017be1ad |
| tools | translate | instructions | aea7033796b9f586ba27c025eaf481e9e08e4d07e1b376f746ff7b91afe1fbdd |
| tools | translate | source | a4dbf3adf61992842a4ed42416788bb8205f518b8778d0609557a7571388e084 |
| tools | translate | source_hint | 02d619790a8df7a63e1cc9cf3dc20679d3f07ceab2913d5c24abef0ff47fac5b |
| tools | translate | target | 438ae4c5eb9dc7ac62a7079938e79403a3bbb74ca4bd372f2e22ab468e6ec2c7 |
| tools | translate | text | e90c9c7e1fab47e18f5fb434088ad160e904936c7d95e19c4e5e3c56d4544c32 |
| tools | update_memory | description | a9c1fe58ed1e1616238d756f69a4f99de5a3fa93de1621812659c0768127e325 |
| tools | update_memory | id | ffd44fc743d295ffac3258171d24997bd7ae32a235d85a7e656d8dd6db0943de |
| tools | update_memory | name | 6b2f947d665ad51cb342dc4a2ca01cbd3a543c2934f81b3309f7af108028f4ed |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
