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


# What is mcp-server-coda?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-coda/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-coda/1.4.1?logo=docker&logoColor=fff&label=1.4.1)](https://hub.docker.com/r/acuvity/mcp-server-coda)
[![PyPI](https://img.shields.io/badge/1.4.1-3775A9?logo=pypi&logoColor=fff&label=coda-mcp)](https://github.com/orellazri/coda-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-coda/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-coda&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_KEY%22%2C%22-e%22%2C%22DOC_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-coda%3A1.4.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for Coda.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from coda-mcp original [sources](https://github.com/orellazri/coda-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-coda/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/charts/mcp-server-coda/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure coda-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-coda scope of operation it can be hosted anywhere.
> But keep in mind that this requires a peristent storage and that is might not be capable of serving mulitple clients at the same time.

**Environment variables and secrets:**
  - `API_KEY` required to be set
  - `DOC_ID` required to be set

For more information and extra configuration you can consult the [package](https://github.com/orellazri/coda-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-coda&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_KEY%22%2C%22-e%22%2C%22DOC_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-coda%3A1.4.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-coda": {
        "env": {
          "API_KEY": "TO_BE_SET",
          "DOC_ID": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "API_KEY",
          "-e",
          "DOC_ID",
          "docker.io/acuvity/mcp-server-coda:1.4.1"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.4.1"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.4.1"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.4.1"
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
    "acuvity-mcp-server-coda": {
      "env": {
        "API_KEY": "TO_BE_SET",
        "DOC_ID": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_KEY",
        "-e",
        "DOC_ID",
        "docker.io/acuvity/mcp-server-coda:1.4.1"
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
        "env": {"API_KEY":"TO_BE_SET","DOC_ID":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","API_KEY","-e","DOC_ID","docker.io/acuvity/mcp-server-coda:1.4.1"]
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
- arguments: `run -i --rm --read-only -e API_KEY -e DOC_ID docker.io/acuvity/mcp-server-coda:1.4.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e API_KEY -e DOC_ID docker.io/acuvity/mcp-server-coda:1.4.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-coda": {
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
    "acuvity-mcp-server-coda": {
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
  - `API_KEY` secret to be set as secrets.API_KEY either by `.value` or from existing with `.valueFrom`
  - `DOC_ID` secret to be set as secrets.DOC_ID either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
````

Install with helm

```console
helm install mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
```

From there your MCP server mcp-server-coda will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-coda` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/charts/mcp-server-coda/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>coda_list_documents</summary>

**Description**:

```
List or search available documents
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The query to search for documents by - optional | No
</details>
<details>
<summary>coda_list_pages</summary>

**Description**:

```
List pages in the current document with pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document to list pages from | Yes
| limit | integer | The number of pages to return - optional, defaults to 25 | No
| nextPageToken | string | The token need to get the next page of results, returned from a previous call to this tool - optional | No
</details>
<details>
<summary>coda_create_page</summary>

**Description**:

```
Create a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content of the page to create - optional | No
| docId | string | The ID of the document to create the page in | Yes
| name | string | The name of the page to create | Yes
| parentPageId | string | The ID of the parent page to create this page under - optional | No
</details>
<details>
<summary>coda_get_page_content</summary>

**Description**:

```
Get the content of a page as markdown
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to get the content of | Yes
| pageIdOrName | string | The ID or name of the page to get the content of | Yes
</details>
<details>
<summary>coda_peek_page</summary>

**Description**:

```
Peek into the beginning of a page and return a limited number of lines
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to peek into | Yes
| numLines | integer | The number of lines to return from the start of the page - usually 30 lines is enough | Yes
| pageIdOrName | string | The ID or name of the page to peek into | Yes
</details>
<details>
<summary>coda_replace_page_content</summary>

**Description**:

```
Replace the content of a page with new markdown content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content to replace the page with | Yes
| docId | string | The ID of the document that contains the page to replace the content of | Yes
| pageIdOrName | string | The ID or name of the page to replace the content of | Yes
</details>
<details>
<summary>coda_append_page_content</summary>

**Description**:

```
Append new markdown content to the end of a page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content to append to the page | Yes
| docId | string | The ID of the document that contains the page to append the content to | Yes
| pageIdOrName | string | The ID or name of the page to append the content to | Yes
</details>
<details>
<summary>coda_duplicate_page</summary>

**Description**:

```
Duplicate a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to duplicate | Yes
| newName | string | The name of the new page | Yes
| pageIdOrName | string | The ID or name of the page to duplicate | Yes
</details>
<details>
<summary>coda_rename_page</summary>

**Description**:

```
Rename a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to rename | Yes
| newName | string | The new name of the page | Yes
| pageIdOrName | string | The ID or name of the page to rename | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | coda_append_page_content | description | d6eb83d5da34ae32ee47e049bfde75b03ca3a7b48c59a3195bb611f69629728c |
| tools | coda_append_page_content | content | 5a10ac2f054a77da9b7959abb4bacdb04cb96dec1697272b5ac8dcd8fb270172 |
| tools | coda_append_page_content | docId | 1a07d4ed809f2c4aa63a55d5635be7ae2eb8c87f3125e6cbc118ba7029879b44 |
| tools | coda_append_page_content | pageIdOrName | 2953a62ac23fd91570996571f459640e50db43ba7acfb27295ce332f276a9205 |
| tools | coda_create_page | description | cc5fb25691258d75039b01e76e47c55ca99243a51ca0a1ca8316d5f9ecf4642e |
| tools | coda_create_page | content | 22bd8cb205205d5c8826180ff748095de56dad85b69aa7d9f3e425e6d7e8f0f8 |
| tools | coda_create_page | docId | 158955c02c5aa26b184216129353a385eedf2b9368448e0b1284ca8482ca5d6a |
| tools | coda_create_page | name | 9200c858ffe87b34c08415c39d7e1111124dc7fbbe8bf606365936cf08fabdb8 |
| tools | coda_create_page | parentPageId | 23e66e983618974de73266d5421c75eedfbbd1884d0a89592ac5b383e1f03031 |
| tools | coda_duplicate_page | description | 4c2496f1d91db963e00ce499c6a64ce127e3e1789f51b7674d9053fc9f11c627 |
| tools | coda_duplicate_page | docId | f0e631f8b92b861f822ef892433ac345f70335c69c96664ae274235830198794 |
| tools | coda_duplicate_page | newName | 8cc9888bfa04926d724ebdfd4283bf915e056c54d7b9568b8c2c0409b00558d7 |
| tools | coda_duplicate_page | pageIdOrName | 23b139479cb7b4beb87d1d9833534d7c323f2db9feb871a75c81fb3abdb58ff4 |
| tools | coda_get_page_content | description | 6e954360c948036e80de20759d8e143ca665cdc6375a04d22b7fe7e79c411277 |
| tools | coda_get_page_content | docId | 48184f2c0fe56bd400f727989f61e00d5d90719df619680dce19a97250cc6039 |
| tools | coda_get_page_content | pageIdOrName | 2660e996c27d04bf1e63551dcf2f49e3414bb72b0a97bf7fce8220bd324b64bf |
| tools | coda_list_documents | description | 71001f60d122cd04f582806689df55db58e556c49e795cfe2006c2b06436ea07 |
| tools | coda_list_documents | query | 3327b3fff59e43d93c8a98177fb17ef6251f8317ed1678dfa0e4a71a89a0ddd4 |
| tools | coda_list_pages | description | 1a8a31861ee35219e4f5f8c8e509efd7987d5a01634fe30c4e33a8a15e534e5a |
| tools | coda_list_pages | docId | 4b9ffcb8819b499cd57463e3e4924724e339c33e09512dcc9abde242099ae041 |
| tools | coda_list_pages | limit | dae9aac415696897b6bf809a8667827bd19d2f208cbcf2604edbfbd76a008efd |
| tools | coda_list_pages | nextPageToken | 5e0ac137194647315f21041aa4015dcac246f338c92938f77b01f8b6b5a80e6c |
| tools | coda_peek_page | description | 7a20ab6508a28ca5ba7008abf98d712e28169db94ff7316f0c2b4b0920d2d2cc |
| tools | coda_peek_page | docId | 88dfaff1fc79e5925d00d140af6bea4710522da7c4a3552f9cabf6742d540031 |
| tools | coda_peek_page | numLines | 8ea4b7fa145c6b5c9f1fda9a7799f76910e69e71212b3f437176093668262ac7 |
| tools | coda_peek_page | pageIdOrName | 50a796ac4b6752c9ec6570e9ca6062a15ec7428a0af9baa93fa2c6f2deceada0 |
| tools | coda_rename_page | description | 037a2e1ce43e2a3eb82f6b3aa83f5e9dafdce96ffaa5186702482bf458a194b6 |
| tools | coda_rename_page | docId | 15a4d415486234c3dd1fda9950b465d5bc886abb98e870c59ada67d6e3e52d3c |
| tools | coda_rename_page | newName | 47633c3d0d36d0564492d812ff19826f72d7b172b3eacad87b98f8246491662a |
| tools | coda_rename_page | pageIdOrName | ffb5e62092ae083458b493ad20c66b6f1277f4a3bf8d35715baf351163449b8f |
| tools | coda_replace_page_content | description | 159be8ca055b41aafbe9770117c4f1579a454f2baaba9b20f33682d5273bcc5c |
| tools | coda_replace_page_content | content | d18f6633054b57d9534e835c3be08e87ef9588cb7127e43e4f0b51449683b75c |
| tools | coda_replace_page_content | docId | 275717187e2b1e8c33652fd85af2b65b81bf4e22580e0a8b905bede2cff0eca1 |
| tools | coda_replace_page_content | pageIdOrName | 54bbde434915298761a0e41ef26c250776e2129a4dc3e682586ca51f8bbc0c3b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
