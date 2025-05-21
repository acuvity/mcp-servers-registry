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


# What is mcp-server-webflow?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-webflow/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-webflow/0.5.1?logo=docker&logoColor=fff&label=0.5.1)](https://hub.docker.com/r/acuvity/mcp-server-webflow)
[![PyPI](https://img.shields.io/badge/0.5.1-3775A9?logo=pypi&logoColor=fff&label=webflow-mcp-server)](https://github.com/webflow/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-webflow/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-webflow&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22WEBFLOW_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-webflow%3A0.5.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Enables AI agents to interact with Webflow APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from webflow-mcp-server original [sources](https://github.com/webflow/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-webflow/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/charts/mcp-server-webflow/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure webflow-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-webflow scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `WEBFLOW_TOKEN` required to be set

For more information and extra configuration you can consult the [package](https://github.com/webflow/mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-webflow&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22WEBFLOW_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-webflow%3A0.5.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-webflow": {
        "env": {
          "WEBFLOW_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "WEBFLOW_TOKEN",
          "docker.io/acuvity/mcp-server-webflow:0.5.1"
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
    "acuvity-mcp-server-webflow": {
      "env": {
        "WEBFLOW_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "WEBFLOW_TOKEN",
        "docker.io/acuvity/mcp-server-webflow:0.5.1"
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
    "acuvity-mcp-server-webflow": {
      "env": {
        "WEBFLOW_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "WEBFLOW_TOKEN",
        "docker.io/acuvity/mcp-server-webflow:0.5.1"
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
    "acuvity-mcp-server-webflow": {
      "env": {
        "WEBFLOW_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "WEBFLOW_TOKEN",
        "docker.io/acuvity/mcp-server-webflow:0.5.1"
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
    "acuvity-mcp-server-webflow": {
      "env": {
        "WEBFLOW_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "WEBFLOW_TOKEN",
        "docker.io/acuvity/mcp-server-webflow:0.5.1"
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
        "env": {"WEBFLOW_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","WEBFLOW_TOKEN","docker.io/acuvity/mcp-server-webflow:0.5.1"]
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
- arguments: `run -i --rm --read-only -e WEBFLOW_TOKEN docker.io/acuvity/mcp-server-webflow:0.5.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e WEBFLOW_TOKEN docker.io/acuvity/mcp-server-webflow:0.5.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-webflow": {
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
    "acuvity-mcp-server-webflow": {
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
  - `WEBFLOW_TOKEN` secret to be set as secrets.WEBFLOW_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
````

Install with helm

```console
helm install mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
```

From there your MCP server mcp-server-webflow will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-webflow` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/charts/mcp-server-webflow/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (26)
<details>
<summary>collections_list</summary>

**Description**:

```
List all CMS collections in a site. Returns collection metadata including IDs, names, and schemas.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>collections_get</summary>

**Description**:

```
Get detailed information about a specific CMS collection including its schema and field definitions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
</details>
<details>
<summary>collections_create</summary>

**Description**:

```
Create a new CMS collection in a site with specified name and schema.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request | object | not set | Yes
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>collection_fields_create_static</summary>

**Description**:

```
Create a new static field in a CMS collection (e.g., text, number, date, etc.).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collection_fields_create_option</summary>

**Description**:

```
Create a new option field in a CMS collection with predefined choices.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collection_fields_create_reference</summary>

**Description**:

```
Create a new reference field in a CMS collection that links to items in another collection.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collection_fields_update</summary>

**Description**:

```
Update properties of an existing field in a CMS collection.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| field_id | string | Unique identifier for the Field. | Yes
| request | object | Request schema to update collection field metadata. | Yes
</details>
<details>
<summary>collections_items_create_item_live</summary>

**Description**:

```
Create and publish new items in a CMS collection directly to the live site.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_update_items_live</summary>

**Description**:

```
Update and publish existing items in a CMS collection directly to the live site.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_list_items</summary>

**Description**:

```
List items in a CMS collection with optional filtering and sorting.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cmsLocaleId | string | Unique identifier for the locale of the CMS Item. | No
| collection_id | string | Unique identifier for the Collection. | Yes
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| name | string | Name of the field. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| slug | string | URL structure of the Item in your site. Note: Updates to an item slug will break all links referencing the old slug. | No
| sortBy | string | Field to sort the items by. Allowed values: lastPublished, name, slug. | No
| sortOrder | string | Order to sort the items by. Allowed values: asc, desc. | No
</details>
<details>
<summary>collections_items_create_item</summary>

**Description**:

```
Create new items in a CMS collection as drafts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | not set | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_update_items</summary>

**Description**:

```
Update existing items in a CMS collection as drafts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_publish_items</summary>

**Description**:

```
Publish draft items in a CMS collection to make them live.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| itemIds | array | Array of item IDs to be published. | Yes
</details>
<details>
<summary>collections_items_delete_item</summary>

**Description**:

```
Delete an item in a CMS collection. Items will only be deleted in the primary locale unless a cmsLocaleId is included in the request. 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cmsLocaleIds | string | Unique identifier for the locale of the CMS Item. | No
| collection_id | string | Unique identifier for the Collection. | Yes
| itemId | string | Item ID to be deleted. | Yes
</details>
<details>
<summary>pages_list</summary>

**Description**:

```
List all pages within a site. Returns page metadata including IDs, titles, and slugs.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| site_id | string | The site’s unique ID, used to list its pages. | Yes
</details>
<details>
<summary>pages_get_metadata</summary>

**Description**:

```
Get metadata for a specific page including SEO settings, Open Graph data, and page status (draft/published).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>pages_update_page_settings</summary>

**Description**:

```
Update page settings including SEO metadata, Open Graph data, slug, and publishing status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | object | not set | Yes
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>pages_get_content</summary>

**Description**:

```
Get the content structure and data for a specific page including all elements and their properties.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>pages_update_static_content</summary>

**Description**:

```
Update content on a static page in secondary locales by modifying text nodes and property overrides.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | Yes
| nodes | array | not set | Yes
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>site_registered_scripts_list</summary>

**Description**:

```
List all registered scripts for a site. To apply a script to a site or page, first register it via the Register Script endpoints, then apply it using the relevant Site or Page endpoints.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>site_applied_scripts_list</summary>

**Description**:

```
Get all scripts applied to a site by the App. To apply a script to a site or page, first register it via the Register Script endpoints, then apply it using the relevant Site or Page endpoints.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>add_inline_site_script</summary>

**Description**:

```
Register an inline script for a site. Inline scripts are limited to 2000 characters. 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request | object | Request schema to register an inline script for a site. | Yes
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>delete_all_site_scripts</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | not set | Yes
</details>
<details>
<summary>sites_list</summary>

**Description**:

```
List all sites accessible to the authenticated user. Returns basic site information including site ID, name, and last published date.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>sites_get</summary>

**Description**:

```
Get detailed information about a specific site including its settings, domains, and publishing status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>sites_publish</summary>

**Description**:

```
Publish a site to specified domains. This will make the latest changes live on the specified domains.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customDomains | array | Array of custom domains to publish the site to. | No
| publishToWebflowSubdomain | boolean | Whether to publish to the Webflow subdomain. | No
| site_id | string | Unique identifier for the site. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_inline_site_script | description | da4ad46026aff6c1441513d12afdfd7f0d735ac69b77f117abe1acaea4ac1a95 |
| tools | add_inline_site_script | request | aa102df180b52825def499e4fe43678565faa9b5d49fb7f252c89e645f251e25 |
| tools | add_inline_site_script | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | collection_fields_create_option | description | 62a672e665513acde53ce1a510df12fc2e7f7689f9a3bb18fd1bd15f224fe285 |
| tools | collection_fields_create_option | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_create_reference | description | bef40d710120c44326c891a239d241cd71673f253f09f04272f442d865e80957 |
| tools | collection_fields_create_reference | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_create_static | description | ba8c9655fc6d1fcdca20a3ccb99563c489f0926a60791c733e24085e50f8005c |
| tools | collection_fields_create_static | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_update | description | 9b2bd3f2e812c999d93db7c3a6fe04f90a5285e1d74144030b69deaf12270ae9 |
| tools | collection_fields_update | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_update | field_id | ae4d9ca9be1202b3aa55e265518c58fe345fbb73d09b64ad2a02f91fd4a47bb4 |
| tools | collection_fields_update | request | 8c2ca159b99a3327d48f1a044b8a51d937b17363e29fddc22112f521bdf43648 |
| tools | collections_create | description | 6f8c2d10f17e8b3bf111d0fa51c9965a11b554b0ca3ced2d5efc39b3e425d1e2 |
| tools | collections_create | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | collections_get | description | 8dc2b780368dc65efbc4a296c22a24e8574001aeb4ae3e24d7eef434ba11a615 |
| tools | collections_get | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_create_item | description | 7e4ba46da466f9cbb3c98b14775d0aaa16bc699072bb5c6e1fe414137689a26c |
| tools | collections_items_create_item_live | description | c34348e4d6324531de00ad31fb0cd8853047260672eaa9af5f19a3c13af7d1af |
| tools | collections_items_create_item_live | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_delete_item | description | 1a0c3cf174193bce310f0aedfa97e5e361a05cd452634df04c590764842d21ba |
| tools | collections_items_delete_item | cmsLocaleIds | 2c80366881f730cbfdd6a5a84e297d080fb9b122f5d862e7d93907291ddf73c3 |
| tools | collections_items_delete_item | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_delete_item | itemId | 93b52bccace2b195765c4741576378311e1a6dc3a7e9d99a54eb3d2f38d4db83 |
| tools | collections_items_list_items | description | 53f750ec5891295e8c14703fde1be5ef65153477a59d56e58d5affbb11cc98b3 |
| tools | collections_items_list_items | cmsLocaleId | 2c80366881f730cbfdd6a5a84e297d080fb9b122f5d862e7d93907291ddf73c3 |
| tools | collections_items_list_items | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_list_items | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | collections_items_list_items | name | 7d2df8838eff32f65b6f7c489a378fa2cd3644d368476d0e47fc16ed5766e92c |
| tools | collections_items_list_items | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | collections_items_list_items | slug | 49d7fede96b1d9e1ba74f82ac8c8ba4042b748b58f164bc5c27108a4a416a1c4 |
| tools | collections_items_list_items | sortBy | 5eaec853a1daebd92184126702156f4a18f7c2c5570b730ce0fef3e9f931ba98 |
| tools | collections_items_list_items | sortOrder | ba6d082117b479734c4dce7f7201f26a31aa5144bd51b840f64b45ade5ff95e9 |
| tools | collections_items_publish_items | description | 770b23bbb398e3161554349f34af62684369a285f1cca171aaa54695a88019fd |
| tools | collections_items_publish_items | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_publish_items | itemIds | 41b108aec95f8e6903de0af0b611968f0b934721ad353e47297cc1d05a027074 |
| tools | collections_items_update_items | description | 0c2b38b1977b3b0b275c9e3e7896c55b7061575e062f74843564711490ea9c62 |
| tools | collections_items_update_items | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_update_items_live | description | 00f101eab1a826bbc3c594a42fae7948d4175cbbb8946dae7ea4111d7e439566 |
| tools | collections_items_update_items_live | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_list | description | 180e254b26e6204a9c607ca35cd5b77bd5d0f3b2d6421e0cb1308a9628d3e032 |
| tools | collections_list | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | delete_all_site_scripts | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | pages_get_content | description | effc85cda69758932ff15da05b2058f56f8c281d4ec570932e4e18e744ef8a46 |
| tools | pages_get_content | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | pages_get_content | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_get_content | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | pages_get_content | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | pages_get_metadata | description | fe6591dc6226af8c68550b3fa1fc33ca48aefe0a391030ccdfa42fd8e2e826c5 |
| tools | pages_get_metadata | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_get_metadata | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | pages_list | description | acdb1a75cfe59d3c84d2d4fe37a0cf0d16d204b927253fd8a2039a4ec375424c |
| tools | pages_list | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | pages_list | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_list | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | pages_list | site_id | 1add0001e1327e44b502de21faf1f7d001ad50c2d3ac250ed54e83c650f66a27 |
| tools | pages_update_page_settings | description | cb85ebb21f2a2d5d3a0a85614f3095d8a3ea9cf88518004e1cfd4cc913962624 |
| tools | pages_update_page_settings | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_update_page_settings | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | pages_update_static_content | description | b2acdb4ed19d91fb06e288f976ba927547715bdfc6dc30604cdb138f43ce5ee3 |
| tools | pages_update_static_content | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_update_static_content | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | site_applied_scripts_list | description | 7f84d7cba120774d342ab8f4cba857c2bfe0dd1c6be3ccd367abca9c159e810a |
| tools | site_applied_scripts_list | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | site_registered_scripts_list | description | 7ff87b19559b7c7f4977b7d9b0a368dd23d08f48adacd2b8093672bd4e6acc34 |
| tools | site_registered_scripts_list | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | sites_get | description | 5b82168721ca142a8df5b4bca54e4f6447d518a729e62291e0d8bbd8a13a5cb6 |
| tools | sites_get | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | sites_list | description | 35adeea1cc0ffb3caf7a994028ed2cd993f7a465721bd59263558b1475bc113f |
| tools | sites_publish | description | 3d55371074f85622832e649d4e5c38b88ed2643f12ee1172d5116c3960faa4f1 |
| tools | sites_publish | customDomains | 18fbd2084e46f0039226e64c99f75c9250c1f422135d86eb7f67a794d9de7ede |
| tools | sites_publish | publishToWebflowSubdomain | f5362553c613f1672e8cd06f80b846ce5c5c234243670b590fce486cea5d89c4 |
| tools | sites_publish | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
