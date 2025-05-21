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


# What is mcp-server-oxylabs?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-oxylabs/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-oxylabs/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-oxylabs)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=oxylabs-mcp)](https://github.com/oxylabs/oxylabs-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-oxylabs/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-oxylabs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OXYLABS_PASSWORD%22%2C%22-e%22%2C%22OXYLABS_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-oxylabs%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Scrapes web data for AI applications using the Model Context Protocol.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from oxylabs-mcp original [sources](https://github.com/oxylabs/oxylabs-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-oxylabs/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/charts/mcp-server-oxylabs/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure oxylabs-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-oxylabs scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `OXYLABS_PASSWORD` required to be set
  - `OXYLABS_USERNAME` required to be set

For more information and extra configuration you can consult the [package](https://github.com/oxylabs/oxylabs-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-oxylabs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OXYLABS_PASSWORD%22%2C%22-e%22%2C%22OXYLABS_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-oxylabs%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-oxylabs": {
        "env": {
          "OXYLABS_PASSWORD": "TO_BE_SET",
          "OXYLABS_USERNAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "OXYLABS_PASSWORD",
          "-e",
          "OXYLABS_USERNAME",
          "docker.io/acuvity/mcp-server-oxylabs:0.2.0"
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
    "acuvity-mcp-server-oxylabs": {
      "env": {
        "OXYLABS_PASSWORD": "TO_BE_SET",
        "OXYLABS_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OXYLABS_PASSWORD",
        "-e",
        "OXYLABS_USERNAME",
        "docker.io/acuvity/mcp-server-oxylabs:0.2.0"
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
    "acuvity-mcp-server-oxylabs": {
      "env": {
        "OXYLABS_PASSWORD": "TO_BE_SET",
        "OXYLABS_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OXYLABS_PASSWORD",
        "-e",
        "OXYLABS_USERNAME",
        "docker.io/acuvity/mcp-server-oxylabs:0.2.0"
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
    "acuvity-mcp-server-oxylabs": {
      "env": {
        "OXYLABS_PASSWORD": "TO_BE_SET",
        "OXYLABS_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OXYLABS_PASSWORD",
        "-e",
        "OXYLABS_USERNAME",
        "docker.io/acuvity/mcp-server-oxylabs:0.2.0"
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
    "acuvity-mcp-server-oxylabs": {
      "env": {
        "OXYLABS_PASSWORD": "TO_BE_SET",
        "OXYLABS_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "OXYLABS_PASSWORD",
        "-e",
        "OXYLABS_USERNAME",
        "docker.io/acuvity/mcp-server-oxylabs:0.2.0"
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
        "env": {"OXYLABS_PASSWORD":"TO_BE_SET","OXYLABS_USERNAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","OXYLABS_PASSWORD","-e","OXYLABS_USERNAME","docker.io/acuvity/mcp-server-oxylabs:0.2.0"]
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
- arguments: `run -i --rm --read-only -e OXYLABS_PASSWORD -e OXYLABS_USERNAME docker.io/acuvity/mcp-server-oxylabs:0.2.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e OXYLABS_PASSWORD -e OXYLABS_USERNAME docker.io/acuvity/mcp-server-oxylabs:0.2.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-oxylabs": {
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
    "acuvity-mcp-server-oxylabs": {
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
  - `OXYLABS_PASSWORD` secret to be set as secrets.OXYLABS_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `OXYLABS_USERNAME` environment variable to be set by env.OXYLABS_USERNAME

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
````

Install with helm

```console
helm install mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
```

From there your MCP server mcp-server-oxylabs will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-oxylabs` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/charts/mcp-server-oxylabs/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (4)
<details>
<summary>universal_scraper</summary>

**Description**:

```
Get a content of any webpage.

    Supports browser rendering, parsing of certain webpages
    and different output formats.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| url | string | Website url to scrape. | Yes
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>
<details>
<summary>google_search_scraper</summary>

**Description**:

```
Scrape Google Search results.

    Supports content parsing, different user agent types, pagination,
    domain, geolocation, locale parameters and different output formats.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ad_mode | boolean | If true will use the Google Ads source optimized for the paid ads. | No
| domain | string | 
        Domain localization for Google.
        Use country top level domains.
        For example:
            - 'co.uk' for United Kingdom
            - 'us' for United States
            - 'fr' for France
         | No
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| limit | integer | Number of results to retrieve in each page. | No
| locale | string | 
        Set 'Accept-Language' header value which changes your Google search page web interface language.
        Examples:
            - 'en-US' for English, United States
            - 'de-AT' for German, Austria
            - 'fr-FR' for French, France
         | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| pages | integer | Number of pages to retrieve. | No
| parse | boolean | Should result be parsed. If the result is not parsed, the output_format parameter is applied. | No
| query | string | URL-encoded keyword to search for. | Yes
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| start_page | integer | Starting page number. | No
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>
<details>
<summary>amazon_search_scraper</summary>

**Description**:

```
Scrape Amazon search results.

    Supports content parsing, different user agent types, pagination,
    domain, geolocation, locale parameters and different output formats.
    Supports Amazon specific parameters such as category id, merchant id, currency.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category_id | string | Search for items in a particular browse node (product category). | No
| currency | string | Currency that will be used to display the prices. | No
| domain | string | 
        Domain localization for Google.
        Use country top level domains.
        For example:
            - 'co.uk' for United Kingdom
            - 'us' for United States
            - 'fr' for France
         | No
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| locale | string | 
        Set 'Accept-Language' header value which changes your Google search page web interface language.
        Examples:
            - 'en-US' for English, United States
            - 'de-AT' for German, Austria
            - 'fr-FR' for French, France
         | No
| merchant_id | string | Search for items sold by a particular seller. | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| pages | integer | Number of pages to retrieve. | No
| parse | boolean | Should result be parsed. If the result is not parsed, the output_format parameter is applied. | No
| query | string | Keyword to search for. | Yes
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| start_page | integer | Starting page number. | No
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>
<details>
<summary>amazon_product_scraper</summary>

**Description**:

```
Scrape Amazon products.

    Supports content parsing, different user agent types, domain,
    geolocation, locale parameters and different output formats.
    Supports Amazon specific parameters such as currency and getting
    more accurate pricing data with auto select variant.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| autoselect_variant | boolean | To get accurate pricing/buybox data, set this parameter to true. | No
| currency | string | Currency that will be used to display the prices. | No
| domain | string | 
        Domain localization for Google.
        Use country top level domains.
        For example:
            - 'co.uk' for United Kingdom
            - 'us' for United States
            - 'fr' for France
         | No
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| locale | string | 
        Set 'Accept-Language' header value which changes your Google search page web interface language.
        Examples:
            - 'en-US' for English, United States
            - 'de-AT' for German, Austria
            - 'fr-FR' for French, France
         | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| parse | boolean | Should result be parsed. If the result is not parsed, the output_format parameter is applied. | No
| query | string | Keyword to search for. | Yes
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | amazon_product_scraper | description | 556ffee33f9b5f0f3da719d7b1b7c37fa398d92b63ad77bfbc024922468e2594 |
| tools | amazon_product_scraper | autoselect_variant | 3578e27b85b918f331e2cb209a684c24839013acd3eaf037f6ba46680214118c |
| tools | amazon_product_scraper | currency | aa5edb7592bad79e700e4134bdfeb65bf2b6c96c81ac459cc1b8d9197101f1e4 |
| tools | amazon_product_scraper | domain | dbd1f8b171d5449998fb7d55dbc8f3baf6867aec480ff864799d805a4563d142 |
| tools | amazon_product_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | amazon_product_scraper | locale | cdbb6d79df927f48d9866b4ac1d085c581cf4f1286fa9b2332be8650326d8079 |
| tools | amazon_product_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | amazon_product_scraper | parse | c27cc9870b8d21da98e8a4a1efc1aeed03266a9adec16794037c90a0c4b25e97 |
| tools | amazon_product_scraper | query | 2b7bab00754c254fbe9efbf66ea830cb4573faeea75fdbd269801084ef67b584 |
| tools | amazon_product_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | amazon_product_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |
| tools | amazon_search_scraper | description | b026096a4c93afe5c9ab78ec43196cc26c0325f5c7d36e637e4f09a1651e3dbf |
| tools | amazon_search_scraper | category_id | 384916ff38c65e7481cc6da4e72d0bb534aafd6b5d10246966301238ae8eb1ba |
| tools | amazon_search_scraper | currency | aa5edb7592bad79e700e4134bdfeb65bf2b6c96c81ac459cc1b8d9197101f1e4 |
| tools | amazon_search_scraper | domain | dbd1f8b171d5449998fb7d55dbc8f3baf6867aec480ff864799d805a4563d142 |
| tools | amazon_search_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | amazon_search_scraper | locale | cdbb6d79df927f48d9866b4ac1d085c581cf4f1286fa9b2332be8650326d8079 |
| tools | amazon_search_scraper | merchant_id | 29666bfc6be92abb60838bfef609ea8f0a2841ad2121b9ae8033a1cc6544ff8a |
| tools | amazon_search_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | amazon_search_scraper | pages | 6db2005db03ae818a014763c6edf9ca97bc018de88b4b7d0941dc0fb8b672946 |
| tools | amazon_search_scraper | parse | c27cc9870b8d21da98e8a4a1efc1aeed03266a9adec16794037c90a0c4b25e97 |
| tools | amazon_search_scraper | query | 2b7bab00754c254fbe9efbf66ea830cb4573faeea75fdbd269801084ef67b584 |
| tools | amazon_search_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | amazon_search_scraper | start_page | 8d3ebdba8acecea8bc50bd6d0b07311cef7fe1ce5f009a0f1be75817c6d8eaef |
| tools | amazon_search_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |
| tools | google_search_scraper | description | 29fbda527f73d022b8ce16fa2cefa7154cdef35b6facfb5d0ec8e274e72a8d82 |
| tools | google_search_scraper | ad_mode | b461196e920ee39fec41727d81c88bb9a88f0fd6457c506a7b77affe3908f294 |
| tools | google_search_scraper | domain | dbd1f8b171d5449998fb7d55dbc8f3baf6867aec480ff864799d805a4563d142 |
| tools | google_search_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | google_search_scraper | limit | 753cb86d3a3ce07de849c5bda9b324700c07e63071cd056a178c575496e0e268 |
| tools | google_search_scraper | locale | cdbb6d79df927f48d9866b4ac1d085c581cf4f1286fa9b2332be8650326d8079 |
| tools | google_search_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | google_search_scraper | pages | 6db2005db03ae818a014763c6edf9ca97bc018de88b4b7d0941dc0fb8b672946 |
| tools | google_search_scraper | parse | c27cc9870b8d21da98e8a4a1efc1aeed03266a9adec16794037c90a0c4b25e97 |
| tools | google_search_scraper | query | 86f841b07fc2d38c87a89cd644f2e5a3a1a640855ad46e2a1c57c2d4df7cb1d8 |
| tools | google_search_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | google_search_scraper | start_page | 8d3ebdba8acecea8bc50bd6d0b07311cef7fe1ce5f009a0f1be75817c6d8eaef |
| tools | google_search_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |
| tools | universal_scraper | description | f17aff38c8d58bd300f276435edd6230f7a92afb25aa1fcf5e5ba10dd0cb237b |
| tools | universal_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | universal_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | universal_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | universal_scraper | url | d0959362daefa321a0e2cac5ca3653682f65d5e25d22b5c30e9fd965f8b3d7e4 |
| tools | universal_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
