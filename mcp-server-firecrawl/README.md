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


# What is mcp-server-firecrawl?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-firecrawl/3.7.4?logo=docker&logoColor=fff&label=3.7.4)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl)
[![PyPI](https://img.shields.io/badge/3.7.4-3775A9?logo=pypi&logoColor=fff&label=firecrawl-mcp)](https://github.com/mendableai/firecrawl-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-firecrawl&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIRECRAWL_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-firecrawl%3A3.7.4%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates Firecrawl for web scraping and data extraction.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from firecrawl-mcp original [sources](https://github.com/mendableai/firecrawl-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-firecrawl/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/charts/mcp-server-firecrawl/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure firecrawl-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-firecrawl scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `FIRECRAWL_API_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/mendableai/firecrawl-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-firecrawl&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIRECRAWL_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-firecrawl%3A3.7.4%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-firecrawl": {
        "env": {
          "FIRECRAWL_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "FIRECRAWL_API_KEY",
          "docker.io/acuvity/mcp-server-firecrawl:3.7.4"
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
    "acuvity-mcp-server-firecrawl": {
      "env": {
        "FIRECRAWL_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIRECRAWL_API_KEY",
        "docker.io/acuvity/mcp-server-firecrawl:3.7.4"
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
    "acuvity-mcp-server-firecrawl": {
      "env": {
        "FIRECRAWL_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIRECRAWL_API_KEY",
        "docker.io/acuvity/mcp-server-firecrawl:3.7.4"
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
    "acuvity-mcp-server-firecrawl": {
      "env": {
        "FIRECRAWL_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIRECRAWL_API_KEY",
        "docker.io/acuvity/mcp-server-firecrawl:3.7.4"
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
    "acuvity-mcp-server-firecrawl": {
      "env": {
        "FIRECRAWL_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "FIRECRAWL_API_KEY",
        "docker.io/acuvity/mcp-server-firecrawl:3.7.4"
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
        "env": {"FIRECRAWL_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","FIRECRAWL_API_KEY","docker.io/acuvity/mcp-server-firecrawl:3.7.4"]
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
- arguments: `run -i --rm --read-only -e FIRECRAWL_API_KEY docker.io/acuvity/mcp-server-firecrawl:3.7.4`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e FIRECRAWL_API_KEY docker.io/acuvity/mcp-server-firecrawl:3.7.4
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-firecrawl": {
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
    "acuvity-mcp-server-firecrawl": {
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
  - `FIRECRAWL_API_KEY` secret to be set as secrets.FIRECRAWL_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
````

Install with helm

```console
helm install mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
```

From there your MCP server mcp-server-firecrawl will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-firecrawl` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/charts/mcp-server-firecrawl/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>firecrawl_scrape</summary>

**Description**:

```

Scrape content from a single URL with advanced options. 
This is the most powerful, fastest and most reliable scraper tool, if available you should always default to using this tool for any web scraping needs.

**Best for:** Single page content extraction, when you know exactly which page contains the information.
**Not recommended for:** Multiple pages (use batch_scrape), unknown page (use search), structured data (use extract).
**Common mistakes:** Using scrape for a list of URLs (use batch_scrape instead). If batch scrape doesnt work, just use scrape and call it multiple times.
**Other Features:** Use 'branding' format to extract brand identity (colors, fonts, typography, spacing, UI components) for design analysis or style replication.
**Prompt Example:** "Get the content of the page at https://example.com."
**Usage Example:**
```json
{
  "name": "firecrawl_scrape",
  "arguments": {
    "url": "https://example.com",
    "formats": ["markdown"],
    "maxAge": 172800000
  }
}
```
**Performance:** Add maxAge parameter for 500% faster scrapes using cached data.
**Returns:** Markdown, HTML, or other formats as specified.


```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| actions | array | not set | No
| excludeTags | array | not set | No
| formats | array | not set | No
| includeTags | array | not set | No
| location | object | not set | No
| maxAge | number | not set | No
| mobile | boolean | not set | No
| onlyMainContent | boolean | not set | No
| parsers | array | not set | No
| proxy | string | not set | No
| removeBase64Images | boolean | not set | No
| skipTlsVerification | boolean | not set | No
| storeInCache | boolean | not set | No
| url | string | not set | Yes
| waitFor | number | not set | No
| zeroDataRetention | boolean | not set | No
</details>
<details>
<summary>firecrawl_map</summary>

**Description**:

```

Map a website to discover all indexed URLs on the site.

**Best for:** Discovering URLs on a website before deciding what to scrape; finding specific sections of a website.
**Not recommended for:** When you already know which specific URL you need (use scrape or batch_scrape); when you need the content of the pages (use scrape after mapping).
**Common mistakes:** Using crawl to discover URLs instead of map.
**Prompt Example:** "List all URLs on example.com."
**Usage Example:**
```json
{
  "name": "firecrawl_map",
  "arguments": {
    "url": "https://example.com"
  }
}
```
**Returns:** Array of URLs found on the site.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreQueryParameters | boolean | not set | No
| includeSubdomains | boolean | not set | No
| limit | number | not set | No
| search | string | not set | No
| sitemap | string | not set | No
| url | string | not set | Yes
</details>
<details>
<summary>firecrawl_search</summary>

**Description**:

```

Search the web and optionally extract content from search results. This is the most powerful web search tool available, and if available you should always default to using this tool for any web search needs.

The query also supports search operators, that you can use if needed to refine the search:
| Operator | Functionality | Examples |
---|-|-|
| `""` | Non-fuzzy matches a string of text | `"Firecrawl"`
| `-` | Excludes certain keywords or negates other operators | `-bad`, `-site:firecrawl.dev`
| `site:` | Only returns results from a specified website | `site:firecrawl.dev`
| `inurl:` | Only returns results that include a word in the URL | `inurl:firecrawl`
| `allinurl:` | Only returns results that include multiple words in the URL | `allinurl:git firecrawl`
| `intitle:` | Only returns results that include a word in the title of the page | `intitle:Firecrawl`
| `allintitle:` | Only returns results that include multiple words in the title of the page | `allintitle:firecrawl playground`
| `related:` | Only returns results that are related to a specific domain | `related:firecrawl.dev`
| `imagesize:` | Only returns images with exact dimensions | `imagesize:1920x1080`
| `larger:` | Only returns images larger than specified dimensions | `larger:1920x1080`

**Best for:** Finding specific information across multiple websites, when you don't know which website has the information; when you need the most relevant content for a query.
**Not recommended for:** When you need to search the filesystem. When you already know which website to scrape (use scrape); when you need comprehensive coverage of a single website (use map or crawl.
**Common mistakes:** Using crawl or map for open-ended questions (use search instead).
**Prompt Example:** "Find the latest research papers on AI published in 2023."
**Sources:** web, images, news, default to web unless needed images or news.
**Scrape Options:** Only use scrapeOptions when you think it is absolutely necessary. When you do so default to a lower limit to avoid timeouts, 5 or lower.
**Optimal Workflow:** Search first using firecrawl_search without formats, then after fetching the results, use the scrape tool to get the content of the relevantpage(s) that you want to scrape

**Usage Example without formats (Preferred):**
```json
{
  "name": "firecrawl_search",
  "arguments": {
    "query": "top AI companies",
    "limit": 5,
    "sources": [
      "web"
    ]
  }
}
```
**Usage Example with formats:**
```json
{
  "name": "firecrawl_search",
  "arguments": {
    "query": "latest AI research papers 2023",
    "limit": 5,
    "lang": "en",
    "country": "us",
    "sources": [
      "web",
      "images",
      "news"
    ],
    "scrapeOptions": {
      "formats": ["markdown"],
      "onlyMainContent": true
    }
  }
}
```
**Returns:** Array of search results (with optional scraped content).

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| enterprise | array | not set | No
| filter | string | not set | No
| limit | number | not set | No
| location | string | not set | No
| query | string | not set | Yes
| scrapeOptions | object | not set | No
| sources | array | not set | No
| tbs | string | not set | No
</details>
<details>
<summary>firecrawl_crawl</summary>

**Description**:

```

 Starts a crawl job on a website and extracts content from all pages.
 
 **Best for:** Extracting content from multiple related pages, when you need comprehensive coverage.
 **Not recommended for:** Extracting content from a single page (use scrape); when token limits are a concern (use map + batch_scrape); when you need fast results (crawling can be slow).
 **Warning:** Crawl responses can be very large and may exceed token limits. Limit the crawl depth and number of pages, or use map + batch_scrape for better control.
 **Common mistakes:** Setting limit or maxDiscoveryDepth too high (causes token overflow) or too low (causes missing pages); using crawl for a single page (use scrape instead). Using a /* wildcard is not recommended.
 **Prompt Example:** "Get all blog posts from the first two levels of example.com/blog."
 **Usage Example:**
 ```json
 {
   "name": "firecrawl_crawl",
   "arguments": {
     "url": "https://example.com/blog/*",
     "maxDiscoveryDepth": 5,
     "limit": 20,
     "allowExternalLinks": false,
     "deduplicateSimilarURLs": true,
     "sitemap": "include"
   }
 }
 ```
 **Returns:** Operation ID for status checking; use firecrawl_check_crawl_status to check progress.
 
 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowExternalLinks | boolean | not set | No
| allowSubdomains | boolean | not set | No
| crawlEntireDomain | boolean | not set | No
| deduplicateSimilarURLs | boolean | not set | No
| delay | number | not set | No
| excludePaths | array | not set | No
| ignoreQueryParameters | boolean | not set | No
| includePaths | array | not set | No
| limit | number | not set | No
| maxConcurrency | number | not set | No
| maxDiscoveryDepth | number | not set | No
| prompt | string | not set | No
| scrapeOptions | object | not set | No
| sitemap | string | not set | No
| url | string | not set | Yes
| webhook | any | not set | No
</details>
<details>
<summary>firecrawl_check_crawl_status</summary>

**Description**:

```

Check the status of a crawl job.

**Usage Example:**
```json
{
  "name": "firecrawl_check_crawl_status",
  "arguments": {
    "id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```
**Returns:** Status and progress of the crawl job, including results if available.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>
<details>
<summary>firecrawl_extract</summary>

**Description**:

```

Extract structured information from web pages using LLM capabilities. Supports both cloud AI and self-hosted LLM extraction.

**Best for:** Extracting specific structured data like prices, names, details from web pages.
**Not recommended for:** When you need the full content of a page (use scrape); when you're not looking for specific structured data.
**Arguments:**
- urls: Array of URLs to extract information from
- prompt: Custom prompt for the LLM extraction
- schema: JSON schema for structured data extraction
- allowExternalLinks: Allow extraction from external links
- enableWebSearch: Enable web search for additional context
- includeSubdomains: Include subdomains in extraction
**Prompt Example:** "Extract the product name, price, and description from these product pages."
**Usage Example:**
```json
{
  "name": "firecrawl_extract",
  "arguments": {
    "urls": ["https://example.com/page1", "https://example.com/page2"],
    "prompt": "Extract product information including name, price, and description",
    "schema": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "price": { "type": "number" },
        "description": { "type": "string" }
      },
      "required": ["name", "price"]
    },
    "allowExternalLinks": false,
    "enableWebSearch": false,
    "includeSubdomains": false
  }
}
```
**Returns:** Extracted structured data as defined by your schema.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowExternalLinks | boolean | not set | No
| enableWebSearch | boolean | not set | No
| includeSubdomains | boolean | not set | No
| prompt | string | not set | No
| schema | object | not set | No
| urls | array | not set | Yes
</details>
<details>
<summary>firecrawl_agent</summary>

**Description**:

```

Autonomous web data gathering agent. Describe what data you want, and the agent searches, navigates, and extracts it from anywhere on the web.

**Best for:** Complex data gathering tasks where you don't know the exact URLs; research tasks requiring multiple sources; finding data in hard-to-reach places.
**Not recommended for:** Simple single-page scraping (use scrape); when you already know the exact URL (use scrape or extract).
**Key advantages over extract:**
- No URLs required - just describe what you need
- Autonomously searches and navigates the web
- Faster and more cost-effective for complex tasks
- Higher reliability for varied queries

**Arguments:**
- prompt: Natural language description of the data you want (required, max 10,000 characters)
- urls: Optional array of URLs to focus the agent on specific pages
- schema: Optional JSON schema for structured output

**Prompt Example:** "Find the founders of Firecrawl and their backgrounds"
**Usage Example (no URLs):**
```json
{
  "name": "firecrawl_agent",
  "arguments": {
    "prompt": "Find the top 5 AI startups founded in 2024 and their funding amounts",
    "schema": {
      "type": "object",
      "properties": {
        "startups": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "funding": { "type": "string" },
              "founded": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```
**Usage Example (with URLs):**
```json
{
  "name": "firecrawl_agent",
  "arguments": {
    "urls": ["https://docs.firecrawl.dev", "https://firecrawl.dev/pricing"],
    "prompt": "Compare the features and pricing information from these pages"
  }
}
```
**Returns:** Extracted data matching your prompt/schema, plus credits used.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt | string | not set | Yes
| schema | object | not set | No
| urls | array | not set | No
</details>
<details>
<summary>firecrawl_agent_status</summary>

**Description**:

```

Check the status of an agent job.

**Usage Example:**
```json
{
  "name": "firecrawl_agent_status",
  "arguments": {
    "id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```
**Possible statuses:**
- processing: Agent is still working
- completed: Extraction finished successfully
- failed: An error occurred

**Returns:** Status, progress, and results (if completed) of the agent job.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | firecrawl_agent | description | b02374bb87d60f67a3b73d30a8934279dde6bdc56f4318b0bae77bf8ddc1ea1c |
| tools | firecrawl_agent_status | description | b7ccb553a02a7a5fc6f2966aea638ee736f829b60989737a5022a8eaa4ccf3ea |
| tools | firecrawl_check_crawl_status | description | b203ead94aae907fe82506e9a27415571fcdcfc37443f3e9139e675032de1ca7 |
| tools | firecrawl_crawl | description | dd06ade8893a0fdfb59db62309f483714fd4ef9075660e50830435d531df7cb7 |
| tools | firecrawl_extract | description | 4d1e1af8ded9e112fa750ae6538321861de40150a5de14774d30920ef61cfe4a |
| tools | firecrawl_map | description | f1889673ef441a4485805204021eebd8d373c2ac49871d2ade46a7cd70c422ba |
| tools | firecrawl_scrape | description | ee58f6ff53532d74731be3215d8922c8cec1f0875f994667bd8b5b8450bda948 |
| tools | firecrawl_search | description | dd960026a92d9b910741ea123119ef6783776ce19c28c8d67620adcc05b1ab0f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
