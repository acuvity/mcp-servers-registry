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


# What is mcp-server-tavily?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-tavily/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-tavily/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-tavily)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=tavily-mcp)](https://github.com/tavily-ai/tavily-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-tavily&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22TAVILY_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-tavily%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates AI models with web search and data extraction tools.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from tavily-mcp original [sources](https://github.com/tavily-ai/tavily-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-tavily/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/charts/mcp-server-tavily/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure tavily-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Gardrails

### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

## Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/charts/mcp-server-tavily#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-tavily scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-tavily&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22TAVILY_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-tavily%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-tavily": {
        "env": {
          "TAVILY_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "TAVILY_API_KEY",
          "docker.io/acuvity/mcp-server-tavily:0.2.0"
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
    "acuvity-mcp-server-tavily": {
      "env": {
        "TAVILY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TAVILY_API_KEY",
        "docker.io/acuvity/mcp-server-tavily:0.2.0"
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
    "acuvity-mcp-server-tavily": {
      "env": {
        "TAVILY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TAVILY_API_KEY",
        "docker.io/acuvity/mcp-server-tavily:0.2.0"
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
    "acuvity-mcp-server-tavily": {
      "env": {
        "TAVILY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TAVILY_API_KEY",
        "docker.io/acuvity/mcp-server-tavily:0.2.0"
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
    "acuvity-mcp-server-tavily": {
      "env": {
        "TAVILY_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "TAVILY_API_KEY",
        "docker.io/acuvity/mcp-server-tavily:0.2.0"
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
        "env": {"TAVILY_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","TAVILY_API_KEY","docker.io/acuvity/mcp-server-tavily:0.2.0"]
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

**Environment variables and secrets:**
  - `TAVILY_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e TAVILY_API_KEY docker.io/acuvity/mcp-server-tavily:0.2.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e TAVILY_API_KEY docker.io/acuvity/mcp-server-tavily:0.2.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-tavily": {
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
    "acuvity-mcp-server-tavily": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Minibridge offers a host of additional features. For step-by-step guidance, please visit the wiki. And if anything’s unclear, don’t hesitate to reach out!

</details>

## 🛡️ Runtime security

**Guardrails:**

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

**Basic Authentication:**

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

Then you can connect through `http/sse` as usual given that you pass an `Authorization: Bearer supersecret` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `TAVILY_API_KEY` secret to be set as secrets.TAVILY_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-tavily --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-tavily --version 1.0.0
````

Install with helm

```console
helm install mcp-server-tavily oci://docker.io/acuvity/mcp-server-tavily --version 1.0.0
```

From there your MCP server mcp-server-tavily will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-tavily` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-tavily/charts/mcp-server-tavily/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (4)
<details>
<summary>tavily-search</summary>

**Description**:

```
A powerful web search tool that provides comprehensive, real-time results using Tavily's AI search engine. Returns relevant web content with customizable parameters for result count, content type, and domain filtering. Ideal for gathering current information, news, and detailed web content analysis.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| days | number | The number of days back from the current date to include in the search results. This specifies the time frame of data to be retrieved. Please note that this feature is only available when using the 'news' search topic | No
| exclude_domains | array | List of domains to specifically exclude, if the user asks to exclude a domain set this to the domain of the site | No
| include_domains | array | A list of domains to specifically include in the search results, if the user asks to search on specific sites set this to the domain of the site | No
| include_image_descriptions | boolean | Include a list of query-related images and their descriptions in the response | No
| include_images | boolean | Include a list of query-related images in the response | No
| include_raw_content | boolean | Include the cleaned and parsed HTML content of each search result | No
| max_results | number | The maximum number of search results to return | No
| query | string | Search query | Yes
| search_depth | string | The depth of the search. It can be 'basic' or 'advanced' | No
| time_range | string | The time range back from the current date to include in the search results. This feature is available for both 'general' and 'news' search topics | No
| topic | string | The category of the search. This will determine which of our agents will be used for the search | No
</details>
<details>
<summary>tavily-extract</summary>

**Description**:

```
A powerful web content extraction tool that retrieves and processes raw content from specified URLs, ideal for data collection, content analysis, and research tasks.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| extract_depth | string | Depth of extraction - 'basic' or 'advanced', if usrls are linkedin use 'advanced' or if explicitly told to use advanced | No
| include_images | boolean | Include a list of images extracted from the urls in the response | No
| urls | array | List of URLs to extract content from | Yes
</details>
<details>
<summary>tavily-crawl</summary>

**Description**:

```
A powerful web crawler that initiates a structured web crawl starting from a specified base URL. The crawler expands from that point like a tree, following internal links across pages. You can control how deep and wide it goes, and guide it to focus on specific sections of the site.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allow_external | boolean | Whether to allow following links that go to external domains | No
| categories | array | Filter URLs using predefined categories like documentation, blog, api, etc | No
| extract_depth | string | Advanced extraction retrieves more data, including tables and embedded content, with higher success but may increase latency | No
| limit | integer | Total number of links the crawler will process before stopping | No
| max_breadth | integer | Max number of links to follow per level of the tree (i.e., per page) | No
| max_depth | integer | Max depth of the crawl. Defines how far from the base URL the crawler can explore. | No
| query | string | Natural language instructions for the crawler | No
| select_domains | array | Regex patterns to select crawling to specific domains or subdomains (e.g., ^docs\.example\.com$) | No
| select_paths | array | Regex patterns to select only URLs with specific path patterns (e.g., /docs/.*, /api/v1.*) | No
| url | string | The root URL to begin the crawl | Yes
</details>
<details>
<summary>tavily-map</summary>

**Description**:

```
A powerful web mapping tool that creates a structured map of website URLs, allowing you to discover and analyze site structure, content organization, and navigation paths. Perfect for site audits, content discovery, and understanding website architecture.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allow_external | boolean | Whether to allow following links that go to external domains | No
| categories | array | Filter URLs using predefined categories like documentation, blog, api, etc | No
| limit | integer | Total number of links the crawler will process before stopping | No
| max_breadth | integer | Max number of links to follow per level of the tree (i.e., per page) | No
| max_depth | integer | Max depth of the mapping. Defines how far from the base URL the crawler can explore | No
| query | string | Natural language instructions for the crawler | No
| select_domains | array | Regex patterns to select crawling to specific domains or subdomains (e.g., ^docs\.example\.com$) | No
| select_paths | array | Regex patterns to select only URLs with specific path patterns (e.g., /docs/.*, /api/v1.*) | No
| url | string | The root URL to begin the mapping | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | tavily-crawl | description | 7c2d7aa75e8204e0a08a14e83ed9b12a4e6479f2636ceb88d713daf259879903 |
| tools | tavily-crawl | allow_external | 5b6ea50394b51a7d712179459ab77efcf5a631bb38d8a47a48516f6d8e615aff |
| tools | tavily-crawl | categories | f7f9439251205a3658776b9db1db48c42f00303b2abcf1574d366cf915d24b93 |
| tools | tavily-crawl | extract_depth | 096630325177fc094ce66f458b58601638b5e38fd50f76ca9add282398d73334 |
| tools | tavily-crawl | limit | ecbdbea1cc664963ec69474afb6c97c57f8ae2752e7128e5fe372b260d7bfbcf |
| tools | tavily-crawl | max_breadth | dcbf82b39474503318763a3c51cff9c45492d021c50fb9e778751ce3533b752c |
| tools | tavily-crawl | max_depth | 467655797e4e5cb1690ae09eeebded8f2a40f80858c6a29f2085772f21bc43c0 |
| tools | tavily-crawl | query | 11e23a677507385405b5498887e41ac4c10e4c36a877e771b24e84fd08020058 |
| tools | tavily-crawl | select_domains | fe6ef4a110db381eb61ff7715cde308a73be299daae35847216beb6ab7a5b975 |
| tools | tavily-crawl | select_paths | 9927be7ee8bc87bcd5363fc754d6b130585836614260a6ad12d88bc99b93fb15 |
| tools | tavily-crawl | url | e18f3f89f38fb901b6e29a35b6138a6accbbfd93a66fc1f421e88cf23f93331e |
| tools | tavily-extract | description | 1345839a938b55e787c772bab510514157f729812c5be9a3165598745c336c76 |
| tools | tavily-extract | extract_depth | aac7e32c9ba05a8437192cf699fffc5a5d83d6d1b3d4f9c4f05ed1faa1fca12e |
| tools | tavily-extract | include_images | ad583d5fbb5404a91cb49e4192e39a9d26339fb5d68afceb0fc5e15654981bda |
| tools | tavily-extract | urls | 694f6f90aa7a13847bf9171b0dd5d9b71c63dbedcc07a9b5f4c204e800640577 |
| tools | tavily-map | description | 42684fee294c35a65925358eb7a82a46be440ecb4cd7a5918f08a4ae7b863b97 |
| tools | tavily-map | allow_external | 5b6ea50394b51a7d712179459ab77efcf5a631bb38d8a47a48516f6d8e615aff |
| tools | tavily-map | categories | f7f9439251205a3658776b9db1db48c42f00303b2abcf1574d366cf915d24b93 |
| tools | tavily-map | limit | ecbdbea1cc664963ec69474afb6c97c57f8ae2752e7128e5fe372b260d7bfbcf |
| tools | tavily-map | max_breadth | dcbf82b39474503318763a3c51cff9c45492d021c50fb9e778751ce3533b752c |
| tools | tavily-map | max_depth | 36ca50681fc627198c6c9606543eeb2e0775126143cb7458bfe211bc010a004c |
| tools | tavily-map | query | 11e23a677507385405b5498887e41ac4c10e4c36a877e771b24e84fd08020058 |
| tools | tavily-map | select_domains | fe6ef4a110db381eb61ff7715cde308a73be299daae35847216beb6ab7a5b975 |
| tools | tavily-map | select_paths | 9927be7ee8bc87bcd5363fc754d6b130585836614260a6ad12d88bc99b93fb15 |
| tools | tavily-map | url | 258310dad942c2b11c0d5b4701b441abd7613970b7a7f459f44fbc995e1dfa6a |
| tools | tavily-search | description | 9f47afceed35d18060a38ec7ec7287d2a805f1f52a8f257884c13672b1d5a572 |
| tools | tavily-search | days | a5166a9dc7b62d6c568b6a86b91e09c679a6fa43d83f2a3178abc5e398f37d22 |
| tools | tavily-search | exclude_domains | 52be69be6c9b81c02d0bc9e24c258ee132e9b0e25272d2e32978693e1cadf94d |
| tools | tavily-search | include_domains | 73af97b9b4b062080f17117145d2c5914c6859636d6faad4c9cf4dbdb5af9b98 |
| tools | tavily-search | include_image_descriptions | 2d86753f90181581cd30756e1f4fdbf30390f83d7485fc09838fc729870ee4fc |
| tools | tavily-search | include_images | 9f36dc8d6377860e782b659d76bfd533ab811329689291f52e2023d091e40e28 |
| tools | tavily-search | include_raw_content | 1826a0e2ecbc2f9ca37a59a85de7f1790344b7e868e5a574d0eaaee9344af2c1 |
| tools | tavily-search | max_results | cfa10b88cdb3330162a8ace39416a69d6c6b39ceed8a521ade22bb77cc33c58c |
| tools | tavily-search | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | tavily-search | search_depth | 09738f4f04b8f023cdec623c20d07928a7e5f877faeecd3b0f9be1b73b6c5906 |
| tools | tavily-search | time_range | 83d9b8fd3353e59e36c6722f96bf9c010347d0df404ca8a0473925a02e7625a9 |
| tools | tavily-search | topic | 855a287cc86efc88b4371771009931d757ce54c794949c2e9d9e39db83d9c37c |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
