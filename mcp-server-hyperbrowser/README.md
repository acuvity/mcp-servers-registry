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


# What is mcp-server-hyperbrowser?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-hyperbrowser/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-hyperbrowser/1.0.25?logo=docker&logoColor=fff&label=1.0.25)](https://hub.docker.com/r/acuvity/mcp-server-hyperbrowser)
[![PyPI](https://img.shields.io/badge/1.0.25-3775A9?logo=pypi&logoColor=fff&label=hyperbrowser-mcp)](https://github.com/hyperbrowserai/mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-hyperbrowser/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-hyperbrowser&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HYPERBROWSER_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-hyperbrowser%3A1.0.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Scrapes, extracts data, and automates web page interactions.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from hyperbrowser-mcp original [sources](https://github.com/hyperbrowserai/mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-hyperbrowser/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-hyperbrowser/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-hyperbrowser/charts/mcp-server-hyperbrowser/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure hyperbrowser-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-hyperbrowser/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-hyperbrowser scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `HYPERBROWSER_API_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/hyperbrowserai/mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-hyperbrowser&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HYPERBROWSER_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-hyperbrowser%3A1.0.25%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-hyperbrowser": {
        "env": {
          "HYPERBROWSER_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "HYPERBROWSER_API_KEY",
          "docker.io/acuvity/mcp-server-hyperbrowser:1.0.25"
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
    "acuvity-mcp-server-hyperbrowser": {
      "env": {
        "HYPERBROWSER_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HYPERBROWSER_API_KEY",
        "docker.io/acuvity/mcp-server-hyperbrowser:1.0.25"
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
    "acuvity-mcp-server-hyperbrowser": {
      "env": {
        "HYPERBROWSER_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HYPERBROWSER_API_KEY",
        "docker.io/acuvity/mcp-server-hyperbrowser:1.0.25"
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
    "acuvity-mcp-server-hyperbrowser": {
      "env": {
        "HYPERBROWSER_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HYPERBROWSER_API_KEY",
        "docker.io/acuvity/mcp-server-hyperbrowser:1.0.25"
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
    "acuvity-mcp-server-hyperbrowser": {
      "env": {
        "HYPERBROWSER_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "HYPERBROWSER_API_KEY",
        "docker.io/acuvity/mcp-server-hyperbrowser:1.0.25"
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
        "env": {"HYPERBROWSER_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","HYPERBROWSER_API_KEY","docker.io/acuvity/mcp-server-hyperbrowser:1.0.25"]
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
- arguments: `run -i --rm --read-only -e HYPERBROWSER_API_KEY docker.io/acuvity/mcp-server-hyperbrowser:1.0.25`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e HYPERBROWSER_API_KEY docker.io/acuvity/mcp-server-hyperbrowser:1.0.25
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-hyperbrowser": {
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
    "acuvity-mcp-server-hyperbrowser": {
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
  - `HYPERBROWSER_API_KEY` secret to be set as secrets.HYPERBROWSER_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-hyperbrowser --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-hyperbrowser --version 1.0.0
````

Install with helm

```console
helm install mcp-server-hyperbrowser oci://docker.io/acuvity/mcp-server-hyperbrowser --version 1.0.0
```

From there your MCP server mcp-server-hyperbrowser will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-hyperbrowser` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-hyperbrowser/charts/mcp-server-hyperbrowser/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>scrape_webpage</summary>

**Description**:

```
Scrape a webpage and extract its content in various formats. This tool allows fetching content from a single URL with configurable browser behavior options. Use this for extracting text content, HTML structure, collecting links, or capturing screenshots of webpages.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| outputFormat | array | The format of the output | Yes
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
| url | string | The URL of the webpage to scrape | Yes
</details>
<details>
<summary>crawl_webpages</summary>

**Description**:

```
Crawl a website starting from a URL and explore linked pages. This tool allows systematic collection of content from multiple pages within a domain. Use this for larger data collection tasks, content indexing, or site mapping.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| followLinks | boolean | Whether to follow links on the crawled webpages | Yes
| ignoreSitemap | boolean | not set | No
| maxPages | integer | not set | No
| outputFormat | array | The format of the output | Yes
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
| url | string | The URL of the webpage to crawl. | Yes
</details>
<details>
<summary>extract_structured_data</summary>

**Description**:

```
Extract structured data from a webpage. This tool allows you to extract structured data from a webpage using a schema.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt | string | The prompt to use for the extraction | Yes
| schema | any | The json schema to use for the extraction. Must provide an object describing a spec compliant json schema, any other types are invalid. | No
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
| urls | array | The list of URLs of the webpages to extract structured information from. Can include wildcards (e.g. https://example.com/*) | Yes
</details>
<details>
<summary>browser_use_agent</summary>

**Description**:

```
This tool employs an open-source browser automation agent optimized specifically for fast, efficient, and cost-effective browser tasks using a cloud browser. It requires explicit, detailed instructions to perform highly specific interactions quickly.

Optimal for tasks requiring:
- Precise, explicitly defined interactions and actions
- Speed and efficiency with clear, unambiguous instructions
- Cost-effective automation at scale with straightforward workflows

Best suited use cases include:
- Explicitly defined registration and login processes
- Clearly guided navigation through web apps
- Structured, step-by-step web scraping with detailed guidance
- Extracting data via explicitly specified browser interactions

You must provide extremely detailed step-by-step instructions, including exact elements, actions, and explicit context. Clearly define the desired outcome for optimal results. Returns the completed result or an error message if issues arise.

Note: This agent trades off flexibility for significantly faster performance and lower costs compared to Claude and OpenAI agents.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxSteps | integer | not set | No
| returnStepInfo | boolean | Whether to return step-by-step information about the task.Should be false by default. May contain excessive information, so we strongly recommend setting this to false. | No
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
| task | string | The task to perform inside the browser | Yes
</details>
<details>
<summary>openai_computer_use_agent</summary>

**Description**:

```
This tool utilizes OpenAI's model to autonomously execute general-purpose browser-based tasks with balanced performance and reliability using a cloud browser. It handles complex interactions effectively with practical reasoning and clear execution.

Optimal for tasks requiring:
- Reliable, general-purpose browser automation
- Clear, structured interactions with moderate complexity
- Efficient handling of common web tasks and workflows

Best suited use cases include:
- Standard multi-step registration or form submissions
- Navigating typical web applications requiring multiple interactions
- Conducting structured web research tasks
- Extracting data through interactive web processes

Provide a clear step-by-step description, necessary context, and expected outcomes. Returns the completed result or an error message if issues arise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxSteps | integer | not set | No
| returnStepInfo | boolean | Whether to return step-by-step information about the task.Should be false by default. May contain excessive information, so we strongly recommend setting this to false. | No
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
| task | string | The task to perform inside the browser | Yes
</details>
<details>
<summary>claude_computer_use_agent</summary>

**Description**:

```
This tool leverages Anthropic's Claude model to autonomously execute complex browser tasks with sophisticated reasoning capabilities using a cloud browser. It specializes in handling intricate, nuanced, or highly context-sensitive web interactions.

Optimal for tasks requiring:
- Complex reasoning over multiple web pages
- Nuanced interpretation and flexible decision-making
- Human-like interaction with detailed context awareness

Best suited use cases include:
- Multi-step processes requiring reasoning (e.g., detailed registrations or onboarding)
- Interacting intelligently with advanced web apps
- Conducting in-depth research with complex conditions
- Extracting information from dynamic or interactive websites

Provide detailed task instructions, relevant context, and clearly specify the desired outcome for best results. Returns the completed result or an error message if issues arise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxSteps | integer | not set | No
| returnStepInfo | boolean | Whether to return step-by-step information about the task.Should be false by default. May contain excessive information, so we strongly recommend setting this to false. | No
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
| task | string | The task to perform inside the browser | Yes
</details>
<details>
<summary>search_with_bing</summary>

**Description**:

```
Search the web using Bing. This tool allows you to search the web using bing.com
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| numResults | integer | Number of search results to return | No
| query | string | The search query to submit to Bing | Yes
| sessionOptions | object | Options for the browser session. Avoid setting these if not mentioned explicitly | No
</details>
<details>
<summary>create_profile</summary>

**Description**:

```
Creates a new persistent Hyperbrowser profile.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>delete_profile</summary>

**Description**:

```
Deletes an existing persistent Hyperbrowser profile.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| profileId | string | ID of the profile to delete | Yes
</details>
<details>
<summary>list_profiles</summary>

**Description**:

```
Lists existing persistent Hyperbrowser profiles, with optional pagination.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Number of profiles per page (optional) | No
| page | integer | Page number for pagination (optional) | No
</details>

## 📚 Resources (54)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Welcome to Hyperbrowser | Hyperbrowser | text/markdown | hyperbrowser:/// | - |
| What are Headless browsers ? | Hyperbrowser | text/markdown | hyperbrowser:///what-are-headless-browsers | - |
| Scraping | Hyperbrowser | text/markdown | hyperbrowser:///get-started/quickstart/scraping | - |
| Crawling | Hyperbrowser | text/markdown | hyperbrowser:///get-started/quickstart/crawling | - |
| Quickstart | Hyperbrowser | text/markdown | hyperbrowser:///get-started/quickstart | - |
| Puppeteer | Hyperbrowser | text/markdown | hyperbrowser:///get-started/quickstart/puppeteer | - |
| Playwright | Hyperbrowser | text/markdown | hyperbrowser:///get-started/quickstart/playwright | - |
| Selenium | Hyperbrowser | text/markdown | hyperbrowser:///get-started/quickstart/selenium | - |
| Overview | Hyperbrowser | text/markdown | hyperbrowser:///sessions/overview | - |
| Session Parameters | Hyperbrowser | text/markdown | hyperbrowser:///sessions/overview/session-parameters | - |
| Advanced Privacy & Anti-Detection | Hyperbrowser | text/markdown | hyperbrowser:///sessions/advanced-privacy-and-anti-detection | - |
| Profiles | Hyperbrowser | text/markdown | hyperbrowser:///sessions/profiles | - |
| Recordings | Hyperbrowser | text/markdown | hyperbrowser:///sessions/recordings | - |
| Live View | Hyperbrowser | text/markdown | hyperbrowser:///sessions/live-view | - |
| Extensions | Hyperbrowser | text/markdown | hyperbrowser:///sessions/extensions | - |
| Scrape | Hyperbrowser | text/markdown | hyperbrowser:///web-scraping/scrape | - |
| Crawl | Hyperbrowser | text/markdown | hyperbrowser:///web-scraping/crawl | - |
| Extract | Hyperbrowser | text/markdown | hyperbrowser:///web-scraping/extract | - |
| Browser Use | Hyperbrowser | text/markdown | hyperbrowser:///agents/browser-use | - |
| Claude Computer Use | Hyperbrowser | text/markdown | hyperbrowser:///agents/claude-computer-use | - |
| OpenAI CUA | Hyperbrowser | text/markdown | hyperbrowser:///agents/openai-cua | - |
| AI Function Calling | Hyperbrowser | text/markdown | hyperbrowser:///guides/ai-function-calling | - |
| Scraping | Hyperbrowser | text/markdown | hyperbrowser:///guides/scraping | - |
| Extract Information with an LLM | Hyperbrowser | text/markdown | hyperbrowser:///guides/extract-information-with-an-llm | - |
| Using Hyperbrowser Session | Hyperbrowser | text/markdown | hyperbrowser:///guides/using-hyperbrowser-session | - |
| CAPTCHA Solving | Hyperbrowser | text/markdown | hyperbrowser:///guides/captcha-solving | - |
| Model Context Protocol | Hyperbrowser | text/markdown | hyperbrowser:///guides/model-context-protocol | - |
| SDKs | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks | - |
| Node | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/node | - |
| Sessions | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/node/sessions | - |
| Profiles | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/node/profiles | - |
| Scrape | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/node/scrape | - |
| Crawl | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/node/crawl | - |
| Extensions | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/node/extensions | - |
| Python | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/python | - |
| Sessions | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/python/sessions | - |
| Profiles | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/python/profiles | - |
| Scrape | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/python/scrape | - |
| Crawl | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/python/crawl | - |
| Extensions | Hyperbrowser | text/markdown | hyperbrowser:///reference/sdks/python/extensions | - |
| API Reference | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference | - |
| Sessions | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/sessions | - |
| Crawl | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/crawl | - |
| Scrape | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/scrape | - |
| Extract | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/extract | - |
| Agents | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/agents | - |
| Browser Use | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/agents/browser-use | - |
| Claude Computer Use | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/agents/claude-computer-use | - |
| OpenAI CUA | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/agents/openai-cua | - |
| Profiles | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/profiles | - |
| Extensions | Hyperbrowser | text/markdown | hyperbrowser:///reference/api-reference/extensions | - |
| LangChain | Hyperbrowser | text/markdown | hyperbrowser:///integrations/langchain | - |
| LlamaIndex | Hyperbrowser | text/markdown | hyperbrowser:///integrations/llamaindex | - |
| Hyperbrowser | text/markdown | hyperbrowser:///~gitbook/pdf | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | browser_use_agent | description | 9f30643bbe130688e8b1486876b99ae3a126e1e947329a98e898917ce1b0775e |
| tools | browser_use_agent | returnStepInfo | 6fd77c54b1fd5707e5f1d561952e639dc2ce6af466b6c0d89457cc10f4b3d1c3 |
| tools | browser_use_agent | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |
| tools | browser_use_agent | task | d86b9390a14d28a895670d40d9282b52f19906dbeb1c6fbdd1be658cbd28ea1f |
| tools | claude_computer_use_agent | description | aeb3065e3e9cf6acb7ed3bd38440f4ee9ec78abb68e786479c58c7f5477f3803 |
| tools | claude_computer_use_agent | returnStepInfo | 6fd77c54b1fd5707e5f1d561952e639dc2ce6af466b6c0d89457cc10f4b3d1c3 |
| tools | claude_computer_use_agent | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |
| tools | claude_computer_use_agent | task | d86b9390a14d28a895670d40d9282b52f19906dbeb1c6fbdd1be658cbd28ea1f |
| tools | crawl_webpages | description | 32153377a9aa1654b71dc94db9a0575b9b9ed318963dae7164b837aa959a46cd |
| tools | crawl_webpages | followLinks | a808ee712212405e3a5282ac380908fc08233e9cafda90ba66e5d239674917aa |
| tools | crawl_webpages | outputFormat | b858159483d2693009577f2d363babd1adffaf3b2903ac1883cd69d447ee06a8 |
| tools | crawl_webpages | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |
| tools | crawl_webpages | url | 8e9859796a12e9320af4f0d3de519ed3a7a3a41576fffeae6140fb25811a8dec |
| tools | create_profile | description | f00a82ed7d28090b4f26d2a747ff963abcf13f96a0bfc1f312b6e75f3f8d23b9 |
| tools | delete_profile | description | e265d2f6a5fb1f9d886510d8cea03dc3e136ad2ba80c242acacd9ecd1a827a5b |
| tools | delete_profile | profileId | ec7d43f54152b25bfb4969ee2fe0a44be8439173cc85306e1cfc8ba29d030804 |
| tools | extract_structured_data | description | a203fe9c3d4703705e6bd6036692bc0816418032d184e5b5ba634aeddc90d8b5 |
| tools | extract_structured_data | prompt | 00505f63b29ac07654374b391c5d44789b9b31500eef5b96b00ab4957531d12d |
| tools | extract_structured_data | schema | 673fd9b74f26960f5e953e0ef6dfa4d77c3850d77231225394e7dae3eae7c309 |
| tools | extract_structured_data | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |
| tools | extract_structured_data | urls | d473451546d84ccf59c686e1a20e5627e681ba49723958779ec4d5cd370f7fe6 |
| tools | list_profiles | description | 9a8ff3692145c0203085acba55c1ddb83a6fc4b936806e1d458f83ba0fba7b3b |
| tools | list_profiles | limit | dcbdf1bfc9b42909f6bb487396cecc1ac1e66612765c0a8a42c7579651faf5aa |
| tools | list_profiles | page | 98a0867b63c70eb1a310c104e968310b536e2c57b23f1a3e5c94c36a1268114f |
| tools | openai_computer_use_agent | description | c0faf745449591f9443462181b05839c68f2ab81bcac457e7a970e423d07f71b |
| tools | openai_computer_use_agent | returnStepInfo | 6fd77c54b1fd5707e5f1d561952e639dc2ce6af466b6c0d89457cc10f4b3d1c3 |
| tools | openai_computer_use_agent | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |
| tools | openai_computer_use_agent | task | d86b9390a14d28a895670d40d9282b52f19906dbeb1c6fbdd1be658cbd28ea1f |
| tools | scrape_webpage | description | 8e3fd9c57ed12338ff8c874ecc9395f7f3dfe56c0c9b456cd8824efb15223900 |
| tools | scrape_webpage | outputFormat | b858159483d2693009577f2d363babd1adffaf3b2903ac1883cd69d447ee06a8 |
| tools | scrape_webpage | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |
| tools | scrape_webpage | url | a8c70529a5a2fd4e637ec140b8ec2b3b75bc8bed6d0530018e88f677949d349a |
| tools | search_with_bing | description | c718f6814bebc3d5ed5d237494839b7c94855caafafa92ecd9b1fb7c52d721d2 |
| tools | search_with_bing | numResults | 9f3b8de8323c5195866eaf4fe5fb6c5cfa1ec9025da54bb7ed4f1576f28e1abe |
| tools | search_with_bing | query | 2f5b6df977b54263575776c19cf2f402aa633b3b7e7b2dc8c56156d5a96deb9a |
| tools | search_with_bing | sessionOptions | 82e76186168e5618d6508918b298731490fd491ab45e733374096016fdc299f9 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
