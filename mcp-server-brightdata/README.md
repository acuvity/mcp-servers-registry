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


# What is mcp-server-brightdata?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-brightdata/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-brightdata/2.1.0?logo=docker&logoColor=fff&label=2.1.0)](https://hub.docker.com/r/acuvity/mcp-server-brightdata)
[![PyPI](https://img.shields.io/badge/2.1.0-3775A9?logo=pypi&logoColor=fff&label=@brightdata/mcp)](https://github.com/luminati-io/brightdata-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-brightdata/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-brightdata&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_TOKEN%22%2C%22-e%22%2C%22BROWSER_AUTH%22%2C%22docker.io%2Facuvity%2Fmcp-server-brightdata%3A2.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Discover, extract, and interact with the web - automated access across the public internet.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @brightdata/mcp original [sources](https://github.com/luminati-io/brightdata-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-brightdata/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/charts/mcp-server-brightdata/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @brightdata/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-brightdata scope of operation the intended usage is to run natively on the targeted machine to access local resources.

**Environment variables and secrets:**
  - `API_TOKEN` required to be set
  - `WEB_UNLOCKER_ZONE` optional (not set)
  - `BROWSER_AUTH` required to be set

For more information and extra configuration you can consult the [package](https://github.com/luminati-io/brightdata-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-brightdata&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_TOKEN%22%2C%22-e%22%2C%22BROWSER_AUTH%22%2C%22docker.io%2Facuvity%2Fmcp-server-brightdata%3A2.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-brightdata": {
        "env": {
          "API_TOKEN": "TO_BE_SET",
          "BROWSER_AUTH": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "API_TOKEN",
          "-e",
          "BROWSER_AUTH",
          "docker.io/acuvity/mcp-server-brightdata:2.1.0"
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
    "acuvity-mcp-server-brightdata": {
      "env": {
        "API_TOKEN": "TO_BE_SET",
        "BROWSER_AUTH": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_TOKEN",
        "-e",
        "BROWSER_AUTH",
        "docker.io/acuvity/mcp-server-brightdata:2.1.0"
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
    "acuvity-mcp-server-brightdata": {
      "env": {
        "API_TOKEN": "TO_BE_SET",
        "BROWSER_AUTH": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_TOKEN",
        "-e",
        "BROWSER_AUTH",
        "docker.io/acuvity/mcp-server-brightdata:2.1.0"
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
    "acuvity-mcp-server-brightdata": {
      "env": {
        "API_TOKEN": "TO_BE_SET",
        "BROWSER_AUTH": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_TOKEN",
        "-e",
        "BROWSER_AUTH",
        "docker.io/acuvity/mcp-server-brightdata:2.1.0"
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
    "acuvity-mcp-server-brightdata": {
      "env": {
        "API_TOKEN": "TO_BE_SET",
        "BROWSER_AUTH": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "API_TOKEN",
        "-e",
        "BROWSER_AUTH",
        "docker.io/acuvity/mcp-server-brightdata:2.1.0"
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
        "env": {"API_TOKEN":"TO_BE_SET","BROWSER_AUTH":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","API_TOKEN","-e","BROWSER_AUTH","docker.io/acuvity/mcp-server-brightdata:2.1.0"]
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
- arguments: `run -i --rm --read-only -e API_TOKEN -e BROWSER_AUTH docker.io/acuvity/mcp-server-brightdata:2.1.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e API_TOKEN -e BROWSER_AUTH docker.io/acuvity/mcp-server-brightdata:2.1.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-brightdata": {
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
    "acuvity-mcp-server-brightdata": {
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
  - `API_TOKEN` secret to be set as secrets.API_TOKEN either by `.value` or from existing with `.valueFrom`
  - `BROWSER_AUTH` secret to be set as secrets.BROWSER_AUTH either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `WEB_UNLOCKER_ZONE=""` environment variable can be changed with env.WEB_UNLOCKER_ZONE=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
````

Install with helm

```console
helm install mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
```

From there your MCP server mcp-server-brightdata will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-brightdata` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/charts/mcp-server-brightdata/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (48)
<details>
<summary>search_engine</summary>

**Description**:

```
Scrape search results from Google, Bing or Yandex. Returns SERP results in markdown (URL, title, description)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Pagination cursor for next page | No
| engine | string | not set | No
| query | string | not set | Yes
</details>
<details>
<summary>scrape_as_markdown</summary>

**Description**:

```
Scrape a single webpage URL with advanced options for content extraction and get back the results in MarkDown language. This tool can unlock any webpage even if it uses bot detection or CAPTCHA.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>scrape_as_html</summary>

**Description**:

```
Scrape a single webpage URL with advanced options for content extraction and get back the results in HTML. This tool can unlock any webpage even if it uses bot detection or CAPTCHA.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>session_stats</summary>

**Description**:

```
Tell the user about the tool usage during this session
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>web_data_amazon_product</summary>

**Description**:

```
Quickly read structured amazon product data.
Requires a valid product URL with /dp/ in it.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_amazon_product_reviews</summary>

**Description**:

```
Quickly read structured amazon product review data.
Requires a valid product URL with /dp/ in it.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_amazon_product_search</summary>

**Description**:

```
Quickly read structured amazon product search data.
Requires a valid search keyword and amazon domain URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keyword | string | not set | Yes
| pages_to_search | string | not set | No
| url | string | not set | Yes
</details>
<details>
<summary>web_data_walmart_product</summary>

**Description**:

```
Quickly read structured walmart product data.
Requires a valid product URL with /ip/ in it.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_walmart_seller</summary>

**Description**:

```
Quickly read structured walmart seller data.
Requires a valid walmart seller URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_ebay_product</summary>

**Description**:

```
Quickly read structured ebay product data.
Requires a valid ebay product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_homedepot_products</summary>

**Description**:

```
Quickly read structured homedepot product data.
Requires a valid homedepot product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_zara_products</summary>

**Description**:

```
Quickly read structured zara product data.
Requires a valid zara product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_etsy_products</summary>

**Description**:

```
Quickly read structured etsy product data.
Requires a valid etsy product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_bestbuy_products</summary>

**Description**:

```
Quickly read structured bestbuy product data.
Requires a valid bestbuy product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_person_profile</summary>

**Description**:

```
Quickly read structured linkedin people profile data.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_company_profile</summary>

**Description**:

```
Quickly read structured linkedin company profile data
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_job_listings</summary>

**Description**:

```
Quickly read structured linkedin job listings data
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_posts</summary>

**Description**:

```
Quickly read structured linkedin posts data
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_people_search</summary>

**Description**:

```
Quickly read structured linkedin people search data
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| first_name | string | not set | Yes
| last_name | string | not set | Yes
| url | string | not set | Yes
</details>
<details>
<summary>web_data_crunchbase_company</summary>

**Description**:

```
Quickly read structured crunchbase company data
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_zoominfo_company_profile</summary>

**Description**:

```
Quickly read structured ZoomInfo company profile data.
Requires a valid ZoomInfo company URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_profiles</summary>

**Description**:

```
Quickly read structured Instagram profile data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_posts</summary>

**Description**:

```
Quickly read structured Instagram post data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_reels</summary>

**Description**:

```
Quickly read structured Instagram reel data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_comments</summary>

**Description**:

```
Quickly read structured Instagram comments data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_posts</summary>

**Description**:

```
Quickly read structured Facebook post data.
Requires a valid Facebook post URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_marketplace_listings</summary>

**Description**:

```
Quickly read structured Facebook marketplace listing data.
Requires a valid Facebook marketplace listing URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_company_reviews</summary>

**Description**:

```
Quickly read structured Facebook company reviews data.
Requires a valid Facebook company URL and number of reviews.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| num_of_reviews | string | not set | Yes
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_events</summary>

**Description**:

```
Quickly read structured Facebook events data.
Requires a valid Facebook event URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_tiktok_profiles</summary>

**Description**:

```
Quickly read structured Tiktok profiles data.
Requires a valid Tiktok profile URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_tiktok_posts</summary>

**Description**:

```
Quickly read structured Tiktok post data.
Requires a valid Tiktok post URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_tiktok_shop</summary>

**Description**:

```
Quickly read structured Tiktok shop data.
Requires a valid Tiktok shop product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_tiktok_comments</summary>

**Description**:

```
Quickly read structured Tiktok comments data.
Requires a valid Tiktok video URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_google_maps_reviews</summary>

**Description**:

```
Quickly read structured Google maps reviews data.
Requires a valid Google maps URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| days_limit | string | not set | No
| url | string | not set | Yes
</details>
<details>
<summary>web_data_google_shopping</summary>

**Description**:

```
Quickly read structured Google shopping data.
Requires a valid Google shopping product URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_google_play_store</summary>

**Description**:

```
Quickly read structured Google play store data.
Requires a valid Google play store app URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_apple_app_store</summary>

**Description**:

```
Quickly read structured apple app store data.
Requires a valid apple app store app URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_reuter_news</summary>

**Description**:

```
Quickly read structured reuter news data.
Requires a valid reuter news report URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_github_repository_file</summary>

**Description**:

```
Quickly read structured github repository data.
Requires a valid github repository file URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_yahoo_finance_business</summary>

**Description**:

```
Quickly read structured yahoo finance business data.
Requires a valid yahoo finance business URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_x_posts</summary>

**Description**:

```
Quickly read structured X post data.
Requires a valid X post URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_zillow_properties_listing</summary>

**Description**:

```
Quickly read structured zillow properties listing data.
Requires a valid zillow properties listing URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_booking_hotel_listings</summary>

**Description**:

```
Quickly read structured booking hotel listings data.
Requires a valid booking hotel listing URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_youtube_profiles</summary>

**Description**:

```
Quickly read structured youtube profiles data.
Requires a valid youtube profile URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_youtube_comments</summary>

**Description**:

```
Quickly read structured youtube comments data.
Requires a valid youtube video URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| num_of_comments | string | not set | No
| url | string | not set | Yes
</details>
<details>
<summary>web_data_reddit_posts</summary>

**Description**:

```
Quickly read structured reddit posts data.
Requires a valid reddit post URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_youtube_videos</summary>

**Description**:

```
Quickly read structured YouTube videos data.
Requires a valid YouTube video URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>scraping_browser_activation_instructions</summary>

**Description**:

```
Instructions for activating the scraping browser
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | scrape_as_html | description | ccb1fe327d30ca65f76fccdc0ce114d0a96d6769d5c08da818bee2aa0374e4ba |
| tools | scrape_as_markdown | description | 48946c5fc24b9fcf9fbadbd981dd26be62eb3f34f642e1950aa4f01e9db9d9bc |
| tools | scraping_browser_activation_instructions | description | d0fa023a72ecd424cdaa1c99a9841fc96d4bb3ce5998e707ace5e45401f44056 |
| tools | search_engine | description | 596a407954d04c093fd9ff3adec1ddab4bcdfe214b6c82189a2607c514f9ade5 |
| tools | search_engine | cursor | 0221fb5bf5262fde4122dbb922c6fd4381a0382dd5ecc0448da97ee8aecc9ae0 |
| tools | session_stats | description | a361dcc45d17f9cad5e4b1872ef7ff26d4b355774d5be01159573e9616ac7c76 |
| tools | web_data_amazon_product | description | 65fba1ff50443ee093a32d8301d918bf2b785e736dbb5cb0aadbc76cb889f599 |
| tools | web_data_amazon_product_reviews | description | 8891e947fd3a6e9d47b6ef925dc5976566a78e8e1ede12b2f1e350fea32bbaac |
| tools | web_data_amazon_product_search | description | 75b2c12f7b2276e3cd007507ac0aebc798e2d9603c56466f37b58aba075aba20 |
| tools | web_data_apple_app_store | description | c6b5f38ed097bfbfb48a0c0c2944ddeada32541838e9107b9a32ddd23c73a02b |
| tools | web_data_bestbuy_products | description | 1abd8c341e69c436b8ed17456b49421a9c36506db5d9e05764eeed72e7c584c2 |
| tools | web_data_booking_hotel_listings | description | 45efafdd1a85f8985481e45e09c96dd3ae729e5cf7fa467f2288d0ca0f068fde |
| tools | web_data_crunchbase_company | description | 4b82d216020c94341dc5440e8d36602cb556518dbe2c45cee21185885e5f0e83 |
| tools | web_data_ebay_product | description | a2b46e418c6929e071e4597fc942456fa3eaed4ed4ab182345c8bf71aee31295 |
| tools | web_data_etsy_products | description | 1a6bfb31dcfae9ef65b9dc31fb54ca8ef762786d6046e36b3487b0e25ce58fc2 |
| tools | web_data_facebook_company_reviews | description | 47afecccab5540c3e5f1505d4a3d66e5dfbd0c231b796be1d9c28db62b6968c6 |
| tools | web_data_facebook_events | description | 04f5b8dee80970194cd67ca2614ef46108d1f7b18cc0631df20d4f6c9cc9b67f |
| tools | web_data_facebook_marketplace_listings | description | 887d03156bd3d324c2cec6bcba737c0d6ee5dd6305cfc86e1821c14cbceaacb4 |
| tools | web_data_facebook_posts | description | 111981d475ce7965823736c78972c7d1d0b07a5bc057af4b1a4e2393719c96b0 |
| tools | web_data_github_repository_file | description | e1fd87f0ffce9681225d3968cb04267112c32bed7f5ab738ca4baa850ad0bbdc |
| tools | web_data_google_maps_reviews | description | 33e28117c37dc5a020419cbcab9c1141d873adff308e2e6ee08ca33c1990a5c5 |
| tools | web_data_google_play_store | description | ed7b901fbade759336574df281112cc5f9604ddb6a0c0ef1d45bfb13c8f662aa |
| tools | web_data_google_shopping | description | daab2605d5868e6f9f43d6fe8c931759d04c7655df844d5f84fcc93fc987ea5e |
| tools | web_data_homedepot_products | description | 8256ab0d8f331a059f8adf38abae23ab8cdaeef74fb7be77c5e2d043dc2ed96e |
| tools | web_data_instagram_comments | description | a52e0e54c786ba9c11485ab321afe7e5105a734c7f4bfec3ebd1f708de3d43e5 |
| tools | web_data_instagram_posts | description | 9b186d6fba3efb94bff3bbd0d03580f86c160b15c49aa4da5ee714ee4f675cad |
| tools | web_data_instagram_profiles | description | 6e61b41570fd385d752770d973317ac34f25c655ea490e20ac2f64b0750e97af |
| tools | web_data_instagram_reels | description | a8435edf89782be578fcc1cdecd65f754634f092e3d24bbf86290c265319d791 |
| tools | web_data_linkedin_company_profile | description | ccffa642e9b1120c15f275650d1b685bb127c4a6ea8f6048ddc9061698c59f95 |
| tools | web_data_linkedin_job_listings | description | 7251693f76663b11172489b17300e515584f3a3b7d28a1304a500a19571f332b |
| tools | web_data_linkedin_people_search | description | 674374fa84fd31fc119f381578cb0577ec03c5942822de1379cb556fbea5a2ad |
| tools | web_data_linkedin_person_profile | description | 652f6bc070db40560b87b14c185a85ead84a45a05840122b0ec5c4e6775ea283 |
| tools | web_data_linkedin_posts | description | 7288f592a6d320bde43378fa5cede5ec1fe75ea7b123fee464a66a93d7de97f8 |
| tools | web_data_reddit_posts | description | 94f3068708ab8c85180e0c86cb70cd087fee7f0f7f0c17fd823a00b3500b4b3c |
| tools | web_data_reuter_news | description | fc7f93076ce14b66b75206799dcc726d532448ee0be3358d40b5c6a06214cd19 |
| tools | web_data_tiktok_comments | description | e52bae1795588292a8ce6834edf0595c871762947bb08312cd587e0b2653af75 |
| tools | web_data_tiktok_posts | description | a6ad4a7d08ed3a2126d985f42112abde2896615cc855701d0dfd342cbefd8200 |
| tools | web_data_tiktok_profiles | description | f5f18c34f6a123787032be62080fb7b76dd9778b0ab3d189eb4c65d4485528a0 |
| tools | web_data_tiktok_shop | description | 320d9c052688fb2a69ba599c0013aa0d76d86e1a2a8ae52d115b07e4fb604deb |
| tools | web_data_walmart_product | description | 5c1e48d30bd30edf723aa15b9294f3961961702043a15f1d9ec4ad6cb1682190 |
| tools | web_data_walmart_seller | description | e92907096da9cb73e633633adc3406a73fde690b8b326c861f8f875371c3400f |
| tools | web_data_x_posts | description | 29aae5cb1605b99c1fc5d29e6e8d1d00bccb99963ca7f3522fde9d8786174192 |
| tools | web_data_yahoo_finance_business | description | a852a1aab3c35a6e1d14fa2b76580f0b1452c6c1dcebcd1a0279245f90efbc2b |
| tools | web_data_youtube_comments | description | bc859783f917730b5ae496199fe4db140baf8e6e8dae6abc7ed02e11eca783d4 |
| tools | web_data_youtube_profiles | description | 500f96700a6fe0c88606828a5fee9418ad3c1d7bc0f15a1f28509b7997c1dd79 |
| tools | web_data_youtube_videos | description | 5a476fcf9bd1c5e69c720fbea400d151da16c8b265f0f237868a96d8994289b6 |
| tools | web_data_zara_products | description | 835f704e3d8b1c93c713eb394d05be67c2f89976ae596fe20f113277e47177f7 |
| tools | web_data_zillow_properties_listing | description | 8e799a15b56be6999cc0634f6276f7c84079cf92e6aa09d62f9ec955e160e25f |
| tools | web_data_zoominfo_company_profile | description | ee4d09fab58d64165808f582046d95685895bb920a2e86954ba0db0918963891 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
