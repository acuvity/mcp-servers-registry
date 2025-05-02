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
</p>


# What is mcp-server-brightdata?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-brightdata/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-brightdata/1.7.0?logo=docker&logoColor=fff&label=1.7.0)](https://hub.docker.com/r/acuvity/mcp-server-brightdata)
[![PyPI](https://img.shields.io/badge/1.7.0-3775A9?logo=pypi&logoColor=fff&label=@brightdata/mcp)](https://github.com/luminati-io/brightdata-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-brightdata&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_TOKEN%22%2C%22-e%22%2C%22BROWSER_AUTH%22%2C%22docker.io%2Facuvity%2Fmcp-server-brightdata%3A1.7.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Discover, extract, and interact with the web - one interface powering automated access across the public internet.

> [!NOTE]
> `@brightdata/mcp` has been repackaged by Acuvity from Bright Data original sources.

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
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails that protect MCP server integrity and detect suspicious behaviors in real-time.:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions - or call arguments - reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognised tokens formats with `[REDACTED]` in outbound content.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# 📦 How to Use


> [!NOTE]
> Given mcp-server-brightdata scope of operation the intended usage is to run natively on the targeted machine to access local resources.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-brightdata&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_TOKEN%22%2C%22-e%22%2C%22BROWSER_AUTH%22%2C%22docker.io%2Facuvity%2Fmcp-server-brightdata%3A1.7.0%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-brightdata:1.7.0"
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
        "docker.io/acuvity/mcp-server-brightdata:1.7.0"
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
        "docker.io/acuvity/mcp-server-brightdata:1.7.0"
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
        "docker.io/acuvity/mcp-server-brightdata:1.7.0"
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
        "docker.io/acuvity/mcp-server-brightdata:1.7.0"
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
        "args": ["run","-i","--rm","--read-only","-e","API_TOKEN","-e","BROWSER_AUTH","docker.io/acuvity/mcp-server-brightdata:1.7.0"]
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
**Environment variables:**
  - `API_TOKEN` required to be set
  - `WEB_UNLOCKER_ZONE` optional (not set)
  - `BROWSER_AUTH` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e API_TOKEN -e BROWSER_AUTH docker.io/acuvity/mcp-server-brightdata:1.7.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e API_TOKEN -e BROWSER_AUTH docker.io/acuvity/mcp-server-brightdata:1.7.0
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-brightdata": {
      "url": "http://localhost:<localport>/sse",
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

Of course there are plenty of other options that minibridge can provide.

Don't be shy to ask question either.

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

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0-
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

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/charts/mcp-server-brightdata/README.md) for more details about settings.

</details>

# 🧠 Server features

## 🧰 Tools (18)
<details>
<summary>search_engine</summary>

**Description**:

```
Scrape search results from Google, Bing or Yandex. Returns SERP results in markdown (URL, title, description)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
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
<summary>scraping_browser_navigate</summary>

**Description**:

```
Navigate a scraping browser session to a new URL
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | The URL to navigate to | Yes
</details>
<details>
<summary>scraping_browser_go_back</summary>

**Description**:

```
Go back to the previous page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_go_forward</summary>

**Description**:

```
Go forward to the next page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_links</summary>

**Description**:

```
Get all links on the current page, text and selectors
It's strongly recommended that you call the links tool to check that your click target is valid
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_click</summary>

**Description**:

```
Click on an element.
Avoid calling this unless you know the element selector (you can use other tools to find those)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for the element to click | Yes
</details>
<details>
<summary>scraping_browser_type</summary>

**Description**:

```
Type text into an element
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for the element to type into | Yes
| submit | boolean | Whether to submit the form after typing (press Enter) | No
| text | string | Text to type | Yes
</details>
<details>
<summary>scraping_browser_wait_for</summary>

**Description**:

```
Wait for an element to be visible on the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector to wait for | Yes
| timeout | number | Maximum time to wait in milliseconds (default: 30000) | No
</details>
<details>
<summary>scraping_browser_screenshot</summary>

**Description**:

```
Take a screenshot of the current page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| full_page | boolean | Whether to screenshot the full page (default: false)
You should avoid fullscreen if it's not important, since the images can be quite large | No
</details>
<details>
<summary>scraping_browser_get_text</summary>

**Description**:

```
Get the text content of the current page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_get_html</summary>

**Description**:

```
Get the HTML content of the current page. Avoid using the full_page option unless it is important to see things like script tags since this can be large
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| full_page | boolean | Whether to get the full page HTML including head and script tags
Avoid this if you only need the extra HTML, since it can be quite large | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | scrape_as_html | description | ccb1fe327d30ca65f76fccdc0ce114d0a96d6769d5c08da818bee2aa0374e4ba |
| tools | scrape_as_markdown | description | 48946c5fc24b9fcf9fbadbd981dd26be62eb3f34f642e1950aa4f01e9db9d9bc |
| tools | scraping_browser_click | description | 9e9459df10de555dc6aedcfcf83c6f24d93f16675d0a62b1150aa15e3c71a1d0 |
| tools | scraping_browser_click | selector | b472eecbbc30b0cf10580e321a828b5b50472aac057c0712023b625869274969 |
| tools | scraping_browser_get_html | description | e9db1ed3982226fa5e634cefeaac3825200257fb26c11720068c9a5c3d28814d |
| tools | scraping_browser_get_html | full_page | 227462f39892944bb89922121fd64f11432bf36046e72adcaaba2df6e402cb73 |
| tools | scraping_browser_get_text | description | da41b92ae44df5399a35b18908cd1ea1c2ccaf5eb058edc749767a9519eaca96 |
| tools | scraping_browser_go_back | description | 1070d603d3951f9282bc8e5111b7a6993fa05215c23ba5099429b567a9bdb467 |
| tools | scraping_browser_go_forward | description | 4f74235e282e3cba526b98047b02c344c6bc32566bb325d5408e897eadfc6a7e |
| tools | scraping_browser_links | description | ad9a62f8931d3317d6627e72de82f4606bab9357cd04d19b7133c81aa4816aa0 |
| tools | scraping_browser_navigate | description | 4dd63c7c00a6ccd7de8df8d4efa78821477c05dd0fe9fee4f9f530a8fbc78ddd |
| tools | scraping_browser_navigate | url | 63d749360d127f3c1d0d108336745c687aaa08760a306f0dadbbef4e9fadf27f |
| tools | scraping_browser_screenshot | description | 769e18b9e5b78a944b15bd8342288959fd92d197631e87a9b6f293a8aa9c7caf |
| tools | scraping_browser_screenshot | full_page | b8634cbc1491ba7afc92714a4c557a81e3ae93ef4cc4ee2568f9c15d1bb4ed22 |
| tools | scraping_browser_type | description | 9cd8fb996ff445688e56e6c500ed27847e27b72c606d5c8174708d92fe8ec726 |
| tools | scraping_browser_type | selector | 8432a6c9577dcae09ef6bd2b0f59c8b350c5e6e0703169193a6639555168f976 |
| tools | scraping_browser_type | submit | 9ad8eef45aadaffc2eceb18d4eded88374b264f66b08c3865109a3d96ba7acac |
| tools | scraping_browser_type | text | 2bf42268dbb30ce1452879e6fdf8c10a259316e899df9c4fb0405b1f0e42fe8c |
| tools | scraping_browser_wait_for | description | dc6f8b68829f63f13684b67baf0e443da64f87e0e4af158f17f798531665b39a |
| tools | scraping_browser_wait_for | selector | 036462863c2f283ab491e0e7b27eaf9d692a530b555b7e805c8841d80ea2e2a3 |
| tools | scraping_browser_wait_for | timeout | 74f20c7f092d948e04cca44c284e61d1fdf8d1a9668dfa5a689ce55bcb15fb32 |
| tools | search_engine | description | 596a407954d04c093fd9ff3adec1ddab4bcdfe214b6c82189a2607c514f9ade5 |
| tools | session_stats | description | a361dcc45d17f9cad5e4b1872ef7ff26d4b355774d5be01159573e9616ac7c76 |
| tools | web_data_amazon_product | description | 65fba1ff50443ee093a32d8301d918bf2b785e736dbb5cb0aadbc76cb889f599 |
| tools | web_data_amazon_product_reviews | description | 8891e947fd3a6e9d47b6ef925dc5976566a78e8e1ede12b2f1e350fea32bbaac |
| tools | web_data_linkedin_company_profile | description | ccffa642e9b1120c15f275650d1b685bb127c4a6ea8f6048ddc9061698c59f95 |
| tools | web_data_linkedin_person_profile | description | 652f6bc070db40560b87b14c185a85ead84a45a05840122b0ec5c4e6775ea283 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
