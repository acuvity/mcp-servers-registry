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


# What is mcp-server-audiense-insights?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-audiense-insights/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-audiense-insights/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-audiense-insights)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=mcp-audiense-insights)](https://github.com/AudienseCo/mcp-audiense-insights)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-audiense-insights&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AUDIENSE_CLIENT_ID%22%2C%22-e%22%2C%22AUDIENSE_CLIENT_SECRET%22%2C%22-e%22%2C%22TWITTER_BEARER_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-audiense-insights%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Extracts marketing insights and audience analysis from Audiense reports.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-audiense-insights original [sources](https://github.com/AudienseCo/mcp-audiense-insights).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-audiense-insights/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/charts/mcp-server-audiense-insights/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-audiense-insights run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/charts/mcp-server-audiense-insights#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-audiense-insights scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-audiense-insights&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AUDIENSE_CLIENT_ID%22%2C%22-e%22%2C%22AUDIENSE_CLIENT_SECRET%22%2C%22-e%22%2C%22TWITTER_BEARER_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-audiense-insights%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-audiense-insights": {
        "env": {
          "AUDIENSE_CLIENT_ID": "TO_BE_SET",
          "AUDIENSE_CLIENT_SECRET": "TO_BE_SET",
          "TWITTER_BEARER_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "AUDIENSE_CLIENT_ID",
          "-e",
          "AUDIENSE_CLIENT_SECRET",
          "-e",
          "TWITTER_BEARER_TOKEN",
          "docker.io/acuvity/mcp-server-audiense-insights:0.2.0"
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
    "acuvity-mcp-server-audiense-insights": {
      "env": {
        "AUDIENSE_CLIENT_ID": "TO_BE_SET",
        "AUDIENSE_CLIENT_SECRET": "TO_BE_SET",
        "TWITTER_BEARER_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AUDIENSE_CLIENT_ID",
        "-e",
        "AUDIENSE_CLIENT_SECRET",
        "-e",
        "TWITTER_BEARER_TOKEN",
        "docker.io/acuvity/mcp-server-audiense-insights:0.2.0"
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
    "acuvity-mcp-server-audiense-insights": {
      "env": {
        "AUDIENSE_CLIENT_ID": "TO_BE_SET",
        "AUDIENSE_CLIENT_SECRET": "TO_BE_SET",
        "TWITTER_BEARER_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AUDIENSE_CLIENT_ID",
        "-e",
        "AUDIENSE_CLIENT_SECRET",
        "-e",
        "TWITTER_BEARER_TOKEN",
        "docker.io/acuvity/mcp-server-audiense-insights:0.2.0"
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
    "acuvity-mcp-server-audiense-insights": {
      "env": {
        "AUDIENSE_CLIENT_ID": "TO_BE_SET",
        "AUDIENSE_CLIENT_SECRET": "TO_BE_SET",
        "TWITTER_BEARER_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AUDIENSE_CLIENT_ID",
        "-e",
        "AUDIENSE_CLIENT_SECRET",
        "-e",
        "TWITTER_BEARER_TOKEN",
        "docker.io/acuvity/mcp-server-audiense-insights:0.2.0"
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
    "acuvity-mcp-server-audiense-insights": {
      "env": {
        "AUDIENSE_CLIENT_ID": "TO_BE_SET",
        "AUDIENSE_CLIENT_SECRET": "TO_BE_SET",
        "TWITTER_BEARER_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AUDIENSE_CLIENT_ID",
        "-e",
        "AUDIENSE_CLIENT_SECRET",
        "-e",
        "TWITTER_BEARER_TOKEN",
        "docker.io/acuvity/mcp-server-audiense-insights:0.2.0"
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
        "env": {"AUDIENSE_CLIENT_ID":"TO_BE_SET","AUDIENSE_CLIENT_SECRET":"TO_BE_SET","TWITTER_BEARER_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","AUDIENSE_CLIENT_ID","-e","AUDIENSE_CLIENT_SECRET","-e","TWITTER_BEARER_TOKEN","docker.io/acuvity/mcp-server-audiense-insights:0.2.0"]
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
  - `AUDIENSE_CLIENT_ID` required to be set
  - `AUDIENSE_CLIENT_SECRET` required to be set
  - `TWITTER_BEARER_TOKEN` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e AUDIENSE_CLIENT_ID -e AUDIENSE_CLIENT_SECRET -e TWITTER_BEARER_TOKEN docker.io/acuvity/mcp-server-audiense-insights:0.2.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e AUDIENSE_CLIENT_ID -e AUDIENSE_CLIENT_SECRET -e TWITTER_BEARER_TOKEN docker.io/acuvity/mcp-server-audiense-insights:0.2.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-audiense-insights": {
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
    "acuvity-mcp-server-audiense-insights": {
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
  - `AUDIENSE_CLIENT_ID` secret to be set as secrets.AUDIENSE_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `AUDIENSE_CLIENT_SECRET` secret to be set as secrets.AUDIENSE_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`
  - `TWITTER_BEARER_TOKEN` secret to be set as secrets.TWITTER_BEARER_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-audiense-insights --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-audiense-insights --version 1.0.0
````

Install with helm

```console
helm install mcp-server-audiense-insights oci://docker.io/acuvity/mcp-server-audiense-insights --version 1.0.0
```

From there your MCP server mcp-server-audiense-insights will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-audiense-insights` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-audiense-insights/charts/mcp-server-audiense-insights/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>get-reports</summary>

**Description**:

```
Retrieves the list of Audiense insights reports owned by the authenticated user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get-report-info</summary>

**Description**:

```
Retrieves detailed information about a specific intelligence report, including its status, segmentation type, audience size, segments, and access links.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| report_id | string | The ID of the intelligence report. | Yes
</details>
<details>
<summary>get-audience-insights</summary>

**Description**:

```
Retrieves aggregated insights for a given audience ID, providing statistical distributions across various attributes.
    Available insights include demographics (e.g., gender, age, country), behavioral traits (e.g., active hours, platform usage), psychographics (e.g., personality traits, interests), and socioeconomic factors (e.g., income, education status).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| audience_insights_id | string | The ID of the audience insights. | Yes
| insights | array | Optional list of insight names to filter. | No
</details>
<details>
<summary>get-baselines</summary>

**Description**:

```
Retrieves available baselines, optionally filtered by country.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| country | string | ISO country code to filter by. | No
</details>
<details>
<summary>get-categories</summary>

**Description**:

```
Retrieves the list of available affinity categories that can be used as the categories parameter in the compare-audience-influencers tool.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>compare-audience-influencers</summary>

**Description**:

```
Compares the influencers of an audience with a baseline audience. The baseline is determined as follows: 
    If the selection was the full audience and a single country represents more than 50% of the audience, that country is used as the baseline.
    Otherwise, the Global baseline is applied. If the selection was a specific segment, the full audience is used as the baseline.
    Each influencer comparison includes: 
        - Affinity (%) - The level of alignment between the influencer and the audience. Baseline Affinity (%)
        - The influencer’s affinity within the baseline audience. Uniqueness Score
        - A measure of how distinct the influencer is within the selected audience compared to the baseline.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| audience_influencers_id | string | The ID of the audience influencers. | Yes
| baseline_audience_influencers_id | string | The ID of the baseline audience influencers. | Yes
| bio_keyword | string | Keyword to filter influencers by their biography. | No
| categories | array | Filter influencers by categories. | No
| count | number | Number of items per page (default: 200). | No
| countries | array | Filter influencers by country ISO codes. | No
| cursor | number | Cursor for pagination. | No
| entity_type | string | Filter by entity type (person or brand). | No
| followers_max | number | Maximum number of followers. | No
| followers_min | number | Minimum number of followers. | No
</details>
<details>
<summary>get-audience-content</summary>

**Description**:

```
Retrieves audience content engagement details for a given audience.

This tool provides a detailed breakdown of the content an audience interacts with, including:
- **Liked Content**: Popular posts, top domains, top emojis, top hashtags, top links, top media, and a word cloud.
- **Shared Content**: Content that the audience shares, categorized similarly to liked content.
- **Influential Content**: Content from influential accounts that impact the audience, with similar categorization.

Each category contains:
- **popularPost**: List of the most engaged posts.
- **topDomains**: Most mentioned domains.
- **topEmojis**: Most used emojis.
- **topHashtags**: Most used hashtags.
- **topLinks**: Most shared links.
- **topMedia**: Media types shared and samples.
- **wordcloud**: Frequently used words.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| audience_content_id | string | The ID of the audience content to retrieve. | Yes
</details>
<details>
<summary>report-summary</summary>

**Description**:

```
Generates a comprehensive summary of an Audiense report, including segment details, top insights, and influencers.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| report_id | string | The ID of the intelligence report to summarize. | Yes
</details>

## 📝 Prompts (3)
<details>
<summary>audiense-demo</summary>

**Description**:

```
A prompt to extract marketing insights and audience understanding from Audiense reports through demographic, cultural, influencer, and content analysis.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| reportName | The name or id of the Audiense Insights report. |Yes |
<details>
<summary>audiense-demo2</summary>

**Description**:

```
A prompt to extract marketing insights and audience understanding from Audiense reports through demographic, cultural, influencer, and content analysis.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| reportName | The name or id of the Audiense Insights report. |Yes |
<details>
<summary>segment-matching</summary>

**Description**:

```
A prompt to match and compare audience segments across Audiense reports, identifying similarities, unique traits, and key insights based on demographics, interests, influencers, and engagement patterns.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| brand1 | The name or ID of the Audiense Insights report for the first brand to analyze. |Yes |
| brand2 | The name or ID of the Audiense Insights report for the second brand to analyze. |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | audiense-demo | description | 40332d402fd30cba47b01f05854cd3ac4190f1ebd000a3e627944aa6106cc4cf |
| prompts | audiense-demo | reportName | 008df0ad49d0fb8b21990591531178f15c5e776f7610c955622aae994343a3d5 |
| prompts | audiense-demo2 | description | 40332d402fd30cba47b01f05854cd3ac4190f1ebd000a3e627944aa6106cc4cf |
| prompts | audiense-demo2 | reportName | 008df0ad49d0fb8b21990591531178f15c5e776f7610c955622aae994343a3d5 |
| prompts | segment-matching | description | 75c417a3e9d24b21d54873676aecfe238336848fadba9e6a495b8fcefb48fb33 |
| prompts | segment-matching | brand1 | 4f2dd26ed146c9a5875a6c46a69bef687be6347df077c521e568921b2cd45794 |
| prompts | segment-matching | brand2 | 15390d336c6cb0a03f341eae3cf943d8638ca54a0df54a9313269701fde9565d |
| tools | compare-audience-influencers | description | c75816db3b063857d0a1be18ea81eebf28c80c972700fcaea7471314a11fc05a |
| tools | compare-audience-influencers | audience_influencers_id | 6a182663654dbd32044ce7137d6059173650cf45f332a55b4939b889aa37a9b2 |
| tools | compare-audience-influencers | baseline_audience_influencers_id | fe6b66e7d340edfbe5cc9a28b1c583d87a65874bb40c6fd2dfbd7062dd0bcf18 |
| tools | compare-audience-influencers | bio_keyword | b277a92bf7daf1d81b95f37f44d051b27e5054e4954ac444d2d9276136c62ccc |
| tools | compare-audience-influencers | categories | 16b80f11515361087542af6e4d202d4aed8e7d4e5c9ef5b9ec6804e04fa113bc |
| tools | compare-audience-influencers | count | 90b3761c6274f71e1bf83dc8399db65d775510fe5be4ad439caeff7e168f4c8a |
| tools | compare-audience-influencers | countries | 693fd227a244fa9e5c04e1ed03beab0357849504e4e9bcb3d987859471814d85 |
| tools | compare-audience-influencers | cursor | 76f7b7f4f1f3eeddedc1f7f8026751253a0d4050089636459f31ab297c14604c |
| tools | compare-audience-influencers | entity_type | 00a30fe5b0c7e442cc474952e80c0d505ac5f265989235f29199763ed855f7b1 |
| tools | compare-audience-influencers | followers_max | 9e46adf0d9ab5c1f7accd877e39e2a99d9abc4bef14b78c8fc47d4c5b8841e36 |
| tools | compare-audience-influencers | followers_min | 60e38f5660b3522f0bc107da75c0620410cea959a5a4dd4a8f3972764cecd831 |
| tools | get-audience-content | description | 1df83209e1715907fd786ec04830f159d18cd474ed2d18adb329c1f20988dd76 |
| tools | get-audience-content | audience_content_id | aa09d5835896f5cae1da7454aa172cbba896adc28d01136beada3e37538a9873 |
| tools | get-audience-insights | description | 6500098a020aaa1464aeba184121ed9459cce38194ec4c996214de9af5048d46 |
| tools | get-audience-insights | audience_insights_id | f4eb81ba76c43facec24c4a7e2a802247a835552c63e1b252a75ecffd8801117 |
| tools | get-audience-insights | insights | dc947e232680d8e5e7e464f74d88f25cb2773654b6ad5c3ff394e0ccf6d1e610 |
| tools | get-baselines | description | db84b495243ab59a99b6c3729fd794ee9813c32062bb2bce7698673dd2f9a889 |
| tools | get-baselines | country | ece3252c19a249446d1f3797b3a85cadcde97492454f87c2e3bb1f9a9102d78e |
| tools | get-categories | description | 3440182ccc2168841de5bb024a4d077fa90b8159066c7c43e0db967d81eaf5b1 |
| tools | get-report-info | description | 1adba7e29e76da8c61f273ef4ae10e3b0f813b3082d1406029bc1d5fc3cc24eb |
| tools | get-report-info | report_id | 0847aac6ca19c3c9f96e268eb279f3607d58b76358f71a1069c2c36396990f5b |
| tools | get-reports | description | d80396ec200a048aeb6ff9228027166c40d523337fd0d8bece3c9c6583a76f70 |
| tools | report-summary | description | fde00c8859afb7cf357bf670411fb579213b05dbc4c325bec729975b2cf1a26c |
| tools | report-summary | report_id | 5e571c91a4591b6f41c54f39370a77e1eb7d7237b6fc89c46e620021c1c47841 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
