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


# What is mcp-server-devhub?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-devhub/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-devhub/0.3.0?logo=docker&logoColor=fff&label=0.3.0)](https://hub.docker.com/r/acuvity/mcp-server-devhub)
[![PyPI](https://img.shields.io/badge/0.3.0-3775A9?logo=pypi&logoColor=fff&label=devhub-cms-mcp)](https://github.com/devhub/devhub-cms-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-devhub&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DEVHUB_API_KEY%22%2C%22-e%22%2C%22DEVHUB_API_SECRET%22%2C%22-e%22%2C%22DEVHUB_BASE_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-devhub%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Manage content and operations in DevHub CMS using MCP.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from devhub-cms-mcp original [sources](https://github.com/devhub/devhub-cms-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-devhub/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/charts/mcp-server-devhub/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure devhub-cms-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/charts/mcp-server-devhub#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-devhub scope of operation the intended usage is to run natively on the targeted machine to access local resources.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-devhub&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DEVHUB_API_KEY%22%2C%22-e%22%2C%22DEVHUB_API_SECRET%22%2C%22-e%22%2C%22DEVHUB_BASE_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-devhub%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-devhub": {
        "env": {
          "DEVHUB_API_KEY": "TO_BE_SET",
          "DEVHUB_API_SECRET": "TO_BE_SET",
          "DEVHUB_BASE_URL": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "DEVHUB_API_KEY",
          "-e",
          "DEVHUB_API_SECRET",
          "-e",
          "DEVHUB_BASE_URL",
          "docker.io/acuvity/mcp-server-devhub:0.3.0"
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
    "acuvity-mcp-server-devhub": {
      "env": {
        "DEVHUB_API_KEY": "TO_BE_SET",
        "DEVHUB_API_SECRET": "TO_BE_SET",
        "DEVHUB_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DEVHUB_API_KEY",
        "-e",
        "DEVHUB_API_SECRET",
        "-e",
        "DEVHUB_BASE_URL",
        "docker.io/acuvity/mcp-server-devhub:0.3.0"
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
    "acuvity-mcp-server-devhub": {
      "env": {
        "DEVHUB_API_KEY": "TO_BE_SET",
        "DEVHUB_API_SECRET": "TO_BE_SET",
        "DEVHUB_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DEVHUB_API_KEY",
        "-e",
        "DEVHUB_API_SECRET",
        "-e",
        "DEVHUB_BASE_URL",
        "docker.io/acuvity/mcp-server-devhub:0.3.0"
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
    "acuvity-mcp-server-devhub": {
      "env": {
        "DEVHUB_API_KEY": "TO_BE_SET",
        "DEVHUB_API_SECRET": "TO_BE_SET",
        "DEVHUB_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DEVHUB_API_KEY",
        "-e",
        "DEVHUB_API_SECRET",
        "-e",
        "DEVHUB_BASE_URL",
        "docker.io/acuvity/mcp-server-devhub:0.3.0"
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
    "acuvity-mcp-server-devhub": {
      "env": {
        "DEVHUB_API_KEY": "TO_BE_SET",
        "DEVHUB_API_SECRET": "TO_BE_SET",
        "DEVHUB_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DEVHUB_API_KEY",
        "-e",
        "DEVHUB_API_SECRET",
        "-e",
        "DEVHUB_BASE_URL",
        "docker.io/acuvity/mcp-server-devhub:0.3.0"
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
        "env": {"DEVHUB_API_KEY":"TO_BE_SET","DEVHUB_API_SECRET":"TO_BE_SET","DEVHUB_BASE_URL":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","DEVHUB_API_KEY","-e","DEVHUB_API_SECRET","-e","DEVHUB_BASE_URL","docker.io/acuvity/mcp-server-devhub:0.3.0"]
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
  - `DEVHUB_API_KEY` required to be set
  - `DEVHUB_API_SECRET` required to be set
  - `DEVHUB_BASE_URL` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e DEVHUB_API_KEY -e DEVHUB_API_SECRET -e DEVHUB_BASE_URL docker.io/acuvity/mcp-server-devhub:0.3.0`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e DEVHUB_API_KEY -e DEVHUB_API_SECRET -e DEVHUB_BASE_URL docker.io/acuvity/mcp-server-devhub:0.3.0
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-devhub": {
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
    "acuvity-mcp-server-devhub": {
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
  - `DEVHUB_API_KEY` secret to be set as secrets.DEVHUB_API_KEY either by `.value` or from existing with `.valueFrom`
  - `DEVHUB_API_SECRET` secret to be set as secrets.DEVHUB_API_SECRET either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `DEVHUB_BASE_URL` environment variable to be set by env.DEVHUB_BASE_URL

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
````

Install with helm

```console
helm install mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
```

From there your MCP server mcp-server-devhub will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-devhub` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/charts/mcp-server-devhub/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>get_hours_of_operation</summary>

**Description**:

```
Get the hours of operation for a DevHub location

    Returns a list of items representing days of the week

    Except for the special case formatting, this object is a list of 7 items which represent each day.

    Each day can can have one-four time ranges. For example, two time ranges denotes a "lunch-break". No time ranges denotes closed.

    Examples:
    9am-5pm [["09:00:00", "17:00:00"]]
    9am-12pm and 1pm-5pm [["09:00:00", "12:00:00"], ["13:00:00", "17:00:00"]]
    Closed - an empty list []

    Args:
        location_id: DevHub Location ID
        hours_type: Defaults to 'primary' unless the user specifies a different type
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hours_type | string | not set | No
| location_id | integer | not set | Yes
</details>
<details>
<summary>get_businesses</summary>

**Description**:

```
Get all businesses within the DevHub account

    Returns a list of businesses with the following fields:
    - id: Business ID that can be used in the other tools
    - business_name: Business name

    If only one business exists in the account, you can assume that the user wants to use that business for any business_id related tools.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_locations</summary>

**Description**:

```
Get all locations for a business

    Returns a list of locations with the following fields:
    - id: Location ID that can be used in the other tools
    - location_name: Location name
    - location_url: Location URL in DevHub
    - street: Street address
    - city: City
    - state: State
    - country: Country
    - postal_code: Postal code
    - lat: Latitude
    - lon: Longitude
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| business_id | integer | not set | Yes
</details>
<details>
<summary>update_hours</summary>

**Description**:

```
Update the hours of operation for a DevHub location

    Send a list of items representing days of the week

    Except for the special case formatting, this object is a list of 7 items which represent each day.

    Each day can can have one-four time ranges. For example, two time ranges denotes a "lunch-break". No time ranges denotes closed.

    Examples:
    9am-5pm [["09:00:00", "17:00:00"]]
    9am-12pm and 1pm-5pm [["09:00:00", "12:00:00"], ["13:00:00", "17:00:00"]]
    Closed - an empty list []

    Args:
        location_id: DevHub Location ID
        new_hours: Structured format of the new hours
        hours_type: Defaults to 'primary' unless the user specifies a different type
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hours_type | string | not set | No
| location_id | integer | not set | Yes
| new_hours | array | not set | Yes
</details>
<details>
<summary>site_from_url</summary>

**Description**:

```
Get the DevHub site ID from a URL.

    Can prompt the user for the URL instead of passing a site_id.

    Returns details about the Site matches the URL that can be used in the other tools.
    - Site ID: ID of the DevHub site
    - Site URL: URL of the DevHub site
    - Site Location IDs: List of location IDs associated with the site

    Args:
        url: URL of the DevHub site, all lowercase and ends with a slash
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>upload_image</summary>

**Description**:

```
Upload an image to the DevHub media gallery

    Supports webp, jpeg and png images

    Args:
        base64_image_content: Base 64 encoded content of the image file
        filename: Filename including the extension
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base64_image_content | string | not set | Yes
| filename | string | not set | Yes
</details>
<details>
<summary>get_blog_post</summary>

**Description**:

```
Get a single blog post

    Args:
        post_id: Blog post id
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| post_id | integer | not set | Yes
</details>
<details>
<summary>create_blog_post</summary>

**Description**:

```
Create a new blog post

    Args:
        site_id: Website ID where the post will be published. Prompt the user for this ID.
        title: Blog post title
        content: HTML content of blog post. Should not include a <h1> tag, only h2+
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| site_id | integer | not set | Yes
| title | string | not set | Yes
</details>
<details>
<summary>update_blog_post</summary>

**Description**:

```
Update a single blog post

    Args:
        post_id: Blog post ID
        title: Blog post title
        content: HTML content of blog post. Should not include a <h1> tag, only h2+
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | No
| post_id | integer | not set | Yes
| title | string | not set | No
</details>
<details>
<summary>get_nearest_location</summary>

**Description**:

```
Get the nearest DevHub location

    Args:
        business_id: DevHub Business ID associated with the location. Prompt the user for this ID
        latitude: Latitude of the location
        longitude: Longitude of the location
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| business_id | integer | not set | Yes
| latitude | number | not set | Yes
| longitude | number | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_blog_post | description | 9e39fbe4f8a7ac6401cf20a346550d90f1dc92afdb9c443939d4a9067f6a8751 |
| tools | get_blog_post | description | 871f9785dccca0da160cf2f62af387303ce45d7a74fac831819388650d399ec8 |
| tools | get_businesses | description | 86b9d98b2e4c8166181626185561b4987e06d267f6402d0238d06e77f91d952b |
| tools | get_hours_of_operation | description | 23e21cb76d1da66b30d8a5e508c714865ce164ca7ae403c69a9af895558d9f28 |
| tools | get_locations | description | 621b4235ef8d26c795d37799148d6d2210a4694fa3cd392fbe2b072584e9eb69 |
| tools | get_nearest_location | description | 55b3ad22cc6a57aa822c3b4580d309ed113f11b5d49ce09008571b1b601c0f9d |
| tools | site_from_url | description | 6fe1b9682bb8f0862fbc692516a2460656da288943ef82258c249b5e24fc3ad0 |
| tools | update_blog_post | description | f404f48ef275837efeaf11092055b954cb470e62f086379370ef36268a0b8e61 |
| tools | update_hours | description | c3c77feafaa539b2cc464e8cdca1edd396646478c172eaabe38d2781ad25a4bf |
| tools | upload_image | description | d09cf5af3e7579af477b3f7652288da152948d0d02c6e9be0c8d1244924f4c69 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
