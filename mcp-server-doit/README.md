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


# What is mcp-server-doit?

[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-doit/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-doit/0.1.29?logo=docker&logoColor=fff&label=0.1.29)](https://hub.docker.com/r/acuvity/mcp-server-doit)
[![PyPI](https://img.shields.io/badge/0.1.29-3775A9?logo=pypi&logoColor=fff&label=@doitintl/doit-mcp-server)](https://github.com/doitintl/doit-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-doit/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-doit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DOIT_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-doit%3A0.1.29%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Access DoiT API for analyzing cloud data and troubleshooting.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @doitintl/doit-mcp-server original [sources](https://github.com/doitintl/doit-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-doit/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-doit/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-doit/charts/mcp-server-doit/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @doitintl/doit-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-doit/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-doit scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `DOIT_API_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/doitintl/doit-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-doit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DOIT_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-doit%3A0.1.29%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-doit": {
        "env": {
          "DOIT_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "DOIT_API_KEY",
          "docker.io/acuvity/mcp-server-doit:0.1.29"
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
    "acuvity-mcp-server-doit": {
      "env": {
        "DOIT_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DOIT_API_KEY",
        "docker.io/acuvity/mcp-server-doit:0.1.29"
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
    "acuvity-mcp-server-doit": {
      "env": {
        "DOIT_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DOIT_API_KEY",
        "docker.io/acuvity/mcp-server-doit:0.1.29"
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
    "acuvity-mcp-server-doit": {
      "env": {
        "DOIT_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DOIT_API_KEY",
        "docker.io/acuvity/mcp-server-doit:0.1.29"
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
    "acuvity-mcp-server-doit": {
      "env": {
        "DOIT_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "DOIT_API_KEY",
        "docker.io/acuvity/mcp-server-doit:0.1.29"
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
        "env": {"DOIT_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","DOIT_API_KEY","docker.io/acuvity/mcp-server-doit:0.1.29"]
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
- arguments: `run -i --rm --read-only -e DOIT_API_KEY docker.io/acuvity/mcp-server-doit:0.1.29`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e DOIT_API_KEY docker.io/acuvity/mcp-server-doit:0.1.29
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-doit": {
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
    "acuvity-mcp-server-doit": {
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
  - `DOIT_API_KEY` secret to be set as secrets.DOIT_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-doit --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-doit --version 1.0.0
````

Install with helm

```console
helm install mcp-server-doit oci://docker.io/acuvity/mcp-server-doit --version 1.0.0
```

From there your MCP server mcp-server-doit will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-doit` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-doit/charts/mcp-server-doit/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>get_cloud_incidents</summary>

**Description**:

```
Get cloud incidents
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter | string | Filter string in format 'key:value|key:value'. Multiple values for same key are treated as OR, different keys as AND. Example: 'platform:google-cloud|status:active' or 'platform:google-cloud|platform:amazon-web-services' | No
| pageToken | string | Token for pagination. Use this to get the next page of results. | No
| platform | string | platform name | No
</details>
<details>
<summary>get_cloud_incident</summary>

**Description**:

```
Get a specific cloud incident by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | incident ID | Yes
</details>
<details>
<summary>get_anomalies</summary>

**Description**:

```
List anomalies detected in cloud costs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter | string | Filter string in format 'key:value|key:value'. Multiple values for same key are treated as OR, different keys as AND. | No
| pageToken | string | Token for pagination. Use this to get the next page of results. | No
</details>
<details>
<summary>get_anomaly</summary>

**Description**:

```
Get a specific anomaly by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | anomaly ID | Yes
</details>
<details>
<summary>list_reports</summary>

**Description**:

```
Lists Cloud Analytics reports that your account has access to
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter | string | Filter string in format 'key:value|key:value'. Multiple values for same key are treated as OR, different keys as AND. Possible filter keys: reportName, owner, type, updateTime, use the filter property only if you know for sure the value is a valid filter key, do not guess it. | No
| pageToken | string | Token for pagination. Use this to get the next page of results. | No
</details>
<details>
<summary>run_query</summary>

**Description**:

```
Runs a report query with the specified configuration without persisting it. 
    Fields that are not populated will use their default values if needed.
    Use the dimension tool before running the query to get the list of dimensions and their types.
    If possible, use `timeRange` instead of `customTimeRange` when no specific dates are given.
    Example for cost report:
    {
      "config": {
        "dataSource": "billing",
        "metric": {"type": "basic", "value": "cost"},
        "timeRange": {"mode": "last", "amount": 1, "unit": "month", "includeCurrent": true},
        "group": [{"id": "service_description", "type": "fixed", "limit": {"metric": {"type": "basic", "value": "cost"}, "sort": "desc", "value": 10}}]
      }
    }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| config | object | The configuration for the query, including dimensions, metrics, filters, etc. | Yes
</details>
<details>
<summary>get_report_results</summary>

**Description**:

```
Get the results of a specific report by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The ID of the report to retrieve results for | Yes
</details>
<details>
<summary>validate_user</summary>

**Description**:

```
Validates the current API user and returns domain and email information
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_dimensions</summary>

**Description**:

```
Lists Cloud Analytics dimensions that your account has access to. Use this tool to get the dimensions that you can use in the run_query tool. Use filter to narrow down the results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter | string | Filter string (optional) in format 'key:value|key:value'. Multiple values for same key are treated as OR, different keys as AND. The fields eligible for filtering are: type, label, key. 
          use the filter parameter only if you know the exact value of the key, otherwise the filter should be empty. | No
| pageToken | string | Token for pagination. Use this to get the next page of results. | No
</details>
<details>
<summary>get_dimension</summary>

**Description**:

```
Get a specific Cloud Analytics dimension by type and ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Dimension id | Yes
| type | string | Dimension type | Yes
</details>
<details>
<summary>list_tickets</summary>

**Description**:

```
List support tickets from DoiT using the support API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pageSize | number | Number of tickets to return per page | No
| pageToken | string | Page token for pagination | No
</details>
<details>
<summary>create_ticket</summary>

**Description**:

```
Create a new support ticket in DoiT using the support API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ticket | object | not set | Yes
</details>
<details>
<summary>list_invoices</summary>

**Description**:

```
List all current and historical invoices for your organization from the DoiT API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pageToken | string | Token for pagination. Use this to get the next page of results. | No
</details>
<details>
<summary>get_invoice</summary>

**Description**:

```
Retrieve the full details of an invoice specified by the invoice number from the DoiT API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The ID of the invoice to retrieve. | Yes
</details>

## 📝 Prompts (10)
<details>
<summary>Filter Fields Reference</summary>

**Description**:

```
<no value>
```
<details>
<summary>Generate Report Document</summary>

**Description**:

```
<no value>
```
<details>
<summary>Query Best Practice</summary>

**Description**:

```
<no value>
```
<details>
<summary>Document Output Reminder</summary>

**Description**:

```
<no value>
```
<details>
<summary>Generate Report Command</summary>

**Description**:

```
<no value>
```
<details>
<summary>Generate Anomalies Document</summary>

**Description**:

```
<no value>
```
<details>
<summary>Dimension Usage Guidance</summary>

**Description**:

```
<no value>
```
<details>
<summary>Create Ticket</summary>

**Description**:

```
<no value>
```
<details>
<summary>Generate Invoice Details Document</summary>

**Description**:

```
<no value>
```
<details>
<summary>DoiT MCP Server tools output</summary>

**Description**:

```
<no value>
```

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | Create Ticket | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Dimension Usage Guidance | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Document Output Reminder | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | DoiT MCP Server tools output | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Filter Fields Reference | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Generate Anomalies Document | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Generate Invoice Details Document | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Generate Report Command | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Generate Report Document | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Query Best Practice | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | create_ticket | description | b0990b45b3f312d4cf1c6756d7e9f8ed2f143385ba7130ec35fa83ab15be317c |
| tools | get_anomalies | description | 5ddc31a7b26a361ee8d3772187396b1159bcbcf4414fd664182ad001a3f655e6 |
| tools | get_anomalies | filter | 2852306a27eee8a8baae33a45b1c208a19e278ef4e5bae15daa3b97845ce8350 |
| tools | get_anomalies | pageToken | 13008295d9364bfd512878a26f7c86cc9ba7773ded8e66340fb6751b58e18800 |
| tools | get_anomaly | description | c715dacb2c5847b249ce2e14e62daaea3aba6f7d9c57d131470d5bcdcdae7aa7 |
| tools | get_anomaly | id | b4c6965122bd1c23d7f2df9b95f082619385d826521a4b0949211080d9e972ef |
| tools | get_cloud_incident | description | 8a8fadf4a373df5df7d7f207d3a6a8f4d205d9d9bea6b604df9d140ca736b047 |
| tools | get_cloud_incident | id | 78da53d5d4c5dceaf57454fcbc961ae3bca21cb9aa7c33c8989487ecaea7c0aa |
| tools | get_cloud_incidents | description | 5d557b142d884c360023eb4cdc9241b47ac965e4a2771b7bdb315c770ffdcd79 |
| tools | get_cloud_incidents | filter | 0674b204842dfcc97375b88e13c9023a303e365950bced8f851da7ee9df0b7bc |
| tools | get_cloud_incidents | pageToken | 13008295d9364bfd512878a26f7c86cc9ba7773ded8e66340fb6751b58e18800 |
| tools | get_cloud_incidents | platform | dc938a1de9751d61da85b8c1132accb0bbee58708b7727191de1c28a0fb66317 |
| tools | get_dimension | description | ad58fcd1ec12bee78c54cc4765825e19a8b6991cf75d8aa1157a3440931faacd |
| tools | get_dimension | id | 80b84b094a100283273c3019ca6bd5a290e9a4c1e4b9b8c41848d64b589bd688 |
| tools | get_dimension | type | 2beb12edc035ab8715c455d09f00f0ddfd54c63a4b6840aa1be51048ba7f45e4 |
| tools | get_invoice | description | dfabef5feba78c82057d06aa90e2683473266acd31f2425f920778a10ab5796e |
| tools | get_invoice | id | d1619687a9b7811554b2b52a162c5db0636d6c1a69c1afa7159728979f6c0dc6 |
| tools | get_report_results | description | 6924c4f21ff6a139b4bcdaf96ded8f1cfffea347515aa19c9860751d83c63746 |
| tools | get_report_results | id | d5825ce03b2d662974a266552fa04f002f835a37310474dc792a6f42ef307fc6 |
| tools | list_dimensions | description | e9ec3b8f2f7cffefdb7d1a7a8f1c848ea2e880af63d71d3cb7367dc42a660efe |
| tools | list_dimensions | filter | fe1ac58d13ee5bc995c0cc7962e299a6958a8acfcfe9b300cdc234a3356e87d8 |
| tools | list_dimensions | pageToken | 13008295d9364bfd512878a26f7c86cc9ba7773ded8e66340fb6751b58e18800 |
| tools | list_invoices | description | cb1a08ab2a5c036029c0e53bc8d0fcdb51d94f9f706b41e9f966dc74c4aa73f8 |
| tools | list_invoices | pageToken | 13008295d9364bfd512878a26f7c86cc9ba7773ded8e66340fb6751b58e18800 |
| tools | list_reports | description | f96f214c9f0fef087c15df548a662993fabaf0763b2926c8f2f92b45f0f27e9e |
| tools | list_reports | filter | 2df2a1056ff6a1005a107ca3112ff4c9104123b2a52d3e8cca9b9556f56b9824 |
| tools | list_reports | pageToken | 13008295d9364bfd512878a26f7c86cc9ba7773ded8e66340fb6751b58e18800 |
| tools | list_tickets | description | 49781956cac6e31b3a74dba206b22151141bb2ee6a4bc71450f91e5732a889b8 |
| tools | list_tickets | pageSize | e05aad3d415e9d87a79b7110464ecd80fb864213d00a8ab7345d8cded3172b03 |
| tools | list_tickets | pageToken | 5296c3041da463734e7ae218bd23d6b450eb81963799837041d74cebdf48e4e5 |
| tools | run_query | description | 8a22e414f5512431140aef2901e09bf33b1964fc51a22f189fdfc6ed267e5eb9 |
| tools | run_query | config | b52ccad97d2b886d7bb949f12b9b0d3d73e1ddacc0f9347dda6d4808ccfe8b99 |
| tools | validate_user | description | 33b088747d3d7660516645ec1d7b9626f650f45741603cbf1dfe2f4adc65a31a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
