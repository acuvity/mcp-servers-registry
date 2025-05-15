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


# What is mcp-server-aws-cost-analysis?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-cost-analysis/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-cost-analysis/0.1.11?logo=docker&logoColor=fff&label=0.1.11)](https://hub.docker.com/r/acuvity/mcp-server-aws-cost-analysis)
[![PyPI](https://img.shields.io/badge/0.1.11-3775A9?logo=pypi&logoColor=fff&label=awslabs.cost-analysis-mcp-server)](https://pypi.org/project/awslabs.cost-analysis-mcp-server/)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cost-analysis&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AWS_PROFILE%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cost-analysis%3A0.1.11%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Analyze CDK projects to identify AWS services used and get pricing information.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.cost-analysis-mcp-server original [sources](https://pypi.org/project/awslabs.cost-analysis-mcp-server/).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-cost-analysis/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/charts/mcp-server-aws-cost-analysis/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.cost-analysis-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/charts/mcp-server-aws-cost-analysis#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-aws-cost-analysis scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cost-analysis&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AWS_PROFILE%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cost-analysis%3A0.1.11%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-cost-analysis": {
        "env": {
          "AWS_PROFILE": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "AWS_PROFILE",
          "docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11"
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
    "acuvity-mcp-server-aws-cost-analysis": {
      "env": {
        "AWS_PROFILE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_PROFILE",
        "docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11"
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
    "acuvity-mcp-server-aws-cost-analysis": {
      "env": {
        "AWS_PROFILE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_PROFILE",
        "docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11"
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
    "acuvity-mcp-server-aws-cost-analysis": {
      "env": {
        "AWS_PROFILE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_PROFILE",
        "docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11"
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
    "acuvity-mcp-server-aws-cost-analysis": {
      "env": {
        "AWS_PROFILE": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_PROFILE",
        "docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11"
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
        "env": {"AWS_PROFILE":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","AWS_PROFILE","docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11"]
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
  - `AWS_PROFILE` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e AWS_PROFILE docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e AWS_PROFILE docker.io/acuvity/mcp-server-aws-cost-analysis:0.1.11
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-cost-analysis": {
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
    "acuvity-mcp-server-aws-cost-analysis": {
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

**Mandatory Environment variables**:
  - `AWS_PROFILE` environment variable to be set by env.AWS_PROFILE

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-cost-analysis --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-cost-analysis --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-cost-analysis oci://docker.io/acuvity/mcp-server-aws-cost-analysis --version 1.0.0
```

From there your MCP server mcp-server-aws-cost-analysis will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-cost-analysis` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-analysis/charts/mcp-server-aws-cost-analysis/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (6)
<details>
<summary>analyze_cdk_project</summary>

**Description**:

```
Analyze a CDK project to identify AWS services used. This tool dynamically extracts service information from CDK constructs without relying on hardcoded service mappings.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_path | string | not set | Yes
</details>
<details>
<summary>analyze_terraform_project</summary>

**Description**:

```
Analyze a Terraform project to identify AWS services used. This tool dynamically extracts service information from Terraform resource declarations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_path | string | not set | Yes
</details>
<details>
<summary>get_pricing_from_web</summary>

**Description**:

```
Get pricing information from AWS pricing webpage. Service codes typically use lowercase with hyphens format (e.g., "opensearch-service" for both OpenSearch and OpenSearch Serverless, "api-gateway", "lambda"). Note that some services like OpenSearch Serverless are part of broader service codes (use "opensearch-service" not "opensearch-serverless"). Important: Web service codes differ from API service codes (e.g., use "opensearch-service" for web but "AmazonES" for API). When retrieving foundation model pricing, always use the latest models for comparison rather than specific named ones that may become outdated.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| service_code | string | not set | Yes
</details>
<details>
<summary>get_pricing_from_api</summary>

**Description**:

```
Get pricing information from AWS Price List API.
    Service codes for API often differ from web URLs.
    (e.g., use "AmazonES" for OpenSearch, not "AmazonOpenSearchService").
    List of service codes can be found with `curl 'https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json' | jq -r '.offers| .[] | .offerCode'`
    IMPORTANT GUIDELINES:
    - When retrieving foundation model pricing, always use the latest models for comparison
    - For database compatibility with services, only include confirmed supported databases
    - Providing less information is better than giving incorrect information

    Filters should be provided in the format:
    [
        {
            'Field': 'feeCode',
            'Type': 'TERM_MATCH',
            'Value': 'Glacier:EarlyDelete'
        },
        {
            'Field': 'regionCode',
            'Type': 'TERM_MATCH',
            'Value': 'ap-southeast-1'
        }
    ]
    Details of the filter can be found at https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_pricing_Filter.html
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | any | not set | No
| region | string | not set | Yes
| service_code | string | not set | Yes
</details>
<details>
<summary>get_bedrock_patterns</summary>

**Description**:

```
Get architecture patterns for Amazon Bedrock applications, including component relationships and cost considerations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ctx | any | not set | No
</details>
<details>
<summary>generate_cost_report</summary>

**Description**:

```
Generate a detailed cost analysis report based on pricing data for one or more AWS services.

This tool requires AWS pricing data and provides options for adding detailed cost information.

IMPORTANT REQUIREMENTS:
- ALWAYS include detailed unit pricing information (e.g., "$0.0008 per 1K input tokens")
- ALWAYS show calculation breakdowns (unit price × usage = total cost)
- ALWAYS specify the pricing model (e.g., "ON DEMAND")
- ALWAYS list all assumptions and exclusions explicitly

Output Format Options:
- 'markdown' (default): Generates a well-formatted markdown report
- 'csv': Generates a CSV format report with sections for service information, unit pricing, cost calculations, etc.

Example usage:

```json
{
  // Required parameters
  "pricing_data": {
    // This should contain pricing data retrieved from get_pricing_from_web or get_pricing_from_api
    "status": "success",
    "service_name": "bedrock",
    "data": "... pricing information ...",
    "message": "Retrieved pricing for bedrock from AWS Pricing url"
  },
  "service_name": "Amazon Bedrock",

  // Core parameters (commonly used)
  "related_services": ["Lambda", "S3"],
  "pricing_model": "ON DEMAND",
  "assumptions": [
    "Standard ON DEMAND pricing model",
    "No caching or optimization applied",
    "Average request size of 4KB"
  ],
  "exclusions": [
    "Data transfer costs between regions",
    "Custom model training costs",
    "Development and maintenance costs"
  ],
  "output_file": "cost_analysis_report.md",  // or "cost_analysis_report.csv" for CSV format
  "format": "markdown",  // or "csv" for CSV format

  // Advanced parameter for complex scenarios
  "detailed_cost_data": {
    "services": {
      "Amazon Bedrock Foundation Models": {
        "usage": "Processing 1M input tokens and 500K output tokens with Claude 3.5 Haiku",
        "estimated_cost": "$80.00",
        "free_tier_info": "No free tier for Bedrock foundation models",
        "unit_pricing": {
          "input_tokens": "$0.0008 per 1K tokens",
          "output_tokens": "$0.0016 per 1K tokens"
        },
        "usage_quantities": {
          "input_tokens": "1,000,000 tokens",
          "output_tokens": "500,000 tokens"
        },
        "calculation_details": "$0.0008/1K × 1,000K input tokens + $0.0016/1K × 500K output tokens = $80.00"
      },
      "AWS Lambda": {
        "usage": "6,000 requests per month with 512 MB memory",
        "estimated_cost": "$0.38",
        "free_tier_info": "First 12 months: 1M requests/month free",
        "unit_pricing": {
          "requests": "$0.20 per 1M requests",
          "compute": "$0.0000166667 per GB-second"
        },
        "usage_quantities": {
          "requests": "6,000 requests",
          "compute": "6,000 requests × 1s × 0.5GB = 3,000 GB-seconds"
        },
        "calculation_details": "$0.20/1M × 0.006M requests + $0.0000166667 × 3,000 GB-seconds = $0.38"
      }
    }
  },

  // Recommendations parameter - can be provided directly or generated
  "recommendations": {
    "immediate": [
      "Optimize prompt engineering to reduce token usage for Claude 3.5 Haiku",
      "Configure Knowledge Base OCUs based on actual query patterns",
      "Implement response caching for common queries to reduce token usage"
    ],
    "best_practices": [
      "Monitor OCU utilization metrics and adjust capacity as needed",
      "Use prompt caching for repeated context across API calls",
      "Consider provisioned throughput for predictable workloads"
    ]
  }
}
```

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assumptions | any | not set | No
| ctx | any | not set | No
| detailed_cost_data | any | not set | No
| exclusions | any | not set | No
| format | string | not set | No
| output_file | any | not set | No
| pricing_data | object | not set | Yes
| pricing_model | string | not set | No
| recommendations | any | not set | No
| related_services | any | not set | No
| service_name | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | analyze_cdk_project | description | 0e59249945ebaa4c942e4eed57fa76a9839a4b7eff29209dc040885df4c7870c |
| tools | analyze_terraform_project | description | a8ceeb0db4ad6ad0150cef1304093130bb62aef8cbc3f87bc9bad4ef9b11c865 |
| tools | generate_cost_report | description | 06f4b7e6b649a5b590f75b53abb7a0ac52f98c4f8ea4eb94087da149dcfb3191 |
| tools | get_bedrock_patterns | description | 24a3e539acdc6692395ef35f1b997e07afb0786c7baf7d894c865609791b9d00 |
| tools | get_pricing_from_api | description | d2a4a78b0f549948dd23f6afdf0f7666f230bbfcf07fc5512873d33bbf6df121 |
| tools | get_pricing_from_web | description | 8e993e44283a59883ac8ca582f22deb90659d6f30af4f7e41aaa947a17dc9736 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
