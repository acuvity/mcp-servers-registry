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


# What is mcp-server-aws-cost-explorer?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-cost-explorer/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-cost-explorer/0.0.17?logo=docker&logoColor=fff&label=0.0.17)](https://hub.docker.com/r/acuvity/mcp-server-aws-cost-explorer)
[![PyPI](https://img.shields.io/badge/0.0.17-3775A9?logo=pypi&logoColor=fff&label=awslabs.cost-explorer-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/cost-explorer-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-cost-explorer/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cost-explorer&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cost-explorer%3A0.0.17%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for analyzing AWS costs and usage data through the AWS Cost Explorer API

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.cost-explorer-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/cost-explorer-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-cost-explorer/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-explorer/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-explorer/charts/mcp-server-aws-cost-explorer/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.cost-explorer-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-explorer/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-aws-cost-explorer scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `AWS_PROFILE` optional (not set)
  - `AWS_ACCESS_KEY_ID` optional (not set)
  - `AWS_SECRET_ACCESS_KEY` optional (not set)
  - `AWS_SESSION_TOKEN` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/cost-explorer-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cost-explorer&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cost-explorer%3A0.0.17%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-cost-explorer": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17"
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
    "acuvity-mcp-server-aws-cost-explorer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17"
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
    "acuvity-mcp-server-aws-cost-explorer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17"
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
    "acuvity-mcp-server-aws-cost-explorer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17"
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
    "acuvity-mcp-server-aws-cost-explorer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17"
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
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-aws-cost-explorer:0.0.17
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-cost-explorer": {
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
    "acuvity-mcp-server-aws-cost-explorer": {
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

**Optional Secrets**:
  - `AWS_SECRET_ACCESS_KEY` secret to be set as secrets.AWS_SECRET_ACCESS_KEY either by `.value` or from existing with `.valueFrom`
  - `AWS_SESSION_TOKEN` secret to be set as secrets.AWS_SESSION_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `AWS_PROFILE=""` environment variable can be changed with env.AWS_PROFILE=""
  - `AWS_ACCESS_KEY_ID=""` environment variable can be changed with env.AWS_ACCESS_KEY_ID=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-cost-explorer --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-cost-explorer --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-cost-explorer oci://docker.io/acuvity/mcp-server-aws-cost-explorer --version 1.0.0
```

From there your MCP server mcp-server-aws-cost-explorer will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-cost-explorer` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cost-explorer/charts/mcp-server-aws-cost-explorer/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>get_today_date</summary>

**Description**:

```
Retrieve current date information in UTC time zone.

    This tool retrieves the current date in YYYY-MM-DD format and the current month in YYYY-MM format.
    It's useful for calculating relevent date when user ask last N months/days.

    Args:
        ctx: MCP context

    Returns:
        Dictionary containing today's date and current month
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_dimension_values</summary>

**Description**:

```
Retrieve available dimension values for AWS Cost Explorer.

    This tool retrieves all available and valid values for a specified dimension (e.g., SERVICE, REGION)
    over a period of time. This is useful for validating filter values or exploring available options
    for cost analysis.

    Args:
        ctx: MCP context
        date_range: The billing period start and end dates in YYYY-MM-DD format
        dimension: The dimension key to retrieve values for (e.g., SERVICE, REGION, LINKED_ACCOUNT)

    Returns:
        Dictionary containing the dimension name and list of available values
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| date_range | any | not set | Yes
| dimension | any | not set | Yes
</details>
<details>
<summary>get_tag_values</summary>

**Description**:

```
Retrieve available tag values for AWS Cost Explorer.

    This tool retrieves all available values for a specified tag key over a period of time.
    This is useful for validating tag filter values or exploring available tag options for cost analysis.

    Args:
        ctx: MCP context
        date_range: The billing period start and end dates in YYYY-MM-DD format
        tag_key: The tag key to retrieve values for

    Returns:
        Dictionary containing the tag key and list of available values
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| date_range | any | not set | Yes
| tag_key | string | The tag key to retrieve values for | Yes
</details>
<details>
<summary>get_cost_forecast</summary>

**Description**:

```
Retrieve AWS cost forecasts based on historical usage patterns.

    This tool generates cost forecasts for future periods using AWS Cost Explorer's machine learning models.
    Forecasts are based on your historical usage patterns and can help with budget planning and cost optimization.

    Important granularity limits:
    - DAILY forecasts: Maximum 3 months into the future
    - MONTHLY forecasts: Maximum 12 months into the future

    Note: The forecast start date must be equal to or no later than the current date, while the end date
    must be in the future. AWS automatically uses available historical data to generate forecasts.
    Forecasts return total costs and cannot be grouped by dimensions like services or regions.

    Example: Get monthly cost forecast for EC2 services for next quarter
        await get_cost_forecast(
            ctx=context,
            date_range={
                "start_date": "2025-06-19",  # Today or earlier
                "end_date": "2025-09-30"     # Future date
            },
            granularity="MONTHLY",
            filter_expression={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": ["Amazon Elastic Compute Cloud - Compute"],
                    "MatchOptions": ["EQUALS"]
                }
            },
            metric="UNBLENDED_COST",
            prediction_interval_level=80
        )

    Args:
        ctx: MCP context
        date_range: The forecast period dates in YYYY-MM-DD format (start_date <= today, end_date > today)
        granularity: The granularity at which forecast data is aggregated (DAILY, MONTHLY)
        filter_expression: Filter criteria as a Python dictionary
        metric: Cost metric to forecast (UNBLENDED_COST, AMORTIZED_COST, etc.)
        prediction_interval_level: Confidence level for prediction intervals (80 or 95)

    Returns:
        Dictionary containing forecast data with confidence intervals and metadata
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| date_range | any | not set | Yes
| filter_expression | any | Filter criteria as a Python dictionary to narrow down AWS cost forecasts. Supports filtering by Dimensions (SERVICE, REGION, etc.), Tags, or CostCategories. You can use logical operators (And, Or, Not) for complex filters. Same format as get_cost_and_usage filter_expression. | No
| granularity | string | The granularity at which forecast data is aggregated. Valid values are DAILY and MONTHLY. DAILY forecasts support up to 3 months, MONTHLY forecasts support up to 12 months. If not provided, defaults to MONTHLY. | No
| metric | string | The metric to forecast. Valid values are AMORTIZED_COST,BLENDED_COST,NET_AMORTIZED_COST,NET_UNBLENDED_COST,UNBLENDED_COST. Note: UsageQuantity forecasting is not supported by AWS Cost Explorer. | No
| prediction_interval_level | integer | The confidence level for the forecast prediction interval. Valid values are 80 and 95. Higher values provide wider confidence ranges. | No
</details>
<details>
<summary>get_cost_and_usage_comparisons</summary>

**Description**:

```
Compare AWS costs and usage between two time periods.

    This tool compares cost and usage data between a baseline period and a comparison period,
    providing percentage changes and absolute differences. Both periods must be exactly one month
    and start/end on the first day of a month. The tool also provides detailed cost drivers
    when available, showing what specific factors contributed to cost changes.

    Important requirements:
    - Both periods must be exactly one month duration
    - Dates must start and end on the first day of a month (e.g., 2025-01-01 to 2025-02-01)
    - Maximum lookback of 13 months (38 months if multi-year data enabled)
    - Start dates must be equal to or no later than current date

    Example: Compare January 2025 vs December 2024 EC2 costs
        await get_cost_and_usage_comparisons(
            ctx=context,
            baseline_date_range={
                "start_date": "2024-12-01",  # December 2024
                "end_date": "2025-01-01"
            },
            comparison_date_range={
                "start_date": "2025-01-01",  # January 2025
                "end_date": "2025-02-01"
            },
            metric_for_comparison="UnblendedCost",
            group_by={"Type": "DIMENSION", "Key": "SERVICE"},
            filter_expression={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": ["Amazon Elastic Compute Cloud - Compute"],
                    "MatchOptions": ["EQUALS"]
                }
            }
        )

    Args:
        ctx: MCP context
        baseline_date_range: The reference period for comparison (exactly one month)
        comparison_date_range: The comparison period (exactly one month)
        metric_for_comparison: Cost metric to compare (UnblendedCost, BlendedCost, etc.)
        group_by: Either a dictionary with Type and Key, or simply a string key to group by
        filter_expression: Filter criteria as a Python dictionary

    Returns:
        Dictionary containing comparison data with percentage changes, absolute differences,
        and detailed cost drivers when available
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| baseline_date_range | any | not set | Yes
| comparison_date_range | any | not set | Yes
| filter_expression | any | Filter criteria as a Python dictionary to narrow down AWS cost comparisons. Supports filtering by Dimensions (SERVICE, REGION, etc.), Tags, or CostCategories. You can use logical operators (And, Or, Not) for complex filters. Same format as get_cost_and_usage filter_expression. | No
| group_by | any | Either a dictionary with Type and Key for grouping comparisons, or simply a string key to group by (which will default to DIMENSION type). Example dictionary: {'Type': 'DIMENSION', 'Key': 'SERVICE'}. Example string: 'SERVICE'. | No
| metric_for_comparison | string | The cost and usage metric to compare. Valid values are AmortizedCost, BlendedCost, NetAmortizedCost, NetUnblendedCost, UnblendedCost, UsageQuantity. | No
</details>
<details>
<summary>get_cost_comparison_drivers</summary>

**Description**:

```
Analyze what drove cost changes between two time periods.

    This tool provides detailed analysis of the TOP 10 most significant cost drivers
    that caused changes between periods. AWS returns only the most impactful drivers
    to focus on the changes that matter most for cost optimization.

    The tool provides rich insights including:
    - Top 10 most significant cost drivers across all services (or filtered subset)
    - Specific usage types that drove changes (e.g., "BoxUsage:c5.large", "NatGateway-Hours")
    - Multiple driver types: usage changes, savings plan impacts, enterprise discounts, support fees
    - Both cost and usage quantity changes with units (hours, GB-months, etc.)
    - Context about what infrastructure components changed
    - Detailed breakdown of usage patterns vs pricing changes

    Can be used with or without filters:
    - Without filters: Shows top 10 cost drivers across ALL services
    - With filters: Shows top 10 cost drivers within the filtered scope
    - Multiple services: Can filter to multiple services and get top 10 within that scope

    Both periods must be exactly one month and start/end on the first day of a month.

    Important requirements:
    - Both periods must be exactly one month duration
    - Dates must start and end on the first day of a month (e.g., 2025-01-01 to 2025-02-01)
    - Maximum lookback of 13 months (38 months if multi-year data enabled)
    - Start dates must be equal to or no later than current date
    - Results limited to top 10 most significant drivers (no pagination)

    Example: Analyze top 10 cost drivers across all services
        await get_cost_comparison_drivers(
            ctx=context,
            baseline_date_range={
                "start_date": "2024-12-01",  # December 2024
                "end_date": "2025-01-01"
            },
            comparison_date_range={
                "start_date": "2025-01-01",  # January 2025
                "end_date": "2025-02-01"
            },
            metric_for_comparison="UnblendedCost",
            group_by={"Type": "DIMENSION", "Key": "SERVICE"}
            # No filter = top 10 drivers across all services
        )

    Example: Analyze top 10 cost drivers for specific services
        await get_cost_comparison_drivers(
            ctx=context,
            baseline_date_range={
                "start_date": "2024-12-01",
                "end_date": "2025-01-01"
            },
            comparison_date_range={
                "start_date": "2025-01-01",
                "end_date": "2025-02-01"
            },
            metric_for_comparison="UnblendedCost",
            group_by={"Type": "DIMENSION", "Key": "SERVICE"},
            filter_expression={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": ["Amazon Elastic Compute Cloud - Compute", "Amazon Simple Storage Service"],
                    "MatchOptions": ["EQUALS"]
                }
            }
        )

    Args:
        ctx: MCP context
        baseline_date_range: The reference period for comparison (exactly one month)
        comparison_date_range: The comparison period (exactly one month)
        metric_for_comparison: Cost metric to analyze drivers for (UnblendedCost, BlendedCost, etc.)
        group_by: Either a dictionary with Type and Key, or simply a string key to group by
        filter_expression: Filter criteria as a Python dictionary

    Returns:
        with specific usage types, usage quantity changes, driver types (savings plans, discounts, usage changes, support fees), and contextual information
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| baseline_date_range | any | not set | Yes
| comparison_date_range | any | not set | Yes
| filter_expression | any | Filter criteria as a Python dictionary to narrow down AWS cost driver analysis. Supports filtering by Dimensions (SERVICE, REGION, etc.), Tags, or CostCategories. You can use logical operators (And, Or, Not) for complex filters. Same format as get_cost_and_usage filter_expression. | No
| group_by | any | Either a dictionary with Type and Key for grouping driver analysis, or simply a string key to group by (which will default to DIMENSION type). Example dictionary: {'Type': 'DIMENSION', 'Key': 'SERVICE'}. Example string: 'SERVICE'. | No
| metric_for_comparison | string | The cost and usage metric to analyze drivers for. Valid values are AmortizedCost, BlendedCost, NetAmortizedCost, NetUnblendedCost, UnblendedCost, UsageQuantity. | No
</details>
<details>
<summary>get_cost_and_usage</summary>

**Description**:

```
Retrieve AWS cost and usage data.

    This tool retrieves AWS cost and usage data for AWS services during a specified billing period,
    with optional filtering and grouping. It dynamically generates cost reports tailored to specific needs
    by specifying parameters such as granularity, billing period dates, and filter criteria.

    Note: The end_date is treated as inclusive in this tool, meaning if you specify an end_date of
    "2025-01-31", the results will include data for January 31st. This differs from the AWS Cost Explorer
    API which treats end_date as exclusive.

    IMPORTANT: When using UsageQuantity metric, AWS aggregates usage numbers without considering units.
    This makes results meaningless when different usage types have different units (e.g., EC2 compute hours
    vs data transfer GB). For meaningful UsageQuantity results, you MUST be very specific with filtering, including USAGE_TYPE or USAGE_TYPE_GROUP.

    Example: Get monthly costs for EC2 and S3 services in us-east-1 for May 2025
        await get_cost_and_usage(
            ctx=context,
            date_range={
                "start_date": "2025-05-01",
                "end_date": "2025-05-31"
            },
            granularity="MONTHLY",
            group_by={"Type": "DIMENSION", "Key": "SERVICE"},
            filter_expression={
                "And": [
                    {
                        "Dimensions": {
                            "Key": "SERVICE",
                            "Values": ["Amazon Elastic Compute Cloud - Compute", "Amazon Simple Storage Service"],
                            "MatchOptions": ["EQUALS"]
                        }
                    },
                    {
                        "Dimensions": {
                            "Key": "REGION",
                            "Values": ["us-east-1"],
                            "MatchOptions": ["EQUALS"]
                        }
                    }
                ]
            },
            metric="UnblendedCost"
        )

    Example: Get meaningful UsageQuantity for specific EC2 instance usage
        await get_cost_and_usage(
            ctx=context,
            {
            "date_range": {
                "start_date": "2025-05-01",
                "end_date": "2025-05-31"
            },
            "filter_expression": {
                "And": [
                {
                    "Dimensions": {
                    "Values": [
                        "Amazon Elastic Compute Cloud - Compute"
                    ],
                    "Key": "SERVICE",
                    "MatchOptions": [
                        "EQUALS"
                    ]
                    }
                },
                {
                    "Dimensions": {
                    "Values": [
                        "EC2: Running Hours"
                    ],
                    "Key": "USAGE_TYPE_GROUP",
                    "MatchOptions": [
                        "EQUALS"
                    ]
                    }
                }
                ]
            },
            "metric": "UsageQuantity",
            "group_by": "USAGE_TYPE",
            "granularity": "MONTHLY"
            }

    Args:
        ctx: MCP context
        date_range: The billing period start and end dates in YYYY-MM-DD format (end date is inclusive)
        granularity: The granularity at which cost data is aggregated (DAILY, MONTHLY, HOURLY)
        group_by: Either a dictionary with Type and Key, or simply a string key to group by
        filter_expression: Filter criteria as a Python dictionary
        metric: Cost metric to use (UnblendedCost, BlendedCost, etc.)

    Returns:
        Dictionary containing cost report data grouped according to the specified parameters
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| date_range | any | not set | Yes
| filter_expression | any | Filter criteria as a Python dictionary to narrow down AWS costs. Supports filtering by Dimensions (SERVICE, REGION, etc.), Tags, or CostCategories. You can use logical operators (And, Or, Not) for complex filters. MatchOptions validation: For Dimensions, valid values are ['EQUALS', 'CASE_SENSITIVE']. For Tags and CostCategories, valid values are ['EQUALS', 'ABSENT', 'CASE_SENSITIVE'] (defaults to EQUALS and CASE_SENSITIVE). Examples: 1) Simple service filter: {'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Elastic Compute Cloud - Compute', 'Amazon Simple Storage Service'], 'MatchOptions': ['EQUALS']}}. 2) Region filter: {'Dimensions': {'Key': 'REGION', 'Values': ['us-east-1'], 'MatchOptions': ['EQUALS']}}. 3) Combined filter: {'And': [{'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Elastic Compute Cloud - Compute'], 'MatchOptions': ['EQUALS']}}, {'Dimensions': {'Key': 'REGION', 'Values': ['us-east-1'], 'MatchOptions': ['EQUALS']}}]}. | No
| granularity | string | The granularity at which cost data is aggregated. Valid values are DAILY, MONTHLY, HOURLY. If not provided, defaults to MONTHLY. | No
| group_by | any | Either a dictionary with Type and Key for grouping costs, or simply a string key to group by (which will default to DIMENSION type). Example dictionary: {'Type': 'DIMENSION', 'Key': 'SERVICE'}. Example string: 'SERVICE'. | No
| metric | string | The metric to return in the query. Valid values are AmortizedCost, BlendedCost, NetAmortizedCost, NetUnblendedCost, UnblendedCost, UsageQuantity. IMPORTANT: For UsageQuantity, the service aggregates usage numbers without considering units, making results meaningless when mixing different unit types (e.g., compute hours + data transfer GB). To get meaningful UsageQuantity metrics, you MUST filter by USAGE_TYPE or group by USAGE_TYPE/USAGE_TYPE_GROUP to ensure consistent units. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | get_cost_and_usage | description | a09f2be386793fac360138ec469727e609890a106067d4980742d6af53296872 |
| tools | get_cost_and_usage | filter_expression | 0eadd6038ace400941ac1273273069f063874acf5f9a75bb104ee203669b01b5 |
| tools | get_cost_and_usage | granularity | c8ee2b0971f84af5b6ef414859f2461b9a6f92bccfb06a3a23841549989a0205 |
| tools | get_cost_and_usage | group_by | 10182d8f10afc788cbb5f04435b9a169356b3f3cb0410d2ccf77da60086572d3 |
| tools | get_cost_and_usage | metric | 1553ff6e9ceaa8fd2b793a7bec7a8108335f79c840497be7cd1d94f90c29cb6e |
| tools | get_cost_and_usage_comparisons | description | 9c749865d7d1e3713dee5d66b886d7065389f32617694132a939e3a1345c54f5 |
| tools | get_cost_and_usage_comparisons | filter_expression | 9b4ef3fd38d3a3cb8e1b03437b9fab8ada225d5ebc6e27890d91cc78ed8dfb88 |
| tools | get_cost_and_usage_comparisons | group_by | 317c3255ae60d63f4e477c4fe2035ab078738fa967d0e654e7bb494efc79fbee |
| tools | get_cost_and_usage_comparisons | metric_for_comparison | b114b72e5ec0c26649995b1e69155a0ff118b31e09e892ac9eb1100c8f161f8e |
| tools | get_cost_comparison_drivers | description | d0b82aa066222a12caa6fd53cd27a094b841c1a6df8285ac5eeed2b83d8c619c |
| tools | get_cost_comparison_drivers | filter_expression | 874529cde5eb005345e1b68129fe14460b8f3741bdcf8874b39c3ca8a6a959ef |
| tools | get_cost_comparison_drivers | group_by | 5d75ffffeae8b8d913a411e095b7211a952c08e6d9cfa047326f27ba545080e5 |
| tools | get_cost_comparison_drivers | metric_for_comparison | 7a716eae32ec6a1190c15fa6bf7c13d68157296e7af72a3f81f15036882001c9 |
| tools | get_cost_forecast | description | 831cbbf0df81eeafad9bcf4a53b78d7eadc908adc4148002218a670dfc6dec6b |
| tools | get_cost_forecast | filter_expression | 7ec072962f2015f83081f6ed55960630a6a0b7957b026661d7efe1a309030c28 |
| tools | get_cost_forecast | granularity | 316aa99a86175840a31410fe295d92f25d01d78cc087f16388d0275dd6c00b96 |
| tools | get_cost_forecast | metric | e6ee0d261abd69c7a7afa17fe49fdd7b411642c733c94bfde39e0752312b4ad5 |
| tools | get_cost_forecast | prediction_interval_level | 4c27aaed55a4e8a6311bc830437e1528e2359f2b63ede301bb819b474b53a7b9 |
| tools | get_dimension_values | description | 1be5397051af32c525e10b8985efe42d736251910382a21718657a532ee63a7e |
| tools | get_tag_values | description | 5951afd9c670a535cdd4b1981ab84beed4134d11a99524094c74bc77125e9213 |
| tools | get_tag_values | tag_key | b6935e9483122325db4f517fe5fcbfcb0d2d6430d00546669dc4d47f61e3ea33 |
| tools | get_today_date | description | ef8ca08b2b5a5c327c482f00ac801271109ad541f0b476b22f0e8c585ad67493 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
