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


# What is mcp-server-alibabacloud-rds?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-rds/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-rds/1.7.7?logo=docker&logoColor=fff&label=1.7.7)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-rds)
[![PyPI](https://img.shields.io/badge/1.7.7-3775A9?logo=pypi&logoColor=fff&label=alibabacloud-rds-openapi-mcp-server)](https://github.com/aliyun/alibabacloud-rds-openapi-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-rds/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-rds&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_ID%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-rds%3A1.7.7%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for Alibaba Cloud RDS OpenAPI, enabling programmatic management of RDS resources.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from alibabacloud-rds-openapi-mcp-server original [sources](https://github.com/aliyun/alibabacloud-rds-openapi-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-rds/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-rds/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-rds/charts/mcp-server-alibabacloud-rds/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure alibabacloud-rds-openapi-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-rds/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-alibabacloud-rds scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `ALIBABA_CLOUD_ACCESS_KEY_ID` required to be set
  - `ALIBABA_CLOUD_ACCESS_KEY_SECRET` required to be set
  - `ALIBABA_CLOUD_SECURITY_TOKEN` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/aliyun/alibabacloud-rds-openapi-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-rds&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_ID%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-rds%3A1.7.7%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-alibabacloud-rds": {
        "env": {
          "ALIBABA_CLOUD_ACCESS_KEY_ID": "TO_BE_SET",
          "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "ALIBABA_CLOUD_ACCESS_KEY_ID",
          "-e",
          "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
          "docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7"
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
    "acuvity-mcp-server-alibabacloud-rds": {
      "env": {
        "ALIBABA_CLOUD_ACCESS_KEY_ID": "TO_BE_SET",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7"
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
    "acuvity-mcp-server-alibabacloud-rds": {
      "env": {
        "ALIBABA_CLOUD_ACCESS_KEY_ID": "TO_BE_SET",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7"
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
    "acuvity-mcp-server-alibabacloud-rds": {
      "env": {
        "ALIBABA_CLOUD_ACCESS_KEY_ID": "TO_BE_SET",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7"
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
    "acuvity-mcp-server-alibabacloud-rds": {
      "env": {
        "ALIBABA_CLOUD_ACCESS_KEY_ID": "TO_BE_SET",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_ID",
        "-e",
        "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        "docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7"
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
        "env": {"ALIBABA_CLOUD_ACCESS_KEY_ID":"TO_BE_SET","ALIBABA_CLOUD_ACCESS_KEY_SECRET":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","ALIBABA_CLOUD_ACCESS_KEY_ID","-e","ALIBABA_CLOUD_ACCESS_KEY_SECRET","docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7"]
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
- arguments: `run -i --rm --read-only -e ALIBABA_CLOUD_ACCESS_KEY_ID -e ALIBABA_CLOUD_ACCESS_KEY_SECRET docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e ALIBABA_CLOUD_ACCESS_KEY_ID -e ALIBABA_CLOUD_ACCESS_KEY_SECRET docker.io/acuvity/mcp-server-alibabacloud-rds:1.7.7
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-alibabacloud-rds": {
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
    "acuvity-mcp-server-alibabacloud-rds": {
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
  - `ALIBABA_CLOUD_ACCESS_KEY_ID` secret to be set as secrets.ALIBABA_CLOUD_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `ALIBABA_CLOUD_ACCESS_KEY_SECRET` secret to be set as secrets.ALIBABA_CLOUD_ACCESS_KEY_SECRET either by `.value` or from existing with `.valueFrom`

**Optional Secrets**:
  - `ALIBABA_CLOUD_SECURITY_TOKEN` secret to be set as secrets.ALIBABA_CLOUD_SECURITY_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-alibabacloud-rds --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-rds --version 1.0.0
````

Install with helm

```console
helm install mcp-server-alibabacloud-rds oci://docker.io/acuvity/mcp-server-alibabacloud-rds --version 1.0.0
```

From there your MCP server mcp-server-alibabacloud-rds will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-rds` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-rds/charts/mcp-server-alibabacloud-rds/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (28)
<details>
<summary>describe_db_instances</summary>

**Description**:

```

    Queries instances.
    Args:
        region_id: queries instances in region id(e.g. cn-hangzhou)
    :return:
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_attribute</summary>

**Description**:

```

    Queries the details of an instance.
    Args:
        region_id: db instance region(e.g. cn-hangzhou)
        db_instance_id: db instance id(e.g. rm-xxx)
    :return:
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_performance</summary>

**Description**:

```

    Queries the performance data of an instance.
    Args:
        region_id: db instance region(e.g. cn-hangzhou)
        db_instance_id: db instance id(e.g. rm-xxx)
        db_type: the db instance database type(e.g. mysql,pgsql,sqlserver)
        perf_keys: Performance Key  (e.g. ["MemCpuUsage", "QPSTPS", "Sessions", "COMDML", "RowDML", "ThreadStatus", "MBPS", "DetailedSpaceUsage"])
        start_time: start time(e.g. 2023-01-01 00:00)
        end_time: end time(e.g. 2023-01-01 00:00)
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| db_type | string | not set | Yes
| end_time | string | not set | Yes
| perf_keys | array | not set | Yes
| region_id | string | not set | Yes
| start_time | string | not set | Yes
</details>
<details>
<summary>modify_parameter</summary>

**Description**:

```
Modify RDS instance parameters.

    Args:
        region_id: The region ID of the RDS instance.
        dbinstance_id: The ID of the RDS instance.
        parameters (Dict[str, str], optional): Parameters and their values in JSON format.
            Example: {"delayed_insert_timeout": "600", "max_length_for_sort_data": "2048"}
        parameter_group_id: Parameter template ID.
        forcerestart: Whether to force restart the database. Default: False.
        switch_time_mode: Execution time mode. Values: Immediate, MaintainTime, ScheduleTime. Default: Immediate.
        switch_time: Scheduled execution time in format: yyyy-MM-ddTHH:mm:ssZ (UTC time).
        client_token: Client token for idempotency, max 64 ASCII characters.

    Returns:
        Dict[str, Any]: The response containing the request ID.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| client_token | string | not set | No
| dbinstance_id | string | not set | Yes
| forcerestart | boolean | not set | No
| parameter_group_id | string | not set | No
| parameters | object | not set | No
| region_id | string | not set | Yes
| switch_time | string | not set | No
| switch_time_mode | string | not set | No
</details>
<details>
<summary>modify_db_instance_spec</summary>

**Description**:

```
Modify RDS instance specifications.

    Args:
        region_id: The region ID of the RDS instance.
        dbinstance_id: The ID of the RDS instance.
        dbinstance_class: Target instance specification.
        dbinstance_storage: Target storage space in GB.
        pay_type: Instance payment type. Values: Postpaid, Prepaid, Serverless.
        effective_time: When the new configuration takes effect. Values: Immediate, MaintainTime, ScheduleTime.
        switch_time: Scheduled switch time in format: yyyy-MM-ddTHH:mm:ssZ (UTC time).
        switch_time_mode: Switch time mode. Values: Immediate, MaintainTime, ScheduleTime.
        source_biz: Source business type.
        dedicated_host_group_id: Dedicated host group ID.
        zone_id: Zone ID.
        vswitch_id: VSwitch ID.
        category: Instance category.
        instance_network_type: Instance network type.
        direction: Specification change direction. Values: UP, DOWN.
        auto_pause: Whether to enable auto pause for Serverless instances.
        max_capacity: Maximum capacity for Serverless instances.
        min_capacity: Minimum capacity for Serverless instances.
        switch_force: Whether to force switch for Serverless instances.
        client_token: Client token for idempotency, max 64 ASCII characters.

    Returns:
        Dict[str, Any]: The response containing the request ID.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_pause | boolean | not set | No
| category | string | not set | No
| client_token | string | not set | No
| dbinstance_class | string | not set | No
| dbinstance_id | string | not set | Yes
| dbinstance_storage | integer | not set | No
| dedicated_host_group_id | string | not set | No
| direction | string | not set | No
| effective_time | string | not set | No
| instance_network_type | string | not set | No
| max_capacity | number | not set | No
| min_capacity | number | not set | No
| pay_type | string | not set | No
| region_id | string | not set | Yes
| source_biz | string | not set | No
| switch_force | boolean | not set | No
| switch_time | string | not set | No
| switch_time_mode | string | not set | No
| vswitch_id | string | not set | No
| zone_id | string | not set | No
</details>
<details>
<summary>describe_available_classes</summary>

**Description**:

```
Query the RDS instance class_code and storage space that can be purchased in the inventory.

    Args:
        region_id: The region ID of the RDS instance.
        zone_id: The zone ID of the RDS instance. Query available zones by `describe_available_zones`.
        instance_charge_type: Instance payment type. Values: Prepaid, Postpaid, Serverless.
        engine: Database engine type. Values: MySQL, SQLServer, PostgreSQL, MariaDB.
        engine_version: Database version.
        dbinstance_storage_type: Storage type. Values: local_ssd,general_essd,cloud_essd,cloud_essd2,cloud_essd3
        category: Instance category. Values: Basic, HighAvailability, cluster, AlwaysOn, Finance, serverless_basic, serverless_standard, serverless_ha.
        dbinstance_id: The ID of the RDS instance.
        order_type: Order type. Currently only supports "BUY".
        commodity_code: Commodity code for read-only instances.

    Returns:
        Dict[str, Any]: The response containing available instance classes and storage ranges.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category | string | not set | Yes
| commodity_code | string | not set | No
| dbinstance_id | string | not set | No
| dbinstance_storage_type | string | not set | Yes
| engine | string | not set | Yes
| engine_version | string | not set | Yes
| instance_charge_type | string | not set | Yes
| order_type | string | not set | No
| region_id | string | not set | Yes
| zone_id | string | not set | Yes
</details>
<details>
<summary>create_db_instance</summary>

**Description**:

```
Create an RDS instance.

    Args:
        region_id: Region ID.
        engine: Database type (MySQL, SQLServer, PostgreSQL, MariaDB).
        engine_version: Database version.
        dbinstance_class: Instance specification. Query available class_codes by `describe_available_classes`.
        dbinstance_storage: Storage space in GB.
        security_ip_list: IP whitelist, separated by commas. Default: "127.0.0.1".
        instance_network_type: Network type (Classic, VPC). Default: VPC.
        zone_id: Zone ID. Query available zones by `describe_available_zones`.
        zone_id_slave1: Slave Node1 Zone ID. Query available zones by `describe_available_zones`.
        zone_id_slave2: Slave Node2 Zone ID. Query available zones by `describe_available_zones`.
        pay_type: Payment type (Postpaid, Prepaid). Default: Postpaid.
        instance_charge_type: Instance charge type.
        system_db_charset: Character set.
        dbinstance_net_type: Network connection type (Internet, Intranet). Default: Internet.
        category: Instance category. Default: Basic.
        dbinstance_storage_type: Storage type. (e.g. local_ssd,general_essd,cloud_essd,cloud_essd2,cloud_essd3)
        vpc_id: VPC ID.
        vswitch_id: VSwitch ID.
        private_ip_address: Private IP address.
        client_token: Idempotence token.
        resource_group_id: Resource group ID.
        tde_status: TDE status (Enable, Disable).
        encryption_key: Custom encryption key.
        serverless_config: Serverless instance configuration.
        table_names_case_sensitive: Are table names case-sensitive.
        db_time_zone: the db instance time zone.
        connection_string: the connection string for db instance.
        db_param_group_id: the db param group id for db instance.
    Returns:
        Dict[str, Any]: Response containing the created instance details.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category | string | not set | No
| client_token | string | not set | No
| connection_string | string | not set | No
| db_param_group_id | string | not set | No
| db_time_zone | string | not set | No
| dbinstance_class | string | not set | Yes
| dbinstance_net_type | string | not set | No
| dbinstance_storage | integer | not set | Yes
| dbinstance_storage_type | string | not set | No
| encryption_key | string | not set | No
| engine | string | not set | Yes
| engine_version | string | not set | Yes
| instance_network_type | string | not set | No
| pay_type | string | not set | No
| private_ip_address | string | not set | No
| region_id | string | not set | Yes
| resource_group_id | string | not set | No
| security_ip_list | string | not set | No
| serverless_config | object | not set | No
| system_db_charset | string | not set | No
| table_names_case_sensitive | boolean | not set | No
| tde_status | string | not set | No
| vpc_id | string | not set | Yes
| vswitch_id | string | not set | Yes
| zone_id | string | not set | Yes
| zone_id_slave1 | string | not set | No
| zone_id_slave2 | string | not set | No
</details>
<details>
<summary>describe_available_zones</summary>

**Description**:

```
Query available zones for RDS instances.

    Args:
        region_id: Region ID.
        engine: Database type (MySQL, SQLServer, PostgreSQL, MariaDB).
        engine_version: Database version.
            MySQL: 5.5, 5.6, 5.7, 8.0
            SQL Server: 2008r2, 2012, 2014, 2016, 2017, 2019
            PostgreSQL: 10.0, 11.0, 12.0, 13.0, 14.0, 15.0
            MariaDB: 10.3
        commodity_code: Commodity code.
            bards: Pay-as-you-go primary instance (China site)
            rds: Subscription primary instance (China site)
            rords: Pay-as-you-go read-only instance (China site)
            rds_rordspre_public_cn: Subscription read-only instance (China site)
            bards_intl: Pay-as-you-go primary instance (International site)
            rds_intl: Subscription primary instance (International site)
            rords_intl: Pay-as-you-go read-only instance (International site)
            rds_rordspre_public_intl: Subscription read-only instance (International site)
            rds_serverless_public_cn: Serverless instance (China site)
            rds_serverless_public_intl: Serverless instance (International site)
        zone_id: Zone ID.
        dispense_mode: Whether to return zones that support single-zone deployment.
            1: Return (default)
            0: Do not return
        dbinstance_name: Primary instance ID. Required when querying read-only instance resources.
        category: Instance category.
            Basic: Basic Edition
            HighAvailability: High-availability Edition
            cluster: MySQL Cluster Edition
            AlwaysOn: SQL Server Cluster Edition
            Finance: Enterprise Edition
            serverless_basic: Serverless Basic Edition
            serverless_standard: MySQL Serverless High-availability Edition
            serverless_ha: SQL Server Serverless High-availability Edition

    Returns:
        Dict[str, Any]: Response containing available zones information.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category | string | not set | No
| commodity_code | string | not set | No
| dbinstance_name | string | not set | No
| dispense_mode | string | not set | No
| engine | string | not set | Yes
| engine_version | string | not set | No
| region_id | string | not set | Yes
| zone_id | string | not set | No
</details>
<details>
<summary>describe_vpcs</summary>

**Description**:

```
Query VPC list.

    Args:
        region_id: The region ID of the VPC.
        vpc_id: The ID of the VPC. Up to 20 VPC IDs can be specified, separated by commas.
        vpc_name: The name of the VPC.
        resource_group_id: The resource group ID of the VPC to query.
        page_number: The page number of the list. Default: 1.
        page_size: The number of entries per page. Maximum value: 50. Default: 10.
        vpc_owner_id: The Alibaba Cloud account ID of the VPC owner.
        tags: The tags of the resource.

    Returns:
        Dict[str, Any]: The response containing the list of VPCs.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page_number | integer | not set | No
| page_size | integer | not set | No
| region_id | string | not set | Yes
| resource_group_id | string | not set | No
| tags | array | not set | No
| vpc_id | string | not set | No
| vpc_name | string | not set | No
| vpc_owner_id | integer | not set | No
</details>
<details>
<summary>describe_vswitches</summary>

**Description**:

```
Query VSwitch list.

    Args:
        region_id: The region ID of the VSwitch. At least one of region_id or vpc_id must be specified.
        vpc_id: The ID of the VPC to which the VSwitch belongs. At least one of region_id or vpc_id must be specified.
        vswitch_id: The ID of the VSwitch to query.
        zone_id: The zone ID of the VSwitch.
        vswitch_name: The name of the VSwitch.
        resource_group_id: The resource group ID of the VSwitch.
        page_number: The page number of the list. Default: 1.
        page_size: The number of entries per page. Maximum value: 50. Default: 10.

    Returns:
        Dict[str, Any]: The response containing the list of VSwitches.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| is_default | boolean | not set | No
| page_number | integer | not set | No
| page_size | integer | not set | No
| region_id | string | not set | No
| resource_group_id | string | not set | No
| vpc_id | string | not set | No
| vswitch_id | string | not set | No
| vswitch_name | string | not set | No
| zone_id | string | not set | No
</details>
<details>
<summary>describe_slow_log_records</summary>

**Description**:

```
Query slow log records for an RDS instance.

    Args:
        region_id: The region ID of the RDS instance.
        dbinstance_id: The ID of the RDS instance.
        start_time: Start time in format: yyyy-MM-dd HH:mm.
            Cannot be earlier than 30 days before the current time.
        end_time: End time in format: yyyy-MM-dd HH:mm.
            Must be later than the start time.
        sqlhash: The unique identifier of the SQL statement in slow log statistics.
            Used to get slow log details for a specific SQL statement.
        db_name: The name of the database.
        page_size: Number of records per page. Range: 30-100. Default: 30.
        page_number: Page number. Must be greater than 0 and not exceed Integer max value. Default: 1.
        node_id: Node ID. Only applicable to cluster instances.
            If not specified, logs from the primary node are returned by default.

    Returns:
        Dict[str, Any]: The response containing slow log records.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_name | string | not set | No
| dbinstance_id | string | not set | Yes
| end_time | string | not set | Yes
| node_id | string | not set | No
| page_number | integer | not set | No
| page_size | integer | not set | No
| region_id | string | not set | Yes
| sqlhash | string | not set | No
| start_time | string | not set | Yes
</details>
<details>
<summary>describe_error_logs</summary>

**Description**:

```

    Query error logs of an RDS instance.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
        start_time: The start time of the query. Format: yyyy-MM-dd HH:mm.
        end_time: The end time of the query. Format: yyyy-MM-dd HH:mm.
        page_size: The number of records per page. Range: 30~100. Default: 30.
        page_number: The page number. Default: 1.
    Returns:
        Dict[str, Any]: A dictionary containing error log information
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| end_time | string | not set | Yes
| page_number | integer | not set | No
| page_size | integer | not set | No
| region_id | string | not set | Yes
| start_time | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_net_info</summary>

**Description**:

```

    Batch retrieves network configuration details for multiple RDS instances.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_ids: List of DB instance identifiers (e.g., ["rm-uf6wjk5****", "db-instance-01"])
    Returns:
        list[dict]: A list of dictionaries containing network configuration details for each instance.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_ids | array | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_ip_allowlist</summary>

**Description**:

```

    Batch retrieves IP allowlist configurations for multiple RDS instances.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_ids: List of DB instance identifiers (e.g., ["rm-uf6wjk5****", "db-instance-01"])
    Returns:
        list[dict]: A list of dictionaries containing network configuration details for each instance.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_ids | array | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_databases</summary>

**Description**:

```

    Batch retrieves database information for multiple RDS instances.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_ids: List of DB instance identifiers (e.g., ["rm-uf6wjk5****", "db-instance-01"])
    Returns:
        list[dict]: A list of dictionaries containing database information for each instance.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_ids | array | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_accounts</summary>

**Description**:

```

    Batch retrieves account information for multiple RDS instances.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_ids: List of DB instance identifiers (e.g., ["rm-uf6wjk5****", "db-instance-01"])
    Returns:
        list[dict]: A list of dictionaries containing account information for each instance.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_ids | array | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>create_db_instance_account</summary>

**Description**:

```

    Create a new account for an RDS instance.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
        account_name: The name of the new account.
        account_password: The password for the new account.
        account_description: The description for the new account.
        account_type: The type of the new account. (e.g. Normal,Super)
    Returns:
         dict[str, Any]: The response.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account_description | string | not set | No
| account_name | string | not set | Yes
| account_password | string | not set | Yes
| account_type | string | not set | No
| db_instance_id | string | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_db_instance_parameters</summary>

**Description**:

```

    Batch retrieves parameter information for multiple RDS instances.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_ids: List of DB instance identifiers (e.g., ["rm-uf6wjk5****", "db-instance-01"])
        paramters: List of parameter names (e.g., ["max_connections", "innodb_buffer_pool_size"])
    Returns:
        list[dict]: A list of dictionaries containing parameter information(ParamGroupInfo,ConfigParameters,RunningParameters) foreach instance.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_ids | array | not set | Yes
| paramters | array | not set | No
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_bills</summary>

**Description**:

```

    Query the consumption summary of all product instances or billing items for a user within a specific billing period.
    Args:
        billing_cycles: bill cycle YYYY－MM, e.g. 2020-03
        db_instance_id: DB instance id (e.g., "rm-xxx")
        is_billing_item: Whether to pull data according to the billing item dimension.
    Returns:
        str: billing information.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| billing_cycles | array | not set | Yes
| db_instance_id | string | not set | No
| is_billing_item | boolean | not set | No
</details>
<details>
<summary>modify_db_instance_description</summary>

**Description**:

```

    modify db instance description.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
        description: The RDS instance description.
    Returns:
        dict[str, Any]: The response.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| description | string | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>allocate_instance_public_connection</summary>

**Description**:

```

    allocate db instance public connection.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
        connection_string_prefix: The prefix of connection string.
    Returns:
        dict[str, Any]: The response.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_string_prefix | string | not set | No
| db_instance_id | string | not set | Yes
| port | string | not set | No
| region_id | string | not set | Yes
</details>
<details>
<summary>describe_all_whitelist_template</summary>

**Description**:

```

    describe all whitelist template.
    Args:
        region_id: The region ID of the RDS instance.
        template_name: The ID of the RDS instance.
    Returns:
        List[Dict[str, Any]]: The response contains all whitelist template information.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_id | string | not set | Yes
| template_name | string | not set | No
</details>
<details>
<summary>describe_instance_linked_whitelist_template</summary>

**Description**:

```

    describe instance linked whitelist template.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
    Returns:
        dict[str, Any]: The response.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| region_id | string | not set | Yes
</details>
<details>
<summary>attach_whitelist_template_to_instance</summary>

**Description**:

```

    allocate db instance public connection.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
        template_id: Whitelist Template ID. Can be obtained via DescribeAllWhitelistTemplate.
    Returns:
        dict[str, Any]: The response.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| region_id | string | not set | Yes
| template_id | integer | not set | Yes
</details>
<details>
<summary>add_tags_to_db_instance</summary>

**Description**:

```

    add tags to db instance.
    Args:
        region_id: The region ID of the RDS instance.
        db_instance_id: The ID of the RDS instance.
        tags: The tags to be added to the RDS instance.
    Returns:
        dict[str, Any]: The response.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_instance_id | string | not set | Yes
| region_id | string | not set | Yes
| tags | object | not set | Yes
</details>
<details>
<summary>get_current_time</summary>

**Description**:

```
Get the current time.

    Returns:
        Dict[str, Any]: The response containing the current time.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>modify_security_ips</summary>

**Description**:

```
modify security ips。

    Args:
        region_id (str): RDS instance region id.
        dbinstance_id (str): RDS instance id.
        security_ips (str): security ips list, separated by commas.
        whitelist_network_type (str, optional): whitelist network type.
            - MIX: mixed network type
            - Classic: classic network
            - VPC: vpc
            default value: MIX
        security_ip_type (str, optional): security ip type.
            - normal: normal security ip
            - hidden: hidden security ip
        dbinstance_ip_array_name (str, optional): security ip array name.
        dbinstance_ip_array_attribute (str, optional): security ip array attribute.
            - hidden: hidden security ip
            - normal: normal security ip
        client_token (str, optional): idempotency token, max 64 ascii characters.

    Returns:
        Dict[str, Any]: response contains request id.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| client_token | string | not set | No
| dbinstance_id | string | not set | Yes
| dbinstance_ip_array_attribute | string | not set | No
| dbinstance_ip_array_name | string | not set | No
| region_id | string | not set | Yes
| security_ip_type | string | not set | No
| security_ips | string | not set | Yes
| whitelist_network_type | string | not set | No
</details>
<details>
<summary>restart_db_instance</summary>

**Description**:

```
Restart an RDS instance.

    Args:
        region_id (str): The region ID of the RDS instance.
        dbinstance_id (str): The ID of the RDS instance.
        effective_time (str, optional): When to restart the instance. Options:
            - Immediate: Restart immediately
            - MaintainTime: Restart during maintenance window
            - ScheduleTime: Restart at specified time
            Default: Immediate
        switch_time (str, optional): The scheduled restart time in format: yyyy-MM-ddTHH:mm:ssZ (UTC time).
            Required when effective_time is ScheduleTime.
        client_token (str, optional): Idempotency token, max 64 ASCII characters.

    Returns:
        Dict[str, Any]: Response containing the request ID.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| client_token | string | not set | No
| dbinstance_id | string | not set | Yes
| effective_time | string | not set | No
| region_id | string | not set | Yes
| switch_time | string | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_tags_to_db_instance | description | 7f8a0420d622c00bad8d485b7526480056da275d92e2877596f396f5b0457bd5 |
| tools | allocate_instance_public_connection | description | d3cae770341b0882e26a7f797471aa7bb3e04a85e7c05228d137964fb97dd9a5 |
| tools | attach_whitelist_template_to_instance | description | 3dbb46ad89524a339ea33ae291c75345d85fc474a5cec8d3df7ad9fb27725c84 |
| tools | create_db_instance | description | 1c349c036449c6ab7cf9029a1541446ee2f1f361cc82d5f5b32d4d12a2dd1852 |
| tools | create_db_instance_account | description | 76f4f70b2e6416932668e7b91d8dbebcfe67b35b039ec2b5fc8dfd79ff0663d7 |
| tools | describe_all_whitelist_template | description | 6972050edee7101279350e137121c3428a301030b6ca6d9e6b979514feb01524 |
| tools | describe_available_classes | description | 60ca915c92983f2f509aed5fb41b1711763c90db4a30c0f6e8e8b35852796122 |
| tools | describe_available_zones | description | 3cb07333029a5dc83cf03fde8e185d0eda1027a6931df1679353b74c0b1f2b20 |
| tools | describe_bills | description | 21b70e30ba551b7782c9468bcac7fc8e5968e1adc0621bf8f1f2163114179346 |
| tools | describe_db_instance_accounts | description | 78ffad5abc4d8d10bcbec21103e4be7345d18cb92040d84a9aacfe1d1ff66cb9 |
| tools | describe_db_instance_attribute | description | e8c1d322c6b8542974d85292b5fb129c1d28aee5025a001c39716ea6f31397f7 |
| tools | describe_db_instance_databases | description | 5efeaebdcb5715be0fe3fbf3c29074f406f214b44c1e90ecd271f948cf435506 |
| tools | describe_db_instance_ip_allowlist | description | c9678a8b66b424b1dac9c2ed9ca5734268a28c37e1f493e9f63e01cfbfdc3a47 |
| tools | describe_db_instance_net_info | description | 803a80a75812b6ad0330bc3ff87f880d1a0078514b094d389532fcafde924733 |
| tools | describe_db_instance_parameters | description | 18473454bf2b1f4f62da53a0456678ddda30cd64042a47b977eca71bbf263da0 |
| tools | describe_db_instance_performance | description | a9879f780ffe599d8002075bcbf61f7a6151eb2b77941d9d3cdb00b076dc12dc |
| tools | describe_db_instances | description | 11d137565a39eae46eb545c175e01e3f80a8c87b41746ab00f7582929b14835a |
| tools | describe_error_logs | description | 40ed367c3771f4408bde70bb405e184dc8387b9f3f60c1e4d0ac389dc02ac983 |
| tools | describe_instance_linked_whitelist_template | description | 7e288fb481d226ce4671af69e9397da4aab8811f7e881cbfad0a1c54cb489d86 |
| tools | describe_slow_log_records | description | 428ae59a731cb803fe90a0327b1c44d1a88fc5948d571f55ff5894e0cb6271e1 |
| tools | describe_vpcs | description | 36f230af9297747024f73ee70cd5ad59fbf6fe903feb345051b344701b4309d2 |
| tools | describe_vswitches | description | abc11a7354d9f15ccda4373c03c4210c6126e3c3f8ba90ccf727da7387ebb08d |
| tools | get_current_time | description | c62d1661d0d638ed6b689471c8449d41e6641bac39e4d4353719e7a07901af7a |
| tools | modify_db_instance_description | description | fe584046327e0bbba0f51ed0afb33d437fe3c0fd8ec81d8feced14ee8b08cb0d |
| tools | modify_db_instance_spec | description | fd2047a56dfb562f438a910d1553bc6e9c3b8d6f6fd2359a1235b9ea3241d0be |
| tools | modify_parameter | description | 59dd0072dfb97d68a151120b51f38517b7eb22b122792fbc4e6b0ac8701ef22c |
| tools | modify_security_ips | description | cbfa4976349483b841ce78dbe0500b9d679942eefb19511784e0727f1814eb75 |
| tools | restart_db_instance | description | 7e85cf0f719d26c5ae57806ae4a44ef3e43f7386019c54f1a4617002d536bbd4 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
