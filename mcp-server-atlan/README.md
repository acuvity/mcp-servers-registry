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


# What is mcp-server-atlan?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-atlan/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-atlan/0.3.1?logo=docker&logoColor=fff&label=0.3.1)](https://hub.docker.com/r/acuvity/mcp-server-atlan)
[![PyPI](https://img.shields.io/badge/0.3.1-3775A9?logo=pypi&logoColor=fff&label=atlan-mcp-server)](https://github.com/atlanhq/agent-toolkit/tree/HEAD/modelcontextprotocol)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-atlan/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-atlan&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ATLAN_API_KEY%22%2C%22-e%22%2C%22ATLAN_BASE_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-atlan%3A0.3.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** The Atlan MCP server allows you to interact with Atlan services through multiple tools.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from atlan-mcp-server original [sources](https://github.com/atlanhq/agent-toolkit/tree/HEAD/modelcontextprotocol).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-atlan/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlan/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlan/charts/mcp-server-atlan/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure atlan-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlan/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-atlan scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `ATLAN_API_KEY` required to be set
  - `ATLAN_BASE_URL` required to be set
  - `ATLAN_AGENT_ID` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/atlanhq/agent-toolkit/tree/HEAD/modelcontextprotocol) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-atlan&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ATLAN_API_KEY%22%2C%22-e%22%2C%22ATLAN_BASE_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-atlan%3A0.3.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-atlan": {
        "env": {
          "ATLAN_API_KEY": "TO_BE_SET",
          "ATLAN_BASE_URL": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "ATLAN_API_KEY",
          "-e",
          "ATLAN_BASE_URL",
          "docker.io/acuvity/mcp-server-atlan:0.3.1"
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
    "acuvity-mcp-server-atlan": {
      "env": {
        "ATLAN_API_KEY": "TO_BE_SET",
        "ATLAN_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLAN_API_KEY",
        "-e",
        "ATLAN_BASE_URL",
        "docker.io/acuvity/mcp-server-atlan:0.3.1"
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
    "acuvity-mcp-server-atlan": {
      "env": {
        "ATLAN_API_KEY": "TO_BE_SET",
        "ATLAN_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLAN_API_KEY",
        "-e",
        "ATLAN_BASE_URL",
        "docker.io/acuvity/mcp-server-atlan:0.3.1"
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
    "acuvity-mcp-server-atlan": {
      "env": {
        "ATLAN_API_KEY": "TO_BE_SET",
        "ATLAN_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLAN_API_KEY",
        "-e",
        "ATLAN_BASE_URL",
        "docker.io/acuvity/mcp-server-atlan:0.3.1"
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
    "acuvity-mcp-server-atlan": {
      "env": {
        "ATLAN_API_KEY": "TO_BE_SET",
        "ATLAN_BASE_URL": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLAN_API_KEY",
        "-e",
        "ATLAN_BASE_URL",
        "docker.io/acuvity/mcp-server-atlan:0.3.1"
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
        "env": {"ATLAN_API_KEY":"TO_BE_SET","ATLAN_BASE_URL":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","ATLAN_API_KEY","-e","ATLAN_BASE_URL","docker.io/acuvity/mcp-server-atlan:0.3.1"]
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
- arguments: `run -i --rm --read-only -e ATLAN_API_KEY -e ATLAN_BASE_URL docker.io/acuvity/mcp-server-atlan:0.3.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e ATLAN_API_KEY -e ATLAN_BASE_URL docker.io/acuvity/mcp-server-atlan:0.3.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-atlan": {
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
    "acuvity-mcp-server-atlan": {
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
  - `ATLAN_API_KEY` secret to be set as secrets.ATLAN_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `ATLAN_BASE_URL` environment variable to be set by env.ATLAN_BASE_URL

**Optional Environment variables**:
  - `ATLAN_AGENT_ID=""` environment variable can be changed with env.ATLAN_AGENT_ID=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-atlan --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-atlan --version 1.0.0
````

Install with helm

```console
helm install mcp-server-atlan oci://docker.io/acuvity/mcp-server-atlan --version 1.0.0
```

From there your MCP server mcp-server-atlan will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-atlan` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atlan/charts/mcp-server-atlan/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>search_assets_tool</summary>

**Description**:

```
Advanced asset search using FluentSearch with flexible conditions.

Args:
    conditions (Dict[str, Any], optional): Dictionary of attribute conditions to match.
        Format: {"attribute_name": value} or {"attribute_name": {"operator": operator, "value": value}}
    negative_conditions (Dict[str, Any], optional): Dictionary of attribute conditions to exclude.
        Format: {"attribute_name": value} or {"attribute_name": {"operator": operator, "value": value}}
    some_conditions (Dict[str, Any], optional): Conditions for where_some() queries that require min_somes of them to match.
        Format: {"attribute_name": value} or {"attribute_name": {"operator": operator, "value": value}}
    min_somes (int): Minimum number of some_conditions that must match. Defaults to 1.
    include_attributes (List[Union[str, AtlanField]], optional): List of specific attributes to include in results.
        Can be string attribute names or AtlanField objects.
    asset_type (Union[Type[Asset], str], optional): Type of asset to search for.
        Either a class (e.g., Table, Column) or a string type name (e.g., "Table", "Column")
    include_archived (bool): Whether to include archived assets. Defaults to False.
    limit (int, optional): Maximum number of results to return. Defaults to 10.
    offset (int, optional): Offset for pagination. Defaults to 0.
    sort_by (str, optional): Attribute to sort by. Defaults to None.
    sort_order (str, optional): Sort order, "ASC" or "DESC". Defaults to "ASC".
    connection_qualified_name (str, optional): Connection qualified name to filter by. ex: default/snowflake/123456/abc
    tags (List[str], optional): List of tags to filter by.
    directly_tagged (bool): Whether to filter for directly tagged assets only. Defaults to True.
    domain_guids (List[str], optional): List of domain GUIDs to filter by.
    date_range (Dict[str, Dict[str, Any]], optional): Date range filters.
        Format: {"attribute_name": {"gte": start_timestamp, "lte": end_timestamp}}
    guids (List[str], optional): List of asset GUIDs to filter by.

Returns:
    List[Asset]: List of assets matching the search criteria

Raises:
    Exception: If there's an error executing the search

Examples:
    # Search for verified tables
    tables = search_assets(
        asset_type="Table",
        conditions={"certificate_status": CertificateStatus.VERIFIED.value}
    )

    # Search for assets missing descriptions from the database/connection default/snowflake/123456/abc
    missing_desc = search_assets(
        connection_qualified_name="default/snowflake/123456/abc",
        negative_conditions={
            "description": "has_any_value",
            "user_description": "has_any_value"
        },
        include_attributes=["owner_users", "owner_groups"]
    )

    # Search for columns with specific certificate status
    columns = search_assets(
        asset_type="Column",
        some_conditions={
            "certificate_status": [CertificateStatus.DRAFT.value, CertificateStatus.VERIFIED.value]
        },
        tags=["PRD"],
        conditions={"created_by": "username"},
        date_range={"create_time": {"gte": 1641034800000, "lte": 1672570800000}}
    )
    # Search for assets with a specific search text
    assets = search_assets(
        conditions = {
            "name": {
                "operator": "match",
                "value": "search_text"
            },
            "description": {
                "operator": "match",
                "value": "search_text"
            }
        }
    )


    # Search for assets using advanced operators
    assets = search_assets(
        conditions={
            "name": {
                "operator": "startswith",
                "value": "prefix_",
                "case_insensitive": True
            },
            "description": {
                "operator": "contains",
                "value": "important data",
                "case_insensitive": True
            },
            "create_time": {
                "operator": "between",
                "value": [1640995200000, 1643673600000]
            }
        }
    )

    # For multiple asset types queries. ex: Search for Table, Column, or View assets from the database/connection default/snowflake/123456/abc
    assets = search_assets(
        connection_qualified_name="default/snowflake/123456/abc",
        conditions={
            "type_name": ["Table", "Column", "View"],
        }
    )

    # Search for assets with compliant business policy
    assets = search_assets(
        conditions={
            "asset_policy_guids": "business_policy_guid"
        },
        include_attributes=["asset_policy_guids"]
    )

    # Search for assets with non compliant business policy
    assets = search_assets(
        conditions={
            "non_compliant_asset_policy_guids": "business_policy_guid"
        },
        include_attributes=["non_compliant_asset_policy_guids"]
    )

    # get non compliant business policies for an asset
     assets = search_assets(
        conditions={
            "name": "has_any_value",
            "displayName": "has_any_value",
            "guid": "has_any_value"
        },
        include_attributes=["non_compliant_asset_policy_guids"]
    )

    # get compliant business policies for an asset
     assets = search_assets(
        conditions={
            "name": "has_any_value",
            "displayName": "has_any_value",
            "guid": "has_any_value"
        },
        include_attributes=["asset_policy_guids"]
    )

    # get incident for a business policy
     assets = search_assets(
        conditions={
            "asset_type": "BusinessPolicyIncident",
            "business_policy_incident_related_policy_guids": "business_policy_guid"
        },
        some_conditions={
            "certificate_status": [CertificateStatus.DRAFT.value, CertificateStatus.VERIFIED.value]
        }
    )

    # Search for glossary terms by name and status
    glossary_terms = search_assets(
        asset_type="AtlasGlossaryTerm",
        conditions={
            "certificate_status": CertificateStatus.VERIFIED.value,
            "name": {
                "operator": "contains",
                "value": "customer",
                "case_insensitive": True
            }
        },
        include_attributes=["categories"]
    )

    # Find popular but expensive assets (cost optimization)
    search_assets(
        conditions={
            "popularityScore": {"operator": "gte", "value": 0.8},
            "sourceReadQueryCost": {"operator": "gte", "value": 1000}
        },
        include_attributes=["sourceReadExpensiveQueryRecordList", "sourceCostUnit"]
    )

    # Find unused assets accessed before 2024
    search_assets(
        conditions={"sourceLastReadAt": {"operator": "lt", "value": 1704067200000}}, # Unix epoch in milliseconds
        include_attributes=["sourceReadCount", "sourceLastReadAt"]
    )

    # Get top users for a specific table
    # Note: Can't directly filter by user, but can retrieve the list
    search_assets(
        conditions={"name": "customer_transactions"},
        include_attributes=["sourceReadTopUserList", "sourceReadUserCount"]
    )

    # Find frequently accessed uncertified assets (governance gap)
    search_assets(
        conditions={
            "sourceReadUserCount": {"operator": "gte", "value": 10},
            "certificate_status": {"operator": "ne", "value": "VERIFIED"}
        }
    )

    # Query assets in specific connection with cost filters
    search_assets(
        connection_qualified_name="default/snowflake/123456",
        conditions={"sourceTotalCost": {"operator": "gte", "value": 500}},
        sort_by="sourceTotalCost",
        sort_order="DESC",
        include_attributes=[
            "sourceReadQueryComputeCostRecordList",  # Shows breakdown by warehouse
            "sourceQueryComputeCostList",  # List of warehouses used
            "sourceCostUnit"
        ]
    )

The search supports various analytics attributes following similar patterns:
- Usage Metrics:
    - `sourceReadCount`, `sourceReadUserCount` - Filter by read frequency or user diversity
    - `sourceLastReadAt`, `lastRowChangedAt` - Time-based filtering (Unix timestamp in ms)
    - `popularityScore` - Float value 0-1 indicating asset popularity

- Cost Metrics:
    - `sourceReadQueryCost`, `sourceTotalCost` - Filter by cost thresholds
    - Include `sourceCostUnit` in attributes to get cost units
    - Include `sourceReadExpensiveQueryRecordList` for detailed breakdowns

- User Analytics:
    - `sourceReadTopUserList`, `sourceReadRecentUserList` - Get user lists
    - `sourceReadTopUserRecordList`, `sourceReadRecentUserRecordList` - Get detailed records

- Query Analytics:
    - `sourceReadPopularQueryRecordList` - Popular queries for the asset
    - `lastRowChangedQuery` - Query that last modified the asset

Additional attributes you can include in the conditions to extract more metadata from an asset:
    - columns
    - column_count
    - row_count
    - readme
    - owner_users
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| asset_type | any | not set | No
| conditions | any | not set | No
| connection_qualified_name | any | not set | No
| date_range | any | not set | No
| directly_tagged | any | not set | No
| domain_guids | any | not set | No
| guids | any | not set | No
| include_archived | any | not set | No
| include_attributes | any | not set | No
| limit | any | not set | No
| min_somes | any | not set | No
| negative_conditions | any | not set | No
| offset | any | not set | No
| some_conditions | any | not set | No
| sort_by | any | not set | No
| sort_order | any | not set | No
| tags | any | not set | No
</details>
<details>
<summary>get_assets_by_dsl_tool</summary>

**Description**:

```
Execute the search with the given query
dsl_query : Union[str, Dict[str, Any]] (required):
    The DSL query used to search the index.

Example:
dsl_query = '''{
"query": {
    "function_score": {
        "boost_mode": "sum",
        "functions": [
            {"filter": {"match": {"starredBy": "john.doe"}}, "weight": 10},
            {"filter": {"match": {"certificateStatus": "VERIFIED"}}, "weight": 15},
            {"filter": {"match": {"certificateStatus": "DRAFT"}}, "weight": 10},
            {"filter": {"bool": {"must_not": [{"exists": {"field": "certificateStatus"}}]}}, "weight": 8},
            {"filter": {"bool": {"must_not": [{"terms": {"__typeName.keyword": ["Process", "DbtProcess"]}}]}}, "weight": 20}
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "minimum_should_match": 1,
                            "must": [
                                {"bool": {"should": [{"terms": {"certificateStatus": ["VERIFIED"]}}]}},
                                {"term": {"__state": "ACTIVE"}}
                            ],
                            "must_not": [
                                {"term": {"isPartial": "true"}},
                                {"terms": {"__typeName.keyword": ["Procedure", "DbtColumnProcess", "BIProcess", "MatillionComponent", "SnowflakeTag", "DbtTag", "BigqueryTag", "AIApplication", "AIModel"]}},
                                {"terms": {"__typeName.keyword": ["MCIncident", "AnomaloCheck"]}}
                            ],
                            "should": [
                                {"terms": {"__typeName.keyword": ["Query", "Collection", "AtlasGlossary", "AtlasGlossaryCategory", "AtlasGlossaryTerm", "Connection", "File"]}},
                            ]
                        }
                    }
                ]
            },
            "score_mode": "sum"
        },
        "score_mode": "sum"
    }
},
"post_filter": {
    "bool": {
        "filter": [
            {
                "bool": {
                    "must": [{"terms": {"__typeName.keyword": ["Table", "Column"]}}],
                    "must_not": [{"exists": {"field": "termType"}}]
                }
            }
        ]
    },
    "sort": [
        {"_score": {"order": "desc"}},
        {"popularityScore": {"order": "desc"}},
        {"starredCount": {"order": "desc"}},
        {"name.keyword": {"order": "asc"}}
    ],
    "track_total_hits": true,
    "size": 10,
    "include_meta": false
}'''
response = get_assets_by_dsl(dsl_query)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dsl_query | any | not set | Yes
</details>
<details>
<summary>traverse_lineage_tool</summary>

**Description**:

```
Traverse asset lineage in specified direction.

By default, essential attributes are included in results. Additional attributes can be
specified via include_attributes parameter for richer lineage information.

Args:
    guid (str): GUID of the starting asset
    direction (str): Direction to traverse ("UPSTREAM" or "DOWNSTREAM")
    depth (int, optional): Maximum depth to traverse. Defaults to 1000000.
    size (int, optional): Maximum number of results to return. Defaults to 10.
    immediate_neighbors (bool, optional): Only return immediate neighbors. Defaults to True.
    include_attributes (List[str], optional): List of additional attribute names to include in results.
        These will be added to the default set.

Default Attributes (always included):
    - name, display_name, description, qualified_name, user_description
    - certificate_status, owner_users, owner_groups
    - connector_name, has_lineage, source_created_at, source_updated_at
    - readme, asset_tags

Returns:
    Dict[str, Any]: Dictionary containing:
        - assets: List of assets in the lineage with processed attributes
        - error: None if no error occurred, otherwise the error message

Examples:
    # Get lineage with default attributes
    lineage = traverse_lineage_tool(
        guid="asset-guid-here",
        direction="DOWNSTREAM",
        depth=1000,
        size=10
    )
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | any | not set | No
| direction | any | not set | Yes
| guid | any | not set | Yes
| immediate_neighbors | any | not set | No
| include_attributes | any | not set | No
| size | any | not set | No
</details>
<details>
<summary>update_assets_tool</summary>

**Description**:

```
Update one or multiple assets with different values for attributes or term operations.

Args:
    assets (Union[Dict[str, Any], List[Dict[str, Any]]]): Asset(s) to update.
        Can be a single UpdatableAsset or a list of UpdatableAsset objects.
        For asset of type_name=AtlasGlossaryTerm or type_name=AtlasGlossaryCategory, each asset dictionary MUST include a "glossary_guid" key which is the GUID of the glossary that the term belongs to.
    attribute_name (str): Name of the attribute to update.
        Supports "user_description", "certificate_status", "readme", and "term".
    attribute_values (List[Union[str, Dict[str, Any]]]): List of values to set for the attribute.
        For certificateStatus, only "VERIFIED", "DRAFT", or "DEPRECATED" are allowed.
        For readme, the value must be a valid Markdown string.
        For term, the value must be a dict with "operation" and "term_guids" keys.

Returns:
    Dict[str, Any]: Dictionary containing:
        - updated_count: Number of assets successfully updated
        - errors: List of any errors encountered
        - operation: The operation that was performed (for term operations)

Examples:
    # Update certificate status for a single asset
    result = update_assets_tool(
        assets={
            "guid": "asset-guid-here",
            "name": "Asset Name",
            "type_name": "Asset Type Name",
            "qualified_name": "Asset Qualified Name"
        },
        attribute_name="certificate_status",
        attribute_values=["VERIFIED"]
    )

    # Update user description for multiple assets
    result = update_assets_tool(
        assets=[
            {
                "guid": "asset-guid-1",
                "name": "Asset Name 1",
                "type_name": "Asset Type Name 1",
                "qualified_name": "Asset Qualified Name 1"
            },
            {
                "guid": "asset-guid-2",
                "name": "Asset Name 2",
                "type_name": "Asset Type Name 2",
                "qualified_name": "Asset Qualified Name 2"
            }
        ],
        attribute_name="user_description",
        attribute_values=[
            "New description for asset 1", "New description for asset 2"
        ]
    )

    # Update readme for a single asset with Markdown
    result = update_assets_tool(
        assets={
            "guid": "asset-guid-here",
            "name": "Asset Name",
            "type_name": "Asset Type Name",
            "qualified_name": "Asset Qualified Name"
        },
        attribute_name="readme",
        attribute_values=['''# Customer Data Table
        Contains customer transaction records for analytics.
        **Key Info:**
        - Updated daily at 2 AM
        - Contains PII data
        - [Documentation](https://docs.example.com)''']
    )

    # Append terms to a single asset
    result = update_assets_tool(
        assets={
            "guid": "asset-guid-here",
            "name": "Customer Name Column",
            "type_name": "Column",
            "qualified_name": "default/snowflake/123456/abc/CUSTOMER_NAME"
        },
        attribute_name="term",
        attribute_values=[{
            "operation": "append",
            "term_guids": ["term-guid-1", "term-guid-2"]
        }]
    )

    # Replace all terms on multiple assets
    result = update_assets_tool(
        assets=[
            {
                "guid": "asset-guid-1",
                "name": "Table 1",
                "type_name": "Table",
                "qualified_name": "default/snowflake/123456/abc/TABLE_1"
            },
            {
                "guid": "asset-guid-2",
                "name": "Table 2",
                "type_name": "Table",
                "qualified_name": "default/snowflake/123456/abc/TABLE_2"
            }
        ],
        attribute_name="term",
        attribute_values=[
            {
                "operation": "replace",
                "term_guids": ["new-term-for-table-1-guid-1", "new-term-for-table-1-guid-2"]
            },
            {
                "operation": "replace",
                "term_guids": ["new-term-for-table-2-guid-1", "new-term-for-table-2-guid-2"]
            }
        ]
    )

    # Remove specific terms from an asset
    result = update_assets_tool(
        assets={
            "guid": "asset-guid-here",
            "name": "Customer Data Table",
            "type_name": "Table",
            "qualified_name": "default/snowflake/123456/abc/CUSTOMER_DATA"
        },
        attribute_name="term",
        attribute_values=[{
            "operation": "remove",
            "term_guids": ["term-guid-to-remove"]
        }]
    )
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assets | any | not set | Yes
| attribute_name | any | not set | Yes
| attribute_values | any | not set | Yes
</details>
<details>
<summary>query_asset_tool</summary>

**Description**:

```
Execute a SQL query on a table/view asset.

This tool enables querying table/view assets on the source similar to
what's available in the insights table. It uses the Atlan query capabilities
to execute SQL against connected data sources.

CRITICAL: Use READ-ONLY queries to retrieve data. Write and modify queries are not supported by this tool.


Args:
    sql (str): The SQL query to execute (read-only queries allowed)
    connection_qualified_name (str): Connection qualified name to use for the query.
        This is the same parameter used in search_assets_tool.
        You can find this value by searching for Table/View assets using search_assets_tool
        and extracting the first part of the 'qualifiedName' attribute.
        Example: from "default/snowflake/1657275059/LANDING/FRONTEND_PROD/PAGES"
        use "default/snowflake/1657275059"
    default_schema (str, optional): Default schema name to use for unqualified
        objects in the SQL, in the form "DB.SCHEMA"
        (e.g., "RAW.WIDEWORLDIMPORTERS_WAREHOUSE")

Examples:
    # Use case: How to query the PAGES table and retrieve the first 10 rows
    # Find tables to query using search_assets_tool
    tables = search_assets_tool(
        asset_type="Table",
        conditions={"name": "PAGES"},
        limit=5
    )
    # Extract connection info from the table's qualifiedName
    # Example qualifiedName: "default/snowflake/1657275059/LANDING/FRONTEND_PROD/PAGES"
    # connection_qualified_name: "default/snowflake/1657275059"
    # database.schema: "LANDING.FRONTEND_PROD"

    # Query the table using extracted connection info
    result = query_asset_tool(
        sql='SELECT * FROM PAGES LIMIT 10',
        connection_qualified_name="default/snowflake/1657275059",
        default_schema="LANDING.FRONTEND_PROD"
    )

    # Query without specifying default schema (fully qualified table names)
    result = query_asset_tool(
        sql='SELECT COUNT(*) FROM "LANDING"."FRONTEND_PROD"."PAGES"',
        connection_qualified_name="default/snowflake/1657275059"
    )

    # Complex analytical query on PAGES table
    result = query_asset_tool(
        sql='''
        SELECT
            page_type,
            COUNT(*) AS page_count,
            AVG(load_time) AS avg_load_time,
            MAX(views) AS max_views
        FROM PAGES
        WHERE created_date >= '2024-01-01'
        GROUP BY page_type
        ORDER BY page_count DESC
        ''',
        connection_qualified_name="default/snowflake/1657275059",
        default_schema="LANDING.FRONTEND_PROD"
    )
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_qualified_name | string | not set | Yes
| default_schema | any | not set | No
| sql | string | not set | Yes
</details>
<details>
<summary>create_glossaries</summary>

**Description**:

```
Create one or multiple AtlasGlossary assets in Atlan.

IMPORTANT BUSINESS RULES & CONSTRAINTS:
- Check for duplicate names within the same request and ask user to choose different names
- Do NOT use search tool before creating glossaries - Atlan will handle existence validation
- If user gives ambiguous instructions, ask clarifying questions

Args:
    glossaries (Union[Dict[str, Any], List[Dict[str, Any]]]): Either a single glossary
        specification (dict) or a list of glossary specifications. Each specification
        can be a dictionary containing:
        - name (str): Name of the glossary (required)
        - user_description (str, optional): Detailed description of the glossary
          proposed by the user
        - certificate_status (str, optional): Certification status
          ("VERIFIED", "DRAFT", or "DEPRECATED")

Returns:
    List[Dict[str, Any]]: List of dictionaries, each with details for a created glossary:
        - guid: The GUID of the created glossary
        - name: The name of the glossary
        - qualified_name: The qualified name of the created glossary


Examples:
    Multiple glossaries creation:
    [
        {
            "name": "Business Terms",
            "user_description": "Common business terminology",
            "certificate_status": "VERIFIED"
        },
        {
            "name": "Technical Dictionary",
            "user_description": "Technical terminology and definitions",
            "certificate_status": "DRAFT"
        }
    ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| glossaries | any | not set | Yes
</details>
<details>
<summary>create_glossary_terms</summary>

**Description**:

```
Create one or multiple AtlasGlossaryTerm assets in Atlan.

IMPORTANT BUSINESS RULES & CONSTRAINTS:
- Within a glossary, a term (single GUID) can be associated with many categories
- Two terms with the same name CANNOT exist within the same glossary (regardless of categories)
- A term is always anchored to a glossary and may also be associated with one or more categories inside the same glossary
- Before creating a term, perform a single search to check if the glossary, categories, or term with the same name already exist. Search for all relevant glossaries, categories, and terms in one call. Skip this step if you already have the required GUIDs.
- Example call for searching glossary categories and terms before term creation(Query - create a term fighterz under category Characters and Locations under Marvel Cinematic Universe (MCU) glossary):
    {
        "limit": 10,
        "conditions": {
            "type_name": ["AtlasGlossary", "AtlasGlossaryCategory","AtlasGlossaryTerm"],
            "name": ["Marvel Cinematic Universe (MCU)", "Characters", "Locations","fighterz"]
        }
    }

Args:
    terms (Union[Dict[str, Any], List[Dict[str, Any]]]): Either a single term
        specification (dict) or a list of term specifications. Each specification
        can be a dictionary containing:
        - name (str): Name of the term (required)
        - glossary_guid (str): GUID of the glossary this term belongs to (required)
        - user_description (str, optional): Detailed description of the term
          proposed by the user
        - certificate_status (str, optional): Certification status
          ("VERIFIED", "DRAFT", or "DEPRECATED")
        - category_guids (List[str], optional): List of category GUIDs this term
          belongs to.

Returns:
    List[Dict[str, Any]]: List of dictionaries, each with details for a created term:
        - guid: The GUID of the created term
        - name: The name of the term
        - qualified_name: The qualified name of the created term

Examples:
    Multiple terms creation:
    [
        {
            "name": "Customer",
            "glossary_guid": "glossary-guid-here",
            "user_description": "An individual or organization that purchases goods or services",
            "certificate_status": "VERIFIED"
        },
        {
            "name": "Annual Recurring Revenue",
            "glossary_guid": "glossary-guid-here",
            "user_description": "The yearly value of recurring revenue from customers",
            "certificate_status": "DRAFT",
            "category_guids": ["category-guid-1"]
        }
    ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| terms | any | not set | Yes
</details>
<details>
<summary>create_glossary_categories</summary>

**Description**:

```
Create one or multiple AtlasGlossaryCategory assets in Atlan.

IMPORTANT BUSINESS RULES & CONSTRAINTS:
- There cannot be two categories with the same name under the same glossary (at the same level)
- Under a parent category, there cannot be subcategories with the same name (at the same level)
- Categories with the same name can exist under different glossaries (this is allowed)
- Cross-level naming is allowed: category "a" can have subcategory "b", and category "b" can have subcategory "a"
- Example allowed structure: Glossary "bui" → category "a" → subcategory "b" AND category "b" → subcategory "a"
- Always check for duplicate names at the same level and ask user to choose different names
- Before creating a category, perform a single search to check if the glossary or categories with the same name already exist. Skip this step if you already have the required GUIDs.
- Example call for searching glossary and categories before category creation(Query - create categories Locations and Characters under Marvel Cinematic Universe (MCU) glossary):
    {
        "limit": 10,
        "conditions": {
            "type_name": ["AtlasGlossary", "AtlasGlossaryCategory"],
            "name": ["Marvel Cinematic Universe (MCU)", "Characters", "Locations"]
        }
    }
- If user gives ambiguous instructions, ask clarifying questions

Args:
    categories (Union[Dict[str, Any], List[Dict[str, Any]]]): Either a single category
        specification (dict) or a list of category specifications. Each specification
        can be a dictionary containing:
        - name (str): Name of the category (required)
        - glossary_guid (str): GUID of the glossary this category belongs to (required)
        - user_description (str, optional): Detailed description of the category
          proposed by the user
        - certificate_status (str, optional): Certification status
          ("VERIFIED", "DRAFT", or "DEPRECATED")
        - parent_category_guid (str, optional): GUID of the parent category if this
          is a subcategory

Returns:
    List[Dict[str, Any]]: List of dictionaries, each with details for a created category:
        - guid: The GUID of the created category
        - name: The name of the category
        - qualified_name: The qualified name of the created category

Examples:
    Multiple categories creation:
    [
        {
            "name": "Customer Data",
            "glossary_guid": "glossary-guid-here",
            "user_description": "Terms related to customer information and attributes",
            "certificate_status": "VERIFIED"
        },
        {
            "name": "PII",
            "glossary_guid": "glossary-guid-here",
            "parent_category_guid": "parent-category-guid-here",
            "user_description": "Subcategory for PII terms",
            "certificate_status": "DRAFT"
        }
    ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| categories | any | not set | Yes
</details>
<details>
<summary>create_domains</summary>

**Description**:

```
Create Data Domains or Sub Domains in Atlan.

IMPORTANT BUSINESS RULES & CONSTRAINTS:
- Before creating a domain/subdomain, you may want to search for existing
  domains to avoid duplicates or to get the qualified_name for parent relationships
- Domain names must be unique at the top level
- Subdomain names must be unique within the same parent domain

Args:
    domains (Union[Dict[str, Any], List[Dict[str, Any]]]): Either a single domain
        specification (dict) or a list of domain specifications.

For Data Domain:
    - name (str): Name of the domain (required)
    - user_description (str, optional): Detailed description
    - certificate_status (str, optional): "VERIFIED", "DRAFT", or "DEPRECATED"

For Sub Domain:
    - name (str): Name of the subdomain (required)
    - parent_domain_qualified_name (str): Qualified name of parent domain (required)
    - user_description (str, optional): Detailed description
    - certificate_status (str, optional): "VERIFIED", "DRAFT", or "DEPRECATED"

Returns:
    List[Dict[str, Any]]: List of dictionaries, each with details for a created asset:
        - guid: The GUID of the created asset
        - name: The name of the asset
        - qualified_name: The qualified name of the created asset

Examples:
    # Create a single Data Domain
    create_domains({
        "name": "Marketing",
        "user_description": "Marketing data domain",
        "certificate_status": "VERIFIED"
    })

    # Create a Sub Domain under an existing domain
    create_domains({
        "name": "Social Marketing",
        "parent_domain_qualified_name": "default/domain/marketing",
        "user_description": "Social media marketing subdomain",
        "certificate_status": "DRAFT"
    })

    # Create multiple domains in one call
    create_domains([
        {
            "name": "Sales",
            "user_description": "Sales data domain"
        },
        {
            "name": "E-commerce Sales",
            "parent_domain_qualified_name": "default/domain/sales",
            "user_description": "E-commerce sales subdomain"
        }
    ])
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| domains | any | not set | Yes
</details>
<details>
<summary>create_data_products</summary>

**Description**:

```
Create Data Products in Atlan.

IMPORTANT BUSINESS RULES & CONSTRAINTS:
- Before creating a product, you may want to search for existing domains
  to get the qualified_name for the domain relationship
- Product names must be unique within the same domain
- At least one asset GUID must be provided for each product

Args:
    products (Union[Dict[str, Any], List[Dict[str, Any]]]): Either a single product
        specification (dict) or a list of product specifications.

For Data Product:
    - name (str): Name of the product (required)
    - domain_qualified_name (str): Qualified name of the domain (required)
    - asset_guids (List[str]): List of asset GUIDs to link to this product (required).
      At least one asset GUID must be provided. Use search_assets_tool to find asset GUIDs.
    - user_description (str, optional): Detailed description
    - certificate_status (str, optional): "VERIFIED", "DRAFT", or "DEPRECATED"

Returns:
    List[Dict[str, Any]]: List of dictionaries, each with details for a created asset:
        - guid: The GUID of the created asset
        - name: The name of the asset
        - qualified_name: The qualified name of the created asset

Examples:
    # Create a Data Product with linked assets (asset_guids required)
    # First, search for assets to get their GUIDs using search_assets_tool
    create_data_products({
        "name": "Marketing Influence",
        "domain_qualified_name": "default/domain/marketing",
        "user_description": "Product for marketing influence analysis",
        "asset_guids": ["asset-guid-1", "asset-guid-2"]  # GUIDs from search_assets_tool
    })

    # Create multiple products in one call
    create_data_products([
        {
            "name": "Sales Analytics",
            "domain_qualified_name": "default/domain/sales",
            "user_description": "Sales analytics product",
            "asset_guids": ["table-guid-1", "table-guid-2"]
        },
        {
            "name": "Customer Insights",
            "domain_qualified_name": "default/domain/marketing",
            "user_description": "Customer insights product",
            "asset_guids": ["view-guid-1"]
        }
    ])
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| products | any | not set | Yes
</details>
<details>
<summary>create_dq_rules_tool</summary>

**Description**:

```
Create one or multiple data quality rules in Atlan.

Supports all rule types: column-level, table-level, and custom SQL rules.
Rules can be created individually or in bulk for efficient setup.

Args:
    rules (Union[Dict[str, Any], List[Dict[str, Any]]]): Either a single rule
        specification or a list of rule specifications. Each specification
        must include:
        - rule_type (str): Type of rule (see Supported Rule Types) [REQUIRED]
        - asset_qualified_name (str): Qualified name of the asset (Table, View, MaterialisedView, or SnowflakeDynamicTable) [REQUIRED]
        - asset_type (str): Type of asset - "Table" | "View" | "MaterialisedView" | "SnowflakeDynamicTable" [OPTIONAL, default: "Table"]
        - threshold_value (int/float): Threshold value for comparison [REQUIRED]
        - column_qualified_name (str): Column qualified name [REQUIRED for column-level rules, NOT for Row Count/Custom SQL]
        - threshold_compare_operator (str): Comparison operator (EQUAL, GREATER_THAN, etc.) [OPTIONAL, default varies by rule]
        - threshold_unit (str): Time unit for Freshness rules (DAYS, HOURS, MINUTES) [REQUIRED for Freshness, N/A for others]
        - alert_priority (str): Alert priority level (LOW, NORMAL, URGENT) [OPTIONAL, default: NORMAL]
        - row_scope_filtering_enabled (bool): Enable row-level filtering [OPTIONAL]
        - rule_conditions (List[Dict]): Conditions for String Length/Regex/Valid Values [REQUIRED for conditional rules]
        - custom_sql (str): SQL query [REQUIRED for Custom SQL rules]
        - rule_name (str): Name for the rule [REQUIRED for Custom SQL rules]
        - dimension (str): DQ dimension [REQUIRED for Custom SQL rules]
        - description (str): Rule description [OPTIONAL]

Returns:
    Dict[str, Any]: Dictionary containing:
        - created_count: Number of rules successfully created
        - created_rules: List of created rules with guid, qualified_name, rule_type
        - errors: List of any errors encountered

Examples:
    # Column-level rules (Null Count, Min/Max Value, Unique/Duplicate Count, etc.)
    rule = create_dq_rules_tool({
        "rule_type": "Null Count",  # or "Min Value", "Max Value", "Unique Count", etc.
        "asset_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE",
        "column_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE/EMAIL",
        "threshold_compare_operator": "LESS_THAN_EQUAL",  # EQUAL, GREATER_THAN, etc.
        "threshold_value": 5,
        "alert_priority": "URGENT",  # LOW, NORMAL, URGENT
        "row_scope_filtering_enabled": True,
        "description": "Email column should have minimal nulls"
    })

    # Conditional rules (String Length, Regex, Valid Values)
    rule = create_dq_rules_tool({
        "rule_type": "String Length",  # or "Regex", "Valid Values"
        "asset_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE",
        "column_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE/PHONE",
        "threshold_value": 10,
        "alert_priority": "URGENT",
        "rule_conditions": [{
            "type": "STRING_LENGTH_BETWEEN",  # See Rule Condition Types below
            "min_value": 10,
            "max_value": 15
        }],
        # For Regex: {"type": "REGEX_NOT_MATCH", "value": "pattern"}
        # For Valid Values: {"type": "IN_LIST", "value": ["ACTIVE", "INACTIVE"]}
        "row_scope_filtering_enabled": True
    })

    # Table-level (Row Count) and Time-based (Freshness)
    rule = create_dq_rules_tool({
        "rule_type": "Row Count",  # No column_qualified_name needed
        "asset_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE",
        "asset_type": "Table",  # Optional: "Table" (default), "View", "MaterialisedView", "SnowflakeDynamicTable"
        "threshold_compare_operator": "GREATER_THAN_EQUAL",
        "threshold_value": 1000,
        "alert_priority": "URGENT"
    })
    # For Freshness: Add "column_qualified_name" + "threshold_unit": "DAYS"/"HOURS"/"MINUTES"

    # Custom SQL rule
    rule = create_dq_rules_tool({
        "rule_type": "Custom SQL",
        "asset_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE",
        "rule_name": "Revenue Consistency Check",
        "custom_sql": "SELECT COUNT(*) FROM TABLE WHERE revenue < 0 OR revenue > 1000000",
        "threshold_compare_operator": "EQUAL",
        "threshold_value": 0,
        "alert_priority": "URGENT",
        "dimension": "CONSISTENCY",  # See Data Quality Dimensions below
        "description": "Ensure revenue values are within expected range"
    })

    # Bulk creation - Pass array instead of single dict
    rules = create_dq_rules_tool([
        {"rule_type": "Null Count", "column_qualified_name": "...EMAIL", ...},
        {"rule_type": "Duplicate Count", "column_qualified_name": "...USER_ID", ...},
        {"rule_type": "Row Count", "asset_qualified_name": "...", ...}
    ])

Supported Rule Types:
    Completeness: "Null Count", "Null Percentage", "Blank Count", "Blank Percentage"
    Statistical: "Min Value", "Max Value", "Average", "Standard Deviation"
    Uniqueness: "Unique Count", "Duplicate Count"
    Validity: "Regex", "String Length", "Valid Values"
    Timeliness: "Freshness"
    Volume: "Row Count"
    Custom: "Custom SQL"

Supported Asset Types:
    "Table", "View", "MaterialisedView", "SnowflakeDynamicTable"

Valid Alert Priority Levels:
    "LOW", "NORMAL" (default), "URGENT"

Threshold Operators:
    "EQUAL", "GREATER_THAN", "GREATER_THAN_EQUAL", "LESS_THAN", "LESS_THAN_EQUAL", "BETWEEN"

Threshold Units (Freshness only):
    "DAYS", "HOURS", "MINUTES"

Data Quality Dimensions (Custom SQL only):
    "COMPLETENESS", "VALIDITY", "UNIQUENESS", "TIMELINESS", "VOLUME", "ACCURACY", "CONSISTENCY"

Rule Condition Types:
    String Length: "STRING_LENGTH_EQUALS", "STRING_LENGTH_BETWEEN",
                  "STRING_LENGTH_GREATER_THAN", "STRING_LENGTH_LESS_THAN"
    Regex: "REGEX_MATCH", "REGEX_NOT_MATCH"
    Valid Values: "IN_LIST", "NOT_IN_LIST"
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| rules | any | not set | Yes
</details>
<details>
<summary>schedule_dq_rules_tool</summary>

**Description**:

```
Schedule data quality rule execution for one or multiple assets.

Args:
    schedules: Single schedule or list of schedules. Each schedule requires:
        - asset_type (str): "Table", "View", "MaterialisedView", or "SnowflakeDynamicTable"
        - asset_name (str): Name of the asset
        - asset_qualified_name (str): Qualified name of the asset
        - schedule_crontab (str): Cron expression (5 fields: min hour day month weekday)
        - schedule_time_zone (str): Timezone (e.g., "UTC", "America/New_York")

Returns:
    Dict with scheduled_count, scheduled_assets, and errors.

Example:
    schedule_dq_rules_tool({
        "asset_type": "Table",
        "asset_name": "CUSTOMERS",
        "asset_qualified_name": "default/snowflake/123/DB/SCHEMA/CUSTOMERS",
        "schedule_crontab": "0 2 * * *",
        "schedule_time_zone": "UTC"
    })
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| schedules | any | not set | Yes
</details>
<details>
<summary>delete_dq_rules_tool</summary>

**Description**:

```
Delete one or multiple data quality rules in Atlan.

Args:
    rule_guids: Single rule GUID (string) or list of rule GUIDs to delete.

Returns:
    Dict with deleted_count, deleted_rules (list of GUIDs), and errors.

Example:
    # Delete single rule
    delete_dq_rules_tool("rule-guid-123")

    # Delete multiple rules
    delete_dq_rules_tool(["rule-guid-1", "rule-guid-2"])
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| rule_guids | any | not set | Yes
</details>
<details>
<summary>update_dq_rules_tool</summary>

**Description**:

```
Update existing data quality rules in Atlan.

Args:
    rules: Single rule dict or list of rule dicts. Required fields:
        - qualified_name: Rule's qualified name
        - rule_type: Rule type (e.g., "Null Count", "Row Count", "Custom SQL")
        - asset_qualified_name: Table/view qualified name
    Optional fields: threshold_value, threshold_compare_operator, threshold_unit,
    alert_priority, custom_sql, rule_name, dimension, rule_conditions,
    row_scope_filtering_enabled, description

Returns:
    Dict with updated_count, updated_rules, and errors.

Examples:
    # Single rule update
    update_dq_rules_tool({
        "qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE/rule/abc-123",
        "rule_type": "Null Count",
        "asset_qualified_name": "default/snowflake/123/DB/SCHEMA/TABLE",
        "threshold_value": 10,
        "alert_priority": "URGENT"
    })

    # Bulk update with conditions
    update_dq_rules_tool([
        {"qualified_name": "...", "rule_type": "Null Count", "threshold_value": 5},
        {"qualified_name": "...", "rule_type": "String Length",
         "rule_conditions": [{"type": "STRING_LENGTH_BETWEEN", "min_value": 10, "max_value": 100}]}
    ])

Rule Types: "Null Count", "Null Percentage", "Blank Count", "Blank Percentage",
"Min Value", "Max Value", "Average", "Standard Deviation", "Unique Count",
"Duplicate Count", "Regex", "String Length", "Valid Values", "Freshness",
"Row Count", "Custom SQL"

Alert Priority: "LOW", "NORMAL", "URGENT"
Operators: "EQUAL", "GREATER_THAN", "GREATER_THAN_EQUAL", "LESS_THAN",
           "LESS_THAN_EQUAL", "BETWEEN"
Threshold Units: "DAYS", "HOURS", "MINUTES" (Freshness only)
Dimensions: "COMPLETENESS", "VALIDITY", "UNIQUENESS", "TIMELINESS", "VOLUME",
            "ACCURACY", "CONSISTENCY" (Custom SQL only)
Condition Types: "STRING_LENGTH_EQUALS", "STRING_LENGTH_BETWEEN",
                 "STRING_LENGTH_GREATER_THAN", "STRING_LENGTH_LESS_THAN",
                 "REGEX_MATCH", "REGEX_NOT_MATCH", "IN_LIST", "NOT_IN_LIST"
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| rules | any | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_data_products | description | 6b5521bfbf46eb209b73a7d3fb53a63da91a2a63d7dd56d6ba0352f4215ff6e4 |
| tools | create_domains | description | 2b35d6c91297a7ce08a35f079b9b863fb3f74e86917348b73b30dac7f342f53d |
| tools | create_dq_rules_tool | description | 71164561aff311869de2b7ad6da3de7ec0fa8fa3fe37e8ea0aff7801bbf096d6 |
| tools | create_glossaries | description | 6def93365ff5a297ccfb06ae4817d9b6bdec17a5c8c8fac2a3f72e9abf3debb4 |
| tools | create_glossary_categories | description | 10973ccbe9bf5be9658e56626fb6686394c9b93a7c4783395a96e309caee3d1d |
| tools | create_glossary_terms | description | 04b0d10b409b75d818e9615ce00fe44ac5b47ec390dafc1d03638d6750886098 |
| tools | delete_dq_rules_tool | description | 2724945d8ce6ddf083e20ce2ce260dfaadb0ce84d3b09ac0d6ab0f4b95efd97c |
| tools | get_assets_by_dsl_tool | description | 3b913d684b59a9e090fbb1ab69bfa7a19ff10e65b0144f5000d0053b2d7293d7 |
| tools | query_asset_tool | description | 03b61eaec2c66b73b3a5d570f9d273005a5be7e4ad8166001cf2ef33c1a48dd2 |
| tools | schedule_dq_rules_tool | description | 2253bc654ab0655925c5bcc3216ece47da5554f6bfee02c346609d61bc418469 |
| tools | search_assets_tool | description | cafd292f6c04be0b99273ab5937c8caac99d0715527dcc3e30c8995e9585bff5 |
| tools | traverse_lineage_tool | description | 5dba0e2d1d195f6c6b1e5c81a15d5df21c60f7c8a06532fd5c78c2abcc1aee1a |
| tools | update_assets_tool | description | 182c1f0fd069655b956ae8456347c255fcbda274f9cfeb345a653f454bfb5953 |
| tools | update_dq_rules_tool | description | aee5aec15758138e984725f92792a46ddcafeec0a2e1ebaee0144068effbfc9b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
