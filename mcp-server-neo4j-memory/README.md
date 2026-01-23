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


# What is mcp-server-neo4j-memory?
[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-neo4j-memory/0.4.4?logo=docker&logoColor=fff&label=0.4.4)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-memory)
[![PyPI](https://img.shields.io/badge/0.4.4-3775A9?logo=pypi&logoColor=fff&label=mcp-neo4j-memory)](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-memory/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_PASSWORD%22%2C%22-e%22%2C%22NEO4J_URL%22%2C%22-e%22%2C%22NEO4J_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-memory%3A0.4.4%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides persistent memory capabilities through Neo4j graph database integration.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-neo4j-memory original [sources](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-neo4j-memory/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/charts/mcp-server-neo4j-memory/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-neo4j-memory run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-neo4j-memory scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `NEO4J_PASSWORD` required to be set
  - `NEO4J_URL` required to be set
  - `NEO4J_USERNAME` required to be set
  - `NEO4J_DATABASE` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_PASSWORD%22%2C%22-e%22%2C%22NEO4J_URL%22%2C%22-e%22%2C%22NEO4J_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-memory%3A0.4.4%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-neo4j-memory": {
        "env": {
          "NEO4J_PASSWORD": "TO_BE_SET",
          "NEO4J_URL": "TO_BE_SET",
          "NEO4J_USERNAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "NEO4J_PASSWORD",
          "-e",
          "NEO4J_URL",
          "-e",
          "NEO4J_USERNAME",
          "docker.io/acuvity/mcp-server-neo4j-memory:0.4.4"
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
    "acuvity-mcp-server-neo4j-memory": {
      "env": {
        "NEO4J_PASSWORD": "TO_BE_SET",
        "NEO4J_URL": "TO_BE_SET",
        "NEO4J_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_PASSWORD",
        "-e",
        "NEO4J_URL",
        "-e",
        "NEO4J_USERNAME",
        "docker.io/acuvity/mcp-server-neo4j-memory:0.4.4"
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
    "acuvity-mcp-server-neo4j-memory": {
      "env": {
        "NEO4J_PASSWORD": "TO_BE_SET",
        "NEO4J_URL": "TO_BE_SET",
        "NEO4J_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_PASSWORD",
        "-e",
        "NEO4J_URL",
        "-e",
        "NEO4J_USERNAME",
        "docker.io/acuvity/mcp-server-neo4j-memory:0.4.4"
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
    "acuvity-mcp-server-neo4j-memory": {
      "env": {
        "NEO4J_PASSWORD": "TO_BE_SET",
        "NEO4J_URL": "TO_BE_SET",
        "NEO4J_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_PASSWORD",
        "-e",
        "NEO4J_URL",
        "-e",
        "NEO4J_USERNAME",
        "docker.io/acuvity/mcp-server-neo4j-memory:0.4.4"
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
    "acuvity-mcp-server-neo4j-memory": {
      "env": {
        "NEO4J_PASSWORD": "TO_BE_SET",
        "NEO4J_URL": "TO_BE_SET",
        "NEO4J_USERNAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "NEO4J_PASSWORD",
        "-e",
        "NEO4J_URL",
        "-e",
        "NEO4J_USERNAME",
        "docker.io/acuvity/mcp-server-neo4j-memory:0.4.4"
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
        "env": {"NEO4J_PASSWORD":"TO_BE_SET","NEO4J_URL":"TO_BE_SET","NEO4J_USERNAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","NEO4J_PASSWORD","-e","NEO4J_URL","-e","NEO4J_USERNAME","docker.io/acuvity/mcp-server-neo4j-memory:0.4.4"]
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
- arguments: `run -i --rm --read-only -e NEO4J_PASSWORD -e NEO4J_URL -e NEO4J_USERNAME docker.io/acuvity/mcp-server-neo4j-memory:0.4.4`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e NEO4J_PASSWORD -e NEO4J_URL -e NEO4J_USERNAME docker.io/acuvity/mcp-server-neo4j-memory:0.4.4
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-neo4j-memory": {
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
    "acuvity-mcp-server-neo4j-memory": {
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
  - `NEO4J_PASSWORD` secret to be set as secrets.NEO4J_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `NEO4J_URL` environment variable to be set by env.NEO4J_URL
  - `NEO4J_USERNAME` environment variable to be set by env.NEO4J_USERNAME

**Optional Environment variables**:
  - `NEO4J_DATABASE=""` environment variable can be changed with env.NEO4J_DATABASE=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
````

Install with helm

```console
helm install mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
```

From there your MCP server mcp-server-neo4j-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-neo4j-memory` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/charts/mcp-server-neo4j-memory/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>read_graph</summary>

**Description**:

```
Read the entire knowledge graph with all entities and relationships.

Returns the complete memory graph including all stored entities and their relationships.
Use this to get a full overview of stored knowledge.

Returns:
    KnowledgeGraph: Complete graph with all entities and relations
    
Example response:
{
    "entities": [
        {"name": "John Smith", "type": "person", "observations": ["Works at Neo4j"]},
        {"name": "Neo4j Inc", "type": "company", "observations": ["Graph database company"]}
    ],
    "relations": [
        {"source": "John Smith", "target": "Neo4j Inc", "relationType": "WORKS_AT"}
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_entities</summary>

**Description**:

```
Create multiple new entities in the knowledge graph.

Creates new memory entities with their associated observations. If an entity with the same name
already exists, this operation will merge the observations with existing ones.

    
Returns:
    list[Entity]: The created entities with their final state
    
Example call:
{
    "entities": [
        {
            "name": "Alice Johnson",
            "type": "person",
            "observations": ["Software engineer", "Lives in Seattle", "Enjoys hiking"]
        },
        {
            "name": "Microsoft",
            "type": "company", 
            "observations": ["Technology company", "Headquartered in Redmond, WA"]
        }
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entities | array | List of entities to create with name, type, and observations | Yes
</details>
<details>
<summary>create_relations</summary>

**Description**:

```
Create multiple new relationships between existing entities in the knowledge graph.

Creates directed relationships between entities that already exist. Both source and target
entities must already be present in the graph. Use descriptive relationship types.

Returns:
    list[Relation]: The created relationships
    
Example call:
{
    "relations": [
        {
            "source": "Alice Johnson",
            "target": "Microsoft", 
            "relationType": "WORKS_AT"
        },
        {
            "source": "Alice Johnson",
            "target": "Seattle",
            "relationType": "LIVES_IN"
        }
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | List of relations to create between existing entities | Yes
</details>
<details>
<summary>add_observations</summary>

**Description**:

```
Add new observations/facts to existing entities in the knowledge graph.

Appends new observations to entities that already exist. The entity must be present
in the graph before adding observations. Each observation should be a distinct fact.

Returns:
    list[dict]: Details about the added observations including entity name and new facts
    
Example call:
{
    "observations": [
        {
            "entityName": "Alice Johnson",
            "observations": ["Promoted to Senior Engineer", "Completed AWS certification"]
        },
        {
            "entityName": "Microsoft",
            "observations": ["Launched new AI products", "Stock price increased 15%"]
        }
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| observations | array | List of observations to add to existing entities | Yes
</details>
<details>
<summary>delete_entities</summary>

**Description**:

```
Delete entities and all their associated relationships from the knowledge graph.

Permanently removes entities from the graph along with all relationships they participate in.
This is a destructive operation that cannot be undone. Entity names must match exactly.

Returns:
    str: Success confirmation message
    
Example call:
{
    "entityNames": ["Old Company", "Outdated Person"]
}

Warning: This will delete the entities and ALL relationships they're involved in.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entityNames | array | List of exact entity names to delete permanently | Yes
</details>
<details>
<summary>delete_observations</summary>

**Description**:

```
Delete specific observations from existing entities in the knowledge graph.

Removes specific observation texts from entities. The observation text must match exactly
what is stored. The entity will remain but the specified observations will be deleted.

Returns:
    str: Success confirmation message
    
Example call:
{
    "deletions": [
        {
            "entityName": "Alice Johnson",
            "observations": ["Old job title", "Outdated phone number"]
        },
        {
            "entityName": "Microsoft", 
            "observations": ["Former CEO information"]
        }
    ]
}

Note: Observation text must match exactly (case-sensitive) to be deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| deletions | array | List of specific observations to remove from entities | Yes
</details>
<details>
<summary>delete_relations</summary>

**Description**:

```
Delete specific relationships between entities in the knowledge graph.

Removes relationships while keeping the entities themselves. The source, target, and 
relationship type must match exactly for deletion. This only affects the relationships,
not the entities they connect.

Returns:
    str: Success confirmation message
    
Example call:
{
    "relations": [
        {
            "source": "Alice Johnson",
            "target": "Old Company",
            "relationType": "WORKS_AT"
        },
        {
            "source": "John Smith", 
            "target": "Former City",
            "relationType": "LIVES_IN"
        }
    ]
}

Note: All fields (source, target, relationType) must match exactly for deletion.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | List of specific relationships to delete from the graph | Yes
</details>
<details>
<summary>search_memories</summary>

**Description**:

```
Search for entities in the knowledge graph using fulltext search.

Searches across entity names, types, and observations using Neo4j's fulltext index.
Returns matching entities and their related connections. Supports partial matches
and multiple search terms.

Returns:
    KnowledgeGraph: Subgraph containing matching entities and their relationships
    
Example call:
{
    "query": "engineer software"
}

This searches for entities containing "engineer" or "software" in their name, type, or observations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Fulltext search query to find entities by name, type, or observations | Yes
</details>
<details>
<summary>find_memories_by_name</summary>

**Description**:

```
Find specific entities by their exact names.

Retrieves entities that exactly match the provided names, along with all their
relationships and connected entities. Use this when you know the exact entity names.

Returns:
    KnowledgeGraph: Subgraph containing the specified entities and their relationships
    
Example call:
{
    "names": ["Alice Johnson", "Microsoft", "Seattle"]
}

This retrieves the entities with exactly those names plus their connections.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| names | array | List of exact entity names to retrieve | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_observations | description | 74685109ad3cb4420a3f78ecd806c01d759803b525dc605879abbb7aac0332f9 |
| tools | add_observations | observations | 1dd71ddf6c37cd97309614815eb4678af3b8ec1fa7d869530c77820f295c640e |
| tools | create_entities | description | a029f2918d3008cf3fb59a0a5e56ef47911680558bde63e5f8de2fe94f5f9018 |
| tools | create_entities | entities | 81bf714250114c87d7635f4f37ec618a4919710bb558f06257409a3dfeb16202 |
| tools | create_relations | description | 867a4b2cc7e44b7e459b51e552fe4cb7228fe39b5ad2d81d34aaa49f3356c7e7 |
| tools | create_relations | relations | 6c7122f97e10ddbd5f84c7ddd9d9486b6d87f7e18c441f0d1cb0fb2049b4ae1d |
| tools | delete_entities | description | 4072c70aecf3e87e22273bf1964eeff7fa7d6baddd9b7af01b99dfeb5d50a844 |
| tools | delete_entities | entityNames | 07de112fc04997e4c54813a6f550234605df1b834c18f3719db8c264dbd196d6 |
| tools | delete_observations | description | 4c2fbb82d68f5fb10f0e051f676537cfc90ff7e470c9a9945a8708732ffc59e1 |
| tools | delete_observations | deletions | 15503546937d809c58c4c7e356abfd5adb13b37fda2af857cfa6c096042eb0f9 |
| tools | delete_relations | description | 9eb23da9b20cf68c38323bc5d32714bdc65a3b2c09f018069e2011744fbf4fb3 |
| tools | delete_relations | relations | 8b67ac0a7ec71340f17625aab674a7b807a98a1a06c883939aaf72c718ae0b11 |
| tools | find_memories_by_name | description | 0cf3fbcbe4d028e188890a4e440486759d35e55ebe22f9eff111d73084619e41 |
| tools | find_memories_by_name | names | 30dd21d889e064d390457c1c99e9d6eb58c49238c0691a8d558f5a2a986ffdc3 |
| tools | read_graph | description | 8eeeccee1fdb8b2a187ce791a2c923e2ee4e82b6480c11f26d515ba4e8a3f348 |
| tools | search_memories | description | 5b768f79973ccec75308c11a712ec3d5641124d594eb7b71358c2334352f3cf6 |
| tools | search_memories | query | 727e760e5c1432a057d24c0d97099961093e08eec261f5cdfcc3af703d851712 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
