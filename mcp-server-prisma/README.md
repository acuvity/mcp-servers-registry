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


# What is mcp-server-prisma?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-prisma/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-prisma/6.8.1?logo=docker&logoColor=fff&label=6.8.1)](https://hub.docker.com/r/acuvity/mcp-server-prisma)
[![PyPI](https://img.shields.io/badge/6.8.1-3775A9?logo=pypi&logoColor=fff&label=prisma)](https://github.com/prisma/prisma)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-prisma&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-prisma%3A6.8.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Gives LLMs the ability to manage Prisma Postgres databases.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from prisma original [sources](https://github.com/prisma/prisma).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-prisma/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/charts/mcp-server-prisma/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure prisma run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/charts/mcp-server-prisma#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# 📦 How to Install


> [!TIP]
> Given mcp-server-prisma scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-prisma&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-prisma%3A6.8.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-prisma": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-prisma:6.8.1"
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
    "acuvity-mcp-server-prisma": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-prisma:6.8.1"
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
    "acuvity-mcp-server-prisma": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-prisma:6.8.1"
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
    "acuvity-mcp-server-prisma": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-prisma:6.8.1"
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
    "acuvity-mcp-server-prisma": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-prisma:6.8.1"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-prisma:6.8.1"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-prisma:6.8.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-prisma:6.8.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-prisma": {
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
    "acuvity-mcp-server-prisma": {
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

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-prisma --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-prisma --version 1.0.0
````

Install with helm

```console
helm install mcp-server-prisma oci://docker.io/acuvity/mcp-server-prisma --version 1.0.0
```

From there your MCP server mcp-server-prisma will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-prisma` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-prisma/charts/mcp-server-prisma/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>migrate-status</summary>

**Description**:

```
The prisma migrate status command looks up the migrations in ./prisma/migrations/* folder and the entries in the _prisma_migrations table and compiles information about the state of the migrations in your database.
            Example output:

            Status
            3 migrations found in prisma/migrations

            Your local migration history and the migrations table from your database are different:

            The last common migration is: 20201127134938_new_migration

            The migration have not yet been applied:
            20201208100950_test_migration

            The migrations from the database are not found locally in prisma/migrations:
            20201208100950_new_migration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectCWD | string | not set | Yes
</details>
<details>
<summary>migrate-dev</summary>

**Description**:

```
Prisma Migrate Dev is used to update Prisma whenever the schema.prisma file has been modified. Always provide a descriptive name argument describing the change that was made to the Prisma Schema.

            The migrate dev command performs these steps:

            1. Reruns the existing migration history in the shadow database in order to detect schema drift (edited or deleted migration file, or a manual changes to the database schema)
            2. Applies pending migrations to the shadow database (for example, new migrations created by colleagues)
            3. Generates a new migration from any changes you made to the Prisma schema before running migrate dev
            4. Applies all unapplied migrations to the development database and updates the _prisma_migrations table
            5. Triggers the generation of artifacts (for example, Prisma Client)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| projectCWD | string | not set | Yes
</details>
<details>
<summary>migrate-reset</summary>

**Description**:

```
Prisma Migrate Reset --force is used to reset the database and migration history if drift is detected. Only run this command on a development database - never on production databases! If in doubt, ask the user to confirm.

                The migrate reset command performs these steps:

                1. Drops the database/schema if possible, or performs a soft reset if the environment does not allow deleting databases/schemas
                2. Creates a new database/schema with the same name if the database/schema was dropped
                3. Applies all migrations
                4. Runs seed scripts
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectCWD | string | not set | Yes
</details>
<details>
<summary>Prisma-Postgres-account-status</summary>

**Description**:

```
Prisma Platform Auth Show provides information about the currently logged in user. If the user is not logged in, you should instruct them to do so by running `npx prisma platform auth login --early-access` and then re-running this command to verify.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectCWD | string | not set | Yes
</details>
<details>
<summary>Create-Prisma-Postgres-Database</summary>

**Description**:

```
Create a new online Prisma Postgres database.
      Specify a name that makes sense to the user - maybe the name of the project they are working on.
      Specify a region that makes sense for the user. Pick between these three options: us-east-1, eu-west-3, ap-northeast-1. If you are unsure, pick us-east-1.
      Provide the current working directory of the users project. This should be the top level directory of the project.
      If the response idicates that you have reached the workspace plan limit, you should instruct the user to do one of these things:
      - If they want to connect to an existing database, they should go to console.prisma.io and copy the connection string
      - If they want to upgrade their plan, they should go to console.prisma.io and upgrade their plan in order to be able to create more databases
      - If they want to delete a database they no longer need, they should go to console.prisma.io and delete the database project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| projectCWD | string | not set | Yes
| region | string | not set | Yes
</details>
<details>
<summary>Prisma-Login</summary>

**Description**:

```
Login or create an account in order to be able to use Prisma Postgres.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectCWD | string | not set | Yes
</details>
<details>
<summary>Prisma-Studio</summary>

**Description**:

```
Open Prisma Studio to view data in your database in a pleasing visual ui.
      Provide the current working directory of the users project. This should be the top level directory of the project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectCWD | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | Create-Prisma-Postgres-Database | description | bb0e90f2a507a7b3768fc2be2ce3a66b7c25402769e57704bb234aaca440cb22 |
| tools | Prisma-Login | description | 8163d84e61b8f79b4616a4bd398cec05d1d70c80849d985b9b2686f11f79ae28 |
| tools | Prisma-Postgres-account-status | description | b33c5b51a7deeb7a622b8acfdab90e8cccc904df9018c8d0a43221a7c80fb48e |
| tools | Prisma-Studio | description | bbd3123c75ec99c4f9dce735cce68528bc8415d6dffa2fb58c5e9409c8b1daa6 |
| tools | migrate-dev | description | 324a01e6a946fab17062b86660128a7491cc605f124b67e4a0c4116554b727e3 |
| tools | migrate-reset | description | e6372b062b0f37fd61446199fc159c779bd59e0f0d77e80c514dbb3a55696c85 |
| tools | migrate-status | description | 7ee70458446575fe2df5c8be660d093aad7e1ee968784a2bc79f0b216200c804 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
