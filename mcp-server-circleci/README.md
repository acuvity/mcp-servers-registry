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


# What is mcp-server-circleci?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-circleci/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-circleci/0.7.1?logo=docker&logoColor=fff&label=0.7.1)](https://hub.docker.com/r/acuvity/mcp-server-circleci)
[![PyPI](https://img.shields.io/badge/0.7.1-3775A9?logo=pypi&logoColor=fff&label=@circleci/mcp-server-circleci)](https://github.com/CircleCI-Public/mcp-server-circleci)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-circleci/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-circleci&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-circleci%3A0.7.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Enable AI Agents to fix build failures from CircleCI.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @circleci/mcp-server-circleci original [sources](https://github.com/CircleCI-Public/mcp-server-circleci).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-circleci/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/charts/mcp-server-circleci/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @circleci/mcp-server-circleci run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-circleci scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `CIRCLECI_TOKEN` optional (not set)
  - `CIRCLECI_BASE_URL` optional (https://circleci.com)

For more information and extra configuration you can consult the [package](https://github.com/CircleCI-Public/mcp-server-circleci) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-circleci&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-circleci%3A0.7.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-circleci": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-circleci:0.7.1"
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
    "acuvity-mcp-server-circleci": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-circleci:0.7.1"
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
    "acuvity-mcp-server-circleci": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-circleci:0.7.1"
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
    "acuvity-mcp-server-circleci": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-circleci:0.7.1"
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
    "acuvity-mcp-server-circleci": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-circleci:0.7.1"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-circleci:0.7.1"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-circleci:0.7.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-circleci:0.7.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-circleci": {
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
    "acuvity-mcp-server-circleci": {
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

**Optional Environment variables**:
  - `CIRCLECI_TOKEN=""` environment variable can be changed with env.CIRCLECI_TOKEN=""
  - `CIRCLECI_BASE_URL="https://circleci.com"` environment variable can be changed with env.CIRCLECI_BASE_URL="https://circleci.com"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
````

Install with helm

```console
helm install mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
```

From there your MCP server mcp-server-circleci will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-circleci` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/charts/mcp-server-circleci/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>get_build_failure_logs</summary>

**Description**:

```

    This tool helps debug CircleCI build failures by retrieving failure logs.

    CRITICAL REQUIREMENTS:
    1. Truncation Handling (HIGHEST PRIORITY):
       - ALWAYS check for <MCPTruncationWarning> in the output
       - When present, you MUST start your response with:
         "WARNING: The logs have been truncated. Only showing the most recent entries. Earlier build failures may not be visible."
       - Only proceed with log analysis after acknowledging the truncation

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL: https://app.circleci.com/pipelines/gh/organization/project
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Legacy Job URL: https://circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch
    
    Recommended Workflow:
    1. Use listFollowedProjects tool to get a list of projects
    2. Extract the projectSlug from the chosen project (format: "gh/organization/project")
    3. Use that projectSlug with a branch name for this tool

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>find_flaky_tests</summary>

**Description**:

```

    This tool retrieves information about flaky tests in a CircleCI project. 
    
    The agent receiving this output MUST analyze the flaky test data and implement appropriate fixes based on the specific issues identified.

    CRITICAL REQUIREMENTS:
    1. Truncation Handling (HIGHEST PRIORITY):
       - ALWAYS check for <MCPTruncationWarning> in the output
       - When present, you MUST start your response with:
         "WARNING: The logs have been truncated. Only showing the most recent entries. Earlier build failures may not be visible."
       - Only proceed with log analysis after acknowledging the truncation

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug:
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL: https://app.circleci.com/pipelines/gh/organization/project
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, BOTH parameters (workspaceRoot, gitRemoteURL) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>get_latest_pipeline_status</summary>

**Description**:

```

    This tool retrieves the status of the latest pipeline for a CircleCI project. It can be used to check pipeline status, get latest build status, or view current pipeline state.

    Common use cases:
    - Check latest pipeline status
    - Get current build status
    - View pipeline state
    - Check build progress
    - Get pipeline information

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL: https://app.circleci.com/pipelines/gh/organization/project
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz
      * Legacy Job URL: https://circleci.com/gh/organization/project/123

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch
    
    Recommended Workflow:
    1. Use listFollowedProjects tool to get a list of projects
    2. Extract the projectSlug from the chosen project (format: "gh/organization/project")
    3. Use that projectSlug with a branch name for this tool

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>get_job_test_results</summary>

**Description**:

```

    This tool retrieves test metadata for a CircleCI job.

    PRIORITY USE CASE:
    - When asked "are tests passing in CI?" or similar questions about test status
    - When asked to "fix failed tests in CI" or help with CI test failures
    - Use this tool to check if tests are passing in CircleCI and identify failed tests
    
    Common use cases:
    - Get test metadata for a specific job
    - Get test metadata for all jobs in a project
    - Get test metadata for a specific branch
    - Get test metadata for a specific pipeline
    - Get test metadata for a specific workflow
    - Get test metadata for a specific job

    CRITICAL REQUIREMENTS:
    1. Truncation Handling (HIGHEST PRIORITY):
       - ALWAYS check for <MCPTruncationWarning> in the output
       - When present, you MUST start your response with:
         "WARNING: The test results have been truncated. Only showing the most recent entries. Some test data may not be visible."
       - Only proceed with test result analysis after acknowledging the truncation

    2. Test Result Filtering:
       - Use filterByTestsResult parameter to filter test results:
         * filterByTestsResult: 'failure' - Show only failed tests
         * filterByTestsResult: 'success' - Show only successful tests
       - When looking for failed tests, ALWAYS set filterByTestsResult to 'failure'
       - When checking if tests are passing, set filterByTestsResult to 'success'

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI job in any of these formats:
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/789
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch
    
    For simple test status checks (e.g., "are tests passing in CI?") or fixing failed tests, prefer Option 1 with a recent pipeline URL if available.

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects and include the branch parameter
    - If using Option 2, the URL MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>config_helper</summary>

**Description**:

```

  This tool helps analyze and validate and fix CircleCI configuration files.

  Parameters:
  - params: An object containing:
    - configFile: string - The full contents of the CircleCI config file as a string. This should be the raw YAML content, not a file path.

  Example usage:
  {
    "params": {
      "configFile": "version: 2.1
orbs:
  node: circleci/node@7
..."
    }
  }

  Note: The configFile content should be provided as a properly escaped string with newlines represented as 
.

  Tool output instructions:
    - If the config is invalid, the tool will return the errors and the original config. Use the errors to fix the config.
    - If the config is valid, do nothing.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>create_prompt_template</summary>

**Description**:

```

  About this tool:
  - This tool is part of a tool chain that generates and provides test cases for a prompt template.
  - This tool helps an AI assistant to generate a prompt template based on feature requirements defined by a user.
  - This tool should be triggered whenever the user provides requirements for a new AI-enabled application or a new feature of an existing AI-enabled application (i.e. one that requires a prompt request to an LLM or any AI model).
  - This tool will return a structured prompt template (e.g. `template`) along with a context schema (e.g. `contextSchema`) that defines the expected input parameters for the prompt template.

  Parameters:
  - params: object
    - prompt: string (the feature requirements that will be used to generate a prompt template)

  Example usage:
  {
    "params": {
      "prompt": "Create an app that takes any topic and an age (in years), then renders a 1-minute bedtime story for a person of that age."
    }
  }

  The tool will return a structured prompt template that can be used to guide an AI assistant's response, along with a context schema that defines the expected input parameters.

  Tool output instructions:
  - The tool will return...
    - a `template` that reformulates the user's prompt into a more structured format.
    - a `contextSchema` that defines the expected input parameters for the template.
  - The tool output -- both the `template` and `contextSchema` -- will also be used as input to the `recommend_prompt_template_tests` tool to generate a list of recommended tests that can be used to test the prompt template.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>recommend_prompt_template_tests</summary>

**Description**:

```

  About this tool:
  - This tool is part of a tool chain that generates and provides test cases for a prompt template.
  - This tool generates an array of recommended tests for a given prompt template.

  Parameters:
  - params: object
    - promptTemplate: string (the prompt template to be tested)
    - contextSchema: object (the context schema that defines the expected input parameters for the prompt template)

  Example usage:
  {
    "params": {
      "promptTemplate": "The user wants a bedtime story about {{topic}} for a person of age {{age}} years old. Please craft a captivating tale that captivates their imagination and provides a delightful bedtime experience.",
      "contextSchema": {
        "topic": "string",
        "age": "number"
      }
    }
  }

  The tool will return a structured array of test cases that can be used to test the prompt template.

  Tool output instructions:
    - The tool will return a `recommendedTests` array that can be used to test the prompt template.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>run_pipeline</summary>

**Description**:

```

    This tool triggers a new CircleCI pipeline and returns the URL to monitor its progress.

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL with branch: https://app.circleci.com/pipelines/gh/organization/project?branch=feature-branch
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch

    Pipeline Selection:
    - If the project has multiple pipeline definitions, the tool will return a list of available pipelines
    - You must then make another call with the chosen pipeline name using the pipelineChoiceName parameter
    - The pipelineChoiceName must exactly match one of the pipeline names returned by the tool
    - If the project has only one pipeline definition, pipelineChoiceName is not needed

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call

    Returns:
    - A URL to the newly triggered pipeline that can be used to monitor its progress
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>list_followed_projects</summary>

**Description**:

```

    This tool lists all projects that the user is following on CircleCI.
    
    Common use cases:
    - Identify which CircleCI projects are available to the user
    - Select a project for subsequent operations
    - Obtain the projectSlug needed for other CircleCI tools
    
    Returns:
    - A list of projects that the user is following on CircleCI
    - Each entry includes the project name and its projectSlug
    
    Workflow:
    1. Run this tool to see available projects
    2. User selects a project from the list
    3. The LLM should extract and use the projectSlug (not the project name) from the selected project for subsequent tool calls
    4. The projectSlug is required for many other CircleCI tools, and will be used for those tool calls after a project is selected
    
    Note: If pagination limits are reached, the tool will indicate that not all projects could be displayed.
    
    IMPORTANT: Do not automatically run any additional tools after this tool is called. Wait for explicit user instruction before executing further tool calls. The LLM MUST NOT invoke any other CircleCI tools until receiving a clear instruction from the user about what to do next, even if the user selects a project. It is acceptable to list out tool call options for the user to choose from, but do not execute them until instructed.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | config_helper | description | f02dd33f38a3495a590d901debe94a7d61f55b1c13aa49695ea04495280a6a81 |
| tools | create_prompt_template | description | 17add6d850d6aa05605db4dff2f1d42f605ca8f7c8e8b0b5c0e1671e1fe615a1 |
| tools | find_flaky_tests | description | d7791ab55054527245f4201e3f3e852a2260aabb35703b49b88f617f585ce931 |
| tools | get_build_failure_logs | description | 0a53cd10b05b19c22e09353276900b0eac42fae325a0a17f0404a38eb917a3da |
| tools | get_job_test_results | description | f193e7ccd1d8695d7c7b830f6ad58ec602a544b679c1309bc6d19a7ec9d61b72 |
| tools | get_latest_pipeline_status | description | 63b01e12f1d869921e612fd53bc8f010312aeec0af67a2a9fad71a73114bdb49 |
| tools | list_followed_projects | description | 505f69b885e2acbd4c3210dd5d405128bef0b85673ecbe797674ecb358410533 |
| tools | recommend_prompt_template_tests | description | 6be9c0e965a6a22ad8a28b40a5d83ab95fb532cbdb02ebffc46f5fe7f4df4888 |
| tools | run_pipeline | description | 61a4e833d3f451f1e5677b7389e316d08daaf247f9fa25df5f1a59ac4ba3b128 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
