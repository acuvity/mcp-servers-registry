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


# What is mcp-server-kubernetes?

[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-kubernetes/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-kubernetes/1.6.2?logo=docker&logoColor=fff&label=1.6.2)](https://hub.docker.com/r/acuvity/mcp-server-kubernetes)
[![PyPI](https://img.shields.io/badge/1.6.2-3775A9?logo=pypi&logoColor=fff&label=mcp-server-kubernetes)](https://github.com/Flux159/mcp-server-kubernetes)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-kubernetes&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-kubernetes%3A1.6.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Typescript implementation of Kubernetes cluster operations for pods, deployments, services.

Packaged by Acuvity from mcp-server-kubernetes original [sources](https://github.com/Flux159/mcp-server-kubernetes).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-kubernetes/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/charts/mcp-server-kubernetes/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-server-kubernetes run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/charts/mcp-server-kubernetes#minibridge) for Helm charts).


# 📦 How to Install


> [!TIP]
> Given mcp-server-kubernetes scope of operation the intended usage is to run natively on the targeted machine to access local resources.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-kubernetes&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-kubernetes%3A1.6.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-kubernetes": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-kubernetes:1.6.2"
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
    "acuvity-mcp-server-kubernetes": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-kubernetes:1.6.2"
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
    "acuvity-mcp-server-kubernetes": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-kubernetes:1.6.2"
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
    "acuvity-mcp-server-kubernetes": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-kubernetes:1.6.2"
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
    "acuvity-mcp-server-kubernetes": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-kubernetes:1.6.2"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-kubernetes:1.6.2"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-kubernetes:1.6.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-kubernetes:1.6.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-kubernetes": {
      "url": "http://localhost:<localport>/sse",
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
    "acuvity-mcp-server-kubernetes": {
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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

for example, `-e GUARDRAILS="secrets-redaction covert-instruction-detection"` will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


To turn on Basic Authentication, set BASIC_AUTH_SECRET like `- e BASIC_AUTH_SECRET="supersecret`

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
helm show readme oci://docker.io/acuvity/mcp-server-kubernetes --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-kubernetes --version 1.0.0
````

Install with helm

```console
helm install mcp-server-kubernetes oci://docker.io/acuvity/mcp-server-kubernetes --version 1.0.0
```

From there your MCP server mcp-server-kubernetes will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-kubernetes` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-kubernetes/charts/mcp-server-kubernetes/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (40)
<details>
<summary>cleanup</summary>

**Description**:

```
Cleanup all managed resources
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_deployment</summary>

**Description**:

```
Create a new Kubernetes deployment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customConfig | object | not set | No
| name | string | not set | Yes
| namespace | string | not set | Yes
| ports | array | not set | No
| replicas | number | not set | No
| template | string | not set | Yes
</details>
<details>
<summary>create_namespace</summary>

**Description**:

```
Create a new Kubernetes namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
</details>
<details>
<summary>create_pod</summary>

**Description**:

```
Create a new Kubernetes pod
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | array | not set | No
| customConfig | object | not set | No
| name | string | not set | Yes
| namespace | string | not set | Yes
| template | string | not set | Yes
</details>
<details>
<summary>create_cronjob</summary>

**Description**:

```
Create a new Kubernetes CronJob
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | array | not set | No
| image | string | not set | Yes
| name | string | not set | Yes
| namespace | string | not set | Yes
| schedule | string | not set | Yes
| suspend | boolean | not set | No
</details>
<details>
<summary>create_service</summary>

**Description**:

```
Create a new Kubernetes service
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | No
| ports | array | not set | Yes
| selector | object | not set | No
| type | string | not set | No
</details>
<details>
<summary>delete_pod</summary>

**Description**:

```
Delete a Kubernetes pod
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreNotFound | boolean | not set | No
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>delete_deployment</summary>

**Description**:

```
Delete a Kubernetes deployment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreNotFound | boolean | not set | No
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>delete_namespace</summary>

**Description**:

```
Delete a Kubernetes namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreNotFound | boolean | not set | No
| name | string | not set | Yes
</details>
<details>
<summary>delete_service</summary>

**Description**:

```
Delete a Kubernetes service
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreNotFound | boolean | not set | No
| name | string | not set | Yes
| namespace | string | not set | No
</details>
<details>
<summary>describe_cronjob</summary>

**Description**:

```
Get detailed information about a Kubernetes CronJob including recent job history
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>describe_pod</summary>

**Description**:

```
Describe a Kubernetes pod (read details like status, containers, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>describe_node</summary>

**Description**:

```
Describe a Kubernetes node (read details like status, capacity, conditions, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
</details>
<details>
<summary>describe_deployment</summary>

**Description**:

```
Get details about a Kubernetes deployment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>describe_service</summary>

**Description**:

```
Describe a Kubernetes service (read details like status, ports, selectors, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | No
</details>
<details>
<summary>explain_resource</summary>

**Description**:

```
Get documentation for a Kubernetes resource or field
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| apiVersion | string | API version to use (e.g. 'apps/v1') | No
| output | string | Output format (plaintext or plaintext-openapiv2) | No
| recursive | boolean | Print the fields of fields recursively | No
| resource | string | Resource name or field path (e.g. 'pods' or 'pods.spec.containers') | Yes
</details>
<details>
<summary>get_events</summary>

**Description**:

```
Get Kubernetes events from the cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fieldSelector | string | Field selector to filter events | No
| namespace | string | Namespace to get events from. If not specified, gets events from all namespaces | No
</details>
<details>
<summary>get_job_logs</summary>

**Description**:

```
Get logs from Pods created by a specific Job
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the Job to get logs from | Yes
| namespace | string | not set | Yes
| tail | number | Number of lines to return from the end of the logs | No
| timestamps | boolean | Include timestamps in the logs | No
</details>
<details>
<summary>get_logs</summary>

**Description**:

```
Get logs from pods, deployments, jobs, or resources matching a label selector
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container | string | Container name (required when pod has multiple containers) | No
| labelSelector | string | Label selector to filter resources | No
| name | string | Name of the resource | No
| namespace | string | Namespace of the resource | No
| resourceType | string | Type of resource to get logs from | Yes
| since | number | Get logs since relative time in seconds | No
| tail | number | Number of lines to show from end of logs | No
| timestamps | boolean | Include timestamps in logs | No
</details>
<details>
<summary>install_helm_chart</summary>

**Description**:

```
Install a Helm chart
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| chart | string | Chart name | Yes
| name | string | Release name | Yes
| namespace | string | Kubernetes namespace | Yes
| repo | string | Chart repository URL | Yes
| values | object | Chart values | No
</details>
<details>
<summary>list_api_resources</summary>

**Description**:

```
List the API resources available in the cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| apiGroup | string | API group to filter by | No
| namespaced | boolean | If true, only show namespaced resources | No
| output | string | Output format (wide, name, or no-headers) | No
| verbs | array | List of verbs to filter by | No
</details>
<details>
<summary>list_cronjobs</summary>

**Description**:

```
List CronJobs in a namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| namespace | string | not set | Yes
</details>
<details>
<summary>list_contexts</summary>

**Description**:

```
List all available Kubernetes contexts
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| showCurrent | boolean | Show which context is currently active | No
</details>
<details>
<summary>get_current_context</summary>

**Description**:

```
Get the current Kubernetes context
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| detailed | boolean | Include detailed information about the current context | No
</details>
<details>
<summary>set_current_context</summary>

**Description**:

```
Set the current Kubernetes context
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the context to set as current | Yes
</details>
<details>
<summary>list_deployments</summary>

**Description**:

```
List deployments in a namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| namespace | string | not set | Yes
</details>
<details>
<summary>list_jobs</summary>

**Description**:

```
List Jobs in a namespace, optionally filtered by a CronJob parent
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cronJobName | string | Optional: Filter jobs created by a specific CronJob | No
| namespace | string | not set | Yes
</details>
<details>
<summary>list_namespaces</summary>

**Description**:

```
List all namespaces
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_nodes</summary>

**Description**:

```
List all nodes in the cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_pods</summary>

**Description**:

```
List pods in a namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| namespace | string | not set | Yes
</details>
<details>
<summary>list_services</summary>

**Description**:

```
List services in a namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| namespace | string | not set | Yes
</details>
<details>
<summary>uninstall_helm_chart</summary>

**Description**:

```
Uninstall a Helm release
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Release name | Yes
| namespace | string | Kubernetes namespace | Yes
</details>
<details>
<summary>update_deployment</summary>

**Description**:

```
Update an existing kubernetes deployment in cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| containerName | string | Name of the container to update | No
| customConfig | object | not set | No
| name | string | not set | Yes
| namespace | string | not set | Yes
| replicas | number | not set | No
| template | string | not set | Yes
</details>
<details>
<summary>upgrade_helm_chart</summary>

**Description**:

```
Upgrade a Helm release
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| chart | string | Chart name | Yes
| name | string | Release name | Yes
| namespace | string | Kubernetes namespace | Yes
| repo | string | Chart repository URL | Yes
| values | object | Chart values | No
</details>
<details>
<summary>port_forward</summary>

**Description**:

```
Forward a local port to a port on a Kubernetes resource
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| localPort | number | not set | Yes
| namespace | string | not set | No
| resourceName | string | not set | Yes
| resourceType | string | not set | Yes
| targetPort | number | not set | Yes
</details>
<details>
<summary>stop_port_forward</summary>

**Description**:

```
Stop a port-forward process
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>
<details>
<summary>scale_deployment</summary>

**Description**:

```
Scale a Kubernetes deployment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | Yes
| replicas | number | not set | Yes
</details>
<details>
<summary>delete_cronjob</summary>

**Description**:

```
Delete a Kubernetes CronJob
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>create_configmap</summary>

**Description**:

```
Create a new Kubernetes ConfigMap
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | not set | Yes
| name | string | not set | Yes
| namespace | string | not set | Yes
</details>
<details>
<summary>update_service</summary>

**Description**:

```
Update an existing kubernetes service in cluster
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | not set | Yes
| namespace | string | not set | Yes
| ports | array | not set | No
| selector | object | not set | No
| type | string | not set | No
</details>

## 📚 Resources (5)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Kubernetes Pods | application/json | k8s://default/pods | - |
| Kubernetes Deployments | application/json | k8s://default/deployments | - |
| Kubernetes Services | application/json | k8s://default/services | - |
| Kubernetes Namespaces | application/json | k8s://namespaces | - |
| Kubernetes Nodes | application/json | k8s://nodes | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | cleanup | description | 8c2018f3780cafa2f853231f129562dc33c6a4571ac939e506f9aeb35665c5e2 |
| tools | create_configmap | description | 17a92ed33786a5559a002beff91a202c7bbd4e7991694d7a4cb0a15286bec822 |
| tools | create_cronjob | description | 33987caf6612dd74489e4a04142bc5cb47109ad68b14b86201daf0dfbf5764bf |
| tools | create_deployment | description | f6a9027d8b6d7ed1312df80d91b87baa6af470fe6fe8765eed88f38950c4d826 |
| tools | create_namespace | description | c0ec1db7373c97f62ee698fff84c7588891231b8263c031c1c86370ba2f6ecce |
| tools | create_pod | description | f5c94c82f254fb69fa66ba466b3a36e25559be7ad69007d855998a829d5cf3eb |
| tools | create_service | description | 98fcc1c883f7c640955771811ee73e9042d99d7c0512991ff0876a2b6a116c7b |
| tools | delete_cronjob | description | 362b54e2d3574a19ac8c2bd8aab1a33e9a8b5fff3b3466ae4b8731a2961f4473 |
| tools | delete_deployment | description | b53026b9a99dd859b688d91342ec70d485ef32edf46d06ebebfdcc4831f30bd1 |
| tools | delete_namespace | description | 2e8b2e974051051be5e181c7eefaa9ccf70777c9dbcb95a99df072add503a46c |
| tools | delete_pod | description | 6fe4e7a7a9c31b0170292322c174e2f5847214f82eba0aa162ea8685bc06009e |
| tools | delete_service | description | 46eaf7c56254ffc86968745e806629f091797d436eccbdbe41e5902c56489b7e |
| tools | describe_cronjob | description | 4f14484541d560b00efea063f5630c12e537e9a9eb3044c0ef6285023e64483b |
| tools | describe_deployment | description | 9a1eaff147f180c1f9e4b698e66dbe63a3457703c671d14e326dd1a0a1823c7a |
| tools | describe_node | description | 02e95802d8c7de0fe4f01fb5ee0dffd609276032cdf7285d61686035b48a24c8 |
| tools | describe_pod | description | 11f020f91951c7a28d56962ca53e81c6fbce13dff6a43bcad775d4d062f8ebf5 |
| tools | describe_service | description | 5803dd1e703e5cd26afaf037b27b712924133a6203ef8c31e91d2d0d2ff1f9f8 |
| tools | explain_resource | description | 592bffdd3e4c0184fd9a22057d0a06b31a60732ac1d7a52de72367880af173f8 |
| tools | explain_resource | apiVersion | 34419a5eb3629e5311644dd9147365296dcdbc65740ea1d235ab5d1cf8cc7add |
| tools | explain_resource | output | 1c93f2d24fb810943e12f684698acc46b732d21f2f1c99c5c4bb85bd4e48560e |
| tools | explain_resource | recursive | db27ec72cc1154d1948550206b399586957968668bac95582a8635d103cc17fa |
| tools | explain_resource | resource | 4ae1f5f38e1fd9e2087c6b08f33a3e9f44270af0a98f96af4264cf8ef277ae54 |
| tools | get_current_context | description | e48b08f2df2f2965a94841da05eb4084205700d5a42bcd7afb6cc08a2a1e3115 |
| tools | get_current_context | detailed | bb123e31ccbd055828b0a28916d1c96e6f3cbb788a4d173ff11827230806e6bb |
| tools | get_events | description | e28be045db8d86214667a716b4b5c65130db0a8facc5c39aa044f8206abd43b9 |
| tools | get_events | fieldSelector | 575d259237b66f1ac66e4ba1ab4a50f21841adfc105fe39a8688738255231b8f |
| tools | get_events | namespace | 75f1f9a422bc123a28e58d6534f499ae896d1155847ef28b233f8eee078040be |
| tools | get_job_logs | description | c0128e751e2b6ff6c261157e56b0f5eef5293a8c4b5ee97b61f58a3fe2e10d70 |
| tools | get_job_logs | name | 501336ec668f2926a8442c8ec92d2cfa6f1f2ccc12d3d8355aed477974ed73b3 |
| tools | get_job_logs | tail | 3d395eab4baa71f75b3c8959b4b5ad01b11e2dddc2bfeaac56362a8ac4e00488 |
| tools | get_job_logs | timestamps | 2e0f82291dcb078b3232e4c9d000ce29382869011f6b890b47bac80cb4df426e |
| tools | get_logs | description | 7d335581f475bbfc3a7ff8c2cee341548689d32d98b1118c92b842907647cc60 |
| tools | get_logs | container | 0f93342e4a7003f29000cd347ee9cffc603c8da3f5ea9a03145b4eca923c051e |
| tools | get_logs | labelSelector | d9473439bc3c3b75bc1609e0cf357e3c9bd8269aadba53540dc4ae3d0e79f050 |
| tools | get_logs | name | dee870968d1591eaf65c3d9d1a017c2c6a44a852bc2d990458b7557c3ae95580 |
| tools | get_logs | namespace | 833b97da46652f738fcf49f1ca6c1ec77724153f7d28c823406712d845265b3b |
| tools | get_logs | resourceType | 1cf99af1321700f2e92cc08578a50342f9a6442758ecead4c2e30ad4d2107b5b |
| tools | get_logs | since | 81ea9ce7a75d8468a154901e3c3861743e3434c2fa5157f706f6a0ff4894c032 |
| tools | get_logs | tail | 9ce48481b1c58f4aa0984172c7717e04cc4c682444c66a003747d50b377e64c4 |
| tools | get_logs | timestamps | bed89b79d63742faca0091c32b57e3e60effe35201e3c42165489a963b7d701b |
| tools | install_helm_chart | description | 626fee4ec45bea4c946ed23014f3533b60a7f1cef73e0dd9ec68b8a16496feef |
| tools | install_helm_chart | chart | b34d6b02df4598648d8c810655f76567962045de26a68a8211ab7b698c481663 |
| tools | install_helm_chart | name | 85f01282f3161086faed8766800c17b4c00472620c5d158e1657d13041a197ed |
| tools | install_helm_chart | namespace | af216e81f96fcf52c4ea61eea71ac34bff7cd232f141faeaed24ae5402463d33 |
| tools | install_helm_chart | repo | e87393dcf00bdf5f518603adad35eaced2f5d9bbc4b438c45c014886fe89079d |
| tools | install_helm_chart | values | cce7f5207579dd6efd533d18288ae81090bd355d07a772b809d854851dfbd7ca |
| tools | list_api_resources | description | d99de9c7cf60b9c8b686ebba4d04eed18da50f8df2b823b4854d00b3a339ccca |
| tools | list_api_resources | apiGroup | db958e31706b8813e758249505765b5aed5e31a5f674c658ce1e91d66769b05d |
| tools | list_api_resources | namespaced | 044ae41369d6760faf5d2316d246f0e8d4acc598c130ae468c541a796e60222a |
| tools | list_api_resources | output | 190426df5246d7950d8e9107d88947ebb5c0a47718ce4cd283d4619db4f71bc1 |
| tools | list_api_resources | verbs | 082234f275654b2dc60aa5da636a7b22d621f90358449504699cafeff5c9c7a8 |
| tools | list_contexts | description | e38deca296a1d9adc29e1e9dbb50741b33fe457ff3c0c20372b5c808442ad884 |
| tools | list_contexts | showCurrent | 8130768108ffa17735ec9148972d1880063b364e26a2aedd82bce3049a6c15bb |
| tools | list_cronjobs | description | 92cc99c1b4166b908a16aa9ea27059aed0ddea844cf9d1779da6d0fbd1e9ca46 |
| tools | list_deployments | description | 68b1b3d6ade3d6993406282100d515f27d4d5eb8ca05edf5d820ffdbb857b6da |
| tools | list_jobs | description | 24c96c3247752c5293e86aa8d7615b99d610096e6944a1eb18544d2f2e874ce8 |
| tools | list_jobs | cronJobName | 2d3bdc0ad09e71d26a7b658e7ba0858e9654960aed1ef49920079fc533c213d7 |
| tools | list_namespaces | description | 3ffcb3cff6b97ab6d2fa1dd856c6117cb2c4a461f26bde68a78b6cebca899475 |
| tools | list_nodes | description | dccd1cdf08f7fc95d3390175f41b1e3a49f2dcce32e1b3edc9f4c676d79ca09e |
| tools | list_pods | description | 8362cffc6b700e74c4695d19e6a640b1efa3e328d3178d7c2f5af0a48dd9918f |
| tools | list_services | description | 6f3de250c0b4988f97cc9ee5805ea9e3add0cde2650db6b1526c2fadffc8b583 |
| tools | port_forward | description | 931f8ee6f95ddbbb2d4cfed7c7ff1c92b59b4a26d98a1d6bbde906f11fcac0a9 |
| tools | scale_deployment | description | 7b74eb50b7e1e72453a34c04405fb6ee2bde818ff5a8244c7064ca061d19f89a |
| tools | set_current_context | description | c1def4853591c7d0360fb0e327eac14b01aee9a23d47b909128da560893732a4 |
| tools | set_current_context | name | a6bf0fd242d001f7a911aaaf9c5e26e52de32801a8ec8718dc1649251500ab5e |
| tools | stop_port_forward | description | d6a519c2332736564873b93cb2fe3f3466fc094cc7af4be14c09a5d5b31bf246 |
| tools | uninstall_helm_chart | description | 49c8f3a48a65df33b4f80b6c23d6793c3f8d2f111dbc9aefbb93c6b066eefc2d |
| tools | uninstall_helm_chart | name | 85f01282f3161086faed8766800c17b4c00472620c5d158e1657d13041a197ed |
| tools | uninstall_helm_chart | namespace | af216e81f96fcf52c4ea61eea71ac34bff7cd232f141faeaed24ae5402463d33 |
| tools | update_deployment | description | 5e3af7a7da3f3ca2a994c30f634ba336b1965e4dc10c47f98fcd9b7c2112eeca |
| tools | update_deployment | containerName | 689f4f4070144e4c6288aaf2d2242adc5f8b323ddfe869368713d7de0ba40244 |
| tools | update_service | description | 32e8b91e6fb52757ea2dd964c35ce1c6a3867fec5163b1f1178f7589c8b2b2cb |
| tools | upgrade_helm_chart | description | e8c91747df6416edacd5b7483df523449010b3bdb8caae457892da1778498f31 |
| tools | upgrade_helm_chart | chart | b34d6b02df4598648d8c810655f76567962045de26a68a8211ab7b698c481663 |
| tools | upgrade_helm_chart | name | 85f01282f3161086faed8766800c17b4c00472620c5d158e1657d13041a197ed |
| tools | upgrade_helm_chart | namespace | af216e81f96fcf52c4ea61eea71ac34bff7cd232f141faeaed24ae5402463d33 |
| tools | upgrade_helm_chart | repo | e87393dcf00bdf5f518603adad35eaced2f5d9bbc4b438c45c014886fe89079d |
| tools | upgrade_helm_chart | values | cce7f5207579dd6efd533d18288ae81090bd355d07a772b809d854851dfbd7ca |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
