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
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-kubernetes/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-kubernetes/2.3.1?logo=docker&logoColor=fff&label=2.3.1)](https://hub.docker.com/r/acuvity/mcp-server-kubernetes)
[![PyPI](https://img.shields.io/badge/2.3.1-3775A9?logo=pypi&logoColor=fff&label=mcp-server-kubernetes)](https://github.com/Flux159/mcp-server-kubernetes)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-kubernetes/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-kubernetes&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-kubernetes%3A2.3.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Typescript implementation of Kubernetes cluster operations for pods, deployments, services.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-server-kubernetes original [sources](https://github.com/Flux159/mcp-server-kubernetes).

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
> Given mcp-server-kubernetes scope of operation the intended usage is to run natively on the targeted machine to access local resources.

For more information and extra configuration you can consult the [package](https://github.com/Flux159/mcp-server-kubernetes) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-kubernetes&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-kubernetes%3A2.3.1%22%5D%2C%22command%22%3A%22docker%22%7D)

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
          "docker.io/acuvity/mcp-server-kubernetes:2.3.1"
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
        "docker.io/acuvity/mcp-server-kubernetes:2.3.1"
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
        "docker.io/acuvity/mcp-server-kubernetes:2.3.1"
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
        "docker.io/acuvity/mcp-server-kubernetes:2.3.1"
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
        "docker.io/acuvity/mcp-server-kubernetes:2.3.1"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-kubernetes:2.3.1"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-kubernetes:2.3.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-kubernetes:2.3.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-kubernetes": {
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

## 🧰 Tools (20)
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
<summary>kubectl_get</summary>

**Description**:

```
Get or list Kubernetes resources by resource type, name, and optionally namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allNamespaces | boolean | If true, list resources across all namespaces | No
| fieldSelector | string | Filter resources by field selector (e.g. 'metadata.name=my-pod') | No
| labelSelector | string | Filter resources by label selector (e.g. 'app=nginx') | No
| name | string | Name of the resource (optional - if not provided, lists all resources of the specified type) | No
| namespace | string | Namespace of the resource (optional - defaults to 'default' for namespaced resources) | No
| output | string | Output format | No
| resourceType | string | Type of resource to get (e.g., pods, deployments, services, configmaps, events, etc.) | Yes
| sortBy | string | Sort events by a field (default: lastTimestamp). Only applicable for events. | No
</details>
<details>
<summary>kubectl_describe</summary>

**Description**:

```
Describe Kubernetes resources by resource type, name, and optionally namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allNamespaces | boolean | If true, describe resources across all namespaces | No
| name | string | Name of the resource to describe | Yes
| namespace | string | Namespace of the resource (optional - defaults to 'default' for namespaced resources) | No
| resourceType | string | Type of resource to describe (e.g., pods, deployments, services, etc.) | Yes
</details>
<details>
<summary>kubectl_list</summary>

**Description**:

```
List Kubernetes resources by resource type and optionally namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allNamespaces | boolean | If true, list resources across all namespaces | No
| fieldSelector | string | Filter resources by field selector (e.g. 'metadata.name=my-pod') | No
| labelSelector | string | Filter resources by label selector (e.g. 'app=nginx') | No
| namespace | string | Namespace of the resources (optional - defaults to 'default' for namespaced resources) | No
| output | string | Output format - 'formatted' uses a resource-specific format with key information | No
| resourceType | string | Type of resource to list (e.g., pods, deployments, services, configmaps, etc.) | Yes
</details>
<details>
<summary>kubectl_apply</summary>

**Description**:

```
Apply a Kubernetes YAML manifest from a string or file
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dryRun | boolean | If true, only validate the resource, don't apply it | No
| filename | string | Path to a YAML file to apply (optional - use either manifest or filename) | No
| force | boolean | If true, immediately remove resources from API and bypass graceful deletion | No
| manifest | string | YAML manifest to apply | No
| namespace | string | Namespace to apply the resource to (optional) | No
</details>
<details>
<summary>kubectl_delete</summary>

**Description**:

```
Delete Kubernetes resources by resource type, name, labels, or from a manifest file
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allNamespaces | boolean | If true, delete resources across all namespaces | No
| filename | string | Path to a YAML file to delete resources from (optional) | No
| force | boolean | If true, immediately remove resources from API and bypass graceful deletion | No
| gracePeriodSeconds | number | Period of time in seconds given to the resource to terminate gracefully | No
| labelSelector | string | Delete resources matching this label selector (e.g. 'app=nginx') | No
| manifest | string | YAML manifest defining resources to delete (optional) | No
| name | string | Name of the resource to delete | No
| namespace | string | Namespace of the resource (optional - defaults to 'default' for namespaced resources) | No
| resourceType | string | Type of resource to delete (e.g., pods, deployments, services, etc.) | No
</details>
<details>
<summary>kubectl_create</summary>

**Description**:

```
Create Kubernetes resources using various methods (from file or using subcommands)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| annotations | array | Annotations to apply to the resource (e.g. ["key1=value1", "key2=value2"]) | No
| command | array | Command to run in the container | No
| dryRun | boolean | If true, only validate the resource, don't actually create it | No
| filename | string | Path to a YAML file to create resources from | No
| fromFile | array | Path to file for creating configmap (e.g. ["key1=/path/to/file1", "key2=/path/to/file2"]) | No
| fromLiteral | array | Key-value pair for creating configmap (e.g. ["key1=value1", "key2=value2"]) | No
| image | string | Image to use for the containers in the deployment | No
| labels | array | Labels to apply to the resource (e.g. ["key1=value1", "key2=value2"]) | No
| manifest | string | YAML manifest to create resources from | No
| name | string | Name of the resource to create | No
| namespace | string | Namespace to create the resource in | No
| output | string | Output format. One of: json|yaml|name|go-template|go-template-file|template|templatefile|jsonpath|jsonpath-as-json|jsonpath-file | No
| port | number | Port that the container exposes | No
| replicas | number | Number of replicas to create for the deployment | No
| resourceType | string | Type of resource to create (namespace, configmap, deployment, service, etc.) | No
| schedule | string | Cron schedule expression for the CronJob (e.g. "*/5 * * * *") | No
| secretType | string | Type of secret to create (generic, docker-registry, tls) | No
| serviceType | string | Type of service to create (clusterip, nodeport, loadbalancer, externalname) | No
| suspend | boolean | Whether to suspend the CronJob | No
| tcpPort | array | Port pairs for tcp service (e.g. ["80:8080", "443:8443"]) | No
| validate | boolean | If true, validate resource schema against server schema | No
</details>
<details>
<summary>kubectl_logs</summary>

**Description**:

```
Get logs from Kubernetes resources like pods, deployments, or jobs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container | string | Container name (required when pod has multiple containers) | No
| follow | boolean | Follow logs output (not recommended, may cause timeouts) | No
| labelSelector | string | Filter resources by label selector | No
| name | string | Name of the resource | Yes
| namespace | string | Namespace of the resource | Yes
| previous | boolean | Include logs from previously terminated containers | No
| resourceType | string | Type of resource to get logs from | Yes
| since | string | Show logs since relative time (e.g. '5s', '2m', '3h') | No
| sinceTime | string | Show logs since absolute time (RFC3339) | No
| tail | number | Number of lines to show from end of logs | No
| timestamps | boolean | Include timestamps in logs | No
</details>
<details>
<summary>kubectl_scale</summary>

**Description**:

```
Scale a Kubernetes deployment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the deployment to scale | Yes
| namespace | string | Namespace of the deployment | No
| replicas | number | Number of replicas to scale to | Yes
| resourceType | string | Resource type to scale (deployment, replicaset, statefulset) | No
</details>
<details>
<summary>kubectl_patch</summary>

**Description**:

```
Update field(s) of a resource using strategic merge patch, JSON merge patch, or JSON patch
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dryRun | boolean | If true, only print the object that would be sent, without sending it | No
| name | string | Name of the resource to patch | Yes
| namespace | string | Namespace of the resource | No
| patchData | object | Patch data as a JSON object | No
| patchFile | string | Path to a file containing the patch data (alternative to patchData) | No
| patchType | string | Type of patch to apply | No
| resourceType | string | Type of resource to patch (e.g., pods, deployments, services) | Yes
</details>
<details>
<summary>kubectl_rollout</summary>

**Description**:

```
Manage the rollout of a resource (e.g., deployment, daemonset, statefulset)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the resource | Yes
| namespace | string | Namespace of the resource | No
| resourceType | string | Type of resource to manage rollout for | Yes
| revision | number | Revision to rollback to (for undo subcommand) | No
| subCommand | string | Rollout subcommand to execute | Yes
| timeout | string | The length of time to wait before giving up (e.g., '30s', '1m', '2m30s') | No
| toRevision | number | Revision to roll back to (for history subcommand) | No
| watch | boolean | Watch the rollout status in real-time until completion | No
</details>
<details>
<summary>kubectl_context</summary>

**Description**:

```
Manage Kubernetes contexts - list, get, or set the current context
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| detailed | boolean | Include detailed information about the context | No
| name | string | Name of the context to set as current (required for set operation) | No
| operation | string | Operation to perform: list contexts, get current context, or set current context | Yes
| output | string | Output format | No
| showCurrent | boolean | When listing contexts, highlight which one is currently active | No
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
<summary>kubectl_generic</summary>

**Description**:

```
Execute any kubectl command with the provided arguments and flags
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| args | array | Additional command arguments | No
| command | string | The kubectl command to execute (e.g. patch, rollout, top) | Yes
| flags | object | Command flags as key-value pairs | No
| name | string | Resource name | No
| namespace | string | Namespace | No
| outputFormat | string | Output format (e.g. json, yaml, wide) | No
| resourceType | string | Resource type (e.g. pod, deployment) | No
| subCommand | string | Subcommand if applicable (e.g. 'history' for rollout) | No
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
| tools | explain_resource | description | 592bffdd3e4c0184fd9a22057d0a06b31a60732ac1d7a52de72367880af173f8 |
| tools | explain_resource | apiVersion | 34419a5eb3629e5311644dd9147365296dcdbc65740ea1d235ab5d1cf8cc7add |
| tools | explain_resource | output | 1c93f2d24fb810943e12f684698acc46b732d21f2f1c99c5c4bb85bd4e48560e |
| tools | explain_resource | recursive | db27ec72cc1154d1948550206b399586957968668bac95582a8635d103cc17fa |
| tools | explain_resource | resource | 4ae1f5f38e1fd9e2087c6b08f33a3e9f44270af0a98f96af4264cf8ef277ae54 |
| tools | install_helm_chart | description | 626fee4ec45bea4c946ed23014f3533b60a7f1cef73e0dd9ec68b8a16496feef |
| tools | install_helm_chart | chart | b34d6b02df4598648d8c810655f76567962045de26a68a8211ab7b698c481663 |
| tools | install_helm_chart | name | 85f01282f3161086faed8766800c17b4c00472620c5d158e1657d13041a197ed |
| tools | install_helm_chart | namespace | af216e81f96fcf52c4ea61eea71ac34bff7cd232f141faeaed24ae5402463d33 |
| tools | install_helm_chart | repo | e87393dcf00bdf5f518603adad35eaced2f5d9bbc4b438c45c014886fe89079d |
| tools | install_helm_chart | values | cce7f5207579dd6efd533d18288ae81090bd355d07a772b809d854851dfbd7ca |
| tools | kubectl_apply | description | 5a424c44d014d49e270431de434f142c4aa4ffd4f8f3dfc2c8361fc75fbb4eb2 |
| tools | kubectl_apply | dryRun | 8671718b127808c7cdeae3a8e3cb5844496b43234365ae278691b8e1b99a9410 |
| tools | kubectl_apply | filename | 50dacf632aa756960b0d7e801053eb5a35d08f21399ee4cbe7d6c6b9d5796105 |
| tools | kubectl_apply | force | 12fe5bb456391f1636077bf710ebb2cfb10cf1bce3e14e257de7a30e07706843 |
| tools | kubectl_apply | manifest | 8d3a6f319f6d1686925f2501285cdd06401df86a619cdcd00563338ff6654bf2 |
| tools | kubectl_apply | namespace | 488b4f5f86eca6948950001cf05b489876e9a3c1dfc910312a50fbc72dd309d9 |
| tools | kubectl_context | description | bac4d9f94d67f5fd86934af217adf6230348d7f49ac4cd978428347245ac3b07 |
| tools | kubectl_context | detailed | 5b60753941be3b793cbd87a088ca08397b4462e4cb1ac0f58f565efb6b304137 |
| tools | kubectl_context | name | ff269fb598abb8581feec408a2c5383b7e7218838add20c0c6e84ad49d43ce76 |
| tools | kubectl_context | operation | bbc7b532305bc00a16f245f6ca1276e748997aa969982dd9d6867084e3aab5d8 |
| tools | kubectl_context | output | 93c53d3745136c4e4e142811cdff560c8dfb4b9c4c875b7a8687dda559f688e1 |
| tools | kubectl_context | showCurrent | 4629e22325e10b54a60a7eb45b5ffb1def4b3236f605d7b7653a0346aa99e22e |
| tools | kubectl_create | description | 19243f532d01abb560d6b5740f1db404fa0c25416d50fb3e0a5f5bd717ff9ca8 |
| tools | kubectl_create | annotations | 07bf97b55db229db4af840ea614842d48c84a27b3792275c5c96355c800483cb |
| tools | kubectl_create | command | 6c63cfa4d17413696117affc971c127357f7d2ec35806dda932e2bd5c5369d59 |
| tools | kubectl_create | dryRun | 8051174bfa6a7d90148738550332ec6835555308da9324cdc17ba2d788781d18 |
| tools | kubectl_create | filename | 326c492e2afa888568258431ec5011070982fa553f2ea88c63311d3e7c90c4cb |
| tools | kubectl_create | fromFile | 7daac169444d113e7bd8c9ceb678c38167f1d1438e0b6cacbbcf45ae5e13d514 |
| tools | kubectl_create | fromLiteral | 8a649a803572c018248575ce5a060bce99f1788943b6a8471438bcc44ad7c74a |
| tools | kubectl_create | image | 13581f590d7b9e629ea7a0f4188d4ac51130cc6b0ed787c773474fbc7d3ac0b8 |
| tools | kubectl_create | labels | bc29c45c1ec89925da5e102d5ea8a3d0ae88a271d3602c45a38571e382c9e59f |
| tools | kubectl_create | manifest | 3a8104c2c44257d9b1377ed08d7004867f80f113a7ac8cbc3ef31711e50c53a8 |
| tools | kubectl_create | name | 4484aea145fec4d23fc437aaaea7e467cd8003dc859ec23355da78e7945be9c5 |
| tools | kubectl_create | namespace | 3890a77bd4699ef2874b2387b75699754858428f7d4da2497d1f78e6c2d4e52c |
| tools | kubectl_create | output | 2d0d977a54a6e549691596c0926d416775ecc233de68ef03f78c9205f768fbe3 |
| tools | kubectl_create | port | bd1d76351ac02b7c803e6008cbaf02118ea5ed38774dd5cdbcbf18ade5445a3a |
| tools | kubectl_create | replicas | af7bf5756cc2f3769b1fabbfa0bb7deb3c7b19a27315b566baa1bc77beb2d875 |
| tools | kubectl_create | resourceType | d7d481e845e4f46928ff3b94570472cc9f27b42f832722bceaccbcf014445241 |
| tools | kubectl_create | schedule | de37231c7b0c316f045dfd22d9c18f527222f9c3f6d0385dfd993796bb676e45 |
| tools | kubectl_create | secretType | bf11482871ffad99d07bc921705b73fdb8d1841cf58f945231861aee10b09a6d |
| tools | kubectl_create | serviceType | 950e55b341614e6e191c8686b95ac2667d44136366ea392d4b6061c676ec67fb |
| tools | kubectl_create | suspend | 3b9d7a4c77af516609f562740d06aeebdc7f919e49d9dee420ce5c5880800ee2 |
| tools | kubectl_create | tcpPort | 660956a586d2634ecc55fa599f425f0056cf9e7838c83a35c96931344612206e |
| tools | kubectl_create | validate | e56eb145be170e57300bfdc98344d9279805f119fd1c506822a80f8216bb33e0 |
| tools | kubectl_delete | description | 32b7082c51457b0ca44795f7724c549a656085bc4966129305941ab30353b609 |
| tools | kubectl_delete | allNamespaces | cb759f7fbeb3101908e89a64821aeb596d463fed199c0ee4e5b9178261796e34 |
| tools | kubectl_delete | filename | 54c5b981bfa320fc203f750c966ebb0cb18235e4d350db38b621e26ab7017ce0 |
| tools | kubectl_delete | force | 12fe5bb456391f1636077bf710ebb2cfb10cf1bce3e14e257de7a30e07706843 |
| tools | kubectl_delete | gracePeriodSeconds | a050518954710d462e4e357ae91fc177ff2921702eb2d353839c088021b06171 |
| tools | kubectl_delete | labelSelector | 0d06fc10a84fea58782010a6f9b02fc0238e8d7cad50ed6ce5ac77321d66b203 |
| tools | kubectl_delete | manifest | 00b01822a35fdcd94e64513f47f1521c025172655013aefb4fb162f8a5a903e3 |
| tools | kubectl_delete | name | 5672110d71001bb921ab6b3c591f08b174c11f5564916283674ea01a2e11e704 |
| tools | kubectl_delete | namespace | 9be52fa9fbccc00b73122daa021fa76c812ea4064f1fd018446c4fbcc5c86b3d |
| tools | kubectl_delete | resourceType | 877665e8f51cb23cd6cb4f5358bb2ef39c9c3b4305a8cfd5acffae3972f0b1a6 |
| tools | kubectl_describe | description | b145e3fce38ca387e810cb2b52f3dbeaf4027fb7f7c51c44bca996b99fd60e9a |
| tools | kubectl_describe | allNamespaces | 4242c1456715ec51c9cc6182e1613c80e27da79efdffc8374ec4e40eaae81bcd |
| tools | kubectl_describe | name | 80a6ffb3265ae3c038762bd7d58eb239cb14e0ee6e926e7a0fd9ab647484cb4a |
| tools | kubectl_describe | namespace | 9be52fa9fbccc00b73122daa021fa76c812ea4064f1fd018446c4fbcc5c86b3d |
| tools | kubectl_describe | resourceType | ed9d03a45ecb7935f8d7dac28e14b89b06291e8bb6b00c36f7f5b5cc18120906 |
| tools | kubectl_generic | description | 701bfa1536b12fb711631b46a57b459a4e32acda030f7f490782500ada7a082c |
| tools | kubectl_generic | args | ed5733d88aa57e46c31bb3ba881680d708d7dff6f16ed7452fdc9c0798702a6e |
| tools | kubectl_generic | command | ba586487496d823e7e6ffc93388ea6f980213e25ca69c998caf7121eb6e44521 |
| tools | kubectl_generic | flags | 60c5c32fad1a2d19230829ec8fa451674dc30543e95beeb2d8ec8eb670d2896d |
| tools | kubectl_generic | name | 2098cc067f8b57f10d53655ff8d926b89dff2abdfae20762f1f00e6d4e5a77ad |
| tools | kubectl_generic | namespace | c4e4e7abda206b07f8f017e706795f5fe305d5df2d99923d92a8ed0ab1d40cf8 |
| tools | kubectl_generic | outputFormat | 731281adc18eb222a661a27664ebff1b6c124532be98a9f7fb03a88840155dcb |
| tools | kubectl_generic | resourceType | 29130a0a6d0ec09eeee5afdec911d6655f40909607a66627bc5d0bd8231db814 |
| tools | kubectl_generic | subCommand | 9ee5d6efbad82222e18ab8b992c5d64c11d6b3f13f709898cce298dce675512e |
| tools | kubectl_get | description | dcbd96c3437e578c18a6cc8af804b4a5a9431718415e3bdb03c5d3f59094b0f8 |
| tools | kubectl_get | allNamespaces | 0ac50381c9661f02483d2d940158e739e7be70f573de32998e358a7076c3646d |
| tools | kubectl_get | fieldSelector | 68eae6f18642d304c402617622b872305d817e438f3bb105c8b779c500152f71 |
| tools | kubectl_get | labelSelector | 24a79fb9db11e42d1ae909c5c38226825f588ca0a4a9375066237b611a41108d |
| tools | kubectl_get | name | fea00e0a31591fba396a54596829ac9f6a6b63a3135247d30c5ad12c74ad3a16 |
| tools | kubectl_get | namespace | 9be52fa9fbccc00b73122daa021fa76c812ea4064f1fd018446c4fbcc5c86b3d |
| tools | kubectl_get | output | 93c53d3745136c4e4e142811cdff560c8dfb4b9c4c875b7a8687dda559f688e1 |
| tools | kubectl_get | resourceType | 991e7076a096b87aefa68583d5a67127a1c71899290691065606a623e52d7a70 |
| tools | kubectl_get | sortBy | 4176b6d93f9a289c284daf08d7048dd0439ee915ad155cec3d15440551c39af0 |
| tools | kubectl_list | description | a80eacb2578f63f0a5f71baf3ac57636cd77a3d8d9c31ea7c78f8de0423a6ac8 |
| tools | kubectl_list | allNamespaces | 0ac50381c9661f02483d2d940158e739e7be70f573de32998e358a7076c3646d |
| tools | kubectl_list | fieldSelector | 68eae6f18642d304c402617622b872305d817e438f3bb105c8b779c500152f71 |
| tools | kubectl_list | labelSelector | 24a79fb9db11e42d1ae909c5c38226825f588ca0a4a9375066237b611a41108d |
| tools | kubectl_list | namespace | 2117705aa920f3b79615221686a425af386718c0c7d369ffba86082c3094c2f6 |
| tools | kubectl_list | output | 6e88d022385884bd783eea276d75a8d6d87ba1173086531426991c00f768fb68 |
| tools | kubectl_list | resourceType | 186d765bbbdd57104b6fb9fd756b3d9d0b98c865b57fb7a53ef8da00c9174cf0 |
| tools | kubectl_logs | description | c8c16259183d8ec613c1e0c8b6829aad33554138516cad991813e875d9e3d5f5 |
| tools | kubectl_logs | container | 0f93342e4a7003f29000cd347ee9cffc603c8da3f5ea9a03145b4eca923c051e |
| tools | kubectl_logs | follow | 2ca79680aa607da7997c210dee37b48a9a4bf90b01c9ad77c7a3bc8b5fe49fac |
| tools | kubectl_logs | labelSelector | 56a1ee9a1259d9f777219cd60ff352eb9a0c86695657422b426caff89779e782 |
| tools | kubectl_logs | name | dee870968d1591eaf65c3d9d1a017c2c6a44a852bc2d990458b7557c3ae95580 |
| tools | kubectl_logs | namespace | 833b97da46652f738fcf49f1ca6c1ec77724153f7d28c823406712d845265b3b |
| tools | kubectl_logs | previous | 967e4ad408de0061a1cd9075b66fb1a3a422ecb873bd4081c8eea7f667be0ae9 |
| tools | kubectl_logs | resourceType | 1cf99af1321700f2e92cc08578a50342f9a6442758ecead4c2e30ad4d2107b5b |
| tools | kubectl_logs | since | fd1abe84433fcb9ff50396f5173912e8a6a78e74ecfe232f8a67747c1290754e |
| tools | kubectl_logs | sinceTime | e916de2278b1ebd68bd72b219ed53dba50f1cce61ba0fbec645ddf05315dc296 |
| tools | kubectl_logs | tail | 9ce48481b1c58f4aa0984172c7717e04cc4c682444c66a003747d50b377e64c4 |
| tools | kubectl_logs | timestamps | bed89b79d63742faca0091c32b57e3e60effe35201e3c42165489a963b7d701b |
| tools | kubectl_patch | description | e64f3326f831bbcfe5f9d3bdcc602af0068d44130dd274dac1652226226c48f0 |
| tools | kubectl_patch | dryRun | e61631178a08ca7c0cba847055dd9a6be82bf239aaa3d0785e7eca9cb5bd282f |
| tools | kubectl_patch | name | 8b33f7f20b7e4494ef6f23ecad58905096afafaa0e90e239104a7778182f5588 |
| tools | kubectl_patch | namespace | 833b97da46652f738fcf49f1ca6c1ec77724153f7d28c823406712d845265b3b |
| tools | kubectl_patch | patchData | 461695af3a519c30126e65e78578f44e7fc0fc45013ebe7e680c9896a5d85e9d |
| tools | kubectl_patch | patchFile | e91918d5025d5e7786b105167784f69396626823bd1ceb19ae66db878d9d418a |
| tools | kubectl_patch | patchType | f326f3ace4820abb2b0c40915fa5d6d2697e0b49492b07be65694a39297f20c2 |
| tools | kubectl_patch | resourceType | 8b53dde8118a07ee31159408d2f8279635b278a742e5ad5d2db722127f211803 |
| tools | kubectl_rollout | description | da59192fbfb0cf4dab8b072b21797ef81eb411c92a2807806b7a469fe0ed2a31 |
| tools | kubectl_rollout | name | dee870968d1591eaf65c3d9d1a017c2c6a44a852bc2d990458b7557c3ae95580 |
| tools | kubectl_rollout | namespace | 833b97da46652f738fcf49f1ca6c1ec77724153f7d28c823406712d845265b3b |
| tools | kubectl_rollout | resourceType | d13f94e9e32c531d46245bb20caa333d108f205c86d2a7ce13a0d3e570c7b194 |
| tools | kubectl_rollout | revision | 0fb813514ae5af4883c9f8722b1fa05c75d0aabe12e8ea89ded9b5658ec27f8a |
| tools | kubectl_rollout | subCommand | ffa990b98a50c83737f199c29fc61a50810168051d832c3b907b9693b8bb0682 |
| tools | kubectl_rollout | timeout | 0814708a107a79dfa05950db59770aa3ae1fde39ee1b11692943cbc672fcc6bf |
| tools | kubectl_rollout | toRevision | 59edd297440bac04677989f02efbba627e34feb01eb7e6d88a169803da5ef78e |
| tools | kubectl_rollout | watch | 66818b63da899aa83958f4aa550783cc46f407a5b79aa61cb31cf17d5719e721 |
| tools | kubectl_scale | description | 7b74eb50b7e1e72453a34c04405fb6ee2bde818ff5a8244c7064ca061d19f89a |
| tools | kubectl_scale | name | b77c2393a323b93504825a018713ece375f72f5d6cc44f3b7b2ef34845041745 |
| tools | kubectl_scale | namespace | 35f26aee248b55350fe8c2a6526c11af34bc3d83b882005c481f2a4b6e2fa911 |
| tools | kubectl_scale | replicas | c087fa65988238bd46789815247cf642ff1d3349986d9c8725182c3901e1733f |
| tools | kubectl_scale | resourceType | 86835514d2926d0e9c8ca5bd7184b08c086d689d845a94cefd0ff2422e4dabbc |
| tools | list_api_resources | description | d99de9c7cf60b9c8b686ebba4d04eed18da50f8df2b823b4854d00b3a339ccca |
| tools | list_api_resources | apiGroup | db958e31706b8813e758249505765b5aed5e31a5f674c658ce1e91d66769b05d |
| tools | list_api_resources | namespaced | 044ae41369d6760faf5d2316d246f0e8d4acc598c130ae468c541a796e60222a |
| tools | list_api_resources | output | 190426df5246d7950d8e9107d88947ebb5c0a47718ce4cd283d4619db4f71bc1 |
| tools | list_api_resources | verbs | 082234f275654b2dc60aa5da636a7b22d621f90358449504699cafeff5c9c7a8 |
| tools | port_forward | description | 931f8ee6f95ddbbb2d4cfed7c7ff1c92b59b4a26d98a1d6bbde906f11fcac0a9 |
| tools | stop_port_forward | description | d6a519c2332736564873b93cb2fe3f3466fc094cc7af4be14c09a5d5b31bf246 |
| tools | uninstall_helm_chart | description | 49c8f3a48a65df33b4f80b6c23d6793c3f8d2f111dbc9aefbb93c6b066eefc2d |
| tools | uninstall_helm_chart | name | 85f01282f3161086faed8766800c17b4c00472620c5d158e1657d13041a197ed |
| tools | uninstall_helm_chart | namespace | af216e81f96fcf52c4ea61eea71ac34bff7cd232f141faeaed24ae5402463d33 |
| tools | upgrade_helm_chart | description | e8c91747df6416edacd5b7483df523449010b3bdb8caae457892da1778498f31 |
| tools | upgrade_helm_chart | chart | b34d6b02df4598648d8c810655f76567962045de26a68a8211ab7b698c481663 |
| tools | upgrade_helm_chart | name | 85f01282f3161086faed8766800c17b4c00472620c5d158e1657d13041a197ed |
| tools | upgrade_helm_chart | namespace | af216e81f96fcf52c4ea61eea71ac34bff7cd232f141faeaed24ae5402463d33 |
| tools | upgrade_helm_chart | repo | e87393dcf00bdf5f518603adad35eaced2f5d9bbc4b438c45c014886fe89079d |
| tools | upgrade_helm_chart | values | cce7f5207579dd6efd533d18288ae81090bd355d07a772b809d854851dfbd7ca |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
