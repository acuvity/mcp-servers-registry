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


# What is mcp-server-docker?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-docker/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-docker/0.2.1?logo=docker&logoColor=fff&label=0.2.1)](https://hub.docker.com/r/acuvity/mcp-server-docker)
[![PyPI](https://img.shields.io/badge/0.2.1-3775A9?logo=pypi&logoColor=fff&label=mcp-server-docker)](https://github.com/ckreiling/mcp-server-docker)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-docker/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-docker&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22%2Fvar%2Frun%2Fdocker.sock%3A%2Fvar%2Frun%2Fdocker.sock%22%2C%22docker.io%2Facuvity%2Fmcp-server-docker%3A0.2.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrate with Docker to manage containers, images, volumes, and networks.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-server-docker original [sources](https://github.com/ckreiling/mcp-server-docker).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-docker/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/charts/mcp-server-docker/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-server-docker run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-docker scope of operation the intended usage is to run natively on the targeted machine to access local resources.
**Required volumes or mountPaths:**
  - data to be mounted on `/var/run/docker.sock`

For more information and extra configuration you can consult the [package](https://github.com/ckreiling/mcp-server-docker) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-docker&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22%2Fvar%2Frun%2Fdocker.sock%3A%2Fvar%2Frun%2Fdocker.sock%22%2C%22docker.io%2Facuvity%2Fmcp-server-docker%3A0.2.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-docker": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-v",
          "/var/run/docker.sock:/var/run/docker.sock",
          "docker.io/acuvity/mcp-server-docker:0.2.1"
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
    "acuvity-mcp-server-docker": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "docker.io/acuvity/mcp-server-docker:0.2.1"
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
    "acuvity-mcp-server-docker": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "docker.io/acuvity/mcp-server-docker:0.2.1"
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
    "acuvity-mcp-server-docker": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "docker.io/acuvity/mcp-server-docker:0.2.1"
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
    "acuvity-mcp-server-docker": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "docker.io/acuvity/mcp-server-docker:0.2.1"
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
        "args": ["run","-i","--rm","--read-only","-v","/var/run/docker.sock:/var/run/docker.sock","docker.io/acuvity/mcp-server-docker:0.2.1"]
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
- arguments: `run -i --rm --read-only -v /var/run/docker.sock:/var/run/docker.sock docker.io/acuvity/mcp-server-docker:0.2.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -v /var/run/docker.sock:/var/run/docker.sock docker.io/acuvity/mcp-server-docker:0.2.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-docker": {
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
    "acuvity-mcp-server-docker": {
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
helm show readme oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
````

Install with helm

```console
helm install mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
```

From there your MCP server mcp-server-docker will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-docker` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/charts/mcp-server-docker/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>list_containers</summary>

**Description**:

```
List all Docker containers
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| all | boolean | Show all containers (default shows just running) | No
| filters | any | Filter containers | No
</details>
<details>
<summary>create_container</summary>

**Description**:

```
Create a new Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_remove | boolean | Automatically remove the container | No
| command | any | Command to run in container | No
| detach | boolean | Run container in the background. Should be True for long-running containers, can be false for short-lived containers | No
| entrypoint | any | Entrypoint to run in container | No
| environment | any | Environment variables dictionary | No
| image | string | Docker image name | Yes
| labels | any | Container labels, either as a dictionary or a list of key=value strings | No
| name | any | Container name | No
| network | any | Network to attach the container to | No
| ports | any | A map whose keys are the container port, and the values are the host port(s) to bind to. | No
| volumes | any | Volume mappings | No
</details>
<details>
<summary>run_container</summary>

**Description**:

```
Run an image in a new Docker container (preferred over `create_container` + `start_container`)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_remove | boolean | Automatically remove the container | No
| command | any | Command to run in container | No
| detach | boolean | Run container in the background. Should be True for long-running containers, can be false for short-lived containers | No
| entrypoint | any | Entrypoint to run in container | No
| environment | any | Environment variables dictionary | No
| image | string | Docker image name | Yes
| labels | any | Container labels, either as a dictionary or a list of key=value strings | No
| name | any | Container name | No
| network | any | Network to attach the container to | No
| ports | any | A map whose keys are the container port, and the values are the host port(s) to bind to. | No
| volumes | any | Volume mappings | No
</details>
<details>
<summary>recreate_container</summary>

**Description**:

```
Stop and remove a container, then run a new container. Fails if the container does not exist.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_remove | boolean | Automatically remove the container | No
| command | any | Command to run in container | No
| container_id | any | Container ID to recreate. The `name` parameter will be used if this is not provided | No
| detach | boolean | Run container in the background. Should be True for long-running containers, can be false for short-lived containers | No
| entrypoint | any | Entrypoint to run in container | No
| environment | any | Environment variables dictionary | No
| image | string | Docker image name | Yes
| labels | any | Container labels, either as a dictionary or a list of key=value strings | No
| name | any | Container name | No
| network | any | Network to attach the container to | No
| ports | any | A map whose keys are the container port, and the values are the host port(s) to bind to. | No
| volumes | any | Volume mappings | No
</details>
<details>
<summary>start_container</summary>

**Description**:

```
Start a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
</details>
<details>
<summary>fetch_container_logs</summary>

**Description**:

```
Fetch logs for a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
| tail | any | Number of lines to show from the end | No
</details>
<details>
<summary>stop_container</summary>

**Description**:

```
Stop a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
</details>
<details>
<summary>remove_container</summary>

**Description**:

```
Remove a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
| force | boolean | Force remove the container | No
</details>
<details>
<summary>list_images</summary>

**Description**:

```
List Docker images
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| all | boolean | Show all images (default hides intermediate) | No
| filters | any | Filter images | No
| name | any | Filter images by repository name, if desired | No
</details>
<details>
<summary>pull_image</summary>

**Description**:

```
Pull a Docker image
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repository | string | Image repository | Yes
| tag | any | Image tag | No
</details>
<details>
<summary>push_image</summary>

**Description**:

```
Push a Docker image
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repository | string | Image repository | Yes
| tag | any | Image tag | No
</details>
<details>
<summary>build_image</summary>

**Description**:

```
Build a Docker image from a Dockerfile
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dockerfile | any | Path to Dockerfile | No
| path | string | Path to build context | Yes
| tag | string | Image tag | Yes
</details>
<details>
<summary>remove_image</summary>

**Description**:

```
Remove a Docker image
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| force | boolean | Force remove the image | No
| image | string | Image ID or name | Yes
</details>
<details>
<summary>list_networks</summary>

**Description**:

```
List Docker networks
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | any | Filter networks | No
</details>
<details>
<summary>create_network</summary>

**Description**:

```
Create a Docker network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| driver | any | Network driver | No
| internal | boolean | Create an internal network | No
| labels | any | Network labels | No
| name | string | Network name | Yes
</details>
<details>
<summary>remove_network</summary>

**Description**:

```
Remove a Docker network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network_id | string | Network ID or name | Yes
</details>
<details>
<summary>list_volumes</summary>

**Description**:

```
List Docker volumes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_volume</summary>

**Description**:

```
Create a Docker volume
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| driver | any | Volume driver | No
| labels | any | Volume labels | No
| name | string | Volume name | Yes
</details>
<details>
<summary>remove_volume</summary>

**Description**:

```
Remove a Docker volume
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| force | boolean | Force remove the volume | No
| volume_name | string | Volume name | Yes
</details>

## 📝 Prompts (1)
<details>
<summary>docker_compose</summary>

**Description**:

```
Treat the LLM like a Docker Compose manager
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| name | Unique name of the project |Yes |
| containers | Describe containers you want |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | docker_compose | description | 1747f0fcc38ce43987a5add1ec0c842f005ff7c543f4bd448707600397805be8 |
| prompts | docker_compose | containers | 54248a6c7bcf5fccbf66bfedebccf37bb90163dfa2b4bd5418f587b81883ca58 |
| prompts | docker_compose | name | e037ff48f8d7aea7707d027e85290c86c6187a9cf8b65f50ad115e2cb4ea38b1 |
| tools | build_image | description | 705c2a1603d119dd8ecdf6ab10334a19192312197dfedc0baf5e7ea096f03f21 |
| tools | build_image | dockerfile | a26f7529cdb6b02baa0fe3f86868d7bdf0b1d61d8df03f9331e3f28dcd4cec88 |
| tools | build_image | path | a4807fcee1dddfc2d8a8105415e6f2a314f2a258039ea62290272c75476c7014 |
| tools | build_image | tag | c4a77afa3d5cd701f32b5f09c195c635b256db8595687828c3ea0785ab5b72f4 |
| tools | create_container | description | b815a8ce79ac0ab46eef91d033a96a6298aaee44fba2209f038df0f290067a30 |
| tools | create_container | auto_remove | 19d5467374321dbf428f0bcbe1dedc6b4ccb3a42c727be97b8d212a3a31952a0 |
| tools | create_container | command | 88bc0bd30d1b7cd4fb79d98d7afca13530d2e8dbec00725d82f7d4cb1664ae95 |
| tools | create_container | detach | 2eee111e7b30a2e387a1079c743fcfd43199452fb08b127186983d60368e1d36 |
| tools | create_container | entrypoint | c938459cad356a96aa690ff14d85f9285ffafee1178de254930aa60269fc3ee7 |
| tools | create_container | environment | 75678c388925b748d3a4156df724c332fb18cfd2800ef5f0f8b506fc6312769d |
| tools | create_container | image | f8dee27723d20cda724d41bf47ef4f5e915948d4f790d7ec7fb9883aa8907439 |
| tools | create_container | labels | 0c9da99b2d6a5801da677fcc8ae643c33730cd34bca0529bff7f0bbe1f092fe5 |
| tools | create_container | name | 8d3a5415ee22e30f39114240c191b98b52f67ea8d52a6d8fede1ed76768cba98 |
| tools | create_container | network | 278df666180dcee703e0ec0372aeb3f2d58aa723d718f0e93554a2d1f3adddce |
| tools | create_container | ports | 1de7c6d7ac848432c94231b4b5900034f268aad3391d2f554ee25d7a87a46ed6 |
| tools | create_container | volumes | 952112ecfb6d84475c049817196f529385c4f70b1edd7b7c7a4612d76ead514d |
| tools | create_network | description | eca09860101dcc7683b41d9a49f27c25828b461cb9eb20602d30bc4ebcb20377 |
| tools | create_network | driver | f331e050c8e9f40de9b06ce2d03672069350da23bc10e56a9ec0e597acf34c71 |
| tools | create_network | internal | 8610f22d1f97f12965e975a97ee7d61185214850ea7d28b97a2fd13a0e988ebf |
| tools | create_network | labels | 03073866f417fa0943fbde2ebb822876a88f2be18d5e8f07a16925677eb589bb |
| tools | create_network | name | b97af01289460424250ff6ffae944f3b692f478e4fe678e05d4a1ba4859990dc |
| tools | create_volume | description | fb7b9660e6b26608d8ba47910fd565c5a6ebd014957bf8675be01a866064f383 |
| tools | create_volume | driver | 8e0db59b3494cbff0ee006edb671dd0554f10d5e178c88d58aff60563a0a0ce3 |
| tools | create_volume | labels | 123172e579a0d2fde759eddc7fe3f90ea9528809ff31dd22b3dac84332101824 |
| tools | create_volume | name | 6f7dd2eff222a379423cc7b906910b3bb1473dbd7b145c1ca3c053dfc8ce5c43 |
| tools | fetch_container_logs | description | a230664008063599fa40b21841e1a2039bfd1c53a9117edaec3cc4ffe85804e5 |
| tools | fetch_container_logs | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |
| tools | fetch_container_logs | tail | e923fbedccdbc7fc6c8c9cc82b95f01fb6eee2d6d9205186aa96ec9e1fa42985 |
| tools | list_containers | description | b2aaef42684012a93ed74f4ae1470bcd33d0d09fd885bbb25a0d6a3cc298a349 |
| tools | list_containers | all | 25217765ac89ca0c21562a18af0b7d06cea3dd6f35f7db05ace677745e8be292 |
| tools | list_containers | filters | 12cce9715b61b46554fe483591ecd0eb1442bbe3acf6afde384c0aa4b064aace |
| tools | list_images | description | 897691804adfd369ab4f463158e458d988823292bc1bd988f437380dde1bdfe3 |
| tools | list_images | all | 1797445beff70492315c96d517fe2c694e9fb4271338fb6f3cea05532d7841b7 |
| tools | list_images | filters | 5a46660ef3acccf6234f7ca539018dd595a3bc0100452356a8adec594deed7bb |
| tools | list_images | name | 49ec60d56114d10bbf4a2318e2096f2bdcb9f1e9dc43267693a95e7430a53eb0 |
| tools | list_networks | description | e0f48e9f0094db78a2fac13454951125b26eac6cd465ba99161f419b4118a6b1 |
| tools | list_networks | filters | 89f87a5ab141b2985d9202a8ee7336fad0558361f0aa55e3a76c169692368961 |
| tools | list_volumes | description | 7eb1265481e78bde4d9cb61ce4e6bd2aa072aedc28e0c468c37deced52ef7ecb |
| tools | pull_image | description | 2dafd1dba3147223f0a035eb647289c88a66a84b93a1f088869efd81c950ed74 |
| tools | pull_image | repository | 9d059b146668a6b686684942d7e00e84a4519e4a2950015ceadc13aa4d651a9d |
| tools | pull_image | tag | c4a77afa3d5cd701f32b5f09c195c635b256db8595687828c3ea0785ab5b72f4 |
| tools | push_image | description | e6664cd117075eb7632367ee61f0a714b6caed15be2bbe73ca8f8c58efa18382 |
| tools | push_image | repository | 9d059b146668a6b686684942d7e00e84a4519e4a2950015ceadc13aa4d651a9d |
| tools | push_image | tag | c4a77afa3d5cd701f32b5f09c195c635b256db8595687828c3ea0785ab5b72f4 |
| tools | recreate_container | description | 4cd16e24bbc67a32475afde1b1443954d95c17f762e9ef642b1f3491765495d8 |
| tools | recreate_container | auto_remove | 19d5467374321dbf428f0bcbe1dedc6b4ccb3a42c727be97b8d212a3a31952a0 |
| tools | recreate_container | command | 88bc0bd30d1b7cd4fb79d98d7afca13530d2e8dbec00725d82f7d4cb1664ae95 |
| tools | recreate_container | container_id | fe957695c0472192c71de78c4a4246f0057b5c5712bd12cdabb4b8d51db2b47c |
| tools | recreate_container | detach | 2eee111e7b30a2e387a1079c743fcfd43199452fb08b127186983d60368e1d36 |
| tools | recreate_container | entrypoint | c938459cad356a96aa690ff14d85f9285ffafee1178de254930aa60269fc3ee7 |
| tools | recreate_container | environment | 75678c388925b748d3a4156df724c332fb18cfd2800ef5f0f8b506fc6312769d |
| tools | recreate_container | image | f8dee27723d20cda724d41bf47ef4f5e915948d4f790d7ec7fb9883aa8907439 |
| tools | recreate_container | labels | 0c9da99b2d6a5801da677fcc8ae643c33730cd34bca0529bff7f0bbe1f092fe5 |
| tools | recreate_container | name | 8d3a5415ee22e30f39114240c191b98b52f67ea8d52a6d8fede1ed76768cba98 |
| tools | recreate_container | network | 278df666180dcee703e0ec0372aeb3f2d58aa723d718f0e93554a2d1f3adddce |
| tools | recreate_container | ports | 1de7c6d7ac848432c94231b4b5900034f268aad3391d2f554ee25d7a87a46ed6 |
| tools | recreate_container | volumes | 952112ecfb6d84475c049817196f529385c4f70b1edd7b7c7a4612d76ead514d |
| tools | remove_container | description | 42bba4e113755275e7e176ee6cf3577ac652910e39c870d4268799cfcc0325cf |
| tools | remove_container | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |
| tools | remove_container | force | 6dd6aa3ffa2b44f62d669a63ee5edfd12aceec7d6d54eac1cef101c6a92fb986 |
| tools | remove_image | description | 48678674b4fa9965fdefb4d8df4b1e9ae411da607c095f21c9633e00e7194483 |
| tools | remove_image | force | ad53029af2640459dd4ef4293274b1b3237ef4bbcb399797f0da6203faeb65b9 |
| tools | remove_image | image | 2c0ca53ceec83f918f22377d3c79850a2aff203b019ed223c633adce802929cd |
| tools | remove_network | description | 05d6a28c8bdd792facc3ae7610477b6e0e15d9493eb71eb14020a69b7e5a57da |
| tools | remove_network | network_id | 662f55d08dfc2dbe245e4118b04bc4df1dd65c37d0c2640f6600619034b6e511 |
| tools | remove_volume | description | 418a93d2135bec9250d71bac6c05ee7ca63d295450e9deebacdb906d61b4e1c5 |
| tools | remove_volume | force | 21f06736c937cacab95a23aaade6aabc81c7f3fe0888c3eb80e2e56bcee4d363 |
| tools | remove_volume | volume_name | 6f7dd2eff222a379423cc7b906910b3bb1473dbd7b145c1ca3c053dfc8ce5c43 |
| tools | run_container | description | be3965a693f5235851dfd36772819a6ac3868f43dbed3f6fdcce0baa89e86eaf |
| tools | run_container | auto_remove | 19d5467374321dbf428f0bcbe1dedc6b4ccb3a42c727be97b8d212a3a31952a0 |
| tools | run_container | command | 88bc0bd30d1b7cd4fb79d98d7afca13530d2e8dbec00725d82f7d4cb1664ae95 |
| tools | run_container | detach | 2eee111e7b30a2e387a1079c743fcfd43199452fb08b127186983d60368e1d36 |
| tools | run_container | entrypoint | c938459cad356a96aa690ff14d85f9285ffafee1178de254930aa60269fc3ee7 |
| tools | run_container | environment | 75678c388925b748d3a4156df724c332fb18cfd2800ef5f0f8b506fc6312769d |
| tools | run_container | image | f8dee27723d20cda724d41bf47ef4f5e915948d4f790d7ec7fb9883aa8907439 |
| tools | run_container | labels | 0c9da99b2d6a5801da677fcc8ae643c33730cd34bca0529bff7f0bbe1f092fe5 |
| tools | run_container | name | 8d3a5415ee22e30f39114240c191b98b52f67ea8d52a6d8fede1ed76768cba98 |
| tools | run_container | network | 278df666180dcee703e0ec0372aeb3f2d58aa723d718f0e93554a2d1f3adddce |
| tools | run_container | ports | 1de7c6d7ac848432c94231b4b5900034f268aad3391d2f554ee25d7a87a46ed6 |
| tools | run_container | volumes | 952112ecfb6d84475c049817196f529385c4f70b1edd7b7c7a4612d76ead514d |
| tools | start_container | description | 8344d6c6b50cf0415a88139fb79566833b8d4f54e151641f604f31b1e1571549 |
| tools | start_container | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |
| tools | stop_container | description | 6e5bdc513791aed6ed64f05478f41f6470937dcd4aab044b4564b7b02fc1a09a |
| tools | stop_container | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
