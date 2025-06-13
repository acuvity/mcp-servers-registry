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


# What is mcp-server-aws-bedrock-data-automation?
[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-bedrock-data-automation/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-bedrock-data-automation/0.0.2?logo=docker&logoColor=fff&label=0.0.2)](https://hub.docker.com/r/acuvity/mcp-server-aws-bedrock-data-automation)
[![PyPI](https://img.shields.io/badge/0.0.2-3775A9?logo=pypi&logoColor=fff&label=awslabs.aws-bedrock-data-automation-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/aws-bedrock-data-automation-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-bedrock-data-automation/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-bedrock-data-automation&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AWS_BUCKET_NAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-bedrock-data-automation%3A0.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Amazon Bedrock Data Automation server for analyzing documents, images, videos, and audio files

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.aws-bedrock-data-automation-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/aws-bedrock-data-automation-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-bedrock-data-automation/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-bedrock-data-automation/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-bedrock-data-automation/charts/mcp-server-aws-bedrock-data-automation/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.aws-bedrock-data-automation-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-bedrock-data-automation/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-aws-bedrock-data-automation scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `AWS_PROFILE` optional (not set)
  - `AWS_REGION` optional (not set)
  - `AWS_BUCKET_NAME` required to be set
  - `BASE_DIR` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/aws-bedrock-data-automation-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-bedrock-data-automation&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AWS_BUCKET_NAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-bedrock-data-automation%3A0.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-bedrock-data-automation": {
        "env": {
          "AWS_BUCKET_NAME": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "AWS_BUCKET_NAME",
          "docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2"
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
    "acuvity-mcp-server-aws-bedrock-data-automation": {
      "env": {
        "AWS_BUCKET_NAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_BUCKET_NAME",
        "docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2"
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
    "acuvity-mcp-server-aws-bedrock-data-automation": {
      "env": {
        "AWS_BUCKET_NAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_BUCKET_NAME",
        "docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2"
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
    "acuvity-mcp-server-aws-bedrock-data-automation": {
      "env": {
        "AWS_BUCKET_NAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_BUCKET_NAME",
        "docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2"
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
    "acuvity-mcp-server-aws-bedrock-data-automation": {
      "env": {
        "AWS_BUCKET_NAME": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "AWS_BUCKET_NAME",
        "docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2"
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
        "env": {"AWS_BUCKET_NAME":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","AWS_BUCKET_NAME","docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2"]
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
- arguments: `run -i --rm --read-only -e AWS_BUCKET_NAME docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e AWS_BUCKET_NAME docker.io/acuvity/mcp-server-aws-bedrock-data-automation:0.0.2
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-bedrock-data-automation": {
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
    "acuvity-mcp-server-aws-bedrock-data-automation": {
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

**Mandatory Environment variables**:
  - `AWS_BUCKET_NAME` environment variable to be set by env.AWS_BUCKET_NAME

**Optional Environment variables**:
  - `AWS_PROFILE=""` environment variable can be changed with env.AWS_PROFILE=""
  - `AWS_REGION=""` environment variable can be changed with env.AWS_REGION=""
  - `BASE_DIR=""` environment variable can be changed with env.BASE_DIR=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-bedrock-data-automation --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-bedrock-data-automation --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-bedrock-data-automation oci://docker.io/acuvity/mcp-server-aws-bedrock-data-automation --version 1.0.0
```

From there your MCP server mcp-server-aws-bedrock-data-automation will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-bedrock-data-automation` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-bedrock-data-automation/charts/mcp-server-aws-bedrock-data-automation/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (3)
<details>
<summary>getprojects</summary>

**Description**:

```
Get a list of data automation projects.

    ## Usage

    Use this tool to retrieve a list of all available data automation projects in your account.
    This is typically the first step when working with data automation to discover what projects
    are available for use.

    ## Example

    ```python
    # Get all available data automation projects
    projects = await getprojects()
    ```

    ## Output Format

    The output is a dictionary containing:
    - `projects`: A list of project objects, each with:
      - `projectArn`: The Amazon Resource Name (ARN) of the project
      - `projectName`: The name of the project
      - `projectStage`: The stage of the project (e.g., DRAFT, PUBLISHED)
      - `creationTime`: When the project was created
      - `lastModifiedTime`: When the project was last modified

    Returns:
        A dict containing a list of data automation projects.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>getprojectdetails</summary>

**Description**:

```
Get details of a data automation project.

    ## Usage

    Use this tool to retrieve detailed information about a specific data automation project
    after you've identified its ARN using the `getprojects` tool.

    ## Example

    ```python
    # Get details for a specific project
    project_details = await getprojectdetails(
        projectArn='arn:aws:bedrock:us-west-2:123456789012:data-automation-project/my-project'
    )
    ```

    ## Output Format

    The output is a dictionary containing comprehensive project details including:
    - Basic project information (name, ARN, stage)
    - Configuration settings
    - Input/output specifications
    - Associated blueprints
    - Creation and modification timestamps

    Args:
        projectArn: The ARN of the project.

    Returns:
        The project details.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| projectArn | string | The ARN of the project | Yes
</details>
<details>
<summary>analyzeasset</summary>

**Description**:

```
Analyze an asset using a data automation project.

    This tool extracts insights from unstructured content (documents, images, videos, audio)
    using Amazon Bedrock Data Automation.

    ## Usage

    Use this tool to analyze various types of assets (documents, images, videos, audio files)
    using a data automation project. You can specify a particular project to use for analysis
    or let the system use a default public project if none is provided.

    ## Supported Asset Types

    - Documents: PDF, DOCX, TXT, etc.
    - Images: JPG, PNG, etc.
    - Videos: MP4, MOV, etc.
    - Audio: MP3, WAV, etc.

    ## Examples

    ```python
    # Analyze a document using the default public project
    results = await analyzeasset(assetPath='/path/to/document.pdf')

    # Analyze an image using a specific project
    results = await analyzeasset(
        assetPath='/path/to/image.jpg',
        projectArn='arn:aws:bedrock:us-west-2:123456789012:data-automation-project/my-project',
    )
    ```

    ## Output Format

    The output is a dictionary containing the analysis results, which vary based on:
    - The type of asset being analyzed
    - The capabilities of the data automation project used
    - The specific insights extracted (text, entities, sentiment, etc.)

    Args:
        assetPath: The path to the asset.
        projectArn: The ARN of the project. Uses default public project if not provided.

    Returns:
        The analysis results.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetPath | string | The path to the asset | Yes
| projectArn | any | The ARN of the project. Uses default public project if not provided | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | analyzeasset | description | 8e85d7c3a38cb220501bb88b3ef09b3319163c728af625466d6dd4397acfee54 |
| tools | analyzeasset | assetPath | cb04d73b9e06b35d2cd0d0643d35facf25cbd413e9fa069bcf8a2d569e8c20d5 |
| tools | analyzeasset | projectArn | 54ec702463a13cf3b5c3e46d92fdba5af7c4acb5b483b30a612f54230bae649b |
| tools | getprojectdetails | description | 1070dbc8d13b0c25488bf6ee25aeb45b22e6ee93e304045a85ca6e7f2d9b4f31 |
| tools | getprojectdetails | projectArn | 092c42c0e2e1efe15b7974504fceea8e42916844f31e5853ce72b654b8718ef3 |
| tools | getprojects | description | 07542f1e635e748d5298f66fabdf2d6cb219e43002ad0a0b2e34915b71c147ee |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
