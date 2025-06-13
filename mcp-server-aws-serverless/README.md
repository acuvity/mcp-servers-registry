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


# What is mcp-server-aws-serverless?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-serverless/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-serverless/0.1.4?logo=docker&logoColor=fff&label=0.1.4)](https://hub.docker.com/r/acuvity/mcp-server-aws-serverless)
[![PyPI](https://img.shields.io/badge/0.1.4-3775A9?logo=pypi&logoColor=fff&label=awslabs.aws-serverless-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/aws-serverless-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-serverless/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-serverless&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-serverless%3A0.1.4%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AI-powered tool for serverless development with AWS best practices and deployment guidance

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.aws-serverless-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/aws-serverless-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-serverless/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-serverless/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-serverless/charts/mcp-server-aws-serverless/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.aws-serverless-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-serverless/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-aws-serverless scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `AWS_PROFILE` optional (not set)
  - `AWS_REGION` optional (not set)
  - `AWS_ACCESS_KEY_ID` optional (not set)
  - `AWS_SECRET_ACCESS_KEY` optional (not set)
  - `AWS_SESSION_TOKEN` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/aws-serverless-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-serverless&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-serverless%3A0.1.4%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-serverless": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "docker.io/acuvity/mcp-server-aws-serverless:0.1.4"
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
    "acuvity-mcp-server-aws-serverless": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-aws-serverless:0.1.4"
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
    "acuvity-mcp-server-aws-serverless": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-aws-serverless:0.1.4"
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
    "acuvity-mcp-server-aws-serverless": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-aws-serverless:0.1.4"
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
    "acuvity-mcp-server-aws-serverless": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "docker.io/acuvity/mcp-server-aws-serverless:0.1.4"
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
        "args": ["run","-i","--rm","--read-only","--tmpfs","/tmp:rw,nosuid,nodev","docker.io/acuvity/mcp-server-aws-serverless:0.1.4"]
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
- arguments: `run -i --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-aws-serverless:0.1.4`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only --tmpfs /tmp:rw,nosuid,nodev docker.io/acuvity/mcp-server-aws-serverless:0.1.4
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-serverless": {
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
    "acuvity-mcp-server-aws-serverless": {
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
  - `AWS_ACCESS_KEY_ID` secret to be set as secrets.AWS_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `AWS_SECRET_ACCESS_KEY` secret to be set as secrets.AWS_SECRET_ACCESS_KEY either by `.value` or from existing with `.valueFrom`
  - `AWS_SESSION_TOKEN` secret to be set as secrets.AWS_SESSION_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `AWS_PROFILE=""` environment variable can be changed with env.AWS_PROFILE=""
  - `AWS_REGION=""` environment variable can be changed with env.AWS_REGION=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-serverless --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-serverless --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-serverless oci://docker.io/acuvity/mcp-server-aws-serverless --version 1.0.0
```

From there your MCP server mcp-server-aws-serverless will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-serverless` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-serverless/charts/mcp-server-aws-serverless/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (18)
<details>
<summary>webapp_deployment_help</summary>

**Description**:

```
Get help information about using the deploy_webapp_tool to perform web application deployments.

        If deployment_type is provided, returns help information for that deployment type.
        Otherwise, returns general help information.

        Returns:
            Dict: Deployment help information
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| deployment_type | any | Type of deployment to get help information for | Yes
</details>
<details>
<summary>deploy_serverless_app_help</summary>

**Description**:

```
Provides instructions on how to deploy a serverless application to AWS Lambda.

        Deploying a Lambda application requires generating IaC templates, building the code, packaging
        the code, selecting a deployment tool, and executing the deployment commands. This tool walks through
        each step and links to tools in this MCP server. For deploying web applications specifically, use the deploy_webapp_tool.

        Returns:
            Dict[str, Any]: A dictionary containing the deployment help information.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_type | string | Type of application to deploy | Yes
</details>
<details>
<summary>get_iac_guidance</summary>

**Description**:

```
Returns guidance on selecting an infrastructure as code (IaC) platform to deploy Serverless applications to AWS.

        Using IaC is a best practice when managing AWS resources. IaC platform choices include AWS SAM, CDK, and CloudFormation.
        Use this tool to decide which IaC tool to use for your Serverless deployments based on your specific use case and requirements.
        By default, SAM is the recomended framework.

        Returns:
            Dict: IaC guidance information
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| iac_tool | any | IaC tool to use | No
| include_examples | any | Whether to include examples | No
</details>
<details>
<summary>get_lambda_event_schemas</summary>

**Description**:

```
Returns AWS Lambda event schemas for different event sources (e.g. s3, sns, apigw) and programming languages.

        When a event source triggers a Lambda function, the request payload comes in a specific format.
        Each Lambda event source defines its own schema and language-specific types, which should be used in
        the Lambda function handler to correctly parse the event data. If you cannot find a schema for your event source, you can directly parse
        the event data as a JSON object. For EventBridge events, you must use the list_registries, search_schema, and describe_schema
        tools to access the schema registry directly, get schema definitions, and generate code processing logic.

        Returns:
            Dict: Lambda event schema source code file for the request runtime and event source
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_source | string | Event source (e.g., api-gw, s3, sqs, sns, kinesis, eventbridge, dynamodb) | Yes
| runtime | string | Programming language for the schema references (e.g., go, nodejs, python, java) | Yes
</details>
<details>
<summary>get_lambda_guidance</summary>

**Description**:

```
Use this tool to determine if AWS Lambda is suitable platform to deploy an application.

        Returns a comprehensive guide on when to choose AWS Lambda as a deployment platform.
        It includes scenarios when to use and not use Lambda, advantages and disadvantages,
        decision criteria, and specific guidance for various use cases (e.g. scheduled tasks, event-driven application).

        Returns:
            Dict: Lambda guidance information
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| include_examples | any | Whether to include examples | No
| use_case | string | Description of the use case. (e.g. scheduled tasks, event-driven application) | Yes
</details>
<details>
<summary>get_serverless_templates</summary>

**Description**:

```
Returns example SAM templates from the Serverless Land GitHub repo.

        Use this tool to get examples for building serverless applications with AWS Lambda and best practices of serverless architecture.
        The examples are centered on event-driven architecture that can help you boost agility and build reliable, scalable applications.
        Services like Lambda, EventBridge, Step Functions, SQS, SNS, and API Gateway are featured here. Examples can be deployed
        out of the box using the SAM CLI, or you can modify examples to fit your needs.

        Usage tips:
        - Each template includes a template.yml, example-pattern.json file, and src directory containing the Lambda function code. The example-pattern.json file
        contains metadata about the template, links to AWS documentation, SAM commands, and a description of the application.
        - Download the YAML template with the gitHubLink in the tool response using the GitHub API
        - Use the sam_build and sam_deploy tools to build and deploy the application to AWS Cloud

        Returns:
            Dict: List of matching Serverless templates with README content and GitHub link
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| runtime | any | Lambda runtime (e.g., nodejs22.x, python3.13) | No
| template_type | string | Template type (e.g., API, ETL, Web) | Yes
</details>
<details>
<summary>sam_build</summary>

**Description**:

```
Builds a serverless application using AWS SAM (Serverless Application Model) CLI.

        Requirements:
        - AWS SAM CLI MUST be installed and configured in your environment
        - An application MUST already be initialized with 'sam_init' tool to create sam project structure.

        This command compiles your Lambda function and layer code, creates deployment artifacts, and prepares your application for deployment and local testing.
        It creates a .aws-sam directory that structures your application in a format and location that sam local and sam deploy require. For Zip
        functions, a .zip file archive is created, which contains your application code and its dependencies. For Image functions, a container image is created,
        which includes the base operating system, runtime, and extensions, in addition to your application code and its dependencies.

        By default, the functions and layers are built in parallel for faster builds.

        Usage tips:
        - Don't edit any code under the .aws-sam/build directory. Instead, update your original source code in
        your project folder and run sam build to update the .aws-sam/build directory.
        - When you modify your original files, run sam build to update the .aws-sam/build directory.
        - You may want the AWS SAM CLI to reference your project's original root directory
        instead of the .aws-sam directory, such as when developing and testing with sam local. Delete the .aws-sam directory
        or the AWS SAM template in the .aws-sam directory to have the AWS SAM CLI recognize your original project directory as
        the root project directory. When ready, run sam build again to create the .aws-sam directory.
        - When you run sam build, the .aws-sam/build directory gets overwritten each time.
        The .aws-sam directory does not. If you want to store files, such as logs, store them in .aws-sam to
        prevent them from being overwritten.

        Returns:
            Dict: SAM init command output
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base_dir | any | Resolve relative paths to function's source code with respect to this folder.
             Use this option if you want to change how relative paths to source code folders are resolved.
             By default, relative paths are resolved with respect to the AWS SAM template's location. | No
| build_dir | any | The absolute path to a directory where the built artifacts are stored
                This directory and all of its content are removed with this option | No
| build_image | any | The URI of the container image that you want to pull for the build. By default, AWS SAM pulls the
             container image from Amazon ECR Public. Use this option to pull the image from another location | No
| container_env_var_file | any | Absolute path to a JSON file containing container environment variables. You can provide a single environment variable that applies to all serverless resources,
                or different environment variables for each resource.
                For example, for all resources:
                {
                    "Parameters": {
                        "GITHUB_TOKEN": "TOKEN_GLOBAL"
                    }
                }
                For individual resources:
                {
                    "MyFunction1": {
                        "GITHUB_TOKEN": "TOKEN1"
                    },
                    "MyFunction2": {
                        "GITHUB_TOKEN": "TOKEN2"
                    }
                }
                 | No
| container_env_vars | any | Environment variables to pass to the build container.
                Each instance takes a key-value pair, where the key is the resource and environment variable, and the
                value is the environment variable's value.
                For example: --container-env-var Function1.GITHUB_TOKEN=TOKEN1 --container-env-var Function2.GITHUB_TOKEN=TOKEN2. | No
| debug | boolean | Turn on debug logging | No
| manifest | any | Absolute path to a custom dependency manifest file (e.g., package.json) instead of the default.
             For example: 'ParameterKey=KeyPairName, ParameterValue=MyKey ParameterKey=InstanceType, ParameterValue=t1.micro. | No
| no_use_container | boolean | Run build in local machine instead of Docker container. | No
| parallel | boolean | Build your AWS SAM application in parallel. | No
| parameter_overrides | any | CloudFormation parameter overrides encoded as key-value pairs.
                For example: 'ParameterKey=KeyPairName, ParameterValue=MyKey ParameterKey=InstanceType, ParameterValue=t1.micro | No
| profile | any | AWS profile to use | No
| project_directory | string | Absolute path to directory containing the SAM project | Yes
| region | any | AWS Region to deploy to (e.g., us-east-1) | No
| save_params | boolean | Save parameters to the SAM configuration file | No
| template_file | any | Absolute path to the template file (defaults to template.yaml) | No
| use_container | boolean | Use a Lambda-like container to build the function. Use this option if your function requires a specific
                runtime environment or dependencies that are not available on the local machine. Docker must be installed | No
</details>
<details>
<summary>sam_deploy</summary>

**Description**:

```
Deploys a serverless application onto AWS Cloud using AWS SAM (Serverless Application Model) CLI and CloudFormation.

        Requirements:
        - AWS SAM CLI MUST be installed and configured in your environment
        - SAM project MUST be initialized using sam_init tool and built with sam_build.

        This command deploys your SAM application's build artifacts located in the .aws-sam directory
        to AWS Cloud using AWS CloudFormation. The only required parameter is project_directory. SAM will automatically
        create a S3 bucket where build artifacts are uploaded and referenced by the SAM template.

        Usage tips:
        - When you make changes to your application's original files, run sam build to update the .aws-sam directory before deploying.

        Returns:
            Dict: SAM deploy command output
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application to be deployed | Yes
| capabilities | any | IAM capabilities required for the deployment | No
| config_env | any | Environment name specifying default parameter values in the configuration file | No
| config_file | any | Absolute path to the SAM configuration file | No
| debug | boolean | Turn on debug logging | No
| metadata | any | Metadata to include with the stack | No
| parameter_overrides | any | CloudFormation parameter overrides encoded as key-value pairs | No
| profile | any | AWS profile to use | No
| project_directory | string | Absolute path to directory containing the SAM project (defaults to current directory) | Yes
| region | any | AWS region to deploy to | No
| resolve_s3 | boolean | Automatically create an S3 bucket for deployment artifacts.  You cannot set both s3_bucket and resolve_s3 parameters | No
| s3_bucket | any | S3 bucket to deploy artifacts to. You cannot set both s3_bucket and resolve_s3 parameters | No
| s3_prefix | any | S3 prefix for the artifacts | No
| tags | any | Tags to apply to the stack | No
| template_file | any | Absolute path to the template file (defaults to template.yaml) | No
</details>
<details>
<summary>sam_init</summary>

**Description**:

```
Initializes a serverless application using AWS SAM (Serverless Application Model) CLI.

        Requirements:
        - AWS SAM CLI MUST be installed and configured in your environment

        This tool creates a new SAM project that consists of:
        - An AWS SAM template to define your infrastructure code
        - A folder structure that organizes your application
        - Configuration for your AWS Lambda functions

        Use this tool to initialize a new project when building a serverless application.
        This tool generates a project based on a pre-defined template. After calling this tool,
        modify the code and infrastructure templates to fit the requirements of your application.

        Usage tips:
        - Do not use this tool on existing projects as it creates brand new directory. Instead manually create SAM templates in the existing application's directory.
        - Either select from one of predefined templates, or from the SAM GitHub repo (https://github.com/aws/aws-sam-cli-app-templates)

        Returns:
            Dict[str, Any]: Result of the initialization
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_insights | any | Activate Amazon CloudWatch Application Insights monitoring.
                Helps you monitor the AWS resources in your applications to help identify potential issues.
                It can analyze AWS resource data for signs of problems and build automated CloudWatch dashboards to visualize them.
                 | No
| application_template | string | Template for the SAM application, e.g., hello-world, quick-start, etc.
             This parameter is required if location is not specified. | No
| architecture | any | Architecture for the Lambda function. | No
| base_image | any | Base image for the application when package type is Image.
                The AWS base images are preloaded with a language runtime, a runtime interface client to manage the
                interaction between Lambda and your function code, and a runtime interface emulator for local testing. | No
| config_env | any | Environment name specifying default parameter values in the configuration file | No
| config_file | any | Absolute path to configuration file containing default parameter values | No
| debug | any | Turn on debug logging | No
| dependency_manager | string | Dependency manager for the Lambda function (e.g. npm, pip) | Yes
| extra_content | any | Override custom parameters in the template's cookiecutter.json | No
| location | any | Template or application location (Git, HTTP/HTTPS, zip file path).
                This GitHub repo https://github.com/aws/aws-sam-cli-app-templates contains a collection of templates.
                This parameter is required if app_template is not specified. | No
| no_application_insights | any | Deactivate Amazon CloudWatch Application Insights monitoring | No
| no_tracing | any | Deactivate AWS X-Ray tracing for Lambda functions | No
| package_type | any | Package type for the Lambda function. Zip creates a .zip file archive, and Image creates a container image. | No
| project_directory | string | Absolute path to directory where the SAM application will be initialized | Yes
| project_name | string | Name of the SAM project to create | Yes
| runtime | any | Runtime environment for the Lambda function.
                             This option applies only when the package type is Zip. | Yes
| save_params | any | Save parameters to the SAM configuration file | No
| tracing | any | Activate AWS X-Ray tracing for Lambda functions. X-ray collects data about requests
            that your application serves and provides tools that you can use to view, filter, and gain insights into that data to identify issues
            and opportunities for optimization. | No
</details>
<details>
<summary>sam_local_invoke</summary>

**Description**:

```
Locally invokes a Lambda function using AWS SAM CLI.

        Requirements:
        - AWS SAM CLI MUST be installed and configured in your environment
        - Docker must be installed and running in your environment.

        This command runs your Lambda function locally in a Docker container that simulates the AWS Lambda environment.
        Use this tool to test your Lambda functions before deploying them to AWS. It allows you to test the logic of your function faster.
        Testing locally first reduces the likelihood of identifying issues when testing in the cloud or during deployment,
        which can help you avoid unnecessary costs. Additionally, local testing makes debugging easier to do.

        Returns:
            Dict: Local invoke result and the execution logs
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_env_vars | any | Environment variables to pass to the container | No
| docker_network | any | Docker network to run the Lambda function in | No
| environment_variables_file | any | Absolute path to a JSON file containing environment variables to pass to the function | No
| event_data | any | JSON string containing event data (alternative to event_file) | No
| event_file | any | Absolute path to a JSON file containing event data | No
| layer_cache_basedir | any | Directory where the layers will be cached | No
| log_file | any | Absolute path to a file where the function logs will be written | No
| parameter | any | Override parameters from the template file | No
| profile | any | AWS profile to use | No
| project_directory | string | Absolute path to directory containing the SAM project | Yes
| region | any | AWS region to use (e.g., us-east-1) | No
| resource_name | string | Name of the Lambda function to invoke locally | Yes
| template_file | any | Absolute path to the SAM template file (defaults to template.yaml) | No
</details>
<details>
<summary>sam_logs</summary>

**Description**:

```
Fetches CloudWatch logs that are generated by Lambda function and API GW resources in a SAM application.

        Requirements:
        - AWS SAM CLI MUST be installed and configured in your environment
        - Your SAM application MUST be deployed and receiving traffic

        After deploying your serverless application, you can use this tool to monitor it to provide insights on
        its operations and detect anomalies. Use this tool to help troubleshoot invocation failures, and function code errors
        and find root causes. Lambda function logs contain application logs emitted by your code and platform level logs emitted by the Lambda service.

        Usage tips:
        - Use logs to debug out-of-memory errors. Platform logs indicate memory usage in the REPORT line. If memory usage is high compared to
        configured memory, out-of-memory could be causing invocation failures.
        - Use logs to debug timeouts errors. Functions that have timed-out contain a log line like ' Task timed out after 3.00 seconds'.

        Note: You MUST explicitly enable logging on API GW resources

        Returns:
            Dict: Log retrieval result
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| config_env | any | Environment name specifying default parameter values in the configuration file | No
| config_file | any | Absolute path to configuration file containing default parameter values | No
| cw_log_group | any | Use AWS CloudWatch to fetch logs. Includes logs from the CloudWatch Logs log groups that you specify.
                If you specify this option along with name, AWS SAM includes logs from the specified log groups in addition to logs from the named resources. | No
| end_time | any | Fetch logs up until this time (format: 5mins ago, tomorrow, or YYYY-MM-DD HH:MM:SS) | No
| profile | any | AWS profile to use | No
| region | any | AWS region to use (e.g., us-east-1) | No
| resource_name | any | Name of the resource to fetch logs for. This is be the logical ID of the function resource in the AWS CloudFormation/AWS SAM template.
                Multiple names can be provided by repeating the parameter again. If you don't specify this option,
                AWS SAM fetches logs for all resources in the stack that you specify. You must specify stack_name wheみ specifying resource_name. | No
| save_params | boolean | Save parameters to the SAM configuration file | No
| stack_name | any | Name of the CloudFormation stack | No
| start_time | any | Fetch logs starting from this time (format: 5mins ago, tomorrow, or YYYY-MM-DD HH:MM:SS) | No
</details>
<details>
<summary>list_registries</summary>

**Description**:

```
Lists the registries in your account.

        REQUIREMENTS:
        - For AWS service events, you MUST use the aws.events registry directly
        - For custom schemas, you MAY use LOCAL scope to manage your own registries
        - When searching AWS service events, you SHOULD use the AWS scope

        USAGE PATTERNS:
        1. Finding AWS Service Event Schemas:
        - Use aws.events registry directly instead of searching
        - Filter by AWS scope to see only AWS-provided schemas

        2. Managing Custom Schemas:
        - Use LOCAL scope to view your custom registries
        - Apply registry_name_prefix to find specific registry groups
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | Maximum number of results to return. If you specify 0, the operation returns up to 10 results. | No
| next_token | any | Next token returned by the previous operation. | No
| registry_name_prefix | any | Specifying this limits the results to only those registry names that start with the specified prefix. For EventBridge events, use aws.events registry directly instead of searching. | No
| scope | any | Can be set to Local or AWS to limit responses to your custom registries, or the ones provided by AWS.
            LOCAL: The registry is created in your account.
            AWS: The registry is created by AWS.

            For EventBridge events, use aws.events registry which is an AWS-managed registry containing all AWS service event schemas. | No
</details>
<details>
<summary>search_schema</summary>

**Description**:

```
Search for schemas in a registry using keywords.

        REQUIREMENTS:
        - You MUST use this tool to find schemas for AWS service events
        - You MUST search in the "aws.events" registry for AWS service events
        - You MUST use this tool when implementing Lambda functions that consume events from EventBridge
        - You SHOULD prefix search keywords with "aws." for optimal results (e.g., "aws.s3", "aws.ec2")
        - You MAY filter results using additional keywords for specific event types

        USE CASES:

        1. Lambda Function Development with EventBridge:
        - CRITICAL: Required for Lambda functions consuming events from EventBridge
        - Search for event schemas your function needs to process
        - Example: "aws.s3" for S3 events, "aws.dynamodb" for DynamoDB streams
        - Use results with describe_schema to get complete event structure

        2. EventBridge Rule Creation:
        - Find schemas to create properly structured event patterns
        - Example: "aws.ec2" for EC2 instance state changes
        - Ensure exact field names and types in rule patterns

        IMPLEMENTATION FLOW:
        1. Search aws.events registry for service schemas
        2. Note relevant schema names from results
        3. Use describe_schema to get complete definitions
        4. Implement handlers using exact schema structure
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keywords | string | Keywords to search for. Prefix service names with "aws." for better results (e.g., "aws.s3" for S3 events, "aws.ec2" for EC2 events). | Yes
| limit | any | Maximum number of results to return. If you specify 0, the operation returns up to 10 results. | No
| next_token | any | Next token returned by the previous operation. | No
| registry_name | string | For AWS service events, use "aws.events" to search the EventBridge schema registry. | Yes
</details>
<details>
<summary>describe_schema</summary>

**Description**:

```
Retrieve the schema definition for the specified schema version.

        REQUIREMENTS:
        - You MUST use this tool to get complete schema definitions before implementing handlers
        - You MUST use this tool when implementing Lambda functions that consume events from EventBridge
        - You MUST use the returned schema structure for type-safe event handling
        - You SHOULD use the latest schema version unless specifically required otherwise
        - You MUST validate all required fields defined in the schema

        USE CASES:

        1. Lambda Function Handlers with EventBridge:
        You MUST:
        - CRITICAL: Required for Lambda functions consuming events from EventBridge
        - Implement handlers using the exact event structure
        - Validate all required fields defined in schema
        - Handle optional fields appropriately
        - Ensure type safety for EventBridge-sourced events

        You SHOULD:
        - Generate strongly typed code based on schema
        - Implement error handling for missing fields
        - Document any assumptions about structure

        2. EventBridge Rules:
        You MUST:
        - Create patterns that exactly match schema
        - Use correct field names and value types
        - Include all required fields in patterns

        You SHOULD:
        - Test patterns against sample events
        - Document pattern matching logic
        - Consider schema versions in design

        The schema content provides complete event structure with all fields and types, ensuring correct event handling.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| registry_name | string | For AWS service events, use "aws.events" to access the EventBridge schema registry. | Yes
| schema_name | string | The name of the schema to retrieve (e.g., "aws.s3@ObjectCreated" for S3 events). | Yes
| schema_version | any | Version number of the schema. For AWS service events, use latest version (default) to ensure up-to-date event handling. | No
</details>
<details>
<summary>get_metrics</summary>

**Description**:

```
Retrieves CloudWatch metrics from a deployed web application.

        Use this tool get metrics on error rates, latency, throttles, etc. of Lambda functions, API Gateways, or CloudFront distributions.
        This tool can help provide insights into anomalies and monitor operations, which can help with troubleshooting.

        Returns:
            Dict: Metrics retrieval result
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| distribution_id | any | CloudFront distribution ID to get metrics for. Find the id from the CFN stack output.
                distribution_id required if the resources parameter list contains cloudfront. | No
| end_time | any | End time for metrics (ISO 8601 format). Example: 2025-05-30T21:00:00Z | No
| function_name | any | Lambda function to get metrics for. Set this
                        parameter if resources parameter contains 'lambda' and the function name is not same as the project_name. Typically, SAM appends a random id suffix to function names.
                        Find the name from CFN stack output. If function_name is not specified, project_name is used as function name. | No
| period | any | Period for metrics in seconds | No
| project_name | string | Project name | Yes
| region | any | AWS region to use (e.g., us-east-1) | No
| resources | any | Resources to get metrics for | No
| stage | any | API Gateway stage | No
| start_time | any | Start time for metrics (ISO 8601 format). Example: 2025-05-30T20:00:00Z | No
</details>
<details>
<summary>configure_domain</summary>

**Description**:

```
Configures a custom domain for a deployed web application on AWS Serverless.

        Before using this tool, you must already own the domain name and have a Route53 hosted zone in your account.
        This tool does not register domain names.
        This tool sets up Route 53 DNS records, ACM certificates, and CloudFront custom domain mappings as needed.
        Use this tool after deploying your web application to associate it with your own domain name.

        Returns:
            Dict: Domain configuration result
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| create_certificate | any | Whether to create a ACM certificate | No
| create_route53_record | any | Whether to create a Route 53 record. When set to True, this tool creates a DNS A record
                that points to the CloudFront distribution associated with this project | No
| domain_name | string | Custom domain name to use for the CloudFront distribution . You must already own the domain name
            and have a Route 53 hosted zone in your account. This tool does not register domain names. | Yes
| project_name | string | Project name | Yes
| region | any | AWS region to use (e.g., us-east-1) | No
</details>
<details>
<summary>deploy_webapp</summary>

**Description**:

```
Deploy web applications to AWS Serverless, including Lambda as compute, DynamoDB as databases, API GW, ACM Certificates, and Route 53 DNS records.

        This tool uses the Lambda Web Adapter framework so that applications can be written in a standard web framework like Express or Next.js can be easily
        deployed to Lambda. You do not need to use integrate the code with any adapter framework before using this tool.

        Returns:
            Dict: Deployment result and link to pending deployment resource
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| backend_configuration | any | Backend configuration | No
| deployment_type | string | Type of deployment | Yes
| frontend_configuration | any | Frontend configuration | No
| project_name | string | Project name | Yes
| project_root | string | Absolute path to the project root directory | Yes
| region | any | AWS Region to deploy to (e.g., us-east-1) | No
</details>
<details>
<summary>update_webapp_frontend</summary>

**Description**:

```
Update the frontend assets of a deployed web application.

        This tool uploads new frontend assets to S3 and optionally invalidates the CloudFront cache.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| built_assets_path | string | Absolute path to pre-built frontend assets | Yes
| invalidate_cache | any | Whether to invalidate the CloudFront cache | No
| project_name | string | Project name | Yes
| project_root | string | Project root | Yes
| region | any | AWS region to use (e.g., us-east-1) | No
</details>

## 📚 Resources (2)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| template_list | text/plain | template://list | - |
| deployment_list | text/plain | deployment://list | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | configure_domain | description | 75fd63a3f330e633d02981af19fa4ea959aea01ed0a5e1a3c84f103ff334690e |
| tools | configure_domain | create_certificate | 3556dbacdd0cf55b7a8f520685656a02566bbbc450dcfcfb8582af875f45c4d5 |
| tools | configure_domain | create_route53_record | a388007455b6e849073fd6e1d5518e43cea816729184ccb9a7ab25dfcbad224f |
| tools | configure_domain | domain_name | 36a3f78b0038bf5715ae4cad746ae15110e141518999883fda9bff2aeb7289e8 |
| tools | configure_domain | project_name | 25498193b898195dca035317a941c506276da563d690c4cccf94af50643dbb44 |
| tools | configure_domain | region | 70c882a9000d21a66d8d362cb9e84d192b4c57b33af02881d3578fb94210ed0c |
| tools | deploy_serverless_app_help | description | 7ca8c5eb1f5a0d1748b19e70891449c4a36859be8411cd649cf80fe2aaaa4517 |
| tools | deploy_serverless_app_help | application_type | d518fd1dcbf8c26f1e868dbeaf1b41a4955cc16262fbb4757f8013030f346ec8 |
| tools | deploy_webapp | description | e251a7e189ed649f3b3e83e28dd48496ed35460e0d47b11e914124ceaf290072 |
| tools | deploy_webapp | backend_configuration | d839af0bdd3b441e966e953946cda369f586047784ec2d192a98c647d6ba86f2 |
| tools | deploy_webapp | deployment_type | 65451734055e3244b351d7a8e15494108e8310635cb64211e3102040588b501f |
| tools | deploy_webapp | frontend_configuration | bf3de163775716e173f1f399dc7e758960519ad437049744c602137b34ed209f |
| tools | deploy_webapp | project_name | 25498193b898195dca035317a941c506276da563d690c4cccf94af50643dbb44 |
| tools | deploy_webapp | project_root | 6303e9e4a0b12ff5e2a097fe5f9abcbdb1ed49ec8ef42ad6fb24134ed64dc822 |
| tools | deploy_webapp | region | d59dc3f562abcbb6a081da79ce7c717ea734ca167042b4e30d80e9cec113dd33 |
| tools | describe_schema | description | 5d2eeb52eff7781f0cd71e7aaeceeebc9a0fdffbc3d58f4282b79dae7571cbdd |
| tools | describe_schema | registry_name | 78f1777d1782064eea1dfc2992fa9159a51b9dbef024ac38be91858e4caaf8f8 |
| tools | describe_schema | schema_name | 4cfa6170bce98464860d06368a98feab6d933a2c7f380f31662408ab5c8706ed |
| tools | describe_schema | schema_version | 6d247cc948a5995933592db4694574a22ab341efab561208cfe2d61d10d2d32d |
| tools | get_iac_guidance | description | 72e3655cfa09700e3dfde110d11498fff45aa2dd2c06a98932a2045fb167b5a3 |
| tools | get_iac_guidance | iac_tool | 5a01b9cb921354234cf422740278ff3300d1cd91294288cbccfcd8be05f1ef38 |
| tools | get_iac_guidance | include_examples | e61965b2496831f968479bc1132dea059f0421b953093488c678894f5968b6f6 |
| tools | get_lambda_event_schemas | description | cd74401798964f66de46f0cfecff33d8f1f171b3c21d2954eefc3f4a4a3b9004 |
| tools | get_lambda_event_schemas | event_source | 69ab7e4af6e495d30688cb601ba1686b8636ee3ee47fe81fed7c7eb551df6c14 |
| tools | get_lambda_event_schemas | runtime | babe5cd1144fd83c54c3955a5fca626c6ee673aa5ae74eb31efac8bd833e0de4 |
| tools | get_lambda_guidance | description | 44b85a34bc71a0129abf186b3cdc878b3b5093a773cf4cb1e3f5376ff661fd88 |
| tools | get_lambda_guidance | include_examples | e61965b2496831f968479bc1132dea059f0421b953093488c678894f5968b6f6 |
| tools | get_lambda_guidance | use_case | ae100061383b136fc1d00717aac528dc78d2bbfd795ca2b8c82a006663e034bc |
| tools | get_metrics | description | bb3ded36efdf8826537b758381e7f1ba3136fa89140bf7f88e3fa6c4770a5bdc |
| tools | get_metrics | distribution_id | 887c5f80cf955f22ffd031feb8ba39cd5972752750c9cf263d581bf14285ed26 |
| tools | get_metrics | end_time | e0352001758408d7374658714e030d6a342fb26b7001d1d31f97ddee2e4334c0 |
| tools | get_metrics | function_name | 666f3a8f5fa1600e5466cc345926bb61538b7389e2f9e5249fe06b34e4d187d2 |
| tools | get_metrics | period | 3fcb99402d846e30d1eed8fc7ad01989285daebac4029f28ab53e5c5c4924de7 |
| tools | get_metrics | project_name | 25498193b898195dca035317a941c506276da563d690c4cccf94af50643dbb44 |
| tools | get_metrics | region | 70c882a9000d21a66d8d362cb9e84d192b4c57b33af02881d3578fb94210ed0c |
| tools | get_metrics | resources | b8dbccf3d0cfdb08e0bf7b19992c253e72aeff4fa4e5aa58aedd3da4563ae235 |
| tools | get_metrics | stage | 1767116e8e1fa87b3f8e8b2d46e7bdf7a2997010156103fa3418062efd6479cb |
| tools | get_metrics | start_time | a08c9eb0afc45482997a160bd1c54f02679fd49fc37d39a852ba4558bb8c129b |
| tools | get_serverless_templates | description | 7eae90308831e6b57866b9db3a079b7871b9856cbac0ba6536bcc59fd60cc3e7 |
| tools | get_serverless_templates | runtime | 8983cc750c9292659ebdcdcbe636294ac7dd0de79b96df0350f47bed86336c68 |
| tools | get_serverless_templates | template_type | 7316a12b58638051526e545d376023aaa9b5e2365aa95cff2ab00a91854011e5 |
| tools | list_registries | description | 626b5e7f36baeadc85a2349f58eea394b6ad9bdafb236b3304e4e6d1688fcf99 |
| tools | list_registries | limit | 55423e9379a6d453ee600ae3c361d3306cb42364ad5f79494d3c229ace4b3283 |
| tools | list_registries | next_token | 6006bfa5ae9e07700d027d9d96b9f757b12fe2b7743d8093a7953d4017692f08 |
| tools | list_registries | registry_name_prefix | 027246872dd9f55b401c3b48eacce9ef3c54b17d94792e3b4458880da786694b |
| tools | list_registries | scope | 6d703d476a2438359d52dc65b6631dabb72e42178d52360023a48977f21e6c75 |
| tools | sam_build | description | 607a50dcdfa0b2063a619bac67092fd84874f885ff08993b87755c39e8e6d417 |
| tools | sam_build | base_dir | e7629f0836ed4345b67e58c370b5ef33ad8e7258a2b9a5bf86d8898ae2a4f04d |
| tools | sam_build | build_dir | c06e25374a2808182fb0a67f488053d63c122c4a023b7e105ff2eda8d2c70caa |
| tools | sam_build | build_image | 5f95d0ad280effd3407d94ee0f85a933cca224db9e8790305edb08f1cb858857 |
| tools | sam_build | container_env_var_file | 0976c625ced97dd4eebfee9bf3c354110c2f07388a2693979a252909de7c2a4f |
| tools | sam_build | container_env_vars | 8ad5777ce2c8614aefe26316a07834d099248f91c332c823aee8891f59885b28 |
| tools | sam_build | debug | aafe814b1770c6908c38e8cf9089ef025261c4ee5b942544e5ba90fb2fc7081d |
| tools | sam_build | manifest | ef73544996c0e4c22cbc6e0d1b6c4d0b65923ae25163317e7f90debf6ea8ee35 |
| tools | sam_build | no_use_container | 3ef33fe7d735896c8945d4968833085f05a20ddefdc637ad6f92729c63e67368 |
| tools | sam_build | parallel | 6083486f30cf9c649cff1d3cb3755ce8e6937f0b62f20bf56018c5225a463ceb |
| tools | sam_build | parameter_overrides | fcdc3da3429292375dd066a160f3343de3990983de7af23d5965d8b3457584a2 |
| tools | sam_build | profile | 44e6d83ff28627b9d4320c07ffbc8c2abfe0fa7a70205cd0042d3e42e4043d91 |
| tools | sam_build | project_directory | f8197a1944c1a96641fe0c1cffbbd4347dfef9c1e97384c648d1b4f5bb900bca |
| tools | sam_build | region | d59dc3f562abcbb6a081da79ce7c717ea734ca167042b4e30d80e9cec113dd33 |
| tools | sam_build | save_params | d0db3f8a294fcf143233fbf2297018add4d14b0caf913b4b9786cc0425a122ae |
| tools | sam_build | template_file | ed515bb379f3517cfa08a1badfd9e14f66d45970cc741aba7a81b8efbe30f342 |
| tools | sam_build | use_container | 14c8ff466922f83da8cbd0a35ebbcfe3ccd628a81e68706ad50bb8e711a6e2eb |
| tools | sam_deploy | description | 4fb3f85f6e930da1f6915a6d9063f10c26cffbce847ae9f12227824c9843fa19 |
| tools | sam_deploy | application_name | 22ee712ebc0bc71789eab47f4110a146431c95c959b8da8f51011985f67ba83c |
| tools | sam_deploy | capabilities | e62f0067b9c459b7a711ae31065895d0a85ba11c9edb0a4cce21f6da50d462da |
| tools | sam_deploy | config_env | 83ad7889be651c5cde37428e683a141e1fd9a91fe299a87dc41208555d03a71e |
| tools | sam_deploy | config_file | 18498ba2dc59bb89b457364fab45e6061205add975c90350e3d7b8e0777dd797 |
| tools | sam_deploy | debug | aafe814b1770c6908c38e8cf9089ef025261c4ee5b942544e5ba90fb2fc7081d |
| tools | sam_deploy | metadata | 169a0ecbf8ce83df314055087c15e3d9d6522b9987a929f5e3f0da68002e3c2c |
| tools | sam_deploy | parameter_overrides | 999bf7b0f540d7ba5e4f27ac2714f51031d519f402f6795d9f4799984cc912d7 |
| tools | sam_deploy | profile | 44e6d83ff28627b9d4320c07ffbc8c2abfe0fa7a70205cd0042d3e42e4043d91 |
| tools | sam_deploy | project_directory | 1c6855ca6e379c0d9149b3b3c7636573dd3baa8bb9011b0f9bb93d9b66d87dd1 |
| tools | sam_deploy | region | 7dc0ad5ebff951b25b23816959500a705ed07346ac1621c18cef1eef584de47d |
| tools | sam_deploy | resolve_s3 | e3c3c52ff95f590e16786bab166b235e699192ea5f72f736aeebd0cf628c4b48 |
| tools | sam_deploy | s3_bucket | beb98a9316511f857a6c16c1933c3419d1931290d0050efdd8da9abd2534478e |
| tools | sam_deploy | s3_prefix | c2183d94878e80d872d626256da2db94776180f570e8f12feb7a66d79cc7b225 |
| tools | sam_deploy | tags | d43462b01a6f08a320fb109288b5ad5cfdc67c4172d3317a63184f09dbd1a58e |
| tools | sam_deploy | template_file | ed515bb379f3517cfa08a1badfd9e14f66d45970cc741aba7a81b8efbe30f342 |
| tools | sam_init | description | b402370b28e99edd2097689b5035aa1e828807d1ef9fa9b3696f150835808e89 |
| tools | sam_init | application_insights | a209734eae3b9d2986ab4109f06497a6dcf5ec9242d0ab1fca1e0b5122521509 |
| tools | sam_init | application_template | da5eb2b5808f4af88d85a5282ade7b6abbfa362e6f0684aee15fe3227b699305 |
| tools | sam_init | architecture | 2785c31213c0c31e50798859e46fe5e9007223ca9adead636af20c9ff45d8497 |
| tools | sam_init | base_image | 6ff89adb3be6a06059e764237a0ec93b17d42c9f1eedd919e32d406b12ced964 |
| tools | sam_init | config_env | 83ad7889be651c5cde37428e683a141e1fd9a91fe299a87dc41208555d03a71e |
| tools | sam_init | config_file | dd075f1393569bf43f174dc5291a3255b9967041d13c5e3a42d5b7dbd3d2bc58 |
| tools | sam_init | debug | aafe814b1770c6908c38e8cf9089ef025261c4ee5b942544e5ba90fb2fc7081d |
| tools | sam_init | dependency_manager | fa1de48e0fa0e4732280ed3e1f7551eb400ef31df8b4d43591edaab9924fdbe6 |
| tools | sam_init | extra_content | fc3ad6fb46f53339d2345d6dea21ad1206b132c69a1f7f6aeb9cb2e694f26135 |
| tools | sam_init | location | 15570ecd6a06d2d2f3a3d54967ffd50c5fb2945edd108313d739f2db6e34ad80 |
| tools | sam_init | no_application_insights | aa525ec3c4829786be24d42fdfe5cd7987f496186fdf7d8f9fd855723f8744f1 |
| tools | sam_init | no_tracing | cd2525018f3d9a93bccf9426bf2cea8d1428caf9c60c2a8f94c52044ff99ee21 |
| tools | sam_init | package_type | 4381bef43ef7b99396fa5bc14bbe11afdbee5524116b7124e57827a2c1c0e1c4 |
| tools | sam_init | project_directory | b9d35c64b1e1562651884eea2b675402617cccd9d96f009ae47dc66a332a8147 |
| tools | sam_init | project_name | 2bc40affdf511f871b97f2ddb8dad8275c46e895f021583dc1163d5419ea570f |
| tools | sam_init | runtime | c81f9864e80c44898077687127851052e1065394477eb92df6ba97d92ec2ddbe |
| tools | sam_init | save_params | d0db3f8a294fcf143233fbf2297018add4d14b0caf913b4b9786cc0425a122ae |
| tools | sam_init | tracing | 03ccd29fae162195fbbbce69e1023024c7b99ac7b5b5da1afe0e30e34fe3f70d |
| tools | sam_local_invoke | description | a51420db25743e0980c12dc6fe53df330fb83ea23e91b21c57109a13dcb69f9a |
| tools | sam_local_invoke | container_env_vars | 4c5b2fe9807a5bd1cfec910d81ad80e892a75c21ca7182de6566f403b7ef4059 |
| tools | sam_local_invoke | docker_network | 5ab3e63eac20dd9223e9be566193b78abe019063b106efcc3e21da571fd2c752 |
| tools | sam_local_invoke | environment_variables_file | ca4b98f1f85ac59853a7d685c5d01cf5d13ba2fd72f08dbaf680d1127f49e9c1 |
| tools | sam_local_invoke | event_data | e4d5469a2fd674157b3702ede4c233f3bd4162a71f859014af85938097b1e1ad |
| tools | sam_local_invoke | event_file | e8de2e90efa6b4c882bbe6717ab52255d2696d210490ca1be9980b1a2274334e |
| tools | sam_local_invoke | layer_cache_basedir | c7883dc5184bf320a554da65665ba700a0ec103d3d0b83730282eae648ea661b |
| tools | sam_local_invoke | log_file | b6f034d178412811dad4f3f252879bbdeeb0883be398a721f4e3642a45137df0 |
| tools | sam_local_invoke | parameter | 38e0ee03f1716a02e0bdef4ef9f07649e8691a5c69d147c46f46eeac287149ea |
| tools | sam_local_invoke | profile | 44e6d83ff28627b9d4320c07ffbc8c2abfe0fa7a70205cd0042d3e42e4043d91 |
| tools | sam_local_invoke | project_directory | f8197a1944c1a96641fe0c1cffbbd4347dfef9c1e97384c648d1b4f5bb900bca |
| tools | sam_local_invoke | region | 70c882a9000d21a66d8d362cb9e84d192b4c57b33af02881d3578fb94210ed0c |
| tools | sam_local_invoke | resource_name | e5164de063784b1fcb8e9255230e8fc26c711666e861dcf0ea6c02937c6c9b1e |
| tools | sam_local_invoke | template_file | c7f3202a4d1039b511ab58144194f713a823233caf6b999ac671c6283b3a6f54 |
| tools | sam_logs | description | b01d60eaed7c420fe50f918d55053efb6ba618a1a38be139dd0d45bb3d8fa89e |
| tools | sam_logs | config_env | 83ad7889be651c5cde37428e683a141e1fd9a91fe299a87dc41208555d03a71e |
| tools | sam_logs | config_file | dd075f1393569bf43f174dc5291a3255b9967041d13c5e3a42d5b7dbd3d2bc58 |
| tools | sam_logs | cw_log_group | e1eea6042240ffa896fe523405b5f5928b853a318ad7227d444f6b07495ddf57 |
| tools | sam_logs | end_time | 804bd4d183da61b42152250e6dc3e8cd08fc68dec01c3561e6180676f3d2eee6 |
| tools | sam_logs | profile | 44e6d83ff28627b9d4320c07ffbc8c2abfe0fa7a70205cd0042d3e42e4043d91 |
| tools | sam_logs | region | 70c882a9000d21a66d8d362cb9e84d192b4c57b33af02881d3578fb94210ed0c |
| tools | sam_logs | resource_name | 459f3054b11484a68ae0dac5c6a3ac7912076f18228e2a3dbb027e61acc3786c |
| tools | sam_logs | save_params | d0db3f8a294fcf143233fbf2297018add4d14b0caf913b4b9786cc0425a122ae |
| tools | sam_logs | stack_name | e8c88df28134eeb7f0c00ed71ece02433bd5b4b8effc00ffceea14f389355ad3 |
| tools | sam_logs | start_time | 5b60be89c8b989926dd113edbe0c28067e0052ea4289953f47aa4e34b3da485f |
| tools | search_schema | description | b6915e957ff9972c7741d13fc3e08c24f19d3d24f1f405b585498c53ef82d9e8 |
| tools | search_schema | keywords | ab7bb2f08a3a403aaa4771e62abdfaf4081283822366edbec343d318026767d7 |
| tools | search_schema | limit | 55423e9379a6d453ee600ae3c361d3306cb42364ad5f79494d3c229ace4b3283 |
| tools | search_schema | next_token | 6006bfa5ae9e07700d027d9d96b9f757b12fe2b7743d8093a7953d4017692f08 |
| tools | search_schema | registry_name | cfabacc828fefa842e7a4cc65e3c67420b63d41f6b15cba00525d9b8e81a9d70 |
| tools | update_webapp_frontend | description | 36a5dec1d27be6074fc3e9963dcb99f02afd5dbaeb14006925a1e1035e78b7b3 |
| tools | update_webapp_frontend | built_assets_path | 64484af1aba8e6af6e19b69c838d4381326750783dcda1e18571a32b10ccc3a1 |
| tools | update_webapp_frontend | invalidate_cache | 499046d3b8dd45bd39969d1249404681652a6311aeb6cce105c30dcae450992e |
| tools | update_webapp_frontend | project_name | 25498193b898195dca035317a941c506276da563d690c4cccf94af50643dbb44 |
| tools | update_webapp_frontend | project_root | f85c5ef53f05a94e4a7e047757ab14ad5a42006c35cadc3e1add4b8c3cb5d107 |
| tools | update_webapp_frontend | region | 70c882a9000d21a66d8d362cb9e84d192b4c57b33af02881d3578fb94210ed0c |
| tools | webapp_deployment_help | description | 414c4c5182a19f99b3b1d76e9380f400ef06aa360357fbf01a042461548193ad |
| tools | webapp_deployment_help | deployment_type | 66438b713825806421db0adcb436a8fb5d513159c8a0df64688f7f22e3bb88ed |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
