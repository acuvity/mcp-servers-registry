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


# What is mcp-server-aws-terraform?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-terraform/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-terraform/0.0.10?logo=docker&logoColor=fff&label=0.0.10)](https://hub.docker.com/r/acuvity/mcp-server-aws-terraform)
[![PyPI](https://img.shields.io/badge/0.0.10-3775A9?logo=pypi&logoColor=fff&label=awslabs.terraform-mcp-server)](https://github.com/awslabs/mcp/tree/main/src/terraform-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-terraform&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-terraform%3A0.0.10%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Terraform AWS best practices, infrastructure as code patterns, and security compliance with Checkov.

Packaged by Acuvity from awslabs.terraform-mcp-server original [sources](https://github.com/awslabs/mcp/tree/main/src/terraform-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-terraform/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/charts/mcp-server-aws-terraform/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.terraform-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/charts/mcp-server-aws-terraform#minibridge) for Helm charts).


# 📦 How to Install


> [!TIP]
> Given mcp-server-aws-terraform scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-terraform&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-terraform%3A0.0.10%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-terraform": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-aws-terraform:0.0.10"
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
    "acuvity-mcp-server-aws-terraform": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-terraform:0.0.10"
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
    "acuvity-mcp-server-aws-terraform": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-terraform:0.0.10"
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
    "acuvity-mcp-server-aws-terraform": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-terraform:0.0.10"
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
    "acuvity-mcp-server-aws-terraform": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-terraform:0.0.10"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-aws-terraform:0.0.10"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-aws-terraform:0.0.10`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-aws-terraform:0.0.10
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-terraform": {
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
    "acuvity-mcp-server-aws-terraform": {
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
helm show readme oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
```

From there your MCP server mcp-server-aws-terraform will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-terraform` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/charts/mcp-server-aws-terraform/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (6)
<details>
<summary>ExecuteTerraformCommand</summary>

**Description**:

```
Execute Terraform workflow commands against an AWS account.

    This tool runs Terraform commands (init, plan, validate, apply, destroy) in the
    specified working directory, with optional variables and region settings.

    Parameters:
        command: Terraform command to execute
        working_directory: Directory containing Terraform files
        variables: Terraform variables to pass
        aws_region: AWS region to use
        strip_ansi: Whether to strip ANSI color codes from output

    Returns:
        A TerraformExecutionResult object containing command output and status
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aws_region | any | AWS region to use | No
| command | string | Terraform command to execute | Yes
| strip_ansi | boolean | Whether to strip ANSI color codes from output | No
| variables | any | Terraform variables to pass | No
| working_directory | string | Directory containing Terraform files | Yes
</details>
<details>
<summary>SearchAwsProviderDocs</summary>

**Description**:

```
Search AWS provider documentation for resources and attributes.

    This tool searches the Terraform AWS provider documentation for information about
    a specific asset in the AWS Provider Documentation, assets can be either resources or data sources. It retrieves comprehensive details including descriptions, example code snippets, argument references, and attribute references.

    Use the 'asset_type' parameter to specify if you are looking for information about provider resources, data sources, or both. Valid values are 'resource', 'data_source' or 'both'.

    The tool will automatically handle prefixes - you can search for either 'aws_s3_bucket' or 's3_bucket'.

    Examples:
        - To get documentation for an S3 bucket resource:
          search_aws_provider_docs(asset_name='aws_s3_bucket')

        - To search only for data sources:
          search_aws_provider_docs(asset_name='aws_ami', asset_type='data_source')

        - To search for both resource and data source documentation of a given name:
          search_aws_provider_docs(asset_name='aws_instance', asset_type='both')

    Parameters:
        asset_name: Name of the service (asset) to look for (e.g., 'aws_s3_bucket', 'aws_lambda_function')
        asset_type: Type of documentation to search - 'resource' (default), 'data_source', or 'both'

    Returns:
        A list of matching documentation entries with details including:
        - Resource name and description
        - URL to the official documentation
        - Example code snippets
        - Arguments with descriptions
        - Attributes with descriptions
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| asset_name | string | Name of the AWS service (asset) to look for (e.g., "aws_s3_bucket", "aws_lambda_function") | Yes
| asset_type | string | Type of documentation to search - 'resource' (default), 'data_source', or 'both' | No
</details>
<details>
<summary>SearchAwsccProviderDocs</summary>

**Description**:

```
Search AWSCC provider documentation for resources and attributes.

    The AWSCC provider is based on the AWS Cloud Control API
    and provides a more consistent interface to AWS resources compared to the standard AWS provider.

    This tool searches the Terraform AWSCC provider documentation for information about
    a specific asset in the AWSCC Provider Documentation, assets can be either resources or data sources. It retrieves comprehensive details including descriptions, example code snippets, and schema references.

    Use the 'asset_type' parameter to specify if you are looking for information about provider resources, data sources, or both. Valid values are 'resource', 'data_source' or 'both'.

    The tool will automatically handle prefixes - you can search for either 'awscc_s3_bucket' or 's3_bucket'.

    Examples:
        - To get documentation for an S3 bucket resource:
          search_awscc_provider_docs(asset_name='awscc_s3_bucket')
          search_awscc_provider_docs(asset_name='awscc_s3_bucket', asset_type='resource')

        - To search only for data sources:
          search_aws_provider_docs(asset_name='awscc_appsync_api', kind='data_source')

        - To search for both resource and data source documentation of a given name:
          search_aws_provider_docs(asset_name='awscc_appsync_api', kind='both')

        - Search of a resource without the prefix:
          search_awscc_provider_docs(resource_type='ec2_instance')

    Parameters:
        asset_name: Name of the AWSCC Provider resource or data source to look for (e.g., 'awscc_s3_bucket', 'awscc_lambda_function')
        asset_type: Type of documentation to search - 'resource' (default), 'data_source', or 'both'. Some resources and data sources share the same name

    Returns:
        A list of matching documentation entries with details including:
        - Resource name and description
        - URL to the official documentation
        - Example code snippets
        - Schema information (required, optional, read-only, and nested structures attributes)
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| asset_name | string | Name of the AWSCC service (asset) to look for (e.g., awscc_s3_bucket, awscc_lambda_function) | Yes
| asset_type | string | Type of documentation to search - 'resource' (default), 'data_source', or 'both' | No
</details>
<details>
<summary>SearchSpecificAwsIaModules</summary>

**Description**:

```
Search for specific AWS-IA Terraform modules.

    This tool checks for information about four specific AWS-IA modules:
    - aws-ia/bedrock/aws - Amazon Bedrock module for generative AI applications
    - aws-ia/opensearch-serverless/aws - OpenSearch Serverless collection for vector search
    - aws-ia/sagemaker-endpoint/aws - SageMaker endpoint deployment module
    - aws-ia/serverless-streamlit-app/aws - Serverless Streamlit application deployment

    It returns detailed information about these modules, including their README content,
    variables.tf content, and submodules when available.

    The search is performed across module names, descriptions, README content, and variable
    definitions. This allows you to find modules based on their functionality or specific
    configuration options.

    Examples:
        - To get information about all four modules:
          search_specific_aws_ia_modules()

        - To find modules related to Bedrock:
          search_specific_aws_ia_modules(query='bedrock')

        - To find modules related to vector search:
          search_specific_aws_ia_modules(query='vector search')

        - To find modules with specific configuration options:
          search_specific_aws_ia_modules(query='endpoint_name')

    Parameters:
        query: Optional search term to filter modules (empty returns all four modules)

    Returns:
        A list of matching modules with their details, including:
        - Basic module information (name, namespace, version)
        - Module documentation (README content)
        - Input and output parameter counts
        - Variables from variables.tf with descriptions and default values
        - Submodules information
        - Version details and release information
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Optional search term to filter modules (empty returns all four modules) | Yes
</details>
<details>
<summary>RunCheckovScan</summary>

**Description**:

```
Run Checkov security scan on Terraform code.

    This tool runs Checkov to scan Terraform code for security and compliance issues,
    identifying potential vulnerabilities and misconfigurations according to best practices.

    Checkov (https://www.checkov.io/) is an open-source static code analysis tool that
    can detect hundreds of security and compliance issues in infrastructure-as-code.

    Parameters:
        working_directory: Directory containing Terraform files to scan
        framework: Framework to scan (default: terraform)
        check_ids: Optional list of specific check IDs to run
        skip_check_ids: Optional list of check IDs to skip
        output_format: Format for scan results (default: json)

    Returns:
        A CheckovScanResult object containing scan results and identified vulnerabilities
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| check_ids | any | Specific check IDs to run | No
| framework | string | Framework to scan (terraform, cloudformation, etc.) | No
| output_format | string | Output format (json, cli, etc.) | No
| skip_check_ids | any | Check IDs to skip | No
| working_directory | string | Directory containing Terraform files | Yes
</details>
<details>
<summary>SearchUserProvidedModule</summary>

**Description**:

```
Search for a user-provided Terraform registry module and understand its inputs, outputs, and usage.

    This tool takes a Terraform registry module URL and analyzes its input variables,
    output variables, README, and other details to provide comprehensive information
    about the module.

    The module URL should be in the format "namespace/name/provider" (e.g., "hashicorp/consul/aws")
    or "registry.terraform.io/namespace/name/provider".

    Examples:
        - To search for the HashiCorp Consul module:
          search_user_provided_module(module_url='hashicorp/consul/aws')

        - To search for a specific version of a module:
          search_user_provided_module(module_url='terraform-aws-modules/vpc/aws', version='3.14.0')

        - To search for a module with specific variables:
          search_user_provided_module(
              module_url='terraform-aws-modules/eks/aws',
              variables={'cluster_name': 'my-cluster', 'vpc_id': 'vpc-12345'}
          )

    Parameters:
        module_url: URL or identifier of the Terraform module (e.g., "hashicorp/consul/aws")
        version: Optional specific version of the module to analyze
        variables: Optional dictionary of variables to use when analyzing the module

    Returns:
        A SearchUserProvidedModuleResult object containing module information
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module_url | string | URL or identifier of the Terraform module (e.g., "hashicorp/consul/aws") | Yes
| variables | any | Variables to use when analyzing the module | No
| version | any | Specific version of the module to analyze | No
</details>

## 📚 Resources (4)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| terraform_development_workflow | text/markdown | terraform://development_workflow | - |
| terraform_aws_provider_resources_listing | text/markdown | terraform://aws_provider_resources_listing | - |
| terraform_awscc_provider_resources_listing | text/markdown | terraform://awscc_provider_resources_listing | - |
| terraform_aws_best_practices | text/markdown | terraform://aws_best_practices | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | ExecuteTerraformCommand | description | 8c3845a7a63a6506e3a1b5f28c035f2ee994019ce7d724a4a78416f17dc25579 |
| tools | ExecuteTerraformCommand | aws_region | 0ccf66d2fc46cf203d8a16166cf11d5b869a7b6e0141a3bfd1af40af5a993db0 |
| tools | ExecuteTerraformCommand | command | fb255919af61b9ed7dbbae1afe09e470cc27880f9a64b3f0406f025bc8c0a6a3 |
| tools | ExecuteTerraformCommand | strip_ansi | 4d24b273dd76107e594dee1d73736fb9e0dfd27a482acfa61217ec6b3bbd6e7f |
| tools | ExecuteTerraformCommand | variables | 956119b45b8389c2b16285de0e326f5ac6cb69f738c4894c0fb3866922d61778 |
| tools | ExecuteTerraformCommand | working_directory | b5bd542c9a74e4f7b692e0b7381f090f6d30c602eaed2b785cd88b549bb0b66c |
| tools | RunCheckovScan | description | c58423fbe608d95358d585d232cd4cfcebd6ffda6c0251197c5c9efd2165765d |
| tools | RunCheckovScan | check_ids | c49e44517c1f7c46d100e0d2295f6d3f464fcc4708f871b3c190ee9407097d5c |
| tools | RunCheckovScan | framework | f51b152c5a92795f8fb904076dff58728ec2538c6ba82134d76804aac04b1e23 |
| tools | RunCheckovScan | output_format | 39591504c5faee5903f2371b283f7b5263076eb3b5e7aaf3e0cb2de4e22cac38 |
| tools | RunCheckovScan | skip_check_ids | de51f984d953383f03ffe3b22944311cb67d58123f439aa16f49309909ba8b1a |
| tools | RunCheckovScan | working_directory | b5bd542c9a74e4f7b692e0b7381f090f6d30c602eaed2b785cd88b549bb0b66c |
| tools | SearchAwsProviderDocs | description | 6f58ea1dc0d7e5b9e21a1fc5460c7e159f7aeb9825b22fd15cbb9ac3232a6074 |
| tools | SearchAwsProviderDocs | asset_name | 842715d3f5b1c7a9b29b25dc2946e1686da9522b3b8287429fe229eacb819a53 |
| tools | SearchAwsProviderDocs | asset_type | c27eec0705d5c708f9f9d460f6173e1a3ae6bdc1d29d10e9f0601be2bf33f673 |
| tools | SearchAwsccProviderDocs | description | 8d836ae66622b0025bb1dc5863c180094b89d9598f6e676a2438c6754bce8c63 |
| tools | SearchAwsccProviderDocs | asset_name | e3e43b55a425ce426955afeb6f7ee5c8e41a77f1766846586eb735f3ae562b74 |
| tools | SearchAwsccProviderDocs | asset_type | c27eec0705d5c708f9f9d460f6173e1a3ae6bdc1d29d10e9f0601be2bf33f673 |
| tools | SearchSpecificAwsIaModules | description | 006c2d5da3e4dc9111b46a1333fad347d69374d883a677345177cacc4a782508 |
| tools | SearchSpecificAwsIaModules | query | c476dc6117aa072fd9825b1ad1f783905cefc2c580461d9b468ca35e3e1ffa26 |
| tools | SearchUserProvidedModule | description | 4fdcda060d11fefcce636d0cc247a7e76556ba027d30091952e1e943b0dca117 |
| tools | SearchUserProvidedModule | module_url | acbe1ae3097b59e6b325d5b3b6265d29a06d8388fba0fda1fb0aa38188805952 |
| tools | SearchUserProvidedModule | variables | 950fb140163783b1024dcb46068909da466c24546d8b0779a5c166b964d2cbaf |
| tools | SearchUserProvidedModule | version | 3356d37e0f2456c14c252e5d6a3e315c0f8d19e86f115c5d13962ea9dbe1e869 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
