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
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-terraform/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-terraform/1.0.1?logo=docker&logoColor=fff&label=1.0.1)](https://hub.docker.com/r/acuvity/mcp-server-aws-terraform)
[![PyPI](https://img.shields.io/badge/1.0.1-3775A9?logo=pypi&logoColor=fff&label=awslabs.terraform-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/terraform-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-terraform/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-terraform&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-terraform%3A1.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Terraform on AWS best practices, infrastructure as code patterns, and security compliance

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.terraform-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/terraform-mcp-server).

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


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Author ](https://github.com/awslabs/mcp/tree/HEAD/src/terraform-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.terraform-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/terraform-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.terraform-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/terraform-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/charts/mcp-server-aws-terraform)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-terraform/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-terraform:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-terraform:1.0.0-1.0.1`

---

# Table of Contents
- [How to install](#how-to-install)
- [Replica Set Configuration](#replica-set-configuration)
- [Chart Name Overrides](#chart-name-overrides)
- [Image Configuration](#image-configuration)
- [Image Pull Secrets](#image-pull-secrets)
- [Container Arguments](#container-arguments)
- [Service Account](#service-account)
- [Annotations and Labels](#annotations-and-labels)
- [Security Contexts](#security-contexts)
- [Service Configuration](#service-configuration)
- [Ingress Configuration](#ingress-configuration)
- [Resource Requests and Limits](#resource-requests-and-limits)
- [Probes](#probes)
- [Autoscaling](#autoscaling)
- [Volumes and Storage](#volumes-and-storage)
- [Placement and Scheduling](#placement-and-scheduling)
- [Minibridge](#minibridge)

---

# How to install


Install will helm

```console
helm install mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-terraform
```

From there your MCP server mcp-server-aws-terraform will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-terraform` on port `8000` by default.


# Configuration through value file

## Replica Set Configuration

```yaml
replicaCount: 1
```

Controls how many pod replicas the ReplicaSet (or Deployment) will maintain.
- **replicaCount**: integer number of desired pods.


## Chart Name Overrides

```yaml
nameOverride: ""
fullnameOverride: ""
```

Allows you to override default naming:
- **nameOverride**: replaces chart name in resource names.
- **fullnameOverride**: replaces the full generated name (including release) for all resources.


## Image Configuration

```yaml
image:
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-terraform
  pullPolicy: IfNotPresent
  tag: ""
```

Defines the container image to deploy:
- **repository**: Docker registry plus image name.
- **pullPolicy**: when Kubernetes should pull the image (`Always`, `IfNotPresent`, etc.).
- **tag**: image tag; defaults to the chart’s `appVersion` if left empty.


## Image Pull Secrets

```yaml
imagePullSecrets: []
```

List of Kubernetes Secret names for authenticating to private image registries. If your image is in a private repo, add its pull‑secret here.


## Container Arguments

```yaml
args: []
```

Passes arbitrary command‑line arguments into the container. This will override the default arguments set in the container.


## Service Account

```yaml
serviceAccount:
  create: true
  automount: true
  annotations: {}
  name: ""
```

Configures the Kubernetes ServiceAccount used by the pods:
- **create**: whether to create a new ServiceAccount.
- **automount**: automatically mount its token into pods.
- **annotations**: add metadata to the ServiceAccount.
- **name**: explicit name; when empty and `create: true`, a name is generated.


## Annotations and Labels

```yaml
podAnnotations: {}

podLabels:
  app.kubernetes.io/component: mcp-server
  mcp-server-scope: native
```

- **podAnnotations**: free‑form key/value map of Kubernetes annotations attached to each Pod.
- **podLabels**: key/value labels applied to each Pod; used for selection, organization, and tooling.


## Security Contexts

```yaml
podSecurityContext: {}

securityContext:
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1001
```

Controls Linux security settings for the Pod and containers:
- **podSecurityContext**: settings applied at the Pod level (UID/GID, fsGroup, etc.).
- **securityContext** (container‑level):
  - **capabilities.drop**: drop Linux capabilities for isolation.
  - **readOnlyRootFilesystem**: prevent writes to root.
  - **runAsNonRoot**: require non‑root user.
  - **runAsUser**: UID under which the container runs.


## Service Configuration

```yaml
service:
  type: ClusterIP
  port: 8000
  healthPort: 8080
  sessionAffinity:
    sessionAffinity: ClientIP
    sessionAffinityConfig:
      clientIP:
        timeoutSeconds: 600
```

Defines the Kubernetes Service to front your pods:
- **type**: `ClusterIP`, `NodePort`, `LoadBalancer`, etc.
- **port**: primary service port.
- **healthPort**: port used by health checks.
- **sessionAffinity**: stick client IPs to the same Pod for long‑lived connections; **timeoutSeconds** controls session duration.


## Resource Requests and Limits

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  # limits:
  #   cpu: 100m
  #   memory: 128Mi
```

Specifies compute resource guarantees and caps:
- **requests**: minimum CPU/memory Kubernetes will reserve.
- **limits** (commented out by default): maximum CPU/memory the container may use.

## Probes

```yaml
livenessProbe:
  httpGet:
    path: /
    port: health
readinessProbe:
  httpGet:
    path: /
    port: health
```

Defines health checks:
- **livenessProbe**: when to restart a failed container.
- **readinessProbe**: when the Pod is ready to receive traffic.

Both use an HTTP GET on the `health` port.

## Autoscaling

```yaml
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 100
  targetCPUUtilizationPercentage: 80
  # targetMemoryUtilizationPercentage: 80
```

Enables a HorizontalPodAutoscaler:
- **enabled**: toggle autoscaling.
- **minReplicas**, **maxReplicas**: bounds on replicas.
- **targetCPUUtilizationPercentage**: CPU usage threshold to scale.
- **targetMemoryUtilizationPercentage**: (optional) memory threshold.

## Volumes and Storage

```yaml
volumes: []
volumeMounts: []
storage:
```

Configures additional volumes and persistent storage:
- **volumes**: arbitrary Kubernetes `volume` entries to attach.
- **volumeMounts**: mount points inside containers.
- **storage**: iterates `package.storage` entries:
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-terraform` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

## Placement and Scheduling

```yaml
nodeSelector: {}
tolerations: []
affinity: {}
```

Controls Pod scheduling to nodes:
- **nodeSelector**: simple key/value match to select nodes.
- **tolerations**: allow Pods to schedule onto tainted nodes.
- **affinity**: advanced rules (node or Pod affinity/anti‑affinity).

## Minibridge

```yaml
## Minibridge section
#
#
minibridge:
  # minibridge mode
  # set to http, is a brige http/see to sdio, compatible with MCP protocol 2025-03-26 and 2024-11-05
  # set to websocket is websocket to stdio, you will need minibridge on the client side.
  mode: http

  # Log level
  log:
    level: info

  # Tracing
  tracing:
    # Set your OTEL endpoint HOST:port to enable tracing
    url:

  # TLS configuration
  tls:
    # To enable TLS
    enabled: false
    # [Required] Path to the server certificate when TLS is enabled
    cert:
      # raw value of certificate b64 encoded
      value:
      # path from existing volume mount
      path:
    # [Required] Path to the private key for the certificate when TLS is enabled
    key:
      # raw value of certificate b64 encoded
      value:
      # path from existing volume mount
      path:
    # [Optional] Passphrase for the certificate private key
    pass:
      # raw value, will be stored as a secret
      value:
      # value from an existing secret
      valueFrom:
        name:
        key:

    # [Optional] MTLS configuration to verify client certificates when TLS is enabled
    clientCA:
      # raw value of certificate b64 encoded
      value:
      # path from existing volume mount
      path:

  # SBOM, to disable set it to false
  sbom: true

  # guardrails to enable (list)
  # default none
  guardrails: []
  # - covert-instruction-detection
  # - sensitive-pattern-detection
  # - shadowing-pattern-detection
  # - schema-misuse-prevention
  # - cross-origin-tool-access
  # - secrets-redaction


  # basic auth from the default policy
  # if not set no auth will be enforced
  basicAuth:
    # raw value, will be stored as secret
    value:
    # value form an existing secret
    valueFrom:
      name:
      key:

  # Policier configuration
  policer:
    # Instruct to enforce policies if enabled
    # otherwise it will jsut log the verdict as a warning
    # message in logs
    enforce: true
    # Use the rego policer (Default)
    rego:
      # To enabled the rego policer
      enabled: true
      # path to the default policy
      policy: /policy.rego

    # Use the remote http policer
    http:
      # To enable the http policer
      enabled: false
      # Address of a Policer to send the traffic to for authentication and/or analysis
      url:
      # Token to use to authenticate against the Policer
      token:
        # raw value, will be stored as a secret
        value:
        # value from an existing secret
        valueFrom:
          name:
          key:
      # CA to trust Policer server certificates
      ca:
        # raw value of certificate b64 encoded
        value:
        # path from existing volume mount
        path:
      # Do not validate Policer CA. Do not do this in production
      # insecure: true
```

To enable guardrails you can set `minibridge.guardrails` list as:

```console
helm upgrade mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
```

or from a `values.yaml` file:

```yaml
minibridge:
  guardrails:
  - covert-instruction-detection
  - sensitive-pattern-detection
  - shadowing-pattern-detection
  - schema-misuse-prevention
  - cross-origin-tool-access
  - secrets-redaction
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-terraform oci://docker.io/acuvity/mcp-server-aws-terraform --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (7)
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
<summary>ExecuteTerragruntCommand</summary>

**Description**:

```
Execute Terragrunt workflow commands against an AWS account.

    This tool runs Terragrunt commands (init, plan, validate, apply, destroy, run-all) in the
    specified working directory, with optional variables and region settings. Terragrunt extends
    Terraform's functionality by providing features like remote state management, dependencies
    between modules, and the ability to execute Terraform commands on multiple modules at once.

    Parameters:
        command: Terragrunt command to execute
        working_directory: Directory containing Terragrunt files
        variables: Terraform variables to pass
        aws_region: AWS region to use
        strip_ansi: Whether to strip ANSI color codes from output
        include_dirs: Directories to include in a multi-module run
        exclude_dirs: Directories to exclude from a multi-module run
        run_all: Run command on all modules in subdirectories
        terragrunt_config: Path to a custom terragrunt config file (not valid with run-all)

    Returns:
        A TerragruntExecutionResult object containing command output and status
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aws_region | any | AWS region to use | No
| command | string | Terragrunt command to execute | Yes
| exclude_dirs | any | Directories to exclude from a multi-module run | No
| include_dirs | any | Directories to include in a multi-module run | No
| run_all | boolean | Run command on all modules in subdirectories | No
| strip_ansi | boolean | Whether to strip ANSI color codes from output | No
| terragrunt_config | any | Path to a custom terragrunt config file (not valid with run-all) | No
| variables | any | Terraform variables to pass | No
| working_directory | string | Directory containing Terragrunt files | Yes
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
| tools | ExecuteTerragruntCommand | description | f2c99bc47f44bcf9a2ea738e4352260d8758271a1ef769aae768c7bdeb2ec3ce |
| tools | ExecuteTerragruntCommand | aws_region | 0ccf66d2fc46cf203d8a16166cf11d5b869a7b6e0141a3bfd1af40af5a993db0 |
| tools | ExecuteTerragruntCommand | command | c545767beb786dbad5a00c48168a9cf85786857d093dbb85f3cbf31f13b0ea2a |
| tools | ExecuteTerragruntCommand | exclude_dirs | 07e52d7df95061ae2394adc309ffa860a8172b79f37e0c2bc423ffc8b9db85e0 |
| tools | ExecuteTerragruntCommand | include_dirs | 276838d7eabc574bd7d36a9d5ffff860e70155a0af378edba804e92ddbb39b54 |
| tools | ExecuteTerragruntCommand | run_all | dca5c811290e7195d468fdc563bf8d57e19a9d5fd3c4f5a647ac07102df31cd2 |
| tools | ExecuteTerragruntCommand | strip_ansi | 4d24b273dd76107e594dee1d73736fb9e0dfd27a482acfa61217ec6b3bbd6e7f |
| tools | ExecuteTerragruntCommand | terragrunt_config | e5e1a01aed9a923ccb79fe4f73fde5ca2e5357b5c5982f91dcd2a50bd6230fcb |
| tools | ExecuteTerragruntCommand | variables | 956119b45b8389c2b16285de0e326f5ac6cb69f738c4894c0fb3866922d61778 |
| tools | ExecuteTerragruntCommand | working_directory | 9f14e71b99500b01e574c27134fe1b834c0a174175835bac4dceea44b715aa25 |
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
