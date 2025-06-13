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


# What is mcp-server-aws-ecs?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-ecs/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-ecs/0.1.3?logo=docker&logoColor=fff&label=0.1.3)](https://hub.docker.com/r/acuvity/mcp-server-aws-ecs)
[![PyPI](https://img.shields.io/badge/0.1.3-3775A9?logo=pypi&logoColor=fff&label=awslabs.ecs-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/ecs-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-ecs/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-ecs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-ecs%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AWS ECS containerization, deployment, troubleshooting, and infrastructure management

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.ecs-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/ecs-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-ecs/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs/charts/mcp-server-aws-ecs/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.ecs-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Amazon Web Services <aws-mcp-servers@amazon.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/ecs-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.ecs-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/ecs-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.ecs-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/ecs-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs/charts/mcp-server-aws-ecs)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.3`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-ecs:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-ecs:1.0.0-0.1.3`

---

# Table of Contents
- [Settings requirements](#chart-settings-requirements)
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

# Chart settings requirements

This chart requires some mandatory information to be installed.

**Optional Environment variables**:
  - `AWS_PROFILE=""` environment variable can be changed with `env.AWS_PROFILE=""`
  - `AWS_REGION=""` environment variable can be changed with `env.AWS_REGION=""`
  - `ALLOW_WRITE="false"` environment variable can be changed with `env.ALLOW_WRITE="false"`
  - `ALLOW_SENSITIVE_DATA="false"` environment variable can be changed with `env.ALLOW_SENSITIVE_DATA="false"`

# How to install


Install will helm

```console
helm install mcp-server-aws-ecs oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-ecs oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-ecs
```

From there your MCP server mcp-server-aws-ecs will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-ecs` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-ecs
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
  mcp-server-scope: remote
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-ecs` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-ecs oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-ecs oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-ecs oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-ecs oci://docker.io/acuvity/mcp-server-aws-ecs --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (6)
<details>
<summary>containerize_app</summary>

**Description**:

```

        Start here if a user wants to run their application locally or deploy an app to the cloud.
        Provides guidance for containerizing a web application.

        This tool provides guidance on how to build Docker images for web applications,
        including recommendations for base images, build tools, and architecture choices.

        USAGE INSTRUCTIONS:
        1. Run this tool to get guidance on how to configure your application for ECS.
        2. Follow the steps generated from the tool.
        3. Proceed to create_ecs_infrastructure tool.

        The guidance includes:
        - Example Dockerfile content
        - Example docker-compose.yml content
        - Build commands for different container tools
        - Architecture recommendations
        - Troubleshooting tips

        Parameters:
            app_path: Path to the web application directory
            port: Port the application listens on

        Returns:
            Dictionary containing containerization guidance
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_path | string | Absolute file path to the web application directory | Yes
| port | integer | Port the application listens on | Yes
</details>
<details>
<summary>create_ecs_infrastructure</summary>

**Description**:

```

        Creates ECS infrastructure using CloudFormation.

        This tool sets up the necessary AWS infrastructure for deploying applications to ECS.
        It creates or uses an existing VPC, sets up security groups, IAM roles, and configures
        the ECS cluster, task definitions, and services. Deployment is asynchronous, poll the
        get_deployment_status tool every 30 seconds after successful invocation of this.

        USAGE INSTRUCTIONS:
        1. Provide a name for your application
        2. Provide the path to your web application directory
        3. Decide whether to use force_deploy:
           - If False (default): Template files will be generated locally for your review
           - If True: Docker image will be built and pushed to ECR, and CloudFormation stacks
             will be deployed
           - ENSURE you get user permission to deploy and inform that this is only for
             non-production applications.
        4. If force_deploy is True, you can optionally specify a deployment_step:
           - Step 1: Create CFN files and deploy ECR to CloudFormation
           - Step 2: Build and deploy Docker image to ECR
           - Step 3: Deploy ECS infrastructure to CloudFormation
           - If no step is specified, all steps will be executed in sequence
        5. Optionally specify VPC and subnet IDs if you want to use existing resources
        6. Configure CPU, memory, and scaling options as needed

        The created infrastructure includes:
        - Security groups
        - IAM roles and policies
        - ECS cluster
        - Task definition template
        - Service configuration
        - Application Load Balancer

        Parameters:
            app_name: Name of the application
            app_path: Path to the web application directory
            force_deploy: Whether to build and deploy the infrastructure or just generate templates
            deployment_step: Which deployment step to execute (1, 2, or 3) when force_deploy is True
            vpc_id: VPC ID for deployment
            subnet_ids: List of subnet IDs for deployment
            route_table_ids: List of route table IDs for S3 Gateway endpoint association
            cpu: CPU units for the task (e.g., 256, 512, 1024)
            memory: Memory (MB) for the task (e.g., 512, 1024, 2048)
            desired_count: Desired number of tasks
            container_port: Port the container listens on
            health_check_path: Path for ALB health checks

        Returns:
            Dictionary containing infrastructure details or template paths
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_name | string | Name of the application | Yes
| app_path | string | Absolute file path to the web application directory | Yes
| container_port | any | Port the container listens on | No
| cpu | any | CPU units for the task (e.g., 256, 512, 1024) | No
| deployment_step | any | Which deployment step to execute (1, 2, or 3) when force_deploy is True. 1: Create CFN files and deploy ECR to CFN, 2: Build and deploy Docker image, 3: Deploy ECS to CFN. You must specify to use force-deploy and it must be done sequentially to prevent timeouts. | No
| desired_count | any | Desired number of tasks | No
| force_deploy | boolean | Set to True ONLY if you have Docker installed and running, and you agree to let the server build and deploy your image to ECR, as well as deploy ECS infrastructure for you in CloudFormation. If False, template files will be generated locally for your review. | No
| health_check_path | any | Path for ALB health checks | No
| memory | any | Memory (MB) for the task (e.g., 512, 1024, 2048) | No
| route_table_ids | any | not set | No
| subnet_ids | any | not set | No
| vpc_id | any | VPC ID for deployment (optional, will use default if not provided) | No
</details>
<details>
<summary>get_deployment_status</summary>

**Description**:

```

        Gets the status of an ECS deployment and returns the ALB URL.

        This tool checks the status of your ECS deployment and provides information
        about the service, tasks, and the Application Load Balancer URL for accessing
        your application.

        USAGE INSTRUCTIONS:
        1. Provide the name of your application
        2. Optionally specify the cluster name if different from the application name
        3. Optionally specify the stack name if different from the default naming convention
        4. Optionally specify the service name if different from the default naming pattern
        5. The tool will return the deployment status and access URL once the deployment
           is complete.

        Poll this tool every 30 seconds till the status is active.

        The status information includes:
        - Service status (active, draining, etc.)
        - Running task count
        - Desired task count
        - Application Load Balancer URL
        - Recent deployment events
        - Health check status
        - Custom domain and HTTPS setup guidance (when deployment is complete)

        Parameters:
            app_name: Name of the application
            cluster_name: Name of the ECS cluster (optional, defaults to app_name)
            stack_name: Name of the CloudFormation stack
                       (optional, defaults to {app_name}-ecs-infrastructure)
            service_name: Name of the ECS service (optional, defaults to {app_name}-service)

        Returns:
            Dictionary containing deployment status and ALB URL
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_name | string | Name of the application | Yes
| cluster_name | any | Name of the ECS cluster | No
| service_name | any | Name of the ECS service (optional, defaults to {app_name}-service) | No
| stack_name | any | Name of the CloudFormation stack (optional, defaults to {app_name}-ecs-infrastructure) | No
</details>
<details>
<summary>ecs_resource_management</summary>

**Description**:

```

        Read-only tool for managing ECS resources.

        This tool provides a consistent interface to list and describe various ECS resources.

        USAGE EXAMPLES:
        - List all clusters: ecs_resource_management("list", "cluster")
        - Describe a cluster: ecs_resource_management("describe", "cluster", "my-cluster")
        - List services in cluster: ecs_resource_management("list", "service",
          filters={"cluster": "my-cluster"})
        - List tasks by status: ecs_resource_management("list", "task",
          filters={"cluster": "my-cluster", "status": "RUNNING"})
        - Describe a task: ecs_resource_management("describe", "task", "task-id",
          filters={"cluster": "my-cluster"})
        - List task definitions: ecs_resource_management("list", "task_definition",
          filters={"family": "nginx"})
        - Describe a task definition: ecs_resource_management("describe", "task_definition",
          "family:revision")

        Parameters:
            action: Action to perform (list, describe)
            resource_type: Type of resource (cluster, service, task, task_definition,
                          container_instance, capacity_provider)
            identifier: Resource identifier (name or ARN) for describe actions (optional)
            filters: Filters for list operations (optional)

        Returns:
            Dictionary containing the requested ECS resources
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | Action to perform (list, describe) | Yes
| filters | any | not set | No
| identifier | any | not set | No
| resource_type | string | Type of resource (cluster, service, task, task_definition, container_instance, capacity_provider) | Yes
</details>
<details>
<summary>ecs_troubleshooting_tool</summary>

**Description**:

```

ECS troubleshooting tool with multiple diagnostic actions.

This tool provides access to all ECS troubleshooting operations through a single
interface. Use the 'action' parameter to specify which troubleshooting operation
to perform.

## Available Actions and Parameters:

### 1. get_ecs_troubleshooting_guidance
Initial assessment and data collection
- Required: app_name
- Optional: symptoms_description (Description of symptoms experienced by the user)
- Example: action="get_ecs_troubleshooting_guidance", parameters={"symptoms_description": "ALB returning 503 errors"}

### 2. fetch_cloudformation_status
Infrastructure-level diagnostics for CloudFormation stacks
- Required: stack_id
- Example: action="fetch_cloudformation_status", parameters={"stack_id": "my-app-stack"}

### 3. fetch_service_events
Service-level diagnostics for ECS services
- Required: app_name, cluster_name, service_name
- Optional: time_window (Time window in seconds to look back for events (default: 3600)), start_time (Explicit start time for the analysis window (UTC, takes precedence over time_window if provided)), end_time (Explicit end time for the analysis window (UTC, defaults to current time if not provided))
- Example: action="fetch_service_events", parameters={"cluster_name": "my-cluster", "service_name": "my-service", "time_window": 7200}

### 4. fetch_task_failures
Task-level diagnostics for ECS task failures
- Required: app_name, cluster_name
- Optional: time_window (Time window in seconds to look back for failures (default: 3600)), start_time (Explicit start time for the analysis window (UTC, takes precedence over time_window if provided)), end_time (Explicit end time for the analysis window (UTC, defaults to current time if not provided))
- Example: action="fetch_task_failures", parameters={"cluster_name": "my-cluster", "time_window": 3600}

### 5. fetch_task_logs
Application-level diagnostics through CloudWatch logs
- Required: app_name, cluster_name
- Optional: task_id (Specific task ID to retrieve logs for), time_window (Time window in seconds to look back for logs (default: 3600)), filter_pattern (CloudWatch logs filter pattern), start_time (Explicit start time for the analysis window (UTC, takes precedence over time_window if provided)), end_time (Explicit end time for the analysis window (UTC, defaults to current time if not provided))
- Example: action="fetch_task_logs", parameters={"cluster_name": "my-cluster", "filter_pattern": "ERROR", "time_window": 1800}

### 6. detect_image_pull_failures
Specialized tool for detecting container image pull failures
- Required: app_name
- Example: action="detect_image_pull_failures", parameters={}

### 7. fetch_network_configuration
Network-level diagnostics for ECS deployments
- Required: app_name
- Optional: vpc_id (Specific VPC ID to analyze), cluster_name (Specific ECS cluster name)
- Example: action="fetch_network_configuration", parameters={"vpc_id": "vpc-12345678", "cluster_name": "my-cluster"}

## Quick Usage Examples:

```
# Initial assessment and data collection
action: "get_ecs_troubleshooting_guidance"
parameters: {"symptoms_description": "ALB returning 503 errors"}

# Infrastructure-level diagnostics for CloudFormation stacks
action: "fetch_cloudformation_status"
parameters: {"stack_id": "my-app-stack"}

# Service-level diagnostics for ECS services
action: "fetch_service_events"
parameters: {"cluster_name": "my-cluster", "service_name": "my-service", "time_window": 7200}

# Task-level diagnostics for ECS task failures
action: "fetch_task_failures"
parameters: {"cluster_name": "my-cluster", "time_window": 3600}

# Application-level diagnostics through CloudWatch logs
action: "fetch_task_logs"
parameters: {"cluster_name": "my-cluster", "filter_pattern": "ERROR", "time_window": 1800}

# Specialized tool for detecting container image pull failures
action: "detect_image_pull_failures"
parameters: {}

# Network-level diagnostics for ECS deployments
action: "fetch_network_configuration"
parameters: {"vpc_id": "vpc-12345678", "cluster_name": "my-cluster"}
```

Parameters:
    app_name: Application/stack name (required for most actions)
    action: The troubleshooting action to perform (see available actions above)
    parameters: Action-specific parameters (see parameter specifications above)

Returns:
    Results from the selected troubleshooting action

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | not set | No
| app_name | any | not set | No
| parameters | any | not set | No
</details>
<details>
<summary>delete_ecs_infrastructure</summary>

**Description**:

```

        Deletes ECS infrastructure created by the ECS MCP Server.

        WARNING: This tool is not intended for production usage and is best suited for
        tearing down prototyped work done with the ECS MCP Server.

        This tool attempts to identify and delete CloudFormation stacks based on the
        provided app name and template files. It will scan the user's CloudFormation stacks,
        using the app name as a heuristic, and identify if the templates match the files
        provided in the input. It will only attempt to delete stacks if they are found and
        match the provided templates.

        USAGE INSTRUCTIONS:
        1. Provide the name of your application
        2. Provide paths to the ECR and ECS CloudFormation template files
           - Templates will be compared to ensure they match the deployed stacks
        3. The tool will attempt to delete the stacks in the correct order (ECS first, then ECR)

        IMPORTANT:
        - This is a best-effort deletion
        - If a stack is in a transitional state (e.g., CREATE_IN_PROGRESS), it will be skipped
        - You may need to manually delete resources if the deletion fails

        Parameters:
            app_name: Name of the application
            ecr_template_path: Path to the ECR CloudFormation template file
            ecs_template_path: Path to the ECS CloudFormation template file

        Returns:
            Dictionary containing deletion results and guidance
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_name | string | Name of the application | Yes
| ecr_template_path | string | Path to the ECR CloudFormation template file | Yes
| ecs_template_path | string | Path to the ECS CloudFormation template file | Yes
</details>

## 📝 Prompts (82)
<details>
<summary>dockerize</summary>

**Description**:

```
User wants to containerize an application
```
<details>
<summary>containerize</summary>

**Description**:

```
User wants to containerize an application
```
<details>
<summary>docker container</summary>

**Description**:

```
User wants to create a Docker container
```
<details>
<summary>put in container</summary>

**Description**:

```
User wants to containerize an application
```
<details>
<summary>containerize and deploy</summary>

**Description**:

```
User wants to containerize and deploy an application
```
<details>
<summary>docker and deploy</summary>

**Description**:

```
User wants to containerize and deploy an application
```
<details>
<summary>deploy to aws</summary>

**Description**:

```
User wants to deploy an application to AWS
```
<details>
<summary>deploy to cloud</summary>

**Description**:

```
User wants to deploy an application to the cloud
```
<details>
<summary>deploy to ecs</summary>

**Description**:

```
User wants to deploy an application to AWS ECS
```
<details>
<summary>ship to cloud</summary>

**Description**:

```
User wants to deploy an application to the cloud
```
<details>
<summary>put on the web</summary>

**Description**:

```
User wants to make an application accessible online
```
<details>
<summary>host online</summary>

**Description**:

```
User wants to host an application online
```
<details>
<summary>make live</summary>

**Description**:

```
User wants to make an application live
```
<details>
<summary>launch online</summary>

**Description**:

```
User wants to launch an application online
```
<details>
<summary>get running on the web</summary>

**Description**:

```
User wants to make an application accessible on the web
```
<details>
<summary>make accessible</summary>

**Description**:

```
User wants to make an application accessible online
```
<details>
<summary>ship it</summary>

**Description**:

```
User wants to ship/deploy their application
```
<details>
<summary>deploy flask</summary>

**Description**:

```
User wants to deploy a Flask application
```
<details>
<summary>deploy django</summary>

**Description**:

```
User wants to deploy a Django application
```
<details>
<summary>deploy react</summary>

**Description**:

```
User wants to deploy a React application
```
<details>
<summary>deploy express</summary>

**Description**:

```
User wants to deploy an Express.js application
```
<details>
<summary>deploy node</summary>

**Description**:

```
User wants to deploy a Node.js application
```
<details>
<summary>push to prod</summary>

**Description**:

```
User wants to deploy an application to production
```
<details>
<summary>get this online</summary>

**Description**:

```
User wants to make an application accessible online
```
<details>
<summary>make this public</summary>

**Description**:

```
User wants to make an application publicly accessible
```
<details>
<summary>put this on aws</summary>

**Description**:

```
User wants to deploy an application to AWS
```
<details>
<summary>can people access this</summary>

**Description**:

```
User wants to make an application accessible to others
```
<details>
<summary>how do i share this app</summary>

**Description**:

```
User wants to make an application accessible to others
```
<details>
<summary>make accessible online</summary>

**Description**:

```
User wants to make an application accessible online
```
<details>
<summary>list ecs resources</summary>

**Description**:

```
User wants to list ECS resources
```
<details>
<summary>show ecs clusters</summary>

**Description**:

```
User wants to see ECS clusters
```
<details>
<summary>describe ecs service</summary>

**Description**:

```
User wants to describe an ECS service
```
<details>
<summary>view ecs tasks</summary>

**Description**:

```
User wants to view ECS tasks
```
<details>
<summary>check task definitions</summary>

**Description**:

```
User wants to check ECS task definitions
```
<details>
<summary>show running containers</summary>

**Description**:

```
User wants to see running containers in ECS
```
<details>
<summary>view ecs resources</summary>

**Description**:

```
User wants to view ECS resources
```
<details>
<summary>inspect ecs</summary>

**Description**:

```
User wants to inspect ECS resources
```
<details>
<summary>check ecs status</summary>

**Description**:

```
User wants to check ECS status
```
<details>
<summary>troubleshoot ecs</summary>

**Description**:

```
General ECS troubleshooting
```
<details>
<summary>ecs deployment failed</summary>

**Description**:

```
General ECS troubleshooting
```
<details>
<summary>diagnose ecs</summary>

**Description**:

```
General ECS troubleshooting
```
<details>
<summary>fix ecs deployment</summary>

**Description**:

```
General ECS troubleshooting
```
<details>
<summary>help debug ecs</summary>

**Description**:

```
General ECS troubleshooting
```
<details>
<summary>ecs tasks failing</summary>

**Description**:

```
Task and container issues
```
<details>
<summary>container is failing</summary>

**Description**:

```
Task and container issues
```
<details>
<summary>service is failing</summary>

**Description**:

```
Task and container issues
```
<details>
<summary>cloudformation stack failed</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>stack .* is broken</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>fix .* stack</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>failed stack .*</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>stack .* failed</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>.*-stack.* is broken</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>.*-stack.* failed</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>help me fix .*-stack.*</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>why did my stack fail</summary>

**Description**:

```
Infrastructure issues
```
<details>
<summary>image pull failure</summary>

**Description**:

```
Image pull failures
```
<details>
<summary>container image not found</summary>

**Description**:

```
Image pull failures
```
<details>
<summary>imagepullbackoff</summary>

**Description**:

```
Image pull failures
```
<details>
<summary>can't pull image</summary>

**Description**:

```
Image pull failures
```
<details>
<summary>invalid container image</summary>

**Description**:

```
Image pull failures
```
<details>
<summary>network issues</summary>

**Description**:

```
Network and connectivity
```
<details>
<summary>security group issues</summary>

**Description**:

```
Network and connectivity
```
<details>
<summary>connectivity issues</summary>

**Description**:

```
Network and connectivity
```
<details>
<summary>unable to connect</summary>

**Description**:

```
Network and connectivity
```
<details>
<summary>service unreachable</summary>

**Description**:

```
Network and connectivity
```
<details>
<summary>alb not working</summary>

**Description**:

```
Load balancer issues
```
<details>
<summary>load balancer not working</summary>

**Description**:

```
Load balancer issues
```
<details>
<summary>alb url not working</summary>

**Description**:

```
Load balancer issues
```
<details>
<summary>healthcheck failing</summary>

**Description**:

```
Load balancer issues
```
<details>
<summary>target group</summary>

**Description**:

```
Load balancer issues
```
<details>
<summary>404 not found</summary>

**Description**:

```
Load balancer issues
```
<details>
<summary>check ecs logs</summary>

**Description**:

```
Logs and monitoring
```
<details>
<summary>ecs service events</summary>

**Description**:

```
Logs and monitoring
```
<details>
<summary>fix my deployment</summary>

**Description**:

```
Generic deployment issues
```
<details>
<summary>deployment issues</summary>

**Description**:

```
Generic deployment issues
```
<details>
<summary>what's wrong with my stack</summary>

**Description**:

```
Generic deployment issues
```
<details>
<summary>deployment is broken</summary>

**Description**:

```
Generic deployment issues
```
<details>
<summary>app won't deploy</summary>

**Description**:

```
Generic deployment issues
```
<details>
<summary>delete infrastructure</summary>

**Description**:

```
User wants to delete an application infrastructure
```
<details>
<summary>tear down</summary>

**Description**:

```
User wants to tear down infrastructure
```
<details>
<summary>remove deployment</summary>

**Description**:

```
User wants to remove a deployment
```
<details>
<summary>clean up resources</summary>

**Description**:

```
User wants to clean up resources
```

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | .*-stack.* failed | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | .*-stack.* is broken | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | 404 not found | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | alb not working | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | alb url not working | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | app won't deploy | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | can people access this | description | 81ff4948b0cce5f488f22b33835aad6b52c3e221177aa9bc69ffa042664010a0 |
| prompts | can't pull image | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | check ecs logs | description | 72fdfe28113f3e81047e188026823f35e6920706914948b367edfd795e23a829 |
| prompts | check ecs status | description | 2d50a6cba97069d288b19b538f055fd2c2893009a6532222b2611404029a658a |
| prompts | check task definitions | description | 88e93d02a8108757653c728933d6e637e678470b74981a16a148708d6dc8af31 |
| prompts | clean up resources | description | 56e580282c804ac316910d39cee5c92185293d994c89ca0e55003f78f610391b |
| prompts | cloudformation stack failed | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | connectivity issues | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | container image not found | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | container is failing | description | 7e9bb5995853bb071e24f679cdcea399946d28a4310af262c21360bd87929e6a |
| prompts | containerize | description | a03d09027d5ef42564851708b2f9269045a34a46abf6642f4abb8c2df9b399e3 |
| prompts | containerize and deploy | description | cb69d96c13a9f9a567972b926364b616c11255c6a0ed94f8134acd8b98043e8d |
| prompts | delete infrastructure | description | 622b3cf659a29ffe7edfb69b80300316a24f9b9a6f645b5ae274c6d6fdd368e1 |
| prompts | deploy django | description | 906366a045d5e9b9f097c8fcd8430493c83b98c2ae7683d97a3931150510b67c |
| prompts | deploy express | description | 96c7136cead6baf5ca5631deba59a37be28b7829233eec6bf106b307644882a8 |
| prompts | deploy flask | description | e3d20dd75b2234877c2fe79e6ba03dc49a2448500e9433d11c92d1f1b67aff0c |
| prompts | deploy node | description | daf6ce09ed310758cabafe71d97762416f3e14d06e100b354371f1319f42092d |
| prompts | deploy react | description | bf4d082206c91a42fc02f833b4b566debbf40ce33cd0e87fdd5656fb4a323424 |
| prompts | deploy to aws | description | 112384f2d0a7dc6723560c0b2ddfd9f9fefbf0bad2f41de679b4089636c08615 |
| prompts | deploy to cloud | description | 7d87b1717bb21ccd0cd9ca725d3be94f8408a76086801ef3621fdf1c4a20d47c |
| prompts | deploy to ecs | description | 0f6e7c2ac59690322aae219188b270efb5bef9863d4d97e03c24694b546a4d1f |
| prompts | deployment is broken | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | deployment issues | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | describe ecs service | description | 2965ce2311cb119c91bea49b346dc7b39a4bce041b5dadc79cc9bed395bc0e31 |
| prompts | diagnose ecs | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | docker and deploy | description | cb69d96c13a9f9a567972b926364b616c11255c6a0ed94f8134acd8b98043e8d |
| prompts | docker container | description | 9a0df1a402671d529a3f61e788549fee140fc94ce9077384bc5353d0dd735d9f |
| prompts | dockerize | description | a03d09027d5ef42564851708b2f9269045a34a46abf6642f4abb8c2df9b399e3 |
| prompts | ecs deployment failed | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | ecs service events | description | 72fdfe28113f3e81047e188026823f35e6920706914948b367edfd795e23a829 |
| prompts | ecs tasks failing | description | 7e9bb5995853bb071e24f679cdcea399946d28a4310af262c21360bd87929e6a |
| prompts | failed stack .* | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | fix .* stack | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | fix ecs deployment | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | fix my deployment | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | get running on the web | description | a0b6d4fddf8c2763ab45af9c5a02afeb359b5d97047a31aff4fd1e2d16a3cee6 |
| prompts | get this online | description | 74eb6883990e4441541c9282385a30924c3ea9d1a739d53f15f1f2e3fc753f68 |
| prompts | healthcheck failing | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | help debug ecs | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | help me fix .*-stack.* | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | host online | description | cf8fe4efbbaf65a8353632eca62d92fccf5ed2ed2cf01029457b6c8e9405a95a |
| prompts | how do i share this app | description | 81ff4948b0cce5f488f22b33835aad6b52c3e221177aa9bc69ffa042664010a0 |
| prompts | image pull failure | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | imagepullbackoff | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | inspect ecs | description | 9b75d1fb0df4fdd4ff60fe28c5a5dd034404cf6f47428cc7293d28643c242fb5 |
| prompts | invalid container image | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | launch online | description | ad16ec4b2de83757817199dbca20f6541d6e2139ddb6158be66db1aa786c9c59 |
| prompts | list ecs resources | description | 3b41f15cf09abe76e368449ce4fbdc29c8371a79c2b727e11b49848d5e86f9e9 |
| prompts | load balancer not working | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | make accessible | description | 74eb6883990e4441541c9282385a30924c3ea9d1a739d53f15f1f2e3fc753f68 |
| prompts | make accessible online | description | 74eb6883990e4441541c9282385a30924c3ea9d1a739d53f15f1f2e3fc753f68 |
| prompts | make live | description | 7755eca68e4713a2c46074ec8245c769ee94396a2016cbe53085cabb3d9abae6 |
| prompts | make this public | description | abf744498929feff47b3cbaa37523a75eba991d520001f089ad392ea94c7e716 |
| prompts | network issues | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | push to prod | description | 58b904c57847d2832f59e33352d1811de8a81af7c47cd9fd80ba5b33ce735959 |
| prompts | put in container | description | a03d09027d5ef42564851708b2f9269045a34a46abf6642f4abb8c2df9b399e3 |
| prompts | put on the web | description | 74eb6883990e4441541c9282385a30924c3ea9d1a739d53f15f1f2e3fc753f68 |
| prompts | put this on aws | description | 112384f2d0a7dc6723560c0b2ddfd9f9fefbf0bad2f41de679b4089636c08615 |
| prompts | remove deployment | description | 5803516174acf5d8a31ed304a6efc3b178a9279bf5dc00e744e1a2b52b8de7f6 |
| prompts | security group issues | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | service is failing | description | 7e9bb5995853bb071e24f679cdcea399946d28a4310af262c21360bd87929e6a |
| prompts | service unreachable | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | ship it | description | bf94e8edab367a9daaeb42216ab94923a657bcaaa6c412796b05bd52ccfa7342 |
| prompts | ship to cloud | description | 7d87b1717bb21ccd0cd9ca725d3be94f8408a76086801ef3621fdf1c4a20d47c |
| prompts | show ecs clusters | description | 166cad6ec4d926be94c31a5d36bc1fc93f55bcdcb17c29c45b0c88edd9c5c825 |
| prompts | show running containers | description | cfc9cefd73c710e5f1933bb14e69ef7c727d6b7f13af4713a4d96c06c7116d8b |
| prompts | stack .* failed | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | stack .* is broken | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | target group | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | tear down | description | c4f4599d9953e35dda54eca34cf54be049cbd1f70a3fc603cef03ab1700f6de1 |
| prompts | troubleshoot ecs | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | unable to connect | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | view ecs resources | description | dfa2c585eba6b6ccb27b27fd02bb12f3b101abf250292812d2a1455ac805a062 |
| prompts | view ecs tasks | description | e487d44ce8fa736f7a2a07c2d708347ca2357ac9ddf1998baa41392ff9946408 |
| prompts | what's wrong with my stack | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | why did my stack fail | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| tools | containerize_app | description | 1a74b55bc00de9667e8787e7bf07faaf31f8123e5f97a40c3e25b8d65eb078a0 |
| tools | containerize_app | app_path | 991a3ebc1e0d5c019f0e13bc75e03597e2f308c6c5e4248935f2a1259c32cf68 |
| tools | containerize_app | port | 21a97d5899ad4e28bb02bdd42de1a36459a77b75c4b6dbb84bedb9c5d6f75bb7 |
| tools | create_ecs_infrastructure | description | 4544f0e794481e25fe7bd0dd32bbbf53c8d26660591ca028dd5221c17708d4e5 |
| tools | create_ecs_infrastructure | app_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | create_ecs_infrastructure | app_path | 991a3ebc1e0d5c019f0e13bc75e03597e2f308c6c5e4248935f2a1259c32cf68 |
| tools | create_ecs_infrastructure | container_port | 449455aab20d2e3c11a9a539ea356f110aa7597aaf7f356fb24e80d553a224e0 |
| tools | create_ecs_infrastructure | cpu | 9216971c2d432760f097c89ba17e408ecfaff3ea02c37c5a85929a1022c7ef48 |
| tools | create_ecs_infrastructure | deployment_step | bd45c0595c2d60e459cc75c413f8bdd86581da4d1b345f4bcfb9eeaa392905c0 |
| tools | create_ecs_infrastructure | desired_count | c3ed70eabf8c5aaf771e5580fbf164f13bc2441501b1137471f57a32d7511db7 |
| tools | create_ecs_infrastructure | force_deploy | 1f180931fbdac7db25a3b3b86f4a2e4d14843b5f14a30b3ddb4080a7da2c17e9 |
| tools | create_ecs_infrastructure | health_check_path | d6f7b6447b521862f76823017f4a8e03ca0a94c8fcdf4dd7e9938050c90aee75 |
| tools | create_ecs_infrastructure | memory | 93c3d58426f5b3f77594c81fcf85914a9e6870514334fea641926a7acb47af92 |
| tools | create_ecs_infrastructure | vpc_id | 6ad09bec5420b20bd585287c65949489a3fc8a37842e5b9863740c1947bb0732 |
| tools | delete_ecs_infrastructure | description | bd08eaa199ebb5406d91d5c229c124ead3725256966622e9b0c9f9efa7680cc4 |
| tools | delete_ecs_infrastructure | app_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | delete_ecs_infrastructure | ecr_template_path | fcbeb3eb3e2b24250b6b46b568949ac91025c86ce9af6ecad59a46fd33f7be7c |
| tools | delete_ecs_infrastructure | ecs_template_path | 2e203cd163e0c36cdb55740996d91c9432793dfd6ea3443f8435d1926de7263b |
| tools | ecs_resource_management | description | 9fe8fc3d1fb347b62bf7b2b9b9abe4af1551925ac91daa2fa9d2f498021667d4 |
| tools | ecs_resource_management | action | 5f035549da23ec95e9d31b8853b7ddc2b00cef9538e96bbde10dca6cd7f4bfa8 |
| tools | ecs_resource_management | resource_type | 47ee9e7e88f3a9220103cbb91c32ba1d2ea5b916eff70e07bb0ff3d0b7397b69 |
| tools | ecs_troubleshooting_tool | description | 4f06fa93abd2e80a3094672cea5c5e48fdd15faca70712a346bb0641377fdb93 |
| tools | get_deployment_status | description | acc8925b2df8853fc2ae89e706c55b6a158d7e3cebbca82570b6d53d8e0ead88 |
| tools | get_deployment_status | app_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | get_deployment_status | cluster_name | 8e2dd7b1c9a70c0173b34cf3834ed43938f843d4b4feda01c2298c5e86e6d613 |
| tools | get_deployment_status | service_name | d1b94d733903d0dd3aa973b87ea01f350d7b5f29720c34aa5e80b81e0280c2f0 |
| tools | get_deployment_status | stack_name | 5720ac7b47a7118008a5d8ab8c062b32d85ae93a596f3ec09eb8fcbc43d877bb |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
