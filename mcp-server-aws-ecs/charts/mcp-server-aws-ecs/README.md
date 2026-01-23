<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://acuvity.ai/wp-content/uploads/2025/09/1.-Acuvity-Logo-Black-scaled-e1758135197226.png" height="90" alt="Acuvity logo"/>
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
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-ecs/0.1.23?logo=docker&logoColor=fff&label=0.1.23)](https://hub.docker.com/r/acuvity/mcp-server-aws-ecs)
[![PyPI](https://img.shields.io/badge/0.1.23-3775A9?logo=pypi&logoColor=fff&label=awslabs.ecs-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/ecs-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-ecs/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-ecs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-ecs%3A0.1.23%22%5D%2C%22command%22%3A%22docker%22%7D)

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

### 📦 Isolated Immutable Sandbox

| Feature                   | Description                                                                                                            |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| Isolated Execution        | All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.         |
| Non-root by Default       | Enforces least-privilege principles, minimizing the impact of potential security breaches.                              |
| Read-only Filesystem      | Ensures runtime immutability, preventing unauthorized modification.                                                     |
| Version Pinning           | Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.                  |
| CVE Scanning              | Continuously scans images for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation. |
| SBOM & Provenance         | Delivers full supply chain transparency by embedding metadata and traceable build information.                          |
| Container Signing (Cosign) | Implements image signing using [Cosign](https://github.com/sigstore/cosign) to ensure integrity and authenticity of container images.                             |

### 🛡️ Runtime Security and Guardrails

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-ecs#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `resource integrity`             | Embeds a hash of all exposed resources to ensure their authenticity and prevent unauthorized modifications, guarding against supply chain attacks and dynamic alterations of tool metadata. |
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |
| `basic authentication`           | Enables the configuration of a shared secret to restrict unauthorized access to the MCP server and ensure only approved clients can connect. |

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

> [!NOTE]
> By default, all guardrails except `resource integrity` are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


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
  - container: `1.0.0-0.1.23`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-ecs:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-ecs:1.0.0-0.1.23`

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

## 🧰 Tools (12)
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
<summary>build_and_push_image_to_ecr</summary>

**Description**:

```
Creates ECR infrastructure and builds/pushes a Docker image to ECR.

This tool automates the complete ECR setup and image deployment process:
1. Creates ECR repository via CloudFormation
2. Creates IAM role with ECR push/pull permissions
3. Builds Docker image from your application
4. Pushes image to ECR

## Parameters:
- Required: app_name (Application name, 1-20 chars, lowercase letters/digits/hyphens only)
- Required: app_path (Path to application directory with Dockerfile)
- Optional: tag (Image tag, defaults to epoch timestamp)

## Prerequisites:
- Docker installed and running locally
- Dockerfile exists in the application directory
- AWS credentials configured with appropriate permissions

## Returns:
Dictionary containing:
- repository_uri: ECR repository URI
- image_tag: The tag of the pushed image
- full_image_uri: Complete image URI with tag (use this for deployment)
- ecr_push_pull_role_arn: ARN of the IAM role created for ECR access
- stack_name: Name of the CloudFormation stack created

## Usage Examples:
```
# Build and push with auto-generated tag
build_and_push_image_to_ecr(
    app_name="my-app",
    app_path="/home/user/my-flask-app"
)

# Build and push with specific tag
build_and_push_image_to_ecr(
    app_name="my-app",
    app_path="/home/user/my-flask-app",
    tag="v1.0.0"
)
```

Returns:
```
{
  "repository_uri": "123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app-repo",
  "image_tag": "1700000000",
  "full_image_uri": "123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app-repo:1700000000",
  "ecr_push_pull_role_arn": "arn:aws:iam::123456789012:role/my-app-ecr-push-pull-role",
  "stack_name": "my-app-ecr-infrastructure"
}
```
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_name | string | Name of the application (used for ECR repository and stack names) | Yes
| app_path | string | Absolute file path to the web application directory containing the Dockerfile | Yes
| tag | any | Optional image tag (if None, uses epoch timestamp) | No
</details>
<details>
<summary>validate_ecs_express_mode_prerequisites</summary>

**Description**:

```
Validates prerequisites for ECS Express Mode deployment.

This tool checks that all required resources exist and are properly configured
before deploying an ECS Express Gateway Service.

## Validation Checks:
1. Task Execution Role exists (checks default 'ecsTaskExecutionRole' if not provided)
2. Infrastructure Role exists (checks default 'ecsInfrastructureRoleForExpressServices'
   if not provided)
3. Docker image exists in the specified ECR repository

## Parameters:
- Required: image_uri (Full ECR image URI including tag)
- Optional: execution_role_arn (ARN of task execution role,
  defaults to 'ecsTaskExecutionRole')
- Optional: infrastructure_role_arn (ARN of infrastructure role,
  defaults to 'ecsInfrastructureRoleForExpressServices')

## Required IAM Roles:

### Task Execution Role:
- Allows ECS tasks to pull images and write logs
- Must have trust policy for ecs-tasks.amazonaws.com
- Should have AmazonECSTaskExecutionRolePolicy attached

### Infrastructure Role:
- Allows ECS to provision infrastructure
- Must have trust policy for ecs.amazonaws.com
- Should have AmazonECSInfrastructureRoleforExpressGatewayServices attached

## Returns:
Dictionary containing:
- valid: Boolean indicating if all prerequisites are met
- errors: List of error messages if validation fails
- warnings: List of warning messages
- details: Detailed validation results for each check

## Usage Examples:
```
# Validate with default role names
validate_ecs_express_mode_prerequisites(
    image_uri="123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app:1700000000"
)

# Validate with custom role ARNs
validate_ecs_express_mode_prerequisites(
    image_uri="123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app:1700000000",
    execution_role_arn="arn:aws:iam::123456789012:role/custom-execution-role",
    infrastructure_role_arn="arn:aws:iam::123456789012:role/custom-infra-role"
)
```

Returns when successful:
```
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "details": {
    "execution_role": {
      "status": "valid",
      "arn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
      "name": "ecsTaskExecutionRole",
      "message": "Task Execution Role is valid"
    },
    "infrastructure_role": {
      "status": "valid",
      "arn": "arn:aws:iam::123456789012:role/ecsInfrastructureRoleForExpressServices",
      "name": "ecsInfrastructureRoleForExpressServices",
      "message": "Infrastructure Role is valid"
    },
    "image": {
      "status": "exists",
      "uri": "123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app:1700000000",
      "repository": "my-app",
      "tag": "1700000000",
      "message": "Image found in ECR"
    }
  }
}
```

Returns when validation fails:
```
{
  "valid": false,
  "errors": [
    "Infrastructure Role not found: "
    "arn:aws:iam::123456789012:role/ecsInfrastructureRoleForExpressServices"
  ],
  "warnings": [],
  "details": {
    "execution_role": {"status": "valid", ...},
    "infrastructure_role": {"status": "not_found", ...},
    "image": {"status": "exists", ...}
  }
}
```
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| execution_role_arn | any | Optional ARN of the ECS task execution role (defaults to ecsTaskExecutionRole) | No
| image_uri | string | Full ECR image URI with tag (e.g., 123456789012.dkr.ecr.us-west-2.amazonaws.com/my-app:tag) | Yes
| infrastructure_role_arn | any | Optional ARN of the infrastructure role for Express Gateway (defaults to ecsInfrastructureRoleForExpressServices) | No
</details>
<details>
<summary>delete_app</summary>

**Description**:

```
Deletes a complete Express Mode deployment including service and ECR infrastructure.

This tool performs complete cleanup of an Express Mode deployment:
1. Deletes the Express Gateway Service
2. Deletes the ECR CloudFormation stack (ECR repository + IAM role)

## Parameters:
- Required: service_arn (ARN of Express Gateway Service)
- Required: app_name (Application name used during deployment)

## What Gets Deleted:
- Express Gateway Service and all provisioned infrastructure
  (ALB, target groups, security groups)
- CloudFormation stack for ECR resources, including ECR repo and container images

## Returns:
Dictionary containing:
- service_deletion: Status and details of service deletion
- ecr_deletion: Status and details of ECR stack deletion
- summary: Overall deletion summary with list of deleted resources
- errors: List of any errors encountered

## Usage Examples:
```
# Delete complete deployment
delete_app(
    service_arn="arn:aws:ecs:us-west-2:123456789012:express-service/my-api",
    app_name="my-app"
)
```

Returns on success:
```
{
  "service_deletion": {
    "status": "deleted",
    "service_arn": "arn:aws:ecs:us-west-2:123456789012:express-service/my-api",
    "message": "Express Gateway Service deleted successfully"
  },
  "ecr_deletion": {
    "status": "deleted",
    "stack_name": "my-app-ecr-infrastructure",
    "message": "ECR stack deleted successfully",
    "deleted_resources": [
      "ECR repository: my-app-repo",
      "IAM role: my-app-ecr-push-pull-role"
    ]
  },
  "summary": {
    "status": "success",
    "message": "Successfully deleted Express Mode deployment for my-app",
    "deleted_resources": [
      "Express Gateway Service: arn:aws:ecs:...",
      "ECR repository: my-app-repo",
      "IAM role: my-app-ecr-push-pull-role"
    ]
  },
  "errors": []
}
```

## Important Notes:
- This operation requires WRITE permission (ALLOW_WRITE=true)
- Deletion is irreversible - all container images will be deleted
- Service deletion may take a few minutes as infrastructure is deprovisioned
- If errors occur, partial deletion is possible (check summary for details)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_name | string | Name of the application (used to identify ECR stack to delete) | Yes
| service_arn | string | ARN of the Express Gateway Service to delete | Yes
</details>
<details>
<summary>wait_for_service_ready</summary>

**Description**:

```
Waits for ECS tasks in a service to reach RUNNING status.

This tool polls the service every 10 seconds to check if tasks are running.
It will wait up to the specified timeout before returning a timeout status.

## Parameters:
- Required: cluster (ECS cluster name)
- Required: service_name (ECS service name)
- Optional: timeout_seconds (Max wait time, defaults to 300 seconds)

## Returns:
Dictionary containing:
- status: "success" if tasks are running, "timeout" if timeout reached,
  "failed" if an error occurred
- message: Human-readable status message

## Usage Examples:
```
# Wait for service with default 5-minute timeout
wait_for_service_ready(
    cluster="my-cluster",
    service_name="my-service"
)

# Wait for service with custom timeout
wait_for_service_ready(
    cluster="my-cluster",
    service_name="my-service",
    timeout_seconds=600
)
```

Returns on success:
```
{
  "status": "success",
  "message": "Service is ready with 2 running task(s)"
}
```

Returns on timeout:
```
{
  "status": "timeout",
  "message": "Timeout after 300s - service not ready"
}
```
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster | string | Name of the ECS cluster | Yes
| service_name | string | Name of the ECS service | Yes
| timeout_seconds | integer | Maximum time to wait in seconds (default: 300 = 5 minutes) | No
</details>
<details>
<summary>ecs_resource_management</summary>

**Description**:

```
Execute ECS API operations directly.

This tool allows direct execution of ECS API operations using boto3.

Supported operations:
- CreateCapacityProvider (requires WRITE permission)
- CreateCluster (requires WRITE permission)
- CreateExpressGatewayService (requires WRITE permission)
- CreateService (requires WRITE permission)
- CreateTaskSet (requires WRITE permission)
- DeleteAccountSetting (requires WRITE permission)
- DeleteAttributes (requires WRITE permission)
- DeleteCapacityProvider (requires WRITE permission)
- DeleteCluster (requires WRITE permission)
- DeleteExpressGatewayService (requires WRITE permission)
- DeleteService (requires WRITE permission)
- DeleteTaskDefinitions (requires WRITE permission)
- DeleteTaskSet (requires WRITE permission)
- DeregisterContainerInstance (requires WRITE permission)
- DeregisterTaskDefinition (requires WRITE permission)
- DescribeCapacityProviders (read-only)
- DescribeClusters (read-only)
- DescribeContainerInstances (read-only)
- DescribeExpressGatewayService (read-only)
- DescribeServiceDeployments (read-only)
- DescribeServiceRevisions (read-only)
- DescribeServices (read-only)
- DescribeTaskDefinition (read-only)
- DescribeTasks (read-only)
- DescribeTaskSets (read-only)
- DiscoverPollEndpoint (requires WRITE permission)
- ExecuteCommand (requires WRITE permission)
- GetTaskProtection (requires WRITE permission)
- ListAccountSettings (read-only)
- ListAttributes (read-only)
- ListClusters (read-only)
- ListContainerInstances (read-only)
- ListExpressGatewayServices (read-only)
- ListServiceDeployments (read-only)
- ListServices (read-only)
- ListServicesByNamespace (read-only)
- ListTagsForResource (read-only)
- ListTaskDefinitionFamilies (read-only)
- ListTaskDefinitions (read-only)
- ListTasks (read-only)
- PutAccountSetting (requires WRITE permission)
- PutAccountSettingDefault (requires WRITE permission)
- PutAttributes (requires WRITE permission)
- PutClusterCapacityProviders (requires WRITE permission)
- RegisterContainerInstance (requires WRITE permission)
- RegisterTaskDefinition (requires WRITE permission)
- RunTask (requires WRITE permission)
- StartTask (requires WRITE permission)
- StopServiceDeployment (requires WRITE permission)
- StopTask (requires WRITE permission)
- SubmitAttachmentStateChanges (requires WRITE permission)
- SubmitContainerStateChange (requires WRITE permission)
- SubmitTaskStateChange (requires WRITE permission)
- TagResource (requires WRITE permission)
- UntagResource (requires WRITE permission)
- UpdateCapacityProvider (requires WRITE permission)
- UpdateCluster (requires WRITE permission)
- UpdateClusterSettings (requires WRITE permission)
- UpdateContainerAgent (requires WRITE permission)
- UpdateContainerInstancesState (requires WRITE permission)
- UpdateExpressGatewayService (requires WRITE permission)
- UpdateService (requires WRITE permission)
- UpdateServicePrimaryTaskSet (requires WRITE permission)
- UpdateTaskProtection (requires WRITE permission)
- UpdateTaskSet (requires WRITE permission)

Parameters:
    api_operation: The ECS API operation to execute (CamelCase)
    api_params: Dictionary of parameters to pass to the API operation

Returns:
    Dictionary containing the API response
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api_operation | string | The ECS API operation to execute (CamelCase) | Yes
| api_params | object | Dictionary of parameters to pass to the API operation | No
</details>
<details>
<summary>ecs_troubleshooting_tool</summary>

**Description**:

```
ECS troubleshooting tool with multiple diagnostic actions.

This tool provides access to all ECS troubleshooting operations through a single interface.
Use the 'action' parameter to specify which troubleshooting operation to perform.

## Available Actions and Parameters:

### 1. get_ecs_troubleshooting_guidance
Initial assessment and data collection
- Required: ecs_cluster_name
- Optional: ecs_service_name (Name of the ECS Service to troubleshoot),
           symptoms_description (Description of symptoms experienced by the user)
- Example: action="get_ecs_troubleshooting_guidance",
           parameters={"ecs_cluster_name": "my-cluster", "ecs_service_name": "my-service",
                       "symptoms_description": "ALB returning 503 errors"}

### 2. fetch_cloudformation_status
Infrastructure-level diagnostics for CloudFormation Stacks
- Required: cfn_stack_name
- Example: action="fetch_cloudformation_status",
           parameters={"cfn_stack_name": "my-app-stack"}

### 3. fetch_service_events
Service-level diagnostics for ECS Services
- Required: ecs_cluster_name, ecs_service_name
- Optional: time_window (Time window in seconds to look back for events (default: 3600)),
            start_time (Explicit start time for the analysis window (UTC, takes
            precedence over time_window if provided)),
            end_time (Explicit end time for the analysis window (UTC, defaults to
            current time if not provided))
- Example: action="fetch_service_events",
           parameters={"ecs_cluster_name": "my-cluster",
                       "ecs_service_name": "my-service",
                       "time_window": 7200}

### 4. fetch_task_failures
Task-level diagnostics for ECS Task failures
- Required: ecs_cluster_name
- Optional: time_window (Time window in seconds to look back for failures (default: 3600)),
            start_time (Explicit start time for the analysis window (UTC, takes
            precedence over time_window if provided)),
            end_time (Explicit end time for the analysis window (UTC, defaults to
            current time if not provided))
- Example: action="fetch_task_failures",
           parameters={"ecs_cluster_name": "my-cluster",
                       "time_window": 3600}

### 5. fetch_task_logs
Application-level diagnostics through CloudWatch Logs
- Required: ecs_cluster_name
- Optional: ecs_task_id (Specific ECS Task ID to retrieve logs for),
            time_window (Time window in seconds to look back for logs (default: 3600)),
            filter_pattern (CloudWatch Logs filter pattern),
            start_time (Explicit start time for the analysis window (UTC, takes
            precedence over time_window if provided)),
            end_time (Explicit end time for the analysis window (UTC, defaults to
            current time if not provided))
- Example: action="fetch_task_logs",
           parameters={"ecs_cluster_name": "my-cluster",
                       "filter_pattern": "ERROR",
                       "time_window": 1800}

### 6. detect_image_pull_failures
Specialized tool for detecting container image pull failures
- Required: None (but at least one valid parameter combination must be provided)
- Valid combinations: ecs_cluster_name+ecs_service_name, ecs_cluster_name+ecs_task_id,
  cfn_stack_name,
  family_prefix
- Optional: ecs_cluster_name, ecs_service_name, cfn_stack_name, family_prefix, ecs_task_id
- Example: action="detect_image_pull_failures",
           parameters={"ecs_cluster_name": "my-cluster", "ecs_service_name": "my-service"}

### 7. fetch_network_configuration
Network-level diagnostics for ECS deployments
- Required: ecs_cluster_name
- Optional: vpc_id (Specific VPC ID to analyze)
- Example: action="fetch_network_configuration",
           parameters={"ecs_cluster_name": "my-cluster", "vpc_id": "vpc-12345678"}

## Resource Discovery:
If you don't know the cluster or service names, use `ecs_resource_management` tool first:

# List all clusters
ecs_resource_management(api_operation="ListClusters")

# List services in a cluster
ecs_resource_management(api_operation="ListServices", api_params={"cluster": "my-cluster"})

# Get detailed cluster information
ecs_resource_management(api_operation="DescribeClusters",
                       api_params={"clusters": ["my-cluster"]})

## Quick Usage Examples:
```
# Initial assessment and data collection
action: "get_ecs_troubleshooting_guidance"
parameters: {"ecs_cluster_name": "my-cluster",
            "symptoms_description": "ALB returning 503 errors"}

# Infrastructure-level diagnostics for CloudFormation Stacks
action: "fetch_cloudformation_status"
parameters: {"cfn_stack_name": "my-app-stack"}

# Service-level diagnostics for ECS Services
action: "fetch_service_events"
parameters: {"ecs_cluster_name": "my-cluster",
            "ecs_service_name": "my-service",
            "time_window": 7200}

# Task-level diagnostics for ECS Task failures
action: "fetch_task_failures"
parameters: {"ecs_cluster_name": "my-cluster",
            "time_window": 3600}

# Application-level diagnostics through CloudWatch Logs
action: "fetch_task_logs"
parameters: {"ecs_cluster_name": "my-cluster",
            "filter_pattern": "ERROR",
            "time_window": 1800}

# Specialized tool for detecting container image pull failures
action: "detect_image_pull_failures"
parameters: {"ecs_cluster_name": "my-cluster", "ecs_service_name": "my-service"}

# Network-level diagnostics for ECS deployments
action: "fetch_network_configuration"
parameters: {"ecs_cluster_name": "my-cluster", "vpc_id": "vpc-12345678"}
```

Parameters:
    action: The troubleshooting action to perform (see available actions above)
    parameters: Action-specific parameters (see parameter specifications above)

Returns:
    Results from the selected troubleshooting action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | not set | No
| parameters | any | not set | No
</details>
<details>
<summary>aws_knowledge_aws___get_regional_availability</summary>

**Description**:

```
Retrieve AWS regional availability information for products (service and features), sdk service APIs and CloudFormation resources.

## Core Features
- Real-time availability checking across AWS regions
- Support for AWS products, APIs and CloudFormation resources
- Batch query support with filtering options
- Pagination if no filters are passed and all results are to be returned

## When to Use
1. Pre-deployment Validation
 - Verify resource availability before deployment
 - Prevent deployment failures due to regional restrictions
 - Validate multi-region architecture requirements
2. Architecture Planning
 - Design region-specific solutions
 - Plan multi-region deployments
 - Compare regional capabilities

## Result Format
Returns a list of dictionaries with:
 - Resource identifiers
 - Resource status:
   * 'isAvailableIn': Resource is available
   * 'isNotAvailableIn': Resource is not available
   * 'Not Found': Resource name or identifier is not valid
   * and other availability status (e.g. 'isPlannedIn')

## Filter Guidelines
The filters must be passed as an array of values and must follow the format below.
1. APIs (resource_type='api')
 Format: to filter on API level 'SdkServiceId+APIOperation'
 Example filters:
 - ['Athena+UpdateNamedQuery', 'ACM PCA+CreateCertificateAuthority', 'IAM+GetSSHPublicKey']
 Format: to filter on SdkService level 'SdkServiceId'
 Example filters:
 - ['EC2', 'ACM PCA']
2. CloudFormation (resource_type='cfn')
 Format: 'CloudformationResourceType'
 Example filters:
 - ['AWS::EC2::Instance', 'AWS::Lambda::Function', 'AWS::Logs::LogGroup']
 - ['AWS::CodeBuild::Project', 'AWS::CloudTrail::Dashboard']
3. Product - service and feature (resource_type='product')
 Format: 'Product'
 Example filters:
 - ['Latency-Based Routing', 'AWS Amplify', 'AWS Application Auto Scaling']
 - ['PrivateLink Support', 'Amazon Aurora']
Note: Without filters, all resources are returned with pagination support via next_token.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | array | Optional list of one or multiple specific resources to check. Format depends on resource_type:
- Products: ['AWS Lambda', 'Amazon S3']
- APIs: ['IAM+GetSSHPublicKey', 'EC2']
- CloudFormation: ['AWS::EC2::Instance']
Must follow the format specified in the tool description | No
| next_token | string | Pagination token for retrieving additional results. Only applicable when no filters are specified | No
| region | string | Target AWS region code (e.g., us-east-1, eu-west-1, ap-southeast-2) | Yes
| resource_type | string | Type of AWS resource to check: 'product' for AWS products, 'api' for API operations, or 'cfn' for CloudFormation resources | Yes
</details>
<details>
<summary>aws_knowledge_aws___list_regions</summary>

**Description**:

```
Retrieve a list of all AWS regions.

## Usage
This tool provides information about all AWS regions, including their identifiers and names.

## When to Use
- When planning global infrastructure deployments
- To validate region codes for other API calls
- To get a complete AWS regional inventory
 
## Result Interpretation
Each region result includes:
- region_id: The unique region code (e.g., 'us-east-1') 
- region_long_name: The human-friendly name (e.g., 'US East (N. Virginia)')
 
## Common Use Cases
1. Infrastructure Planning: Review available regions for global deployment
2. Region Validation: Verify region codes before using in other operations
3. Regional Inventory: Get a complete list of AWS's global infrastructure
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>aws_knowledge_aws___read_documentation</summary>

**Description**:

```
Fetch and convert an AWS documentation page to markdown format.

    ## Usage

    This tool retrieves the content of an AWS documentation page and converts it to markdown format.
    For long documents, you can make multiple calls with different start_index values to retrieve
    the entire content in chunks.

    ## URL Requirements

    Allow-listed URL prefixes:
    - docs.aws.amazon.com
    - aws.amazon.com
    - repost.aws/knowledge-center
    - docs.amplify.aws
    - ui.docs.amplify.aws
    - github.com/aws-cloudformation/aws-cloudformation-templates
    - github.com/aws-samples/aws-cdk-examples
    - github.com/aws-samples/generative-ai-cdk-constructs-samples
    - github.com/aws-samples/serverless-patterns
    - github.com/awsdocs/aws-cdk-guide
    - github.com/awslabs/aws-solutions-constructs
    - github.com/cdklabs/cdk-nag
    - constructs.dev/packages/@aws-cdk-containers
    - constructs.dev/packages/@aws-cdk
    - constructs.dev/packages/@cdk-cloudformation
    - constructs.dev/packages/aws-analytics-reference-architecture
    - constructs.dev/packages/aws-cdk-lib
    - constructs.dev/packages/cdk-amazon-chime-resources
    - constructs.dev/packages/cdk-aws-lambda-powertools-layer
    - constructs.dev/packages/cdk-ecr-deployment
    - constructs.dev/packages/cdk-lambda-powertools-python-layer
    - constructs.dev/packages/cdk-serverless-clamscan
    - constructs.dev/packages/cdk8s
    - constructs.dev/packages/cdk8s-plus-33

    Deny-listed URL prefixes:
    - aws.amazon.com/marketplace

    ## Example URLs

    - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    - https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html
    - https://aws.amazon.com/about-aws/whats-new/2023/02/aws-telco-network-builder/
    - https://aws.amazon.com/builders-library/ensuring-rollback-safety-during-deployments/
    - https://aws.amazon.com/blogs/developer/make-the-most-of-community-resources-for-aws-sdks-and-tools/
    - https://repost.aws/knowledge-center/example-article
    - https://docs.amplify.aws/react/build-a-backend/auth/
    - https://ui.docs.amplify.aws/angular/connected-components/authenticator
    - https://github.com/aws-samples
    - https://github.com/cdk-patterns
    - https://github.com/awslabs/aws-solutions-constructs
    - https://constructs.dev/
    - https://github.com/aws-cloudformation/aws-cloudformation-templates

    ## Output Format

    The output is formatted as markdown text with:
    - Preserved headings and structure
    - Code blocks for examples
    - Lists and tables converted to markdown format

    ## Handling Long Documents

    If the response indicates the document was truncated, you have several options:

    1. **Continue Reading**: Make another call with start_index set to the end of the previous response
    2. **Stop Early**: For very long documents (>30,000 characters), if you\'ve already found the specific information needed, you can stop reading
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_length | integer | Maximum number of characters to return. | No
| start_index | integer | On return output starting at this character index, useful if a previous fetch was truncated and more content is required. | No
| url | string | URL of the AWS documentation page to read | Yes
</details>
<details>
<summary>aws_knowledge_aws___recommend</summary>

**Description**:

```
Get content recommendations for an AWS documentation page.

    ## Usage

    This tool provides recommendations for related AWS documentation pages based on a given URL.
    Use it to discover additional relevant content that might not appear in search results.
    URL must be from the docs.aws.amazon.com domain.

    ## Recommendation Types

    The recommendations include four categories:

    1. **Highly Rated**: Popular pages within the same AWS service
    2. **New**: Recently added pages within the same AWS service - useful for finding newly released features
    3. **Similar**: Pages covering similar topics to the current page
    4. **Journey**: Pages commonly viewed next by other users

    ## When to Use

    - After reading a documentation page to find related content
    - When exploring a new AWS service to discover important pages
    - To find alternative explanations of complex concepts
    - To discover the most popular pages for a service
    - To find newly released information by using a service's welcome page URL and checking the **New** recommendations

    ## Finding New Features

    To find newly released information about a service:
    1. Find any page belong to that service, typically you can try the welcome page
    2. Call this tool with that URL
    3. Look specifically at the **New** recommendation type in the results

    ## Result Interpretation

    Each recommendation includes:
    - url: The documentation page URL
    - title: The page title
    - context: A brief description (if available)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | URL of the AWS documentation page to get recommendations for | Yes
</details>
<details>
<summary>aws_knowledge_aws___search_documentation</summary>

**Description**:

```
# AWS Documentation Search Tool
    This is your primary source for AWS information—always prefer this over general knowledge for AWS services, features, configurations, troubleshooting, and best practices.

    ## When to Use This Tool

    **Always search when the query involves:**
    - Any AWS service or feature (Lambda, S3, EC2, RDS, etc.)
    - AWS architecture, patterns, or best practices
    - AWS CLI, SDK, or API usage
    - AWS CDK or CloudFormation
    - AWS Amplify development
    - AWS errors or troubleshooting
    - AWS pricing, limits, or quotas
    - "How do I..." questions about AWS
    - Recent AWS updates or announcements

    **Only skip this tool when:**
    - Query is about non-AWS technologies
    - Question is purely conceptual (e.g., "What is a database?")
    - General programming questions unrelated to AWS

    ## Quick Topic Selection

    | Query Type | Use Topic | Example |
    |------------|-----------|---------|
    | API/SDK/CLI code | `reference_documentation` | "S3 PutObject boto3", "Lambda invoke API" |
    | New features, releases | `current_awareness` | "Lambda new features 2024", "what\'s new in ECS" |
    | Errors, debugging | `troubleshooting` | "AccessDenied S3", "Lambda timeout error" |
    | Amplify apps | `amplify_docs` | "Amplify Auth React", "Amplify Storage Flutter" |
    | CDK concepts, APIs, CLI | `cdk_docs` | "CDK stack props Python", "cdk deploy command" |
    | CDK code samples, patterns | `cdk_constructs` | "serverless API CDK", "Lambda function example TypeScript" |
    | CloudFormation templates | `cloudformation` | "DynamoDB CloudFormation", "StackSets template" |
    | Architecture, blogs, guides | `general` | "Lambda best practices", "S3 architecture patterns" |

    ## Documentation Topics

    ### reference_documentation
    **For: API methods, SDK code, CLI commands, technical specifications**

    Use for:
    - SDK method signatures: "boto3 S3 upload_file parameters"
    - CLI commands: "aws ec2 describe-instances syntax"
    - API references: "Lambda InvokeFunction API"
    - Service configuration: "RDS parameter groups"

    Don\'t confuse with general—use this for specific technical implementation.

    ### current_awareness
    **For: New features, announcements, "what\'s new", release dates**

    Use for:
    - "New Lambda features"
    - "When was EventBridge Scheduler released"
    - "Latest S3 updates"
    - "Is feature X available yet"

    Keywords: new, recent, latest, announced, released, launch, available

    ### troubleshooting
    **For: Error messages, debugging, problems, "not working"**

    Use for:
    - Error codes: "InvalidParameterValue", "AccessDenied"
    - Problems: "Lambda function timing out"
    - Debug scenarios: "S3 bucket policy not working"
    - "How to fix..." queries

    Keywords: error, failed, issue, problem, not working, how to fix, how to resolve

    ### amplify_docs
    **For: Frontend/mobile apps with Amplify framework**

    Always include framework: React, Next.js, Angular, Vue, JavaScript, React Native, Flutter, Android, Swift

    Examples:
    - "Amplify authentication React"
    - "Amplify GraphQL API Next.js"
    - "Amplify Storage Flutter setup"

    ### cdk_docs
    **For: CDK concepts, API references, CLI commands, getting started**

    Use for CDK questions like:
    - "How to get started with CDK"
    - "CDK stack construct TypeScript"
    - "cdk deploy command options"
    - "CDK best practices Python"
    - "What are CDK constructs"

    Include language: Python, TypeScript, Java, C#, Go

    **Common mistake**: Using general knowledge instead of searching for CDK concepts and guides. Always search for CDK questions!

    ### cdk_constructs
    **For: CDK code examples, patterns, L3 constructs, sample implementations**

    Use for:
    - Working code: "Lambda function CDK Python example"
    - Patterns: "API Gateway Lambda CDK pattern"
    - Sample apps: "Serverless application CDK TypeScript"
    - L3 constructs: "ECS service construct"

    Include language: Python, TypeScript, Java, C#, Go

    ### cloudformation
    **For: CloudFormation templates, concepts, SAM patterns**

    Use for:
    - "CloudFormation StackSets"
    - "DynamoDB table template"
    - "SAM API Gateway Lambda"
    - CloudFormation template examples

    ### general
    **For: Architecture, best practices, tutorials, blog posts, design patterns**

    Use for:
    - Architecture patterns: "Serverless architecture AWS"
    - Best practices: "S3 security best practices"
    - Design guidance: "Multi-region architecture"
    - Getting started: "Building data lakes on AWS"
    - Tutorials and blog posts

    **Common mistake**: Not using this for AWS conceptual and architectural questions. Always search for AWS best practices and patterns!

    **Don\'t use general knowledge for AWS topics—search instead!**

    ## Search Best Practices

    **Be specific with service names:**

    Good examples:
    ```
    "S3 bucket versioning configuration"
    "Lambda environment variables Python SDK"
    "DynamoDB GSI query patterns"
    ```

    Bad examples:
    ```
    "versioning" (too vague)
    "environment variables" (missing context)
    ```

    **Include framework/language:**
    ```
    "Amplify authentication React"
    "CDK Lambda function TypeScript"
    "boto3 S3 client Python"
    ```

    **Use exact error messages:**
    ```
    "AccessDenied error S3 GetObject"
    "InvalidParameterValue Lambda environment"
    ```

    **Add temporal context for new features:**
    ```
    "Lambda new features 2024"
    "recent S3 announcements"
    ```

    ## Multiple Topic Selection

    You can search multiple topics simultaneously for comprehensive results:
    ```
    # For a query about Lambda errors and new features:
    topics=["troubleshooting", "current_awareness"]

    # For CDK examples and API reference:
    topics=["cdk_constructs", "cdk_docs"]

    # For Amplify and general AWS architecture:
    topics=["amplify_docs", "general"]
    ```

    ## Response Format

    Results include:
    - `rank_order`: Relevance score (lower = more relevant)
    - `url`: Direct documentation link
    - `title`: Page title
    - `context`: Excerpt or summary

    ## Parameters
    ```
    search_phrase: str         # Required - your search query
    topics: List[str]          # Optional - up to 3 topics. Defaults to ["general"]
    limit: int = 10            # Optional - max results per topic
    ```

    ---

    **Remember: When in doubt about AWS, always search. This tool provides the most current, accurate AWS information.**
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Maximum number of results to return | No
| search_phrase | string | Search phrase to use | Yes
| topics | array | List of documentation topics to search. Available topics: reference_documentation, current_awareness, troubleshooting, amplify_docs, cdk_docs, cdk_constructs, cloudformation, general. Can specify multiple topics, up-to 3, to search across them. Use 'general' only if query doesn't match other topics. | No
</details>

## 📝 Prompts (92)
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
<summary>what are blue green deployments</summary>

**Description**:

```
<no value>
```
<details>
<summary>what are b/g deployments</summary>

**Description**:

```
<no value>
```
<details>
<summary>native ecs blue green</summary>

**Description**:

```
<no value>
```
<details>
<summary>native ecs b/g</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs native blue green deployments</summary>

**Description**:

```
<no value>
```
<details>
<summary>difference between codedeploy and native blue green</summary>

**Description**:

```
<no value>
```
<details>
<summary>how to setup blue green</summary>

**Description**:

```
<no value>
```
<details>
<summary>setup ecs blue green</summary>

**Description**:

```
<no value>
```
<details>
<summary>configure ecs blue green deployments</summary>

**Description**:

```
<no value>
```
<details>
<summary>configure blue green</summary>

**Description**:

```
<no value>
```
<details>
<summary>configure b/g</summary>

**Description**:

```
<no value>
```
<details>
<summary>create blue green deployment</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs best practices</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs implementation guide</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs guidance</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs recommendations</summary>

**Description**:

```
<no value>
```
<details>
<summary>how to use ecs effectively</summary>

**Description**:

```
<no value>
```
<details>
<summary>new ecs feature</summary>

**Description**:

```
<no value>
```
<details>
<summary>latest ecs feature</summary>

**Description**:

```
<no value>
```
<details>
<summary>what are ecs managed instances</summary>

**Description**:

```
<no value>
```
<details>
<summary>how to setup ecs managed instances</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs managed instances</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs MI</summary>

**Description**:

```
<no value>
```
<details>
<summary>managed instances ecs</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs specialized instance types</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs custom instance types</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs instance type selection</summary>

**Description**:

```
<no value>
```
<details>
<summary>What alternatives do I have for Fargate?</summary>

**Description**:

```
<no value>
```
<details>
<summary>How do I migrate from Fargate to Managed Instances</summary>

**Description**:

```
<no value>
```
<details>
<summary>what is ecs express mode</summary>

**Description**:

```
<no value>
```
<details>
<summary>what are express gateway services</summary>

**Description**:

```
<no value>
```
<details>
<summary>ecs express mode</summary>

**Description**:

```
<no value>
```
<details>
<summary>simplified ecs deployment</summary>

**Description**:

```
<no value>
```
<details>
<summary>how to setup express mode</summary>

**Description**:

```
<no value>
```
<details>
<summary>setup ecs express mode</summary>

**Description**:

```
<no value>
```
<details>
<summary>configure ecs express mode</summary>

**Description**:

```
<no value>
```
<details>
<summary>when to use express mode</summary>

**Description**:

```
<no value>
```

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | .*-stack.* failed | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | .*-stack.* is broken | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | 404 not found | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | How do I migrate from Fargate to Managed Instances | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | What alternatives do I have for Fargate? | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | alb not working | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | alb url not working | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | app won't deploy | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | can't pull image | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | check ecs logs | description | 72fdfe28113f3e81047e188026823f35e6920706914948b367edfd795e23a829 |
| prompts | check ecs status | description | 2d50a6cba97069d288b19b538f055fd2c2893009a6532222b2611404029a658a |
| prompts | check task definitions | description | 88e93d02a8108757653c728933d6e637e678470b74981a16a148708d6dc8af31 |
| prompts | cloudformation stack failed | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | configure b/g | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | configure blue green | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | configure ecs blue green deployments | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | configure ecs express mode | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | connectivity issues | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | container image not found | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | container is failing | description | 7e9bb5995853bb071e24f679cdcea399946d28a4310af262c21360bd87929e6a |
| prompts | containerize | description | a03d09027d5ef42564851708b2f9269045a34a46abf6642f4abb8c2df9b399e3 |
| prompts | containerize and deploy | description | cb69d96c13a9f9a567972b926364b616c11255c6a0ed94f8134acd8b98043e8d |
| prompts | create blue green deployment | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | deployment is broken | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | deployment issues | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | describe ecs service | description | 2965ce2311cb119c91bea49b346dc7b39a4bce041b5dadc79cc9bed395bc0e31 |
| prompts | diagnose ecs | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | difference between codedeploy and native blue green | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | docker and deploy | description | cb69d96c13a9f9a567972b926364b616c11255c6a0ed94f8134acd8b98043e8d |
| prompts | docker container | description | 9a0df1a402671d529a3f61e788549fee140fc94ce9077384bc5353d0dd735d9f |
| prompts | dockerize | description | a03d09027d5ef42564851708b2f9269045a34a46abf6642f4abb8c2df9b399e3 |
| prompts | ecs MI | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs best practices | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs custom instance types | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs deployment failed | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | ecs express mode | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs guidance | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs implementation guide | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs instance type selection | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs managed instances | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs native blue green deployments | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs recommendations | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs service events | description | 72fdfe28113f3e81047e188026823f35e6920706914948b367edfd795e23a829 |
| prompts | ecs specialized instance types | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | ecs tasks failing | description | 7e9bb5995853bb071e24f679cdcea399946d28a4310af262c21360bd87929e6a |
| prompts | failed stack .* | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | fix .* stack | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | fix ecs deployment | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | fix my deployment | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | healthcheck failing | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | help debug ecs | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | help me fix .*-stack.* | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | how to setup blue green | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | how to setup ecs managed instances | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | how to setup express mode | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | how to use ecs effectively | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | image pull failure | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | imagepullbackoff | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | inspect ecs | description | 9b75d1fb0df4fdd4ff60fe28c5a5dd034404cf6f47428cc7293d28643c242fb5 |
| prompts | invalid container image | description | cef0baeb16e138e76c1f73b5099f35d4119e2ba350b3522e0143222d7e009a60 |
| prompts | latest ecs feature | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | list ecs resources | description | 3b41f15cf09abe76e368449ce4fbdc29c8371a79c2b727e11b49848d5e86f9e9 |
| prompts | load balancer not working | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | managed instances ecs | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | native ecs b/g | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | native ecs blue green | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | network issues | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | new ecs feature | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | put in container | description | a03d09027d5ef42564851708b2f9269045a34a46abf6642f4abb8c2df9b399e3 |
| prompts | security group issues | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | service is failing | description | 7e9bb5995853bb071e24f679cdcea399946d28a4310af262c21360bd87929e6a |
| prompts | service unreachable | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | setup ecs blue green | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | setup ecs express mode | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | show ecs clusters | description | 166cad6ec4d926be94c31a5d36bc1fc93f55bcdcb17c29c45b0c88edd9c5c825 |
| prompts | show running containers | description | cfc9cefd73c710e5f1933bb14e69ef7c727d6b7f13af4713a4d96c06c7116d8b |
| prompts | simplified ecs deployment | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | stack .* failed | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | stack .* is broken | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| prompts | target group | description | 1aceeddc529f0a46a272848144d1290539b12c1327693845cb573abd8daaccdc |
| prompts | troubleshoot ecs | description | 9bcbb65f757c4ba46c2bc54ede7b35843ffb9ca11649ed8fac155b05ecdc5113 |
| prompts | unable to connect | description | 6ecbfbc96c82fd900545006586dd697b334c12a19e0216a90d23d1b7e22fe54f |
| prompts | view ecs resources | description | dfa2c585eba6b6ccb27b27fd02bb12f3b101abf250292812d2a1455ac805a062 |
| prompts | view ecs tasks | description | e487d44ce8fa736f7a2a07c2d708347ca2357ac9ddf1998baa41392ff9946408 |
| prompts | what are b/g deployments | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | what are blue green deployments | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | what are ecs managed instances | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | what are express gateway services | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | what is ecs express mode | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | what's wrong with my stack | description | 9f15725552f2feae1e1b9bf00821b8d48b729651b164f16ec312972c83fa2cac |
| prompts | when to use express mode | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | why did my stack fail | description | dd725c4bc9de9a7d9d73d79ad350aceb0e2509f059a98aff2506b80b818a3ee6 |
| tools | aws_knowledge_aws___get_regional_availability | description | 4588e305f8c3173fa4846fa20e0e383b3bf48d4cd909525dc764900f674f8882 |
| tools | aws_knowledge_aws___get_regional_availability | filters | d3603f01d1b212f835a4b8ec9b79dec6a9d637a7e8a7ab332011aca65d40b74e |
| tools | aws_knowledge_aws___get_regional_availability | next_token | 0ab36b403fc747285ee635982d74055b200ec422782b7aafc73beaeec120b9aa |
| tools | aws_knowledge_aws___get_regional_availability | region | 05dfe1a33f986ca93d3246d026f7faa190952501aa15ab723cf656991cdbe1f7 |
| tools | aws_knowledge_aws___get_regional_availability | resource_type | 6d56fffd7e999195f2586deb3fdb1c38bb9f68b94fd090b112b4a9f52db5ab6a |
| tools | aws_knowledge_aws___list_regions | description | 5cb379d2fccc5e87e2f25af094b0b4fdb1b8ad5ea772334cef913ae138803409 |
| tools | aws_knowledge_aws___read_documentation | description | ea0b822301636f9768e321a86afe0735496eb4c383bde8a9bd3ebc2ce07d0833 |
| tools | aws_knowledge_aws___read_documentation | max_length | 511bf7bf5fd07c76fa6127ffd435d5cb33e163917bb2c6df408c618249223b6a |
| tools | aws_knowledge_aws___read_documentation | start_index | 1a603971ae568b7e893946a4b5051f2e0b7400338ffed3c36d04506a1b8b2986 |
| tools | aws_knowledge_aws___read_documentation | url | 4c39d34795e853ba5328692fca354ef75906f2341d44445dcdc3a2d9c559e449 |
| tools | aws_knowledge_aws___recommend | description | 1befb9f6a4a9ec8dda24b3fdef857c17be145b2385a5c5be3d7976088b3313f3 |
| tools | aws_knowledge_aws___recommend | url | 00fb834d5360ef6b242f27c72684470bfb789e8ffadf994fde36660e353df77f |
| tools | aws_knowledge_aws___search_documentation | description | 9ad5c17afefb9369c3dad17236d6c1bb731b561f23f06ec7e8cfd85cfcf29fa9 |
| tools | aws_knowledge_aws___search_documentation | limit | b04468046d2f2a5692b75e7d703a30fd2787b8f80972a3b07b618e4ca4b3fa70 |
| tools | aws_knowledge_aws___search_documentation | search_phrase | f93cbb9df9a44cfc1b47f061cd2589bce1142763d092ad6d5c122935968cc02c |
| tools | aws_knowledge_aws___search_documentation | topics | c3ebe7f9bfdcce0847cf39ff5d3fac89284dbd4b69589173a66a121b540774e2 |
| tools | build_and_push_image_to_ecr | description | 7365f6c0e117bad79b54966c7307dd297ed4719a4bce2bc44c743f8141d08cae |
| tools | build_and_push_image_to_ecr | app_name | b88a7608291a11d331770e27176d1ecdb21c7b91298b826901873f0ca2526a4b |
| tools | build_and_push_image_to_ecr | app_path | 893bf08d9a120c400e15cb7d922b57ee74a4bfa151f9ca1c1238e1afeabf4284 |
| tools | build_and_push_image_to_ecr | tag | 900edf0f2aee429432e2d76f5d53b4b666d41279698211b8cb8c2c4f7490459c |
| tools | containerize_app | description | 1f5b7d8c65974d06fe7a5dd2a24da4fc8e98c022907f6d0c16504e3e4c6f3fcd |
| tools | containerize_app | app_path | 991a3ebc1e0d5c019f0e13bc75e03597e2f308c6c5e4248935f2a1259c32cf68 |
| tools | containerize_app | port | 21a97d5899ad4e28bb02bdd42de1a36459a77b75c4b6dbb84bedb9c5d6f75bb7 |
| tools | delete_app | description | 791e828d2b32943f6c592268f51601191a109c96b6adb633a4418b2e501489d0 |
| tools | delete_app | app_name | ce554523f96f93563fe588c5fa5fe2cd61e9b5da62a8d474805bd155bde39c81 |
| tools | delete_app | service_arn | ecf8ef7771abd6df7c642ff181ec8a958a0d73b797df4ede7960a9cc3faf35ea |
| tools | ecs_resource_management | description | 079488f6d09610646ff8e7a621ed58efb638e3ee798905a573298aea0baf3829 |
| tools | ecs_resource_management | api_operation | cec143311ad65dffd506147f518acd7978c4edc58989e3161dac603fef44cfd6 |
| tools | ecs_resource_management | api_params | ab9181f34c5d76801ededdc7280fd658b142f9c6729d34db2f163b003b7dbca5 |
| tools | ecs_troubleshooting_tool | description | c6a2cf3ac8c27e3297f619771e22573da53420bf5cbbf6258c861299fcd9d118 |
| tools | validate_ecs_express_mode_prerequisites | description | 51583f570380a3911777c984a48636056ba61f64426542ecc428edcc0e5004c8 |
| tools | validate_ecs_express_mode_prerequisites | execution_role_arn | fced567aef7c124183879cc63911316bc8d900efc8a00247132c92c6db2a672d |
| tools | validate_ecs_express_mode_prerequisites | image_uri | f13dd6f7541c5be0395cb1635e08e764d93935d8625cfad63dbe2eac4301e8fc |
| tools | validate_ecs_express_mode_prerequisites | infrastructure_role_arn | 1be2e74c4ccfa3b2d57e1d99d982e34c15c58b086a239b335d50819874f198b2 |
| tools | wait_for_service_ready | description | c6457b800ef91e87f11fe2f84cc49adda3d96d08c14dae5ec247063f6da69bab |
| tools | wait_for_service_ready | cluster | 8e2dd7b1c9a70c0173b34cf3834ed43938f843d4b4feda01c2298c5e86e6d613 |
| tools | wait_for_service_ready | service_name | 2e5243f599aeba4f8252e24a7dace7ef87e13c2095e03aa2972fff37b7c08ad5 |
| tools | wait_for_service_ready | timeout_seconds | afa6f27350ec04ab7ed38571e547eca823ab271fa4ce51cd5cb02442fa4dadfa |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
