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


# What is mcp-server-pulumi?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-pulumi/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-pulumi/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-pulumi)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=@pulumi/mcp-server)](https://github.com/pulumi/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-pulumi/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-pulumi&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22cache%3A%2Fapp%2Fnode_modules%2F%40pulumi%2Fmcp-server%2Fdist%2F.cache%22%2C%22docker.io%2Facuvity%2Fmcp-server-pulumi%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Server for programmatic Pulumi operations via Model Context Protocol.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @pulumi/mcp-server original [sources](https://github.com/pulumi/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-pulumi/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/charts/mcp-server-pulumi/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @pulumi/mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Pulumi Corporation ](https://github.com/pulumi/mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @pulumi/mcp-server ](https://github.com/pulumi/mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @pulumi/mcp-server ](https://github.com/pulumi/mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/charts/mcp-server-pulumi)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-pulumi/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-pulumi:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-pulumi:1.0.0-0.2.0`

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
helm install mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-pulumi
```

From there your MCP server mcp-server-pulumi will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-pulumi` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-pulumi
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-pulumi` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-pulumi oci://docker.io/acuvity/mcp-server-pulumi --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>pulumi-registry-get-type</summary>

**Description**:

```
Get the JSON schema for a specific JSON schema type reference
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | The module to query (e.g., 's3', 'ec2', 'lambda'). Optional for smaller providers, will be 'index by default. | No
| name | string | The name of the type to query (e.g., 'BucketGrant', 'FunctionEnvironment', 'InstanceCpuOptions') | Yes
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-get-resource</summary>

**Description**:

```
Returns information about a Pulumi Registry resource
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | The module to query (e.g., 's3', 'ec2', 'lambda'). If not specified it will match resources with the given name in any module. | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| resource | string | The resource type to query (e.g., 'Bucket', 'Function', 'Instance') | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-get-function</summary>

**Description**:

```
Returns information about a Pulumi Registry function
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| function | string | The function type to query (e.g., 'getBucket', 'getFunction', 'getInstance') | Yes
| module | string | The module to query (e.g., 's3', 'ec2', 'lambda'). If not specified it will match functions with the given name in any module. | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-list-resources</summary>

**Description**:

```
List all resource types for a given provider and module
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | Optional module to filter by (e.g., 's3', 'ec2', 'lambda') | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-registry-list-functions</summary>

**Description**:

```
List all function types for a given provider and module
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| module | string | Optional module to filter by (e.g., 's3', 'ec2', 'lambda') | No
| provider | string | The cloud provider (e.g., 'aws', 'azure', 'gcp', 'random') or github.com/org/repo for Git-hosted components | Yes
| version | string | The provider version to use (e.g., '6.0.0'). If not specified, uses the latest available version. | No
</details>
<details>
<summary>pulumi-cli-preview</summary>

**Description**:

```
Run pulumi preview for a given project and stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>pulumi-cli-up</summary>

**Description**:

```
Run pulumi up for a given project and stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>pulumi-cli-stack-output</summary>

**Description**:

```
Get the output value(s) of a given stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| outputName | string | The specific stack output name to retrieve. | No
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>pulumi-cli-refresh</summary>

**Description**:

```
Run pulumi refresh for a given project and stack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stackName | string | The associated stack name. Defaults to 'dev'. | No
| workDir | string | The working directory of the program. | Yes
</details>
<details>
<summary>deploy-to-aws</summary>

**Description**:

```
Deploy application code to AWS by generating Pulumi infrastructure. This tool automatically analyzes your application files and provisions the appropriate AWS resources (S3, Lambda, EC2, etc.) based on what it finds. No prior analysis needed -  just invoke directly.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>pulumi-resource-search</summary>

**Description**:

```
Search and analyze Pulumi-managed cloud resources using a strict subset of Lucene query syntax.

QUERY SYNTAX RULES:
- The search query syntax is a strict subset of Lucene query syntax
- The documents being searched are Pulumi resources
- The implicit operator is AND
- Parentheses and OR are supported between fields but not within fields
- All resources are returned by default (use empty query "" to get all)
- Wildcard queries are NOT supported (no * allowed)
- Fuzzy queries are NOT supported
- Boosting is NOT supported
- Field grouping is NOT supported
- Whitespace is NOT supported
- field:value produces a match_phrase query
- field:"value" produces a term query
- -field:value produces a bool must_not match_phrase query
- -field:"value" produces a bool must_not term query
- field: produces an existence query
- Resource properties can be queried with leading dot: .property.path:value or .property.path: (existence)
- You absolutely must not produce queries that use fields other than: type, name, id, stack, project, package, modified, provider, provider_urn, team and protected, unless the field is the name of a property.
- You absolutely must not produce queries that use wildcards (e.g., *).
- You absolutely must not produce queries that use field grouping (e.g., type:(a OR b))

AVAILABLE FIELDS:
- type: Pulumi types used for pulumi import operations (e.g., aws:s3/bucket:Bucket)
- name: logical Pulumi resource names
- id: physical Pulumi resource names
- stack: name of the stack the resource belongs to
- project: name of the project the resource belongs to
- created: when the resource was first created (absolute dates only)
- modified: when the resource was last modified (absolute dates only)
- package: package of the resource (e.g., aws, gcp)
- provider: alias for the "package" field
- provider_urn: full URN of the resource's provider
- protected: boolean representing whether a resource is protected
- team: name of a team with access to the resource

IMPORTANT QUERY PATTERNS:
For AWS resources, do not use specific provider prefixes (aws: or aws-native:) in type filters. Instead:
WRONG: type:aws:s3/bucket:Bucket
WRONG: type:aws-native:s3:Bucket
CORRECT: type:"Bucket" (searches across both aws and aws-native providers)
For package filtering, use the generic package name:
CORRECT: package:aws (matches both aws and aws-native packages)
For finding resources by service, prefer the module field when possible:
PREFERRED: module:s3 (finds all S3 resources regardless of provider)
For property existence queries, always use the dot notation:
CORRECT: .tags: (checks if tags property exists)
For property negation queries (finding resources WITHOUT a property):
CORRECT: -.tags: or NOT .tags: (finds resources without tags)
COMMON TRANSLATIONS:
- "untagged resources" → -.tags: or NOT .tags:
- "resources without tags" → -.tags: or NOT .tags:

Supports field filters, boolean operators (AND, OR, NOT), exact matches with quotes, and property searches. The top parameter controls the maximum number of results to return (defaults to 20).

Resources may not have a repository url. This means that there is no available information about the repository that the resource is associated with.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org | string | Pulumi organization name (optional, defaults to current default org) | No
| properties | boolean | Whether to include resource properties in the response (defaults to false). WARNING: Setting this to true produces significantly more tokens and can cause response size limits to be exceeded. Only set to true when: (1) user explicitly requests properties/details, (2) querying a very small number of specific resources, or (3) user needs property-based analysis. NOT recommended for loose queries (empty query, broad type searches, etc.) that return many resources. | No
| query | string | Lucene query string using strict subset syntax (see tool description for full rules). NO WILDCARDS (*) allowed. | Yes
| top | number | Maximum number of top results to return (defaults to 20) | No
</details>
<details>
<summary>neo-task-launcher</summary>

**Description**:

```
Launch a Neo task when user asks Neo to perform a task. Pulumi Neo is a purpose-built cloud infrastructure automation agent.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| context | string | Optional conversation context with details of work done so far. Include: 1) Summary of what the user has been working on, 2) For any files modified, provide git diff format showing the changes, 3) Textual explanation of what was changed and why. Example: "The user has been working on authentication. Files modified: src/auth.ts - Added token support: ```diff\n- function login(user) {\n+ function login(user, token) {\n```\nThis change adds token-based auth for better security." | No
| query | string | The task query to send to Neo (what the user wants Neo to do) | Yes
</details>

## 📝 Prompts (2)
<details>
<summary>deploy-to-aws</summary>

**Description**:

```
Deploy application code to AWS by generating Pulumi infrastructure
```
<details>
<summary>convert-terraform-to-typescript</summary>

**Description**:

```
Converts a Terraform file to TypeScript
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| outputDir | The directory to output the TypeScript code to |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | convert-terraform-to-typescript | description | 46721b1af46ad5dc9f006d54a92682b4651a280fcc5ed1eb8c0c16508cf3676a |
| prompts | convert-terraform-to-typescript | outputDir | 79fb78573933eef422e5c6cfe8967a19bd80a3087dfb49427c7af29b9256c027 |
| prompts | deploy-to-aws | description | 84b5819f8a04f39f97b66ee3b302729d18ef812bec8446af245d45b485d4f216 |
| tools | deploy-to-aws | description | 0a24c7371bb30010e043be7eba2ec686194bf50cd5668be3c4fbee2bc48cb539 |
| tools | neo-task-launcher | description | a7d7f5ffe9094b383d72e88104f5e2b5d6670f6c344e41371f0a42704abcb477 |
| tools | neo-task-launcher | context | 05ae8e4b48f5db2ba701750fc2396c0fae821c9afc1f4ae91400ccd8dcb15eb0 |
| tools | neo-task-launcher | query | f48f47ff5fa0476e249b322261995d7bbeded518bb5f84efe3fef21baddb2573 |
| tools | pulumi-cli-preview | description | 77eebbe43ea5f25cc6c6afba4493876241cb4553c3c800fefa38414777f9001a |
| tools | pulumi-cli-preview | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-preview | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-cli-refresh | description | 2051576b742f677f54e34cc7073cd22f5d8a115bab0ff1a7379edb686020caab |
| tools | pulumi-cli-refresh | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-refresh | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-cli-stack-output | description | 4b26ee5e37a27ae0158d38c55fe154141fe0068d75f5ef35a60f78ffab49ffd0 |
| tools | pulumi-cli-stack-output | outputName | af5e3b5255274599dd681b448adaa308c2c9aa54bb3203fecb449b2fd2a4db2a |
| tools | pulumi-cli-stack-output | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-stack-output | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-cli-up | description | 76e44523dd1858cf57baa3a7014a59eac6a8b8d352f0cfbb530c18ddbddf3336 |
| tools | pulumi-cli-up | stackName | 62db21bdc5f99aa735c5e247f7aa2b6a2df24ae221ab3bec8febd721ed361613 |
| tools | pulumi-cli-up | workDir | 197b126116a83a35d62f31f452c357c2b06c809cc9523c3ef31c02940ee17b98 |
| tools | pulumi-registry-get-function | description | deca77a2cd724e1e6347de7f3cd46f0bef35629a208c7afbe3b9f1f3d411d745 |
| tools | pulumi-registry-get-function | function | 41781d7673ae216d861a74916a1d1140b37b9d23ac78e7f3365a770bca14ab80 |
| tools | pulumi-registry-get-function | module | 863b6f97dae28a9dfe55e288a125140172423942393113c8f56af5fac089b5bb |
| tools | pulumi-registry-get-function | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-get-function | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-get-resource | description | 187e34cb220dab47370d558de593b9157264cbae9bf52d1ff54ab6dba5783991 |
| tools | pulumi-registry-get-resource | module | c6939148bd48eb3acc755f0bb65d2ef94c5ee91c265b948ffc9d10cb26848b85 |
| tools | pulumi-registry-get-resource | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-get-resource | resource | bd4be36001049fe09082abdb3eecc5b2a427e0d1fb0b0873bb28a897be45263b |
| tools | pulumi-registry-get-resource | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-get-type | description | c86705d3607c12cc3050e20ea36461dd7f58b32850e2e378295a19776ff440e7 |
| tools | pulumi-registry-get-type | module | 912e142e135630c83cb0e36edc94b26ef20354d5b8e38f3ec948dccfac468bca |
| tools | pulumi-registry-get-type | name | ff0e769d54e1fdb895b7bd957584af333e5204c04050bbe34c91e7570c22f5aa |
| tools | pulumi-registry-get-type | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-get-type | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-list-functions | description | a7693331d1d6b2de628d279a752dbd8e1baebb00b9cc7210973def3639728716 |
| tools | pulumi-registry-list-functions | module | de9a6844786d8547d8e984bdb7c39b73da5ac3917ae7761d956471cc31160d18 |
| tools | pulumi-registry-list-functions | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-list-functions | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-registry-list-resources | description | c020cf469c10b34c06eed648d7a647881a1b5b2ee1cd482b605f74afed6cce82 |
| tools | pulumi-registry-list-resources | module | de9a6844786d8547d8e984bdb7c39b73da5ac3917ae7761d956471cc31160d18 |
| tools | pulumi-registry-list-resources | provider | 10128898059af3093cf26e98c16097f70b2db1b2912ca6b498295c0e4f8a58b0 |
| tools | pulumi-registry-list-resources | version | b91e073ffba9f6b18bcc0a7601843f0500b25630eb841dc715b1af9a7a09de29 |
| tools | pulumi-resource-search | description | 32a16c5be45c3dbb6d30530060f7d7330cd1db7778a7612d9f725668fa77adc2 |
| tools | pulumi-resource-search | org | c7136e5ee12fab855f78fbad9925612fcd3db02f6702871de9ca37ff7331484f |
| tools | pulumi-resource-search | properties | 29e8397d40408a28c654f7e9ea1c76ff3b3b0d1c024ac280a267dbaf2bab9059 |
| tools | pulumi-resource-search | query | 7ccf6bcba87c263358dd3d49be6c27167d2bb13b940e592bf1eb71f03cfb836c |
| tools | pulumi-resource-search | top | 347f9266497294660354199156e84cbe89f03552f9d449fcfd0f7439e675cc41 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
