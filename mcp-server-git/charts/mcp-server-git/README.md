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


# What is mcp-server-git?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.1-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-git/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-git/2026.1.14?logo=docker&logoColor=fff&label=2026.1.14)](https://hub.docker.com/r/acuvity/mcp-server-git)
[![PyPI](https://img.shields.io/badge/2026.1.14-3775A9?logo=pypi&logoColor=fff&label=mcp-server-git)](https://github.com/modelcontextprotocol/servers/tree/HEAD/src/git)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-git/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-git&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-git%3A2026.1.14%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Tools to read, search, and manipulate Git repositories.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-server-git original [sources](https://github.com/modelcontextprotocol/servers/tree/HEAD/src/git).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-git/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-git/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-git/charts/mcp-server-git/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-server-git run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-git/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-git#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Anthropic, PBC. ](https://github.com/modelcontextprotocol/servers/tree/HEAD/src/git) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-server-git ](https://github.com/modelcontextprotocol/servers/tree/HEAD/src/git)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-server-git ](https://github.com/modelcontextprotocol/servers/tree/HEAD/src/git)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-git/charts/mcp-server-git)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-git/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.1`
  - container: `1.0.1-2026.1.14`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-git:1.0.1`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-git:1.0.1-2026.1.14`

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
helm install mcp-server-git oci://docker.io/acuvity/mcp-server-git --version 1.0.1
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-git --version 1.0.1
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-git --version 1.0.1
````

Upgrade will helm

```console
helm upgrade mcp-server-git oci://docker.io/acuvity/mcp-server-git --version 1.0.1
```

Uninstall with helm

```console
helm uninstall mcp-server-git
```

From there your MCP server mcp-server-git will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-git` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-git
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-git` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-git oci://docker.io/acuvity/mcp-server-git --version 1.0.1 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-git oci://docker.io/acuvity/mcp-server-git --version 1.0.1 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-git oci://docker.io/acuvity/mcp-server-git --version 1.0.1 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-git oci://docker.io/acuvity/mcp-server-git --version 1.0.1 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>git_status</summary>

**Description**:

```
Shows the working tree status
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_diff_unstaged</summary>

**Description**:

```
Shows changes in the working directory that are not yet staged
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| context_lines | integer | not set | No
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_diff_staged</summary>

**Description**:

```
Shows changes that are staged for commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| context_lines | integer | not set | No
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_diff</summary>

**Description**:

```
Shows differences between branches or commits
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| context_lines | integer | not set | No
| repo_path | string | not set | Yes
| target | string | not set | Yes
</details>
<details>
<summary>git_commit</summary>

**Description**:

```
Records changes to the repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | not set | Yes
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_add</summary>

**Description**:

```
Adds file contents to the staging area
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| files | array | not set | Yes
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_reset</summary>

**Description**:

```
Unstages all staged changes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_log</summary>

**Description**:

```
Shows the commit logs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end_timestamp | any | End timestamp for filtering commits. Accepts: ISO 8601 format (e.g., '2024-01-15T14:30:25'), relative dates (e.g., '2 weeks ago', 'yesterday'), or absolute dates (e.g., '2024-01-15', 'Jan 15 2024') | No
| max_count | integer | not set | No
| repo_path | string | not set | Yes
| start_timestamp | any | Start timestamp for filtering commits. Accepts: ISO 8601 format (e.g., '2024-01-15T14:30:25'), relative dates (e.g., '2 weeks ago', 'yesterday'), or absolute dates (e.g., '2024-01-15', 'Jan 15 2024') | No
</details>
<details>
<summary>git_create_branch</summary>

**Description**:

```
Creates a new branch from an optional base branch
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base_branch | any | not set | No
| branch_name | string | not set | Yes
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_checkout</summary>

**Description**:

```
Switches branches
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch_name | string | not set | Yes
| repo_path | string | not set | Yes
</details>
<details>
<summary>git_show</summary>

**Description**:

```
Shows the contents of a commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repo_path | string | not set | Yes
| revision | string | not set | Yes
</details>
<details>
<summary>git_branch</summary>

**Description**:

```
List Git branches
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch_type | string | Whether to list local branches ('local'), remote branches ('remote') or all branches('all'). | Yes
| contains | any | The commit sha that branch should contain. Do not pass anything to this param if no commit sha is specified | No
| not_contains | any | The commit sha that branch should NOT contain. Do not pass anything to this param if no commit sha is specified | No
| repo_path | string | The path to the Git repository. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | git_add | description | acbb1287741f13ed1321c0440055bb47469c4b80c151d7cf63c066013f7f99bc |
| tools | git_branch | description | d124e3dba2d5b3f4bc2e23d8ebad95a094192aec2d5c9853f723f5e874edcbf3 |
| tools | git_branch | branch_type | d98fc69f3ada12a4206cc8041194db3adc993e3575eb83f99d290444d4a704d9 |
| tools | git_branch | contains | 3aea6dbb8341c770d5008dd1f2bde7de4e3b264345fa72e83ee34e2a1b979e3f |
| tools | git_branch | not_contains | c6778a7e39ce013797b10e9446ff627dfc4dd030536b4eea984cacd4d3f1b404 |
| tools | git_branch | repo_path | 686efaada41b9d54430f2a73c0588d635022e8ddda3efb98167d15fde8ffe547 |
| tools | git_checkout | description | cef303fb5169c48c7afb36c66738ac6f54bd19edd08b96cba0ea07796900a7ec |
| tools | git_commit | description | 06de1d865828b1bbd62ed46e982e9fc8402f9a84a00b9f0f36250aa85b1e4beb |
| tools | git_create_branch | description | af53f21afe3f7e12c569649756872a2601f7fe9ec37ed39e70a7e16b5d3322f6 |
| tools | git_diff | description | ecc4cfd56a6bcc34709cd89b8c0ac0d1075529e351b3eb46d9452b81d224ff51 |
| tools | git_diff_staged | description | fe98ec6b642e743c352dfc6ba5d4ba070e02ccaeeb7bafc3f83488cd9a97c1cb |
| tools | git_diff_unstaged | description | a0785f5b24f18cff8e217c8d19d5a82feeb88a3b2d7e54c4419d1233b142ab51 |
| tools | git_log | description | 2dde51c25be72faa18b13b012a04c680b7055345964936b9cadac78b33ae9f10 |
| tools | git_log | end_timestamp | 96ee6006d39020184393056cc402f4aa5336ebb66b674d79f216f20ac4cb1bbc |
| tools | git_log | start_timestamp | bfada74c37e2d628f41285ffd3e66b296ec3af82ef1561642fa2ff7d9e3d7831 |
| tools | git_reset | description | 27a9a7645420815c2b823de535988cc834a87548f668c340d2fea14cdd0cb2fd |
| tools | git_show | description | eadfec3e4527b7281b53ef4a55bce41d087818c0c0d65d3bd4dc197f494aede6 |
| tools | git_status | description | 6d422a00f372216df99866e4d8aca786b7cdae40939876d12052ddca2af65eed |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
