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


# What is mcp-server-azure-devops?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-azure-devops/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-azure-devops/0.1.43?logo=docker&logoColor=fff&label=0.1.43)](https://hub.docker.com/r/acuvity/mcp-server-azure-devops)
[![PyPI](https://img.shields.io/badge/0.1.43-3775A9?logo=pypi&logoColor=fff&label=@tiberriver256/mcp-server-azure-devops)](https://github.com/Tiberriver256/mcp-server-azure-devops)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-azure-devops/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-azure-devops&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AZURE_DEVOPS_AUTH_METHOD%22%2C%22-e%22%2C%22AZURE_DEVOPS_DEFAULT_PROJECT%22%2C%22-e%22%2C%22AZURE_DEVOPS_ORG_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-azure-devops%3A0.1.43%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Azure DevOps integration for repository management, work items, and pipelines.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @tiberriver256/mcp-server-azure-devops original [sources](https://github.com/Tiberriver256/mcp-server-azure-devops).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-azure-devops/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure-devops/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure-devops/charts/mcp-server-azure-devops/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @tiberriver256/mcp-server-azure-devops run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure-devops/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure-devops#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Author ](https://github.com/Tiberriver256/mcp-server-azure-devops) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @tiberriver256/mcp-server-azure-devops ](https://github.com/Tiberriver256/mcp-server-azure-devops)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @tiberriver256/mcp-server-azure-devops ](https://github.com/Tiberriver256/mcp-server-azure-devops)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure-devops/charts/mcp-server-azure-devops)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure-devops/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.43`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-azure-devops:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-azure-devops:1.0.0-0.1.43`

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

**Mandatory Environment variables**:
  - `AZURE_DEVOPS_AUTH_METHOD` environment variable to be set by env.AZURE_DEVOPS_AUTH_METHOD
  - `AZURE_DEVOPS_DEFAULT_PROJECT` environment variable to be set by env.AZURE_DEVOPS_DEFAULT_PROJECT
  - `AZURE_DEVOPS_ORG_URL` environment variable to be set by env.AZURE_DEVOPS_ORG_URL

# How to install


Install will helm

```console
helm install mcp-server-azure-devops oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-azure-devops oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-azure-devops
```

From there your MCP server mcp-server-azure-devops will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-azure-devops` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-azure-devops
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-azure-devops` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-azure-devops oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-azure-devops oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-azure-devops oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-azure-devops oci://docker.io/acuvity/mcp-server-azure-devops --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (43)
<details>
<summary>get_me</summary>

**Description**:

```
Get details of the authenticated user (id, displayName, email)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_organizations</summary>

**Description**:

```
List all Azure DevOps organizations accessible to the current authentication
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_projects</summary>

**Description**:

```
List all projects in an organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| continuationToken | number | Gets the projects after the continuation token provided | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| skip | number | Number of projects to skip | No
| stateFilter | number | Filter on team project state (0: all, 1: well-formed, 2: creating, 3: deleting, 4: new) | No
| top | number | Maximum number of projects to return | No
</details>
<details>
<summary>get_project</summary>

**Description**:

```
Get details of a specific project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
</details>
<details>
<summary>get_project_details</summary>

**Description**:

```
Get comprehensive details of a project including process, work item types, and teams
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expandTeamIdentity | boolean | Expand identity information in the team objects | No
| includeFields | boolean | Include field information for work item types | No
| includeProcess | boolean | Include process information in the project result | No
| includeTeams | boolean | Include associated teams in the project result | No
| includeWorkItemTypes | boolean | Include work item types and their structure | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
</details>
<details>
<summary>get_repository</summary>

**Description**:

```
Get details of a specific repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
</details>
<details>
<summary>get_repository_details</summary>

**Description**:

```
Get detailed information about a repository including statistics and refs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branchName | string | Name of specific branch to get statistics for (if includeStatistics is true) | No
| includeRefs | boolean | Whether to include repository refs | No
| includeStatistics | boolean | Whether to include branch statistics | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| refFilter | string | Optional filter for refs (e.g., "heads/" or "tags/") | No
| repositoryId | string | The ID or name of the repository | Yes
</details>
<details>
<summary>list_repositories</summary>

**Description**:

```
List repositories in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeLinks | boolean | Whether to include reference links | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
</details>
<details>
<summary>get_file_content</summary>

**Description**:

```
Get content of a file or directory from a repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| path | string | Path to the file or folder | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
| version | string | The version (branch, tag, or commit) to get content from | No
| versionType | string | Type of version specified (branch, commit, or tag) | No
</details>
<details>
<summary>get_all_repositories_tree</summary>

**Description**:

```
Displays a hierarchical tree view of files and directories across multiple Azure DevOps repositories within a project, based on their default branches
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | integer | Maximum depth to traverse within each repository (0 = unlimited) | No
| organizationId | string | The ID or name of the Azure DevOps organization (Default: unknown-organization) | No
| pattern | string | File pattern (wildcard characters allowed) to filter files by within each repository | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryPattern | string | Repository name pattern (wildcard characters allowed) to filter which repositories are included | No
</details>
<details>
<summary>get_repository_tree</summary>

**Description**:

```
Displays a hierarchical tree view of files and directories within a single repository starting from an optional path
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | integer | Maximum depth to traverse (0 = unlimited) | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| path | string | Path within the repository to start from | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
</details>
<details>
<summary>create_branch</summary>

**Description**:

```
Create a new branch from an existing one
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| newBranch | string | Name of the new branch to create (without "refs/heads/", e.g., "feature/my-branch") | Yes
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
| sourceBranch | string | Name of the branch to copy from (without "refs/heads/", e.g., "master") | Yes
</details>
<details>
<summary>create_commit</summary>

**Description**:

```
Create a commit on an existing branch using file changes.
- Provide plain branch names (no "refs/heads/").
- ⚠️ Each file path may appear only once per commit request—combine all edits to a file into a single change entry.
- Prefer multiple commits when you have sparse or unrelated edits; smaller focused commits keep review context clear.

🎯 RECOMMENDED: Use the SEARCH/REPLACE format (much easier, no line counting!).

**Option 1: SEARCH/REPLACE format (EASIEST)**
Simply provide the exact text to find and replace:
```json
{
  "changes": [{
    "path": "src/api/services/function-call.ts",
    "search": "return axios.post(apiUrl, payload, requestConfig);",
    "replace": "return axios.post(apiUrl, payload, requestConfig).then(r => { processResponse(r); return r; });"
  }]
}
```
The server fetches the file, performs the replacement, and generates the diff automatically.
No line counting, no hunk headers, no context lines needed!

**Option 2: UNIFIED DIFF format (Advanced)**
If you prefer full control, provide complete unified diffs:
- Each patch MUST have complete hunk headers: @@ -oldStart,oldLines +newStart,newLines @@
- CRITICAL: Every @@ marker MUST include line numbers. Do NOT use @@ without line ranges.
- Include 3-5 context lines before and after changes.
- For deletions: `--- a/filepath` and `+++ /dev/null`
- For additions: `--- /dev/null` and `+++ b/filepath`

Example unified diff:
```json
{
  "changes": [{
    "patch": "diff --git a/file.yaml b/file.yaml\n--- a/file.yaml\n+++ b/file.yaml\n@@ -4,7 +4,7 @@ spec:\n spec:\n   type: ClusterIP\n   ports:\n-    - port: 8080\n+    - port: 9090\n       targetPort: http\n"
  }]
}
```
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branchName | string | The branch to commit to (without "refs/heads/", e.g., "codex/test2-delete-main-py") | Yes
| changes | array | List of file changes as either unified git diffs OR search/replace pairs | Yes
| commitMessage | string | Commit message | Yes
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
</details>
<details>
<summary>list_commits</summary>

**Description**:

```
List recent commits on a branch including file-level diff content for each commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branchName | string | Branch name to list commits from | Yes
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
| skip | integer | Number of commits to skip from the newest | No
| top | integer | Maximum number of commits to return (Default: 10) | No
</details>
<details>
<summary>list_work_items</summary>

**Description**:

```
List work items in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| queryId | string | ID of a saved work item query | No
| skip | number | Number of work items to skip | No
| teamId | string | The ID of the team | No
| top | number | Maximum number of work items to return | No
| wiql | string | Work Item Query Language (WIQL) query | No
</details>
<details>
<summary>get_work_item</summary>

**Description**:

```
Get details of a specific work item
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expand | string | The level of detail to include in the response. Defaults to "all" if not specified. | No
| workItemId | number | The ID of the work item | Yes
</details>
<details>
<summary>create_work_item</summary>

**Description**:

```
Create a new work item
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additionalFields | object | Additional fields to set on the work item. Multi-line text fields (i.e., System.History, AcceptanceCriteria, etc.) must use HTML format. Do not use CDATA tags. | No
| areaPath | string | The area path for the work item | No
| assignedTo | string | The email or name of the user to assign the work item to | No
| description | string | Work item description in HTML format. Multi-line text fields (i.e., System.History, AcceptanceCriteria, etc.) must use HTML format. Do not use CDATA tags. | No
| iterationPath | string | The iteration path for the work item | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| parentId | number | The ID of the parent work item to create a relationship with | No
| priority | number | The priority of the work item | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| title | string | The title of the work item | Yes
| workItemType | string | The type of work item to create (e.g., "Task", "Bug", "User Story") | Yes
</details>
<details>
<summary>update_work_item</summary>

**Description**:

```
Update an existing work item
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additionalFields | object | Additional fields to update on the work item. Multi-line text fields (i.e., System.History, AcceptanceCriteria, etc.) must use HTML format. Do not use CDATA tags. | No
| areaPath | string | The updated area path for the work item | No
| assignedTo | string | The email or name of the user to assign the work item to | No
| description | string | Work item description in HTML format. Multi-line text fields (i.e., System.History, AcceptanceCriteria, etc.) must use HTML format. Do not use CDATA tags. | No
| iterationPath | string | The updated iteration path for the work item | No
| priority | number | The updated priority of the work item | No
| state | string | The updated state of the work item | No
| title | string | The updated title of the work item | No
| workItemId | number | The ID of the work item to update | Yes
</details>
<details>
<summary>manage_work_item_link</summary>

**Description**:

```
Add or remove links between work items
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | string | Optional comment explaining the link | No
| newRelationType | string | The new relation type to use when updating a link | No
| operation | string | The operation to perform on the link | Yes
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| relationType | string | The reference name of the relation type (e.g., "System.LinkTypes.Hierarchy-Forward") | Yes
| sourceWorkItemId | number | The ID of the source work item | Yes
| targetWorkItemId | number | The ID of the target work item | Yes
</details>
<details>
<summary>search_code</summary>

**Description**:

```
Search for code across repositories in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | Optional filters to narrow search results | No
| includeContent | boolean | Whether to include full file content in results (default: true) | No
| includeSnippet | boolean | Whether to include code snippets in results (default: true) | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project to search in (Default: dummy). If not provided, the default project will be used. | No
| searchText | string | The text to search for | Yes
| skip | integer | Number of results to skip for pagination (default: 0) | No
| top | integer | Number of results to return (default: 100, max: 1000) | No
</details>
<details>
<summary>search_wiki</summary>

**Description**:

```
Search for content across wiki pages in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | Optional filters to narrow search results | No
| includeFacets | boolean | Whether to include faceting in results (default: true) | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project to search in (Default: dummy). If not provided, the default project will be used. | No
| searchText | string | The text to search for in wikis | Yes
| skip | integer | Number of results to skip for pagination (default: 0) | No
| top | integer | Number of results to return (default: 100, max: 1000) | No
</details>
<details>
<summary>search_work_items</summary>

**Description**:

```
Search for work items across projects in Azure DevOps
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | Optional filters to narrow search results | No
| includeFacets | boolean | Whether to include faceting in results (default: true) | No
| orderBy | array | Options for sorting search results | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project to search in (Default: dummy). If not provided, the default project will be used. | No
| searchText | string | The text to search for in work items | Yes
| skip | integer | Number of results to skip for pagination (default: 0) | No
| top | integer | Number of results to return (default: 100, max: 1000) | No
</details>
<details>
<summary>create_pull_request</summary>

**Description**:

```
Create a new pull request, including reviewers, linked work items, and optional tags
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additionalProperties | object | Additional properties to set on the pull request | No
| description | string | The description of the pull request (markdown is supported) | No
| isDraft | boolean | Whether the pull request should be created as a draft | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| repositoryId | string | The ID or name of the repository | Yes
| reviewers | array | List of reviewer email addresses or IDs | No
| sourceRefName | string | The source branch name (e.g., refs/heads/feature-branch) | Yes
| tags | array | List of tags to apply to the pull request | No
| targetRefName | string | The target branch name (e.g., refs/heads/main) | Yes
| title | string | The title of the pull request | Yes
| workItemRefs | array | List of work item IDs to link to the pull request | No
</details>
<details>
<summary>list_pull_requests</summary>

**Description**:

```
List pull requests in a repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| creatorId | string | Filter by creator ID (must be a UUID string) | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| pullRequestId | number | If provided, return only the matching pull request ID | No
| repositoryId | string | The ID or name of the repository | Yes
| reviewerId | string | Filter by reviewer ID (must be a UUID string) | No
| skip | number | Number of pull requests to skip for pagination | No
| sourceRefName | string | Filter by source branch name | No
| status | string | Filter by pull request status | No
| targetRefName | string | Filter by target branch name | No
| top | number | Maximum number of pull requests to return (default: 10) | No
</details>
<details>
<summary>get_pull_request_comments</summary>

**Description**:

```
Get comments from a specific pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeDeleted | boolean | Whether to include deleted comments | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| pullRequestId | number | The ID of the pull request | Yes
| repositoryId | string | The ID or name of the repository | Yes
| threadId | number | The ID of the specific thread to get comments from | No
| top | number | Maximum number of threads/comments to return | No
</details>
<details>
<summary>add_pull_request_comment</summary>

**Description**:

```
Add a comment to a pull request (reply to existing comments or create new threads)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The content of the comment in markdown | Yes
| filePath | string | The path of the file to comment on (for new thread on file) | No
| lineNumber | number | The line number to comment on (for new thread on file) | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| parentCommentId | number | ID of the parent comment when replying to an existing comment | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| pullRequestId | number | The ID of the pull request | Yes
| repositoryId | string | The ID or name of the repository | Yes
| status | string | The status to set for a new thread | No
| threadId | number | The ID of the thread to add the comment to | No
</details>
<details>
<summary>update_pull_request</summary>

**Description**:

```
Update an existing pull request with new properties, manage reviewers and work items, and add or remove tags
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addReviewers | array | List of reviewer email addresses or IDs to add | No
| addTags | array | List of tags to add to the pull request | No
| addWorkItemIds | array | List of work item IDs to link to the pull request | No
| additionalProperties | object | Additional properties to update on the pull request | No
| description | string | The updated description of the pull request | No
| isDraft | boolean | Whether the pull request should be marked as a draft (true) or unmarked (false) | No
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| pullRequestId | number | The ID of the pull request to update | Yes
| removeReviewers | array | List of reviewer email addresses or IDs to remove | No
| removeTags | array | List of tags to remove from the pull request | No
| removeWorkItemIds | array | List of work item IDs to unlink from the pull request | No
| repositoryId | string | The ID or name of the repository | Yes
| status | string | The updated status of the pull request | No
| title | string | The updated title of the pull request | No
</details>
<details>
<summary>get_pull_request_changes</summary>

**Description**:

```
Get the files changed in a pull request, their unified diffs, source/target branch names, and the status of policy evaluations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| pullRequestId | number | The ID of the pull request | Yes
| repositoryId | string | The ID or name of the repository | Yes
</details>
<details>
<summary>get_pull_request_checks</summary>

**Description**:

```
Summarize the latest status checks and policy evaluations for a pull request.
- Surfaces pipeline and run identifiers so you can jump straight to the blocking validation.
- Pair with pipeline tools (e.g., get_pipeline_run, pipeline_timeline) to inspect failures in depth.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | string | The ID or name of the organization (Default: unknown-organization) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| pullRequestId | number | The ID of the pull request | Yes
| repositoryId | string | The ID or name of the repository | Yes
</details>
<details>
<summary>list_pipelines</summary>

**Description**:

```
List pipelines in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| orderBy | string | Order by field and direction (e.g., "createdDate desc") | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| top | number | Maximum number of pipelines to return | No
</details>
<details>
<summary>get_pipeline</summary>

**Description**:

```
Get details of a specific pipeline
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pipelineId | integer | The numeric ID of the pipeline to retrieve | Yes
| pipelineVersion | integer | The version of the pipeline to retrieve (latest if not specified) | No
| projectId | string | The ID or name of the project (Default: dummy) | No
</details>
<details>
<summary>list_pipeline_runs</summary>

**Description**:

```
List recent runs for a pipeline
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to filter by (e.g., "main" or "refs/heads/main") | No
| continuationToken | string | Continuation token for pagination | No
| createdFrom | string | Filter runs created at or after this time (ISO 8601) | No
| createdTo | string | Filter runs created at or before this time (ISO 8601) | No
| orderBy | string | Sort order for run creation date | No
| pipelineId | integer | Pipeline numeric ID | Yes
| projectId | string | The ID or name of the project (Default: dummy) | No
| result | string | Filter by final run result | No
| state | string | Filter by current run state | No
| top | integer | Maximum number of runs to return (1-100) | No
</details>
<details>
<summary>get_pipeline_run</summary>

**Description**:

```
Get details for a specific pipeline run
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pipelineId | integer | Optional guard; validates the run belongs to this pipeline | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| runId | integer | Pipeline run identifier | Yes
</details>
<details>
<summary>download_pipeline_artifact</summary>

**Description**:

```
Download a file from a pipeline run artifact and return its textual content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| artifactPath | string | Path to the desired file inside the artifact (format: <artifactName>/<path/to/file>) | Yes
| pipelineId | integer | Optional guard; validates the run belongs to this pipeline | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| runId | integer | Pipeline run identifier | Yes
</details>
<details>
<summary>pipeline_timeline</summary>

**Description**:

```
Retrieve the timeline of stages and jobs for a pipeline run, to reduce the amount of data returned, you can filter by state and result
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pipelineId | integer | Optional pipeline numeric ID for reference only | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| result | any | Optional result filter (single value or array) applied to returned timeline records | No
| runId | integer | Run identifier | Yes
| state | any | Optional state filter (single value or array) applied to returned timeline records | No
| timelineId | string | Optional timeline identifier to select a specific timeline record | No
</details>
<details>
<summary>get_pipeline_log</summary>

**Description**:

```
Retrieve a specific pipeline log using the timeline log identifier
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| endLine | integer | Optional ending line number for the log segment | No
| format | string | Optional format for the log contents (plain or json) | No
| logId | integer | Log identifier from the timeline record | Yes
| pipelineId | integer | Optional pipeline numeric ID for reference only | No
| projectId | string | The ID or name of the project (Default: dummy) | No
| runId | integer | Pipeline run identifier | Yes
| startLine | integer | Optional starting line number for the log segment | No
</details>
<details>
<summary>trigger_pipeline</summary>

**Description**:

```
Trigger a pipeline run
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | The branch to run the pipeline on (e.g., "main", "feature/my-branch"). If left empty, the default branch will be used | No
| pipelineId | integer | The numeric ID of the pipeline to trigger | Yes
| projectId | string | The ID or name of the project (Default: dummy) | No
| stagesToSkip | array | Stages to skip in the pipeline run | No
| templateParameters | object | Parameters for template-based pipelines | No
| variables | object | Variables to pass to the pipeline run | No
</details>
<details>
<summary>get_wikis</summary>

**Description**:

```
Get details of wikis in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | any | The ID or name of the organization (Default: unknown-organization) | No
| projectId | any | The ID or name of the project (Default: dummy) | No
</details>
<details>
<summary>get_wiki_page</summary>

**Description**:

```
Get the content of a wiki page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | any | The ID or name of the organization (Default: unknown-organization) | No
| pagePath | string | The path of the page within the wiki | Yes
| projectId | any | The ID or name of the project (Default: dummy) | No
| wikiId | string | The ID or name of the wiki | Yes
</details>
<details>
<summary>create_wiki</summary>

**Description**:

```
Create a new wiki in the project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| mappedPath | any | Folder path inside repository which is shown as Wiki (only for codeWiki) | No
| name | string | The name of the new wiki | Yes
| organizationId | any | The ID or name of the organization (Default: unknown-organization) | No
| projectId | any | The ID or name of the project (Default: dummy) | No
| repositoryId | any | The ID of the repository to associate with the wiki (required for codeWiki) | No
| type | string | Type of wiki to create (projectWiki or codeWiki) | No
</details>
<details>
<summary>update_wiki_page</summary>

**Description**:

```
Update content of a wiki page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | any | Optional comment for the update | No
| content | string | The new content for the wiki page in markdown format | Yes
| organizationId | any | The ID or name of the organization (Default: unknown-organization) | No
| pagePath | string | Path of the wiki page to update | Yes
| projectId | any | The ID or name of the project (Default: dummy) | No
| wikiId | string | The ID or name of the wiki | Yes
</details>
<details>
<summary>list_wiki_pages</summary>

**Description**:

```
List pages within an Azure DevOps wiki
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organizationId | any | The ID or name of the organization (Default: unknown-organization) | No
| projectId | any | The ID or name of the project (Default: dummy) | No
| wikiId | string | The ID or name of the wiki | Yes
</details>
<details>
<summary>create_wiki_page</summary>

**Description**:

```
Create a new page in a wiki. If the page already exists at the specified path, it will be updated.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| comment | string | Optional comment for the creation or update | No
| content | string | The content for the new wiki page in markdown format | Yes
| organizationId | any | The ID or name of the organization (Default: unknown-organization) | No
| pagePath | any | Path of the wiki page to create. If the path does not exist, it will be created. Defaults to the wiki root (/). Example: /ParentPage/NewPage | No
| projectId | any | The ID or name of the project (Default: dummy) | No
| wikiId | string | The ID or name of the wiki | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_pull_request_comment | description | 9f7519ec0b4a1e92e153cc9ae49ab368acf37c24fdfe79d45bf4afd68f196448 |
| tools | add_pull_request_comment | content | ee2d16bf1a75dffbae4ac0b0163b8770c1422b9f8b0b31dc86b3e5197e51b3eb |
| tools | add_pull_request_comment | filePath | a65c76259f733bf4841377941eaf656e161a5f50309736cc9ac34026f36a5b81 |
| tools | add_pull_request_comment | lineNumber | a08fb5fa017612f04f709fbef0a8a96cfa7e26c2233cbc8c07530bb381615844 |
| tools | add_pull_request_comment | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | add_pull_request_comment | parentCommentId | 3a9855b77c13f83d14ababff746d083d0f3a429dfd10df32ba76fe0e24f3e4bc |
| tools | add_pull_request_comment | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | add_pull_request_comment | pullRequestId | faf140fca98b8a45fc0c9dc4461ab9413be8326738129cd5d090465518d984fe |
| tools | add_pull_request_comment | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | add_pull_request_comment | status | ffabf76df390217c5584db6a238698fa71738990aabdbb41cf3058dd0c5dd319 |
| tools | add_pull_request_comment | threadId | d3decffddc296ca72b0ca9a08b4f035eb7149cb508377250dec9509cfe526832 |
| tools | create_branch | description | ded66835d556738922df328692d05d6fd3d91115c8780e9bcc7094524bfe86cd |
| tools | create_branch | newBranch | 4a4819fd7fddf77ae488085d27c5e790ab202ae01e37c2437fd02e4332263392 |
| tools | create_branch | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | create_branch | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | create_branch | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | create_branch | sourceBranch | a9f5b34159c283e69c3a1388dd7ce34d3155c4196ea86bca9919ebd3d38b9ee9 |
| tools | create_commit | description | 62c1907416cbeb65477d30afccf4de0f7d795c19104fe356d2f6bd90c7283061 |
| tools | create_commit | branchName | c0859107733ec445a43dbe600df19b6cfa5555440bbc742c43e3d86daf4485b2 |
| tools | create_commit | changes | 877036ed0397e503383acf75f574ad027526ad2f87bc85a9c523ca9e57f3cdaa |
| tools | create_commit | commitMessage | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | create_commit | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | create_commit | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | create_commit | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | create_pull_request | description | 438bd552e9937251bc456d2100714a766003943e316179a50bc9ff49cf54d244 |
| tools | create_pull_request | additionalProperties | f29eb78476fa56c582446f2e64a5bf31ee4c76441197d37b854d54b1ebd1367d |
| tools | create_pull_request | description | f5ddbb7163df84576aa7ed0cc776499df12f0d859d115d47ccfc075fafeeb943 |
| tools | create_pull_request | isDraft | fc1ebd4bb02f777c1a5fb6665e78069749476d7ae61d824e85f1abb3d36a9322 |
| tools | create_pull_request | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | create_pull_request | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | create_pull_request | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | create_pull_request | reviewers | 7699755d118f22187776790eaf762040d1d52c1f4fa5fb647896e751517bdd44 |
| tools | create_pull_request | sourceRefName | 9485211a2d365d553c7837244a3fb308bc673a0b835481fa1e254078b804a2ad |
| tools | create_pull_request | tags | 7806a0f800971e85a2f7b74fa6cb2756e37394e18c8c03d1c8fa93beb95ac9bc |
| tools | create_pull_request | targetRefName | 6fb245df5be7d9a6f883a102f56cef002848a14fbc5bf162363d4395d47630b5 |
| tools | create_pull_request | title | c04c47bf2f47f484df617492655df04711f8dc4320b2c1fb9dfcbd6defdb18bc |
| tools | create_pull_request | workItemRefs | d560f7bd59700bd8a96094e68ae4a51b7a09950aa589c9b6b0a9a11d1648ebcc |
| tools | create_wiki | description | bde4d33becd59d2f22896a6cc66a1b2f3ca3121482eeab23407546dedc3a5cb8 |
| tools | create_wiki | mappedPath | 97d7dca602585dad7a02efee2242ed358eea3560d01cf97d40d22e2daaddeb1a |
| tools | create_wiki | name | f7bab0207a2cf22fe9a7a1a9e83083848807e548eb7dced7162d6ca60a6b4ec1 |
| tools | create_wiki | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | create_wiki | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | create_wiki | repositoryId | da1440b528913e51eaa132c3e51e6a1f041942a9438a65c4489868c3b25e0940 |
| tools | create_wiki | type | 383bce361fc08d5071e56a83e54f569ea1286d03fd6162b13880aa4e2ece74c4 |
| tools | create_wiki_page | description | 29c6c9e53d803075c361c5b66377931f309096182548b9ed17882cb8c49e11cf |
| tools | create_wiki_page | comment | 0f5441e9ef75e3d773f02f1c5edd742c358f3ed62b76c337dcd090af21098032 |
| tools | create_wiki_page | content | 56cda341901186dd38bf582954088c1118749de2cdc530da4765f9dc8ecebda4 |
| tools | create_wiki_page | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | create_wiki_page | pagePath | f960c8738038d524128e5511e4405b18be2bb8046998c935a8666cffb549c80f |
| tools | create_wiki_page | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | create_wiki_page | wikiId | 78550a0c4ca8efa5ee86b117ad438fdbd5060fbeed8d645d5dabd48b052eaf3e |
| tools | create_work_item | description | 438508a61955ee2e09252b89a5a72d22b458c5fc601c85ba5cbdd0b60369f1fe |
| tools | create_work_item | additionalFields | 079cb4e5ea2e193405d4000e4e7134b871f9ac0adb77c154817361f97edbeede |
| tools | create_work_item | areaPath | 9757fac9cc1c35c5741ada321f5121ffa6c82a70bf82e2e4c77dfb6c4bfe2d64 |
| tools | create_work_item | assignedTo | c0c5f209ac0c7ec3442571e1eadb49d0b9f383cb016b60015362ce09daff015e |
| tools | create_work_item | description | 7dd97974eb4ce52d49e21e1330423c5c214da8d4b201cc23b570ba47b3a95603 |
| tools | create_work_item | iterationPath | 6822e4b4e77f0e3a3dbafdffdd61c4c8b69c6147af211b17a3bcb8a1bf96c54a |
| tools | create_work_item | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | create_work_item | parentId | 22b7de22c6273b78a33970f2e00d4705a67fc3ebf2869ffdb1eb26be40ac2b07 |
| tools | create_work_item | priority | bc71633191571e19dc0b2f453f1516fcbb14fd67fbb5d83c216f24736353b3ec |
| tools | create_work_item | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | create_work_item | title | 8886851671d368f793dcd912835deb0e2c2c6d2522c42252b65ded204bf40041 |
| tools | create_work_item | workItemType | d70897a90d287102c3282e884c418c0900fb61a7681ffad29375af537029b74e |
| tools | download_pipeline_artifact | description | 73328d56180f1db1dae7f659aa55abc4be770c18a79349668aa12dd5498fec95 |
| tools | download_pipeline_artifact | artifactPath | 4d40c1a515c5da932cd2c51365a71ccd97695458b5743f89c85482249bb801e0 |
| tools | download_pipeline_artifact | pipelineId | 0341ab6cacc44a0ef6cc39cf26598326a107aec48be14387fa89cf67aebd4d39 |
| tools | download_pipeline_artifact | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | download_pipeline_artifact | runId | 67642779884a6f188a54ac644b28f31d70f5fa549aeb014f3533e6a0b0e39471 |
| tools | get_all_repositories_tree | description | 751c855a11f9ecc11c0dc3a71502da74a7f190b9144a04ddc64294423f1e3c7b |
| tools | get_all_repositories_tree | depth | 9d649941d89d15735723a23948d6883cf8d8cde4baaf68e25872219c8e7f54ae |
| tools | get_all_repositories_tree | organizationId | 45a145894e6832430715feb14051c28bc4155b6902b0377b8e75c7a7f0ae4d3e |
| tools | get_all_repositories_tree | pattern | faf2ae58055b747b347c291b6b05abfc8b081b7b7a3558aab89c496f291b6270 |
| tools | get_all_repositories_tree | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_all_repositories_tree | repositoryPattern | 23a224d8bf54db16effdd286689ca80713e0937a030496674fb088a2dd5f3c08 |
| tools | get_file_content | description | d8fa341d861af4d67fa20d3cfcb01d2f8254666dc611e4e7f167c736a196fa38 |
| tools | get_file_content | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_file_content | path | d7b7f3273fb91954cf27f4b8fe1acdac6c985d9a50d4c408ea51fa1136b512f9 |
| tools | get_file_content | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_file_content | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_file_content | version | 05ef8d6918062c09540b4eb2eea75cd79544c00917c1baf2a28a45cca292bb89 |
| tools | get_file_content | versionType | 74e79d233d22b6886a4e6fb4f09fdbc229683fdfd9f6e1e369fe82443ef1ef2e |
| tools | get_me | description | 33d3b1695297b27d0e1dcb0f664b31c331cbbeb90183c0daa946cf08c7bd1e6b |
| tools | get_pipeline | description | 21b37aaa8caf4028c729bfb6fc59be8612045d83a73573ad55c4f9e28959c9db |
| tools | get_pipeline | pipelineId | 967805b0daea9b77f8272a8ce7b834931086cd27497bf4d178016c4e7eed018f |
| tools | get_pipeline | pipelineVersion | 9f4d20c046eb5ba7685a731295851b0c1e4554819912e9bc95c86b8a2f4b12f2 |
| tools | get_pipeline | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pipeline_log | description | d197b2a8b610432199ae462eb6542697c7661f7e8a4fa224f48055310a9db4e2 |
| tools | get_pipeline_log | endLine | 9f4162d4bda6c73e65b0cdb7de6684b2c7550a35a5aa7bb3c8cb29834143c61b |
| tools | get_pipeline_log | format | 77617d306dc9d21f4fe84172b319523b8b0d71b5252861030dab6fb6cd77fc1a |
| tools | get_pipeline_log | logId | ef394c6ddd53c48b6313f7a79e06d671bedf7172cb0e29b7b369ad57848edaea |
| tools | get_pipeline_log | pipelineId | 1062b58d44d4ea4283dac897077edc284a0d93577a5e994af19158396e66bab3 |
| tools | get_pipeline_log | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pipeline_log | runId | 67642779884a6f188a54ac644b28f31d70f5fa549aeb014f3533e6a0b0e39471 |
| tools | get_pipeline_log | startLine | 90be271c934158252773c935b12e30b5c4cc98dfafaf448a582b237c9db0fc45 |
| tools | get_pipeline_run | description | 5ca67ae749466f5cd36833ae4e1b7a0a64cf0534a853501b57b112add068a420 |
| tools | get_pipeline_run | pipelineId | 0341ab6cacc44a0ef6cc39cf26598326a107aec48be14387fa89cf67aebd4d39 |
| tools | get_pipeline_run | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pipeline_run | runId | 67642779884a6f188a54ac644b28f31d70f5fa549aeb014f3533e6a0b0e39471 |
| tools | get_project | description | e6712b6fce183aa5bd921363a8279ee29647a257a79449c7cde1059257cd2d30 |
| tools | get_project | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_project | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_project_details | description | 1b3b67953b74557bc1c54d70861723599577094404c86004e032fb85bd7e32ab |
| tools | get_project_details | expandTeamIdentity | 2db1e43434ac8421ac9a8c4652235c79bb911d38af98e3e9713819ec3bf5fabf |
| tools | get_project_details | includeFields | ac6c9457091e41174602256453d327e5b9c733e0679eb69945b6befba64b0c7e |
| tools | get_project_details | includeProcess | 7f35fff308f463c52b8966b4552298cb2b533c984263ec07280f104933972490 |
| tools | get_project_details | includeTeams | 2261cdd6a2e7b2f1e25d5bb82613ee88f1fd6a2a30dda5248bfb017f265fa4e6 |
| tools | get_project_details | includeWorkItemTypes | 5e24f07d0c3b56704119a6367070ce6e9f6e61e84c7272964086dc71e94cec75 |
| tools | get_project_details | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_project_details | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pull_request_changes | description | 25e794c9870ff28299622b123acb35314c8a17615b8dfe498b0e7384da50f7f6 |
| tools | get_pull_request_changes | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_pull_request_changes | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pull_request_changes | pullRequestId | faf140fca98b8a45fc0c9dc4461ab9413be8326738129cd5d090465518d984fe |
| tools | get_pull_request_changes | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_pull_request_checks | description | 12d693a36c387c1bb5b7ccd4327f98b569ee4e52350ebc802a40f28a0db7e148 |
| tools | get_pull_request_checks | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_pull_request_checks | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pull_request_checks | pullRequestId | faf140fca98b8a45fc0c9dc4461ab9413be8326738129cd5d090465518d984fe |
| tools | get_pull_request_checks | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_pull_request_comments | description | a730322602d53fca58d7213d941db6c36fa59c592e34062d1f9539d38aec0308 |
| tools | get_pull_request_comments | includeDeleted | 7919ed9ff4de588ab7c4b6feb10d4815bea1814188aa1b32f76bdc09034bed6f |
| tools | get_pull_request_comments | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_pull_request_comments | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_pull_request_comments | pullRequestId | faf140fca98b8a45fc0c9dc4461ab9413be8326738129cd5d090465518d984fe |
| tools | get_pull_request_comments | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_pull_request_comments | threadId | 35382c7caecdb7192d98f334bb26a518d8ad57a0b72a42ae8fbc85f8f1676044 |
| tools | get_pull_request_comments | top | c6e9d5edb336a1aabc61a9e8b74ef433a3851f8f08a8b5bb1e90f2021eef0eb0 |
| tools | get_repository | description | 89fad20506b62eb2ba6a73c196d6f60a04d03643e8dd7028503ab057ee653b0e |
| tools | get_repository | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_repository | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_repository | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_repository_details | description | 4e892a94b4e55600d43e6a028c1f9629924b0082097429d3e25786df96fc8e9b |
| tools | get_repository_details | branchName | 45d735d6a13909090ba6944a48f1ee74f9b2b6eaef1f3167f67849d0c50c6161 |
| tools | get_repository_details | includeRefs | de9abeecb220d78d3d497991696151646fbeb3b0e69498b019c62a721d1c77ff |
| tools | get_repository_details | includeStatistics | 54603ac4c5596ffd1006655ceb9ec69c0958abd54e1394a9de01387581a5ed7f |
| tools | get_repository_details | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_repository_details | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_repository_details | refFilter | 70bbd90e9678f46b907bb1b82bf4568290fdfa5e78c6c3072f791a624b59a7c8 |
| tools | get_repository_details | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_repository_tree | description | a512abfa58a8cca23783422e448ac4f113dab9a8dafffc02c04fbb85c350d494 |
| tools | get_repository_tree | depth | 285a8be4c4ff0565bc3aac970484e453b847514e91f708c0c35f7a7b7fc7cefc |
| tools | get_repository_tree | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_repository_tree | path | b500aab70836b580aed1ca22c8457812ac9df2390a585230d95cba07d61bc419 |
| tools | get_repository_tree | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_repository_tree | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | get_wiki_page | description | 376312ddc80ab4b81fe3641df1d638090060a4a14260c695519c8948aeb3bbb4 |
| tools | get_wiki_page | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_wiki_page | pagePath | 0247b6415ece2a73b548d6e9e8e438cbec8d5de27b71ea21b45f1b529ba1ba41 |
| tools | get_wiki_page | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_wiki_page | wikiId | 78550a0c4ca8efa5ee86b117ad438fdbd5060fbeed8d645d5dabd48b052eaf3e |
| tools | get_wikis | description | dfd5a86acae7212d664c8f31afa79335e98d397115af1cb429b824c141784ce6 |
| tools | get_wikis | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | get_wikis | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | get_work_item | description | 0e0fae1a4ed60686cbcf47bcaf735a6f3a42ab8caeacecaec3fdb6512de8a2ce |
| tools | get_work_item | expand | 02aa8717162266539b6ed4ab4edd28b4711e0ee31c3cb9242f5f8499f455e0d6 |
| tools | get_work_item | workItemId | 2dfe12e41305496ae1a2f82193f4be4c451b791ea81e544805780994d2295114 |
| tools | list_commits | description | 17a02a08857a2bc2825d528848925b08421d0416f07ab2ababd93705b70dc9d1 |
| tools | list_commits | branchName | 3d95d6cef02256a9ec37c423eaf4a105a0164b1e90c52b4535fdff76f2eb671b |
| tools | list_commits | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | list_commits | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_commits | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | list_commits | skip | 641ede42f74f802fd4d53d6671261f5e4f5d166534ee397eeff0d0a00ba1847d |
| tools | list_commits | top | 7200c05749d915d4b105715923946eb0b29464cb894cc34508bbde920eec17b2 |
| tools | list_organizations | description | bb0ebe702f2822dd6f75132f5a246022f95812a8112d3bfdbafd06a31c08f234 |
| tools | list_pipeline_runs | description | 80367a4fe8a202e030d83f87fcac3404c5d55dbe640274ad2830a85d6f0c9159 |
| tools | list_pipeline_runs | branch | 6e37e38c4571883f041aa516a6f8beee572e760395b13e940b03e0abf64c3b2d |
| tools | list_pipeline_runs | continuationToken | 29d66d992bc57ae68440820b96c14d7ce3ec83329d6ca094b564f3d770f037e2 |
| tools | list_pipeline_runs | createdFrom | f62a7c5da24b18692be7f8df3b632c71189259b439270826650e735fff8b5000 |
| tools | list_pipeline_runs | createdTo | bfe73a58a4e82e3fbdb941e3fb4aacd68a561ea0bc4da104f268bf3de0dda858 |
| tools | list_pipeline_runs | orderBy | e6106f0caa2c2b1e244c9187a8e8c9cf8109d679efdc2c5e8819ad0566dfd83b |
| tools | list_pipeline_runs | pipelineId | e8ec00e8196243e52745b7e1bd8ea2b2bfa80bcd088089c0f6ebd468060f0439 |
| tools | list_pipeline_runs | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_pipeline_runs | result | 4ccbe2a8ef21fe7e8a2166ccdff89bb627cdb4fbacbc5474926876b1a9817c6a |
| tools | list_pipeline_runs | state | 5fcb307bc4bc8f2f301b9818ca80c23165a5aae709c047dd8d16abafe7649864 |
| tools | list_pipeline_runs | top | bce099ff87d98b869f2a8ab9d13d889fd50d8885a3b7b2f25ba03adda3f38211 |
| tools | list_pipelines | description | 0a8b4b2b0d10e3d28b756b34f02423a29ba0a125bf85b74c25f2fa42e329727c |
| tools | list_pipelines | orderBy | 111d019c08bf032933f9b508f0a66f36c75cb7bc2a773aaf9186bc2befa8fe1d |
| tools | list_pipelines | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_pipelines | top | c2ae7152f03bf1c2b2281e243002d583f6226e46c7f812a7453f38e056071731 |
| tools | list_projects | description | b76d66f5fb856cb86090f628de4ed0eeb474fde3d5fe230d3f007caa56f7a82b |
| tools | list_projects | continuationToken | f3061096f8d4a78150c8de3478b6fffb5e79280d3cfc9697974756c1e6278486 |
| tools | list_projects | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | list_projects | skip | 68e6859913cb055503b67f2b36b413f034a1130e7004d48f9837964ebbfe6661 |
| tools | list_projects | stateFilter | 50b2d3b52a3a35a1b0613d0921fd4942c13872a5995f4da8cab4458de3ec8eeb |
| tools | list_projects | top | cf9a1abb12538d7c05deed0df3fe14249d5d1d41c634c6c788db9e5c5da45c15 |
| tools | list_pull_requests | description | d195a17f9c9cd457b03cf72f3c3a5627b6916a8dfcca8db0242cd583f21f28b6 |
| tools | list_pull_requests | creatorId | 604bb366130e373e07329cc0a5c704221075c0b929a0fcccce0638cb9923c3d0 |
| tools | list_pull_requests | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | list_pull_requests | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_pull_requests | pullRequestId | 0bb604b8c71dc6e87d3b8a7573a827b60b2c4a84802ebdba19becb47ddb994f6 |
| tools | list_pull_requests | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | list_pull_requests | reviewerId | 963cdfdf0fd27b3a230c616e41fce56b1b6e83904bf58bbd4d444cb27f33e2df |
| tools | list_pull_requests | skip | e6f769171fda17635735e3363f18a234318adc5eb5a057ce450751c93e04a0bd |
| tools | list_pull_requests | sourceRefName | 415ff45abee7b8f4ee57a398dce864746496a2ecd56ee6936d765e99181e26b5 |
| tools | list_pull_requests | status | 9cc75a02f8e797e1f3b556f49f8e3f9a9f385b10333008cde7738509f8a5b01c |
| tools | list_pull_requests | targetRefName | 6108fd2f1cab32df6a40711ac52b918491997b5b084cb4ca223738e87a2d7753 |
| tools | list_pull_requests | top | 6c2bcc7c0c55270ed00b2f81245c188c5a8772078b98ebb4e31ad921f9e43828 |
| tools | list_repositories | description | 5ffc96e3b6a5471d1b480f319ef0d914601040611994e64718f794a1a1986daa |
| tools | list_repositories | includeLinks | 3ad912e2c352994a166004d273a2bb1ee99f9ef0a9a39ff84754ae7449d4e292 |
| tools | list_repositories | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | list_repositories | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_wiki_pages | description | 8ae746206428a0798645596459caddfcaf00e65c5d2990c4badf22439ec7f7e0 |
| tools | list_wiki_pages | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | list_wiki_pages | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_wiki_pages | wikiId | 78550a0c4ca8efa5ee86b117ad438fdbd5060fbeed8d645d5dabd48b052eaf3e |
| tools | list_work_items | description | 2661d95fe94e7baab4c9355f8bbc018769fb50cde6027fcf7e9b560170a77a29 |
| tools | list_work_items | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | list_work_items | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | list_work_items | queryId | f9a76495f0bb2dda732af86d9189229f57facb21a34adbb4f77acd2fd6885766 |
| tools | list_work_items | skip | 705928156834ff118e2ce9f056b001d510842ac8ef90051114e4b31dce7de244 |
| tools | list_work_items | teamId | 4f94d5fffe47981feea154ebfbc8566c87b89796e4660a475bcda48ebc838481 |
| tools | list_work_items | top | 1c5ce616a7d9c79ba058900513593c13a47ebdb88b37195d779a97dc8bbf0a35 |
| tools | list_work_items | wiql | 7c49f75ad3bfaf6a22b935f31140f8787162d16f87439b0a6039e7cdfdc40770 |
| tools | manage_work_item_link | description | 56a251614cf951eef60e16436e562f8360d44cb97e1ac37b011417f461cc9458 |
| tools | manage_work_item_link | comment | 04182c14990f3f0396af37431e68b620459f020ca73c1b8584498e84adbed303 |
| tools | manage_work_item_link | newRelationType | 37da6731187c5ec5e039354ed4a312aea326d466cab596192a174a7a5a476037 |
| tools | manage_work_item_link | operation | d200040309eae3132123d75056d985a3c6d3cb777d1217c46879cf2a07c4e960 |
| tools | manage_work_item_link | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | manage_work_item_link | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | manage_work_item_link | relationType | 70bf840f3959c5b3c45a14f8deff72e379d3a35a9de37857418449a9729b3a38 |
| tools | manage_work_item_link | sourceWorkItemId | 7933bb03b851cd4b988691b3d7ff7ae85ba8f38084c16702de580d9f710586b3 |
| tools | manage_work_item_link | targetWorkItemId | d359310764ca599c2392a2fce1afa1adbab33ad60ffa7bd60a798ba9f12c58cf |
| tools | pipeline_timeline | description | e6eb1e4db750982aac31adc9e8e0cdf5dba8f53c7c61deabfcd2ca53a74d9211 |
| tools | pipeline_timeline | pipelineId | 1062b58d44d4ea4283dac897077edc284a0d93577a5e994af19158396e66bab3 |
| tools | pipeline_timeline | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | pipeline_timeline | result | d36bb83f0c8396a6dfd1a6e1697c9717bfd682d26c74460458bb7efc321ba338 |
| tools | pipeline_timeline | runId | c311c160ac577c175533b63b2eaa4edab064a821a7d21d1a426cfb5849e7b77c |
| tools | pipeline_timeline | state | a51f2004c229182084f81492fab2e6d56a86cd55e2c9e80cbfecc15bcb9da2cb |
| tools | pipeline_timeline | timelineId | 1199e395248d8b42083c1974a4f3578779b51033ef5b1e777a444ff4a5357666 |
| tools | search_code | description | 0dad1b913d26c0d415a65ceba2907e23c99ddd312e7a454fb091f4f64aac8018 |
| tools | search_code | filters | ee03a819e5cf30874c29321481f56f5b7e6249a9eb54b4ace3820b2404b8097c |
| tools | search_code | includeContent | 4bcd0580d5c54f189903bbbd31d20c78178a316e177aea7e6d892210f4dbdfb9 |
| tools | search_code | includeSnippet | 34a8b60facbcff10ba2db7759b51b6756297c871e972a27df6733e9814f40cb6 |
| tools | search_code | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | search_code | projectId | b98b6d37e986ba05b9e0739a3f23aff157f4d2fcf2ea0e6521b91f0a078719dd |
| tools | search_code | searchText | b4a87c0a91986545dcc27d7654b6c60f6fa168d1dd9effe5371ce4f1c9efb649 |
| tools | search_code | skip | d6746abb8bc88bb1b20d3e8d375105ad5d23cee8d8adce15cfc4d353e8fe2762 |
| tools | search_code | top | e092e063b9e40556c3379a46552358749fe3030f99d0d03c5ef7a57d679afccd |
| tools | search_wiki | description | 3159e7a0aa009a46c561cef9b8ce0c88870b3eb7b5fcc556406291c21ffb6199 |
| tools | search_wiki | filters | ee03a819e5cf30874c29321481f56f5b7e6249a9eb54b4ace3820b2404b8097c |
| tools | search_wiki | includeFacets | 8517d65b6268203ae894836cb683e3f754a0b318f7ba0b28e932b09bea048375 |
| tools | search_wiki | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | search_wiki | projectId | b98b6d37e986ba05b9e0739a3f23aff157f4d2fcf2ea0e6521b91f0a078719dd |
| tools | search_wiki | searchText | 974308f384c0f3866c5594099fb1c22e56733782bf12992f2abfdecae3de415c |
| tools | search_wiki | skip | d6746abb8bc88bb1b20d3e8d375105ad5d23cee8d8adce15cfc4d353e8fe2762 |
| tools | search_wiki | top | e092e063b9e40556c3379a46552358749fe3030f99d0d03c5ef7a57d679afccd |
| tools | search_work_items | description | 4ea78b59dc7bbf0e6cfc7e2c4dfb79620d740b4558b1e8150e3a90a225bd7d5d |
| tools | search_work_items | filters | ee03a819e5cf30874c29321481f56f5b7e6249a9eb54b4ace3820b2404b8097c |
| tools | search_work_items | includeFacets | 8517d65b6268203ae894836cb683e3f754a0b318f7ba0b28e932b09bea048375 |
| tools | search_work_items | orderBy | 8c097d45ec69f33fe2135f1fa9f4b99c05fa7434a0361a3014cca50bef1d5594 |
| tools | search_work_items | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | search_work_items | projectId | b98b6d37e986ba05b9e0739a3f23aff157f4d2fcf2ea0e6521b91f0a078719dd |
| tools | search_work_items | searchText | ffe99955e8df741c6fab13e264f5c6cb07ef4e62818dcfc24d22a7e509b6c351 |
| tools | search_work_items | skip | d6746abb8bc88bb1b20d3e8d375105ad5d23cee8d8adce15cfc4d353e8fe2762 |
| tools | search_work_items | top | e092e063b9e40556c3379a46552358749fe3030f99d0d03c5ef7a57d679afccd |
| tools | trigger_pipeline | description | 3d5cd53aa4ba07b575533af5169cacfda5af724b4debf92860b4bb9a1fab0d6e |
| tools | trigger_pipeline | branch | b876232e18540a3e5af9061741380c0047e54dcc929bd4c98173387c30b12a8c |
| tools | trigger_pipeline | pipelineId | 0dfcf34603265606d0c6160cedc244f900cf5b8e5fbfe8d477d84e46fbda6ab2 |
| tools | trigger_pipeline | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | trigger_pipeline | stagesToSkip | 087dc6c739a5d75a45a1f7f3402cbff0476ad9bc905faf830eaa468085b7a8c6 |
| tools | trigger_pipeline | templateParameters | 8bf18a6fc53caa7283d42fdd06d1f2a3b2cfad9817c1b3feb28718701488a66c |
| tools | trigger_pipeline | variables | fddf63ee4400ea8cc3b8703749653ad2b443dbec0dd44034776c8b0ec4df0dc5 |
| tools | update_pull_request | description | 490e5b82efedd99507a84c108b5c8add845279abe957923fc4786844dfaf7a07 |
| tools | update_pull_request | addReviewers | 74b1dd5c4f24146e3ce1167d0027ffac422a1a30ada0cd0a10f61603dc18f206 |
| tools | update_pull_request | addTags | 006e11db8a0ca807d88ba939841c14059c6361e03b53cecb416e27c268bd1ed9 |
| tools | update_pull_request | addWorkItemIds | d560f7bd59700bd8a96094e68ae4a51b7a09950aa589c9b6b0a9a11d1648ebcc |
| tools | update_pull_request | additionalProperties | 3cb0c1ef84f3e816b840d6f0af54efc881ca99370a6e54b9711e62174d3de4d6 |
| tools | update_pull_request | description | b3599eafb7dc913c5d6db96af7ff530a47213835847be3f1d251126553885c90 |
| tools | update_pull_request | isDraft | 767e464e7ada41a2147dc34640c95cabbe0c36a901ac98fff883138e100183c0 |
| tools | update_pull_request | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | update_pull_request | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | update_pull_request | pullRequestId | bab06b80be47af9f3c7339eb8d1d383335f8a84a807f11a1f9f48ced70c0ec6f |
| tools | update_pull_request | removeReviewers | 6c32225e4b816f57b404b295ebd0df1e47fef9306b5f981e9f3f17c8d30cfe49 |
| tools | update_pull_request | removeTags | a886df1e71e25a6904cd5c248b801c5b31679aa3adfb95e6244b28f99ceb3284 |
| tools | update_pull_request | removeWorkItemIds | 2b50fded783214a18b76c80e4a7ebdbfcdb93d7b62aa952af9b4984b6c85c820 |
| tools | update_pull_request | repositoryId | 25d0eeb6f8988c62240119c72427edb9c77cf55278a72464848f34bab83dc50f |
| tools | update_pull_request | status | 24f8d8a7b8739c72aef4ae32a2285614508c424b43e20096331455825249d20f |
| tools | update_pull_request | title | 7f70b2cfc64feab279163d8ed13e3b3ee6c33fe43d3121b85b7c8b51f843cdf1 |
| tools | update_wiki_page | description | aa45424350d4c30e6943af448aa2e166331656918ab5d13fd40602f59f8d4719 |
| tools | update_wiki_page | comment | 788862b6f123589e8509be67124e6b88656a5660f20d1131476528d30a4d100e |
| tools | update_wiki_page | content | edf59a386951b3eb9594514b9b8712b548b0538c0f790f40381b9b5fff012b54 |
| tools | update_wiki_page | organizationId | 1e49f115f85bb882bdd2858436d548a50ea0ce592e01b9c1966169fedecd394c |
| tools | update_wiki_page | pagePath | 68701a7545d83733e6f22644c62bc7269aa138089d7bd3cba9c08feb0f3f01c2 |
| tools | update_wiki_page | projectId | 2327c42e84ad2de11e684f8f34e0bedc0dcb85eb63e767b3c008698fd4ca8de0 |
| tools | update_wiki_page | wikiId | 78550a0c4ca8efa5ee86b117ad438fdbd5060fbeed8d645d5dabd48b052eaf3e |
| tools | update_work_item | description | 1268988709dd867f896ee334daaf3dbcb0614049f4460802433223df1a3b7906 |
| tools | update_work_item | additionalFields | cdf5ee443e1f9ef1faa563938eec5702bd22d4013e34ea031522fa59f876cd66 |
| tools | update_work_item | areaPath | d8324d34cc44a9af2e58a866d3310861e1a2649f2fed1574bd668813f3585b16 |
| tools | update_work_item | assignedTo | c0c5f209ac0c7ec3442571e1eadb49d0b9f383cb016b60015362ce09daff015e |
| tools | update_work_item | description | 7dd97974eb4ce52d49e21e1330423c5c214da8d4b201cc23b570ba47b3a95603 |
| tools | update_work_item | iterationPath | a358f09b4e72b1d4314a40d807e748370c497ff5e688c79777b730c576a1763c |
| tools | update_work_item | priority | c16a90abda15ea81067453efcbbc89af0321cf4739845ae80662355305295173 |
| tools | update_work_item | state | 6840863a9fcd974ff7cbc7623a7c95c148aae0c11248aed414af9afb190f19b6 |
| tools | update_work_item | title | edbac3c8c0dbb4509110a03f08bb17ea1e3700d45a2f1b76dff363d199f7a785 |
| tools | update_work_item | workItemId | efe56f35343cc9f28e5acad370f46864a7fbcf76d00af30aa33dca86714aec07 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
