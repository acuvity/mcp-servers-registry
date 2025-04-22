

<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://mma.prnewswire.com/media/2544052/Acuvity__Logo.jpg" height="90" alt="Acuvity logo"/>
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://discord.gg/BkU7fBkrNk">
    <img src="https://img.shields.io/badge/Acuvity-Join-7289DA?logo=discord&logoColor=fff)](https://discord.gg/BkU7fBkrNk" alt="Join Acuvity community" /></a>
<a href="https://www.linkedin.com/company/acuvity/">
    <img src="https://img.shields.io/badge/LinkedIn-follow-0a66c2" alt="Follow us on LinkedIn" />
  </a>
</p>


# What is mcp-server-github?

[![Helm](https://img.shields.io/badge/v1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-github/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/v0.2.1?logo=docker&logoColor=fff&label=v0.2.1)](https://hub.docker.com/r/acuvity/mcp-server-github/tags/v0.2.1)
[![PyPI](https://img.shields.io/badge/v0.2.1-3775A9?logo=github&logoColor=fff&label=github/github-mcp-server)](https://github.com/github/github-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** GitHub's official MCP Server

> [!NOTE]
> `github/github-mcp-server` has been repackaged by Acuvity from its original [sources](https://github.com/github/github-mcp-server).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure github/github-mcp-server run reliably and safely.

## 🔐 Key Security Features

<details>
<summary>📦 Isolated Immutable Sandbox </summary>

- **Isolated Execution**: All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.
- **Non-root by Default**: Enforces least-privilege principles, minimizing the impact of potential security breaches.
- **Read-only Filesystem**: Ensures runtime immutability, preventing unauthorized modification.
- **Version Pinning**: Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.
- **CVE Scanning**: Continuously monitors for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation.
- **SBOM & Provenance**: Provides full supply chain transparency with embedded metadata and traceable build information.
</details>

<details>
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails to protect MCP server integrity and detect suspicious behavior:

- **Integrity via Hashing**: Verifies the authenticity and integrity of tool descriptors and runtime components.
- **Threat Detection**:
  - Detects hidden or covert instruction patterns.
  - Monitors for schema parameter misuse as potential exfiltration channels.
  - Flags unauthorized access to sensitive files or credentials.
  - Identifies tool shadowing and override attempts.
  - Enforces cross-origin and server-mismatch protection policies.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ github ](https://github.com/github/github-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ github/github-mcp-server ](https://github.com/github/github-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ github/github-mcp-server ](https://github.com/github/github-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/mcp-server-github/charts/mcp-server-github)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/mcp-server-github/docker/Dockerfile)

**Current supported version:**
  - charts: `v1.0.0`
  - container: `v0.2.1`

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

**Mandatory Secrets**:
  - `GITHUB_PERSONAL_ACCESS_TOKEN` secret to be set as secrets.GITHUB_PERSONAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `GITHUB_HOST=""` environment variable can be changed with `env.GITHUB_HOST=""`

# How to install


Install will helm

```console
helm install helm install mcp-server-github oci://docker.io/acuvity/mcp-server-github --version v1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-github --version v1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-github --version v1.0.0
````
From there your MCP server mcp-server-github will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-github` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-github
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
args:
  - stdio
```

Passes arbitrary command‑line arguments into the container.


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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-github` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
minibridge:
  mode: http
  log:
    level: info
  tls:
    enabled: false
    cert:
      value:
      path:
    key:
      value:
      path:
    pass:
      value:
      valueFrom:
        name:
        key:
    clientCA:
      value:
      path:
  policer:
    url:
    token:
      value:
      valueFrom:
        name:
        key:
    ca:
      value:
      path:
    # insecure: true
```

Custom “minibridge” settings for HTTP↔STDIO or WebSocket↔STDIO bridging:
- **mode**: `http` or `websocket`.
- **log.level**: log verbosity.
- **tls**: server TLS certificate/key and optional client‑CA.
- **policer**: external service URL, auth token, and CA for traffic policing.

# 🧠 Server features

## 🧰 Tools (36)
<details>
<summary>add_issue_comment</summary>

**Description**:

```
Add a comment to an existing issue
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | Comment content | Yes
| issue_number | number | Issue number to comment on | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>add_pull_request_review_comment</summary>

**Description**:

```
Add a review comment to a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | The text of the review comment | Yes
| commit_id | string | The SHA of the commit to comment on. Required unless in_reply_to is specified. | No
| in_reply_to | number | The ID of the review comment to reply to. When specified, only body is required and all other parameters are ignored | No
| line | number | The line of the blob in the pull request diff that the comment applies to. For multi-line comments, the last line of the range | No
| owner | string | Repository owner | Yes
| path | string | The relative path to the file that necessitates a comment. Required unless in_reply_to is specified. | No
| pull_number | number | Pull request number | Yes
| repo | string | Repository name | Yes
| side | string | The side of the diff to comment on | No
| start_line | number | For multi-line comments, the first line of the range that the comment applies to | No
| start_side | string | For multi-line comments, the starting side of the diff that the comment applies to | No
| subject_type | string | The level at which the comment is targeted | No
</details>
<details>
<summary>create_branch</summary>

**Description**:

```
Create a new branch in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Name for new branch | Yes
| from_branch | string | Source branch (defaults to repo default) | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_issue</summary>

**Description**:

```
Create a new issue in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignees | array | Usernames to assign to this issue | No
| body | string | Issue body content | No
| labels | array | Labels to apply to this issue | No
| milestone | number | Milestone number | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| title | string | Issue title | Yes
</details>
<details>
<summary>create_or_update_file</summary>

**Description**:

```
Create or update a single file in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to create/update the file in | Yes
| content | string | Content of the file | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path where to create/update the file | Yes
| repo | string | Repository name | Yes
| sha | string | SHA of file being replaced (for updates) | No
</details>
<details>
<summary>create_pull_request</summary>

**Description**:

```
Create a new pull request in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | Branch to merge into | Yes
| body | string | PR description | No
| draft | boolean | Create as draft PR | No
| head | string | Branch containing changes | Yes
| maintainer_can_modify | boolean | Allow maintainer edits | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| title | string | PR title | Yes
</details>
<details>
<summary>create_pull_request_review</summary>

**Description**:

```
Create a review on a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | Review comment text | No
| comments | array | Line-specific comments array of objects to place comments on pull request changes. Requires path and body. For line comments use line or position. For multi-line comments use start_line and line with optional side parameters. | No
| commitId | string | SHA of commit to review | No
| event | string | Review action to perform | Yes
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_repository</summary>

**Description**:

```
Create a new GitHub repository in your account
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| autoInit | boolean | Initialize with README | No
| description | string | Repository description | No
| name | string | Repository name | Yes
| private | boolean | Whether repo should be private | No
</details>
<details>
<summary>fork_repository</summary>

**Description**:

```
Fork a GitHub repository to your account or specified organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organization | string | Organization to fork to | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_code_scanning_alert</summary>

**Description**:

```
Get details of a specific code scanning alert in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| alertNumber | number | The number of the alert. | Yes
| owner | string | The owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
</details>
<details>
<summary>get_commit</summary>

**Description**:

```
Get details for a commit from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sha | string | Commit SHA, branch name, or tag name | Yes
</details>
<details>
<summary>get_file_contents</summary>

**Description**:

```
Get the contents of a file or directory from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to get contents from | No
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path to file/directory | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_issue</summary>

**Description**:

```
Get details of a specific issue in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_number | number | The number of the issue | Yes
| owner | string | The owner of the repository | Yes
| repo | string | The name of the repository | Yes
</details>
<details>
<summary>get_issue_comments</summary>

**Description**:

```
Get comments for a GitHub issue
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_number | number | Issue number | Yes
| owner | string | Repository owner | Yes
| page | number | Page number | No
| per_page | number | Number of records per page | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_me</summary>

**Description**:

```
Get details of the authenticated GitHub user. Use this when a request include "me", "my"...
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| reason | string | Optional: reason the session was created | No
</details>
<details>
<summary>get_pull_request</summary>

**Description**:

```
Get details of a specific pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_comments</summary>

**Description**:

```
Get the review comments on a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_files</summary>

**Description**:

```
Get the list of files changed in a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_reviews</summary>

**Description**:

```
Get the reviews on a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_status</summary>

**Description**:

```
Get the combined status of all status checks for a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_secret_scanning_alert</summary>

**Description**:

```
Get details of a specific secret scanning alert in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| alertNumber | number | The number of the alert. | Yes
| owner | string | The owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
</details>
<details>
<summary>list_branches</summary>

**Description**:

```
List branches in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>list_code_scanning_alerts</summary>

**Description**:

```
List code scanning alerts in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | The owner of the repository. | Yes
| ref | string | The Git reference for the results you want to list. | No
| repo | string | The name of the repository. | Yes
| severity | string | Filter code scanning alerts by severity | No
| state | string | Filter code scanning alerts by state. Defaults to open | No
| tool_name | string | The name of the tool used for code scanning. | No
</details>
<details>
<summary>list_commits</summary>

**Description**:

```
Get list of commits of a branch in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sha | string | SHA or Branch name | No
</details>
<details>
<summary>list_issues</summary>

**Description**:

```
List issues in a GitHub repository with filtering options
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| direction | string | Sort direction | No
| labels | array | Filter by labels | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| since | string | Filter by date (ISO 8601 timestamp) | No
| sort | string | Sort order | No
| state | string | Filter by state | No
</details>
<details>
<summary>list_pull_requests</summary>

**Description**:

```
List and filter repository pull requests
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | Filter by base branch | No
| direction | string | Sort direction | No
| head | string | Filter by head user/org and branch | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sort | string | Sort by | No
| state | string | Filter by state | No
</details>
<details>
<summary>list_secret_scanning_alerts</summary>

**Description**:

```
List secret scanning alerts in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | The owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
| resolution | string | Filter by resolution | No
| secret_type | string | A comma-separated list of secret types to return. All default secret patterns are returned. To return generic patterns, pass the token name(s) in the parameter. | No
| state | string | Filter by state | No
</details>
<details>
<summary>merge_pull_request</summary>

**Description**:

```
Merge a pull request
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| commit_message | string | Extra detail for merge commit | No
| commit_title | string | Title for merge commit | No
| merge_method | string | Merge method | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>push_files</summary>

**Description**:

```
Push multiple files to a GitHub repository in a single commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to push to | Yes
| files | array | Array of file objects to push, each object with path (string) and content (string) | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>search_code</summary>

**Description**:

```
Search for code across GitHub repositories
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| q | string | Search query using GitHub code search syntax | Yes
| sort | string | Sort field ('indexed' only) | No
</details>
<details>
<summary>search_issues</summary>

**Description**:

```
Search for issues and pull requests across GitHub repositories
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| q | string | Search query using GitHub issues search syntax | Yes
| sort | string | Sort field by number of matches of categories, defaults to best match | No
</details>
<details>
<summary>search_repositories</summary>

**Description**:

```
Search for GitHub repositories
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | Search query | Yes
</details>
<details>
<summary>search_users</summary>

**Description**:

```
Search for GitHub users
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| q | string | Search query using GitHub users search syntax | Yes
| sort | string | Sort field by category | No
</details>
<details>
<summary>update_issue</summary>

**Description**:

```
Update an existing issue in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignees | array | New assignees | No
| body | string | New description | No
| issue_number | number | Issue number to update | Yes
| labels | array | New labels | No
| milestone | number | New milestone number | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| state | string | New state | No
| title | string | New title | No
</details>
<details>
<summary>update_pull_request</summary>

**Description**:

```
Update an existing pull request in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | New base branch name | No
| body | string | New description | No
| maintainer_can_modify | boolean | Allow maintainer edits | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number to update | Yes
| repo | string | Repository name | Yes
| state | string | New state | No
| title | string | New title | No
</details>
<details>
<summary>update_pull_request_branch</summary>

**Description**:

```
Update a pull request branch with the latest changes from the base branch
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expectedHeadSha | string | The expected SHA of the pull request's HEAD ref | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_issue_comment | description | 86d43e20a27a7a50e9ebf6309a8f9b194fb4f4964f8a8d5c04037e23557efd05 |
| tools | add_issue_comment | body | 76196e088940dc7627854dccef8d659636b54a66ba71c85512d65beb0131a5a8 |
| tools | add_issue_comment | issue_number | 55508553706f381501225c1367bc7f12548ab08da5ce677d10875fb316ee3ce4 |
| tools | add_issue_comment | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | add_issue_comment | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | add_pull_request_review_comment | description | be6d0820be1f2a517d8783198cb7234cb644690e90ace4d65b4143af39159fa2 |
| tools | add_pull_request_review_comment | body | 150bf72e1256c35c56d58cce6912ae25bb0a02e2a048a422297a7eead2024635 |
| tools | add_pull_request_review_comment | commit_id | 9069a6843465d00eccd533d78bed87ea5d4ceb313230c7cacc54755e79b98838 |
| tools | add_pull_request_review_comment | in_reply_to | 516313212479077b2a058b8d792e88fd75d67d923e22f6160477be7276718913 |
| tools | add_pull_request_review_comment | line | 819e79a56ebb1ecd61715def06ef3dda6306d32677da2d9c797a17ea0c2fe4bc |
| tools | add_pull_request_review_comment | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | add_pull_request_review_comment | path | 8c7c87f1a8b168380c995c8bf1610dbe0af9bb72bdcf770ac3ba4e37f70f76bd |
| tools | add_pull_request_review_comment | pull_number | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | add_pull_request_review_comment | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | add_pull_request_review_comment | side | 85e03845e1cd96ec3eaec2d871420dab0a2fd45267f4eaa0e3b7070854f3c094 |
| tools | add_pull_request_review_comment | start_line | 19184c9e73d4d7fbb9661702c5af2054059047e4b6cfc56b0e66f31fe3c2ba16 |
| tools | add_pull_request_review_comment | start_side | 4a49cb10f1305f775326b0b486cd9612333c13de063b30ac98262a7e091596cf |
| tools | add_pull_request_review_comment | subject_type | 12fc508ce13c1c2a9607f35cb7add1b0335cddf96c243530df7db80cab254182 |
| tools | create_branch | description | 178c4aa2cad9c4dec2d6883eb0913ba5385f367e681e9d97cb751a2eb0983645 |
| tools | create_branch | branch | 23431660a4982622d8107024b732941aab6327a832c6715c57299e716e175d88 |
| tools | create_branch | from_branch | 5fa655e2e4b9da16f3de9e22d4d842abb6226464a2e91758242eacc4fec42dc9 |
| tools | create_branch | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_branch | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_issue | description | 0fdca60b28749f86d062d711471bfc3c6670dad2e8a02c9be2caa40753f717e2 |
| tools | create_issue | assignees | 4b3bd4c85313c2684d6dcf769e368485947d08818835207a231a61700dc3552b |
| tools | create_issue | body | 16e4f6813850b28daf1d698946455b18a587988665d95175da2e415938a906f7 |
| tools | create_issue | labels | 14ab87d13af5cc4d90c937d8c30258158c0afe9d6cedfb89b4a10d0d057d0397 |
| tools | create_issue | milestone | 87dbe6860309e747c0fc0fc44621cdc1b20e79faaccdd485a4b74c5daa8e333d |
| tools | create_issue | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_issue | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_issue | title | baebb0f722db7150e454ecfb2d432205f6331d57837328637d25ac8413f84644 |
| tools | create_or_update_file | description | 10268460cbe672f7ab7e9881678fb8ae50af83dcd8bec8f4115f6de03d565628 |
| tools | create_or_update_file | branch | d6a5e87fe732d76cc378c1d1f1210e9b2deb75c9a0dc93b4e453bd5681e9ebe9 |
| tools | create_or_update_file | content | 651936dc46e2fa051b60ccb3cbfe9f87f0f58f41773e79b4839a814525a7d688 |
| tools | create_or_update_file | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | create_or_update_file | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | create_or_update_file | path | c57e5f48646295c4493f5d052c3ce4d46f88f8c963d162f44c187ff5defa6791 |
| tools | create_or_update_file | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_or_update_file | sha | aedc7ce1b7de89c1f0197052ccff35b4ed4f7836d9d93f2fc154b02d7ed67c75 |
| tools | create_pull_request | description | fdced4e921543e06e2878514ba1ba1e4852e1f8118f98d3979eb812c8a27e773 |
| tools | create_pull_request | base | 68d3d352a8e9b1b21daef0144ddbd5ebbfdfafa1c150afd9184f2889aeba0f54 |
| tools | create_pull_request | body | 6b20fc28a2739e184ca6e00b2e894ed90a2213780fe67c05664a6917b26e1010 |
| tools | create_pull_request | draft | 13570f145a780449c8841dec203e2f3b37b7ced1b53e0a675553880b30b743db |
| tools | create_pull_request | head | f30a2f6fcdb7af894b1cd42fd17f7651a3e9de4c432a615fe383235d8822d669 |
| tools | create_pull_request | maintainer_can_modify | 4c61cb2daa11e76d1bd1483894ba1f0c8d8430cf9011793815d3cbd017f341ad |
| tools | create_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_pull_request | title | 878bfb1640ec1cecdf8cab8f3c62f5413e6b4084e0e1a4494df8f65a5a5eebf7 |
| tools | create_pull_request_review | description | 3c801d778b5fa0ec62aa4b1d0e830895c3cbde0cd0f75e931a2220331d598820 |
| tools | create_pull_request_review | body | 305435be37ca49348dd59f76ed78d1d3db653263c87268f19e38edd8e9903f8a |
| tools | create_pull_request_review | comments | 0112ff59985194d41ebb916c7c90ada3cff928b2d2d8b09e0f63034e89065185 |
| tools | create_pull_request_review | commitId | 8edaee0cc39481736353ab6b261838e08ea25f5a48ff2235247349671fd2d092 |
| tools | create_pull_request_review | event | 91cce26ef9317542f329d7df06c21c3f7640f53bac235489e5537867c87b579e |
| tools | create_pull_request_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_pull_request_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | create_pull_request_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_repository | description | f44928d7808fe825e9451518452be54abfa32929ece5256d2c96a8c91f7df5d1 |
| tools | create_repository | autoInit | fb659aaef50b97ff2f1d0518139663caef0d38424fc1107a8bf1a0cd7d7a637b |
| tools | create_repository | description | 2b96b72a003b28027236e3a9d7b66958233d752e92381122915202c3c00f6058 |
| tools | create_repository | name | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_repository | private | d2180d4e67c48806764e44a9533344b63b6c05db56d6974818cb393c38e666e1 |
| tools | fork_repository | description | b9c81712c56e48175df559052b73f7e28646208f961b6b61c3ac3f3545eef86f |
| tools | fork_repository | organization | 715d8a3a0d64573efa8d492a5ac06ccf88e4ecb1db7a7b6cb0d30ee9369e6ccb |
| tools | fork_repository | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | fork_repository | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_code_scanning_alert | description | c9355e6046bba99a24d2d56a7b7ae04bd213029c8921890e6a080b11cf924a17 |
| tools | get_code_scanning_alert | alertNumber | 1cf32d483c0692dad2135b6c2188b130c24fe94e4b770e95250652466e365605 |
| tools | get_code_scanning_alert | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | get_code_scanning_alert | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | get_commit | description | a27095bf05dc570a18bf4f6db26662c8dd39f2997f914127c59e8ecf906bf30f |
| tools | get_commit | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_commit | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | get_commit | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | get_commit | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_commit | sha | dcf39de8e2207559c31e5f4576561e8e569c991a889b697d8db7a3460924b445 |
| tools | get_file_contents | description | 54de6216aa12cd8da08e335b6955e2261b4241359f184959829407d0e40dcdc0 |
| tools | get_file_contents | branch | 845c6e38397f1251842f78808bd433f2656d160a31e29109bae6088fba5037b4 |
| tools | get_file_contents | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | get_file_contents | path | 2957637372ff4e19e270a582b546db31597054befcac8ee9aa597018697273be |
| tools | get_file_contents | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_issue | description | b15f8cd84a7e4f6728f2588bebb5b40f611f2670439d552c23b804be2c7d1648 |
| tools | get_issue | issue_number | 792880d24307a7c2e3ccb34d164888a960335024892f6faa8729fe06657409fe |
| tools | get_issue | owner | ee38b59dccfd5b3c8d391330a1f61654141c77f7a3bfcd3da617d6f32f3fba55 |
| tools | get_issue | repo | 707cdfc2a1225dbd1d0ab3c3e9c69aa50df8556f176cfcb822744bef5cee4481 |
| tools | get_issue_comments | description | b75abd5fc64cd3e969f79d8533fd1d0287d4d648944ab049d3f88cad2ccb41e0 |
| tools | get_issue_comments | issue_number | b90458b6339c0e14f5cea20207035c8a316ca33c0fda5d372ab8c4fc51fdb075 |
| tools | get_issue_comments | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_issue_comments | page | 05fa2e3b0a10226acb6eb73c76977fe622ae5d2e1c11d1e00ea5e83da9321069 |
| tools | get_issue_comments | per_page | 1da3c6e59c56c4f9ee1b4b0efd181852a0424750dc1dcce569d8a7fab419b678 |
| tools | get_issue_comments | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_me | description | d77fb42681f3a5318efa4edfd0001c01fb63b8d4cfe1e6d5d9ba94a3f702b4c1 |
| tools | get_me | reason | d73c654f9f80bd273b750233b6a38a9abc07756f3652b33c8f1c51ea83eac9dc |
| tools | get_pull_request | description | d650e84e528c6d4d67b779dce2e364ba32de2fb604c420c10812453de0fc788e |
| tools | get_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_comments | description | cf753bbf730e4379cbf18f0d8220866c82a9ad3f8a7a88ab3edc017acf121622 |
| tools | get_pull_request_comments | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_comments | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_comments | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_files | description | 675aa3851f469f24f37f8d2370b10cb0229da05df7c0d7190587887c8e68560c |
| tools | get_pull_request_files | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_files | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_files | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_reviews | description | 5a2a1781698aed24c7395cd640b044ea6d79a9d72c7fb5ce616ce1902f02c337 |
| tools | get_pull_request_reviews | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_reviews | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_reviews | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_status | description | f79f879dc44f92838788cef23f02cf6cdd4047677137c545228026f6f2e5cc3e |
| tools | get_pull_request_status | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_status | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_status | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_secret_scanning_alert | description | 0cc5a272aafe264f496df0317c38e5b24c554afbc136cfe98919d2447663e5c3 |
| tools | get_secret_scanning_alert | alertNumber | 1cf32d483c0692dad2135b6c2188b130c24fe94e4b770e95250652466e365605 |
| tools | get_secret_scanning_alert | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | get_secret_scanning_alert | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | list_branches | description | 8ce903bf8c1572fd527fd93f38d7d2ccb9b8d463ffe947100aeb1b8187363840 |
| tools | list_branches | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_branches | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_branches | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_branches | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_code_scanning_alerts | description | 2157c013472c46218c4a0315e1b0ba5e6eb9315cf7065b1f572d0a4c25fd7db7 |
| tools | list_code_scanning_alerts | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | list_code_scanning_alerts | ref | 2b4293ec0232d33ef23f0d89a5a150e1e4e234c5a3dc9a6b4273cd37d25393bc |
| tools | list_code_scanning_alerts | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | list_code_scanning_alerts | severity | 9e8b684d29e88335cb2d708ce5ceca799ddb6094c60e0cb74c691f5f3b5cf2d9 |
| tools | list_code_scanning_alerts | state | 9ddc484fe54a5a6c6c4633c8e012a31307a78cc9a8c11377ea40a724a5b741ed |
| tools | list_code_scanning_alerts | tool_name | 8b7eaf66d0062b14f656ad3c31c6a95a723f743d0094208b0776ead3cbdf5402 |
| tools | list_commits | description | 1c0d03ab4c651faf18fe16b157121151639027341f9e0e708ab106150cb23461 |
| tools | list_commits | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_commits | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_commits | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_commits | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_commits | sha | 1cb4096e4bfb01ccc794b77a3f36efdbd471ec34b3dea0516efaf93c0201f642 |
| tools | list_issues | description | 21237fe6f68699ae824a400794c67f88eb8a2a047451f4d5f454da7e63172e15 |
| tools | list_issues | direction | 29c8371d927b118d8d71544c8c8d336f340b0fe893a48faa5a746880f578f373 |
| tools | list_issues | labels | cd8837d9c837a6e1991502a822f57a44fc95a741eeece870f890f82c275c16a3 |
| tools | list_issues | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_issues | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_issues | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_issues | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_issues | since | ea0dd87c74f5845692af7bc86972f1f210d984342fb26602fe35c0c04a3a49cd |
| tools | list_issues | sort | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | list_issues | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | list_pull_requests | description | 527c8cf6af2f7861b8afba445dededbf598ccd0283b23bed99a7a9968f8c1b96 |
| tools | list_pull_requests | base | 3915eefd074b833c42fa1a78466ff3667210bb7cd9e867bce531f6d69b6b25f1 |
| tools | list_pull_requests | direction | 29c8371d927b118d8d71544c8c8d336f340b0fe893a48faa5a746880f578f373 |
| tools | list_pull_requests | head | dc15fecf43097ca55e53fff94ae252ac6f7a0325fa37efb0ba854276c2eea920 |
| tools | list_pull_requests | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_pull_requests | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_pull_requests | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_pull_requests | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_pull_requests | sort | c9129025bd3ff6522a7eeebc1abf1481f36e4ac9d74524a473ac1c3be1c6fc2f |
| tools | list_pull_requests | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | list_secret_scanning_alerts | description | 3894671d369d1afd5626bc7a85fd304dc23c40e42ac99eab42ef7472f50cf231 |
| tools | list_secret_scanning_alerts | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | list_secret_scanning_alerts | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | list_secret_scanning_alerts | resolution | 43f25b84021219ca1dc81d938db1e65ba764b7c84b208724d8f426c9ab2f1004 |
| tools | list_secret_scanning_alerts | secret_type | d92ec333a3e61d232bf74066b54f328522d20f590d20ef126cffdcc1af676e21 |
| tools | list_secret_scanning_alerts | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | merge_pull_request | description | 66d8d76bded29183eecb5cd36d4d58f40a897cd9f0928a6fd18d9788d44b48ce |
| tools | merge_pull_request | commit_message | 8b3fd7f52419bc6922db1546614fcd15e214033be38066ff4cd1cbb841ba27ce |
| tools | merge_pull_request | commit_title | df303c95cc0cb2a4ceb92b29c47c9b965ec484d53b5fee6add5c9189e2f96342 |
| tools | merge_pull_request | merge_method | 889b19c3b7a37b0d3249fd662f04c6cdc914c42bfc45d642c5d74946ca8837db |
| tools | merge_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | merge_pull_request | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | merge_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | push_files | description | 0ea99ad23e44e739ed503658bdaab5ee2dc239246cb00e715d8fff3d80fe544f |
| tools | push_files | branch | 903fd236be715d2d2dabe8871e567bebdb55a876b1f9b4db0c49400e3b944e01 |
| tools | push_files | files | 1c55ce034da38092a4c35795368bf7da13897eb6ab576f0539b22e02cda877a0 |
| tools | push_files | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | push_files | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | push_files | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | search_code | description | c47330f5060c9cac8a1867a95cd93c42ab1e6e3b5e6aa7e7dd8b1dec1a8d1e79 |
| tools | search_code | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_code | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_code | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_code | q | f28bd330504534bb418432cb9ed5d2710fd6ab8ce3ad1a15eef949522f7be10e |
| tools | search_code | sort | 5a8b728c15aab0284ebfeb9dfb94debf67e55d178d8bf7c3b660fe36ef92855f |
| tools | search_issues | description | 6b0eee260141d7c3b1a5ebd4a1be8754c249d5283b803f1f9bad160ee8869aa3 |
| tools | search_issues | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_issues | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_issues | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_issues | q | ba2ce5263245f1c7beda19f750b937dee26e69df9b0773c5ee3902142e81e3ee |
| tools | search_issues | sort | 45f652334776f448a204bdd17cb144e1d6a7b0bf6e6746e677874ad01432470d |
| tools | search_repositories | description | adf4a039f4409fab912a621c93aea801631f04db16e035808e7bab8e0f67aa82 |
| tools | search_repositories | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_repositories | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_repositories | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | search_users | description | 89d1a69aba0bca0b320f01ef132c9a72005ebefc054b69a0d01e035ed188a61e |
| tools | search_users | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_users | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_users | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_users | q | 411fdded1833c9660c80d3528c9fe3117d7fc0efd34b8f6756fd7dd82b6b16fd |
| tools | search_users | sort | 7b4f03e0b12896994cd874649134fe440d505ae1eafaa19f7f330a8b2fa4b055 |
| tools | update_issue | description | 569ede23be8abcc963cbb9d6e11ecad0abbd818fa3c898c231d4e3c9dcc1b483 |
| tools | update_issue | assignees | 09ed592a172e1fab692d52395b578ddb80014f1348ab79b3685483856aecfbef |
| tools | update_issue | body | 23b7ce65508de7bbfb013fd25a384491f896e839f62116c96813ec6f53945e98 |
| tools | update_issue | issue_number | 45f54a035e52ddd24bd931710aed635cc2d5a202ba687d0708c618fe76095437 |
| tools | update_issue | labels | d5304eef496f551a4ae71c2345ef665475ae22c93b4c8b3fc7043385e0011194 |
| tools | update_issue | milestone | e503beb4738eefdedd535449eb967367e51888787a8c6d246206e94de8fdc60d |
| tools | update_issue | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_issue | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | update_issue | state | 73d2abfb99c5146711a52488e33aa097ebd94cc1f1d14a0e21e9a6ed88709818 |
| tools | update_issue | title | 522156b9b0af7eb99063569c92036931a3c9f027728ac6de8a70bcd0a1d3721c |
| tools | update_pull_request | description | b3d321bc09628f9bfc1fafd575f09855d3e82ca9e582f8f09c1838f816014e3e |
| tools | update_pull_request | base | 33cd739abf299499afc569d0b3bf88e53d9833841bb0af1c9e7c3a61c827991a |
| tools | update_pull_request | body | 23b7ce65508de7bbfb013fd25a384491f896e839f62116c96813ec6f53945e98 |
| tools | update_pull_request | maintainer_can_modify | 4c61cb2daa11e76d1bd1483894ba1f0c8d8430cf9011793815d3cbd017f341ad |
| tools | update_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_pull_request | pullNumber | 4f4b068a5c13d2a2547b7a13655111963fd97b583156f8cea0fd62c4a16f7375 |
| tools | update_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | update_pull_request | state | 73d2abfb99c5146711a52488e33aa097ebd94cc1f1d14a0e21e9a6ed88709818 |
| tools | update_pull_request | title | 522156b9b0af7eb99063569c92036931a3c9f027728ac6de8a70bcd0a1d3721c |
| tools | update_pull_request_branch | description | ba5c9de20ac5c30e61b9484d11c92936beb365e422118dd34afa8e80d9037037 |
| tools | update_pull_request_branch | expectedHeadSha | 86e4137627e7ef4e6244395428104ab03f903b5c98f1a4be25279deb54f96c00 |
| tools | update_pull_request_branch | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_pull_request_branch | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | update_pull_request_branch | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
