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
</p>


# What is mcp-server-asana?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-asana/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-asana/1.7.0?logo=docker&logoColor=fff&label=1.7.0)](https://hub.docker.com/r/acuvity/mcp-server-asana)
[![PyPI](https://img.shields.io/badge/1.7.0-3775A9?logo=pypi&logoColor=fff&label=@roychri/mcp-server-asana)](https://github.com/roychri/mcp-server-asana)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-asana&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ASANA_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-asana%3A1.7.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Asana API integration.

> [!NOTE]
> `@roychri/mcp-server-asana` has been repackaged by Acuvity from Christian Roy original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @roychri/mcp-server-asana run reliably and safely.

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
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails that protect MCP server integrity and detect suspicious behaviors in real-time.:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions - or call arguments - reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognised tokens formats with `[REDACTED]` in outbound content.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Christian Roy ](https://github.com/roychri/mcp-server-asana) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @roychri/mcp-server-asana ](https://github.com/roychri/mcp-server-asana)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @roychri/mcp-server-asana ](https://github.com/roychri/mcp-server-asana)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asana/charts/mcp-server-asana)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asana/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.7.0`

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
  - `ASANA_ACCESS_TOKEN` secret to be set as secrets.ASANA_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install helm install mcp-server-asana oci://docker.io/acuvity/mcp-server-asana --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-asana --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-asana --version 1.0.0
````
From there your MCP server mcp-server-asana will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-asana` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-asana
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-asana` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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

  # Policier configuration
  policer:
    # Instruct to enforce policies if enabled
    # otherwise it will jsut log the verdict as a warning
    # message in logs
    enforce: false
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

# 🧠 Server features

## 🧰 Tools (22)
<details>
<summary>asana_list_workspaces</summary>

**Description**:

```
List all available workspaces in Asana
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
</details>
<details>
<summary>asana_search_projects</summary>

**Description**:

```
Search for projects in Asana using name pattern matching
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| archived | boolean | Only return archived projects | No
| name_pattern | string | Regular expression pattern to match project names | Yes
| opt_fields | string | Comma-separated list of optional fields to include | No
| workspace | string | The workspace to search in | Yes
</details>
<details>
<summary>asana_search_tasks</summary>

**Description**:

```
Search tasks in a workspace with advanced filtering options
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assigned_by_any | string | Comma-separated list of user IDs | No
| assigned_by_not | string | Comma-separated list of user IDs to exclude | No
| assignee_any | string | Comma-separated list of user IDs | No
| assignee_not | string | Comma-separated list of user IDs to exclude | No
| commented_on_by_not | string | Comma-separated list of user IDs to exclude | No
| completed | boolean | Filter for completed tasks | No
| completed_at_after | string | ISO 8601 datetime string | No
| completed_at_before | string | ISO 8601 datetime string | No
| completed_on | string | ISO 8601 date string or null | No
| completed_on_after | string | ISO 8601 date string | No
| completed_on_before | string | ISO 8601 date string | No
| created_at_after | string | ISO 8601 datetime string | No
| created_at_before | string | ISO 8601 datetime string | No
| created_by_any | string | Comma-separated list of user IDs | No
| created_by_not | string | Comma-separated list of user IDs to exclude | No
| created_on | string | ISO 8601 date string or null | No
| created_on_after | string | ISO 8601 date string | No
| created_on_before | string | ISO 8601 date string | No
| custom_fields | object | Object containing custom field filters. Keys should be in the format "{gid}.{operation}" where operation can be:
- {gid}.is_set: Boolean - For all custom field types, check if value is set
- {gid}.value: String|Number|String(enum_option_gid) - Direct value match for Text, Number or Enum fields
- {gid}.starts_with: String - For Text fields only, check if value starts with string
- {gid}.ends_with: String - For Text fields only, check if value ends with string
- {gid}.contains: String - For Text fields only, check if value contains string
- {gid}.less_than: Number - For Number fields only, check if value is less than number
- {gid}.greater_than: Number - For Number fields only, check if value is greater than number

Example: { "12345.value": "high", "67890.contains": "urgent" } | No
| due_at_after | string | ISO 8601 datetime string | No
| due_at_before | string | ISO 8601 datetime string | No
| due_on | string | ISO 8601 date string or null | No
| due_on_after | string | ISO 8601 date string | No
| due_on_before | string | ISO 8601 date string | No
| followers_not | string | Comma-separated list of user IDs to exclude | No
| has_attachment | boolean | Filter for tasks with attachments | No
| is_blocked | boolean | Filter for tasks with incomplete dependencies | No
| is_blocking | boolean | Filter for incomplete tasks with dependents | No
| is_subtask | boolean | Filter for subtasks | No
| liked_by_not | string | Comma-separated list of user IDs to exclude | No
| modified_at_after | string | ISO 8601 datetime string | No
| modified_at_before | string | ISO 8601 datetime string | No
| modified_on | string | ISO 8601 date string or null | No
| modified_on_after | string | ISO 8601 date string | No
| modified_on_before | string | ISO 8601 date string | No
| opt_fields | string | Comma-separated list of optional fields to include | No
| portfolios_any | string | Comma-separated list of portfolio IDs | No
| projects_all | string | Comma-separated list of project IDs that must all match | No
| projects_any | string | Comma-separated list of project IDs | No
| projects_not | string | Comma-separated list of project IDs to exclude | No
| resource_subtype | string | Filter by task subtype (e.g. milestone) | No
| sections_all | string | Comma-separated list of section IDs that must all match | No
| sections_any | string | Comma-separated list of section IDs | No
| sections_not | string | Comma-separated list of section IDs to exclude | No
| sort_ascending | boolean | Sort in ascending order | No
| sort_by | string | Sort by: due_date, created_at, completed_at, likes, modified_at | No
| start_on | string | ISO 8601 date string or null | No
| start_on_after | string | ISO 8601 date string | No
| start_on_before | string | ISO 8601 date string | No
| tags_all | string | Comma-separated list of tag IDs that must all match | No
| tags_any | string | Comma-separated list of tag IDs | No
| tags_not | string | Comma-separated list of tag IDs to exclude | No
| teams_any | string | Comma-separated list of team IDs | No
| text | string | Text to search for in task names and descriptions | No
| workspace | string | The workspace to search in | Yes
</details>
<details>
<summary>asana_get_task</summary>

**Description**:

```
Get detailed information about a specific task
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| task_id | string | The task ID to retrieve | Yes
</details>
<details>
<summary>asana_create_task</summary>

**Description**:

```
Create a new task in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee | string | Assignee (can be 'me' or a user ID) | No
| custom_fields | object | Object mapping custom field GID strings to their values. For enum fields use the enum option GID as the value. | No
| due_on | string | Due date in YYYY-MM-DD format | No
| followers | array | Array of user IDs to add as followers | No
| html_notes | string | HTML-like formatted description of the task. Does not support ALL HTML tags. Only a subset. The only allowed TAG in the HTML are: <body> <h1> <h2> <ol> <ul> <li> <strong> <em> <u> <s> <code> <pre> <blockquote> <a data-asana-type="" data-asana-gid=""> <hr> <img> <table> <tr> <td>. No other tags are allowed. Use the \n to create a newline. Do not use \n after <body>. Example: <body><h1>Motivation</h1>
A customer called in to complain
<h1>Goal</h1>
Fix the problem</body> | No
| name | string | Name of the task | Yes
| notes | string | Description of the task | No
| parent | string | The parent task ID to set this task under | No
| project_id | string | The project to create the task in | Yes
| projects | array | Array of project IDs to add this task to | No
| resource_subtype | string | The type of the task. Can be one of 'default_task' or 'milestone' | No
</details>
<details>
<summary>asana_get_task_stories</summary>

**Description**:

```
Get comments and stories for a specific task
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| task_id | string | The task ID to get stories for | Yes
</details>
<details>
<summary>asana_update_task</summary>

**Description**:

```
Update an existing task's details
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee | string | New assignee (can be 'me' or a user ID) | No
| completed | boolean | Mark task as completed or not | No
| custom_fields | object | Object mapping custom field GID strings to their values. For enum fields use the enum option GID as the value. | No
| due_on | string | New due date in YYYY-MM-DD format | No
| name | string | New name for the task | No
| notes | string | New description for the task | No
| resource_subtype | string | The type of the task. Can be one of 'default_task' or 'milestone' | No
| task_id | string | The task ID to update | Yes
</details>
<details>
<summary>asana_get_project</summary>

**Description**:

```
Get detailed information about a specific project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| project_id | string | The project ID to retrieve | Yes
</details>
<details>
<summary>asana_get_project_task_counts</summary>

**Description**:

```
Get the number of tasks in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| project_id | string | The project ID to get task counts for | Yes
</details>
<details>
<summary>asana_get_project_sections</summary>

**Description**:

```
Get sections in a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| project_id | string | The project ID to get sections for | Yes
</details>
<details>
<summary>asana_create_task_story</summary>

**Description**:

```
Create a comment or story on a task
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| task_id | string | The task ID to add the story to | Yes
| text | string | The text content of the story/comment | Yes
</details>
<details>
<summary>asana_add_task_dependencies</summary>

**Description**:

```
Set dependencies for a task
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dependencies | array | Array of task IDs that this task depends on | Yes
| task_id | string | The task ID to add dependencies to | Yes
</details>
<details>
<summary>asana_add_task_dependents</summary>

**Description**:

```
Set dependents for a task (tasks that depend on this task)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dependents | array | Array of task IDs that depend on this task | Yes
| task_id | string | The task ID to add dependents to | Yes
</details>
<details>
<summary>asana_create_subtask</summary>

**Description**:

```
Create a new subtask for an existing task
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee | string | Assignee (can be 'me' or a user ID) | No
| due_on | string | Due date in YYYY-MM-DD format | No
| name | string | Name of the subtask | Yes
| notes | string | Description of the subtask | No
| opt_fields | string | Comma-separated list of optional fields to include | No
| parent_task_id | string | The parent task ID to create the subtask under | Yes
</details>
<details>
<summary>asana_get_multiple_tasks_by_gid</summary>

**Description**:

```
Get detailed information about multiple tasks by their GIDs (maximum 25 tasks)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| task_ids | any | Array or comma-separated string of task GIDs to retrieve (max 25) | Yes
</details>
<details>
<summary>asana_get_project_status</summary>

**Description**:

```
Get a project status update
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| opt_fields | string | Comma-separated list of optional fields to include | No
| project_status_gid | string | The project status GID to retrieve | Yes
</details>
<details>
<summary>asana_get_project_statuses</summary>

**Description**:

```
Get all status updates for a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Results per page (1-100) | No
| offset | string | Pagination offset token | No
| opt_fields | string | Comma-separated list of optional fields to include | No
| project_gid | string | The project GID to get statuses for | Yes
</details>
<details>
<summary>asana_create_project_status</summary>

**Description**:

```
Create a new status update for a project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| color | string | The color of the status (green, yellow, red) | No
| html_text | string | HTML formatted text for the status update | No
| opt_fields | string | Comma-separated list of optional fields to include | No
| project_gid | string | The project GID to create the status for | Yes
| text | string | The text content of the status update | Yes
| title | string | The title of the status update | No
</details>
<details>
<summary>asana_delete_project_status</summary>

**Description**:

```
Delete a project status update
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_status_gid | string | The project status GID to delete | Yes
</details>
<details>
<summary>asana_set_parent_for_task</summary>

**Description**:

```
Set the parent of a task and position the subtask within the other subtasks of that parent
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | any | not set | Yes
| opts | any | not set | No
| task_id | string | The task ID to operate on | Yes
</details>
<details>
<summary>asana_get_tasks_for_tag</summary>

**Description**:

```
Get tasks for a specific tag
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | The number of objects to return per page. The value must be between 1 and 100. | No
| offset | string | An offset to the next page returned by the API. | No
| opt_fields | string | Comma-separated list of optional fields to include | No
| opt_pretty | boolean | Provides the response in a 'pretty' format | No
| tag_gid | string | The tag GID to retrieve tasks for | Yes
</details>
<details>
<summary>asana_get_tags_for_workspace</summary>

**Description**:

```
Get tags in a workspace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Results per page. The number of objects to return per page. The value must be between 1 and 100. | No
| offset | string | Offset token. An offset to the next page returned by the API. | No
| opt_fields | string | Comma-separated list of optional fields to include | No
| workspace_gid | string | Globally unique identifier for the workspace or organization | Yes
</details>

## 📝 Prompts (3)
<details>
<summary>task-summary</summary>

**Description**:

```
Get a summary and status update for a task based on its notes, custom fields and comments
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task_id | The task ID to get summary for |Yes |
<details>
<summary>task-completeness</summary>

**Description**:

```
Analyze if a task description contains all necessary details for completion
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task_id | The task ID or URL to analyze |Yes |
<details>
<summary>create-task</summary>

**Description**:

```
Create a new task with specified details
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| project_name | The name of the Asana project where the task should be created |Yes |
| title | The title of the task |Yes |
| notes | Notes or description for the task |No |
| due_date | Due date for the task (YYYY-MM-DD format) |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | create-task | description | ef2bf4cf1171403456efde64e512f1dc747f67226648eb0c3f6ebb721b902f7e |
| prompts | create-task | due_date | 1e9af4d07246b3de2b2ee3316103f70f0e3d648468ad2aef9af559062d253519 |
| prompts | create-task | notes | dca1a8296d13ab4754cc93b2d923e9510ab40c78b50484bccb657eb729764a81 |
| prompts | create-task | project_name | 3c496caa6cb9b444ad71730074c988cab465fa225bb0ababcd2d4701eb62901d |
| prompts | create-task | title | d8da4c4d3526af1a57622c424e319610776173949629e64383033f6f28dae876 |
| prompts | task-completeness | description | 11bb9c71cd8e51785c11222bec854455afccb24cd853d2ff74d7ba3946128571 |
| prompts | task-completeness | task_id | f78e647c34a2c96b7bff023f520ca2f6ff4d71e4f317496df44810658bcef098 |
| prompts | task-summary | description | 2cff30a50d2c96dd1e2b6d1ad2d4745e683fa0962a22e4ece0fafa161f059edd |
| prompts | task-summary | task_id | 3dfdc18e1f23a15b26832b738fa25ebf48853051fdfedf4e07c84f431911c71d |
| tools | asana_add_task_dependencies | description | d32fd56574de2103751c42911a3affc7c05a3b2460d1e89447ea8853a7f1593b |
| tools | asana_add_task_dependencies | dependencies | 96bb442490ee7e72d93d93f218793bd6cd46e72ec0f11edda34e34c1b6502d78 |
| tools | asana_add_task_dependencies | task_id | aef1a766ee8802da1a26638a2faaf698606b7cde85b7926023611f201d497dc4 |
| tools | asana_add_task_dependents | description | 14c2a23582926adb7eeeb9ed296c9faf28328008c2b75325b2c3fff91489d0fa |
| tools | asana_add_task_dependents | dependents | 1def03152a648aa9a30854aa779859c4a9b24eaa59acb1e16f9222e680ad1202 |
| tools | asana_add_task_dependents | task_id | 80039f1dc430aa74b03e88a6790e2077f45d64ac102fe4cad0e439e28833ae9f |
| tools | asana_create_project_status | description | da53f764cc00160e25327399e97957c0037b398a87a8306c77a8a94930e73c31 |
| tools | asana_create_project_status | color | 26b22f769724651fedb8492940742a416d38f415ee786b4667c6c5baef2abc2e |
| tools | asana_create_project_status | html_text | 278c495b02ced56ed50a9c44582a364db6badd0e35994d949bbd8d5762f5558a |
| tools | asana_create_project_status | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_create_project_status | project_gid | a93ee08cbd122d9d4e72de0b1176a02f43295e8d541927460a26efbafb5337c2 |
| tools | asana_create_project_status | text | 89a70b218beefe9b17e464be6bac085a5365533f690d3232dcbfdb637ca739d3 |
| tools | asana_create_project_status | title | b8017abc5b8970caef50fce2f38efbee50f0e4eecd4ad76ad133fb2849c69c59 |
| tools | asana_create_subtask | description | 70f4f8d795b562bc5fefa2963283c979a40de3a92acd90cc7186d7d171507b9a |
| tools | asana_create_subtask | assignee | bc5272b7abc6993a6ab294cf3725ded994c0b607e164004a77b1b577ab49d49b |
| tools | asana_create_subtask | due_on | 21e135937bb93d6ed0f232d5dbe842929b58ab5130cafe9be7dcba837203bea8 |
| tools | asana_create_subtask | name | e06f72dfe1ec9bd043e1bd43c1a1c0d91a52363ba61bc25dfc5060b9c74bedbb |
| tools | asana_create_subtask | notes | cec0f204e6a1b639ccabc452ecb5d36eccd7c3cd419c47735cdda5359af0fe03 |
| tools | asana_create_subtask | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_create_subtask | parent_task_id | 70a8662aef3eeb608d507118768bbc831bd98072ad6a9aab209097d524d8955d |
| tools | asana_create_task | description | c23c7e418e4ec60ecf4c87af245649dcac85bf197620b39803ac4f081b12f447 |
| tools | asana_create_task | assignee | bc5272b7abc6993a6ab294cf3725ded994c0b607e164004a77b1b577ab49d49b |
| tools | asana_create_task | custom_fields | f0d14e376ebca9bb027f0238cf0cd8aef43ee4a9b777dd396bb7fd838a9283cd |
| tools | asana_create_task | due_on | 21e135937bb93d6ed0f232d5dbe842929b58ab5130cafe9be7dcba837203bea8 |
| tools | asana_create_task | followers | c7409785bdb367b99dfc71805a449a78170fd2c9362986f1905d94b812cdd3b5 |
| tools | asana_create_task | html_notes | 86ad39ec2a222c3e284f4cf480188d677bc9255e820f8f8ec962db060fdbea11 |
| tools | asana_create_task | name | 5362f769279c77085e52d04dc2f152827490059c61f5ed6d1996c37f87acb710 |
| tools | asana_create_task | notes | e2e7e8c11e7e795951b86786622612b34e22f9f055de975624246c0b2d9be26e |
| tools | asana_create_task | parent | 457dada16f09c3ebceb339d96fd964cdcc47076118fc424e278b430ed1a1503f |
| tools | asana_create_task | project_id | 4ca4b40fe8cddec1509564149f0946c089ca481daf2ffdf3367364342fd3f269 |
| tools | asana_create_task | projects | d4614a5cdc125e77cf18255bd75535a4ca9f0fa32cef10471d7031d67be18979 |
| tools | asana_create_task | resource_subtype | 5fe76412323c750c22bcb1ea9eb80b417084ed611989ba580a3467519cd04bde |
| tools | asana_create_task_story | description | 58e383048a725fe7119ac9fd8709c634e04002a06e9b732e87f0ba18143ecf86 |
| tools | asana_create_task_story | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_create_task_story | task_id | c6e6c0498aeb696b7ff1be3c6aa0af1079373733077095b30f932ff3b45b88e4 |
| tools | asana_create_task_story | text | 4f5b962be5c656efa99679c8666c023ee9dab29e86b482f169105141bacaaf52 |
| tools | asana_delete_project_status | description | 052d463f46c857d1ed8168dddc0b67f485756d5c1f4139e2e39ff502aeceb07a |
| tools | asana_delete_project_status | project_status_gid | 4fb1620efecca77fbb3369b7a097e53a960a8a3accca6c447f5804a9c6ecac5d |
| tools | asana_get_multiple_tasks_by_gid | description | 19641b140af5b31751be9c3260772fc4b8853121b6136af8b84dd93f63886cf7 |
| tools | asana_get_multiple_tasks_by_gid | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_multiple_tasks_by_gid | task_ids | cb5c3313d3887c72636a9800b3ac8896441dc84cd094b986c4dd1347ac60cbd4 |
| tools | asana_get_project | description | a20ba6be15b4a0732c9eae9cbc067ebe85c7a002bcaeb380fd4d40e8f1c00113 |
| tools | asana_get_project | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_project | project_id | 77d7e81f188b6ad66f5f3cecdae26ab5bf37a82e1fc3df8af450991d676e0536 |
| tools | asana_get_project_sections | description | 5d252b58dbb43470b9d65504aa614e071eb6818edb74fee9c65271f2fb8c7862 |
| tools | asana_get_project_sections | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_project_sections | project_id | 2d0ae1e620a21f8a60fcf983eef80e7a81b6d92631f6cd6ff6daab0f07b5b181 |
| tools | asana_get_project_status | description | 7118d8d7036a9299cb602985f7b71e3d8ca69521e7d7867261d79d5a18d1f640 |
| tools | asana_get_project_status | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_project_status | project_status_gid | ccd3e275077efe2aaf9f79ad9498f944cb03f392c1eb13901e0d51377cf4da0f |
| tools | asana_get_project_statuses | description | 6aa8858bd2a9af5b987ac9b24f2295aa0244db56712abdd50a70d3eacbfc3a5d |
| tools | asana_get_project_statuses | limit | d03f5766ac9c4149ebd39769582e65a2ff2fc0d348932d0883e67eba49be786a |
| tools | asana_get_project_statuses | offset | 1b228d1b190aa9087ec05ad28810146f9688281055753a2b4d209c5d25172e93 |
| tools | asana_get_project_statuses | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_project_statuses | project_gid | e9e1afb3c289b591c0949b644140706f0fe82dac31b4cccf250eac57f2284b92 |
| tools | asana_get_project_task_counts | description | d6f55d4556a66caa61bc01b45227e971db414320e04f4fab4877067085e835ac |
| tools | asana_get_project_task_counts | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_project_task_counts | project_id | a8aca7ab1398a0d47ee2d7a1cdcdd87582b31607b2b851ed4459ad1d1d1b8e42 |
| tools | asana_get_tags_for_workspace | description | bdc0a8cd01a2c49221b7f9445f5e425c9aec0ce604602c8731cffd332e63ca56 |
| tools | asana_get_tags_for_workspace | limit | ffbee25753639cab74591413831f32462f0a3ce0bf6e7457539080e029295044 |
| tools | asana_get_tags_for_workspace | offset | 7bd23006991d2017bd74097ab5334950ac2f0baeada7d99de848fbbb2f133970 |
| tools | asana_get_tags_for_workspace | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_tags_for_workspace | workspace_gid | 709303f231c1986443ecace03c0258c2ee9e912fcf02ffab14cd6d3352095150 |
| tools | asana_get_task | description | ad4f4d05452acb4fdba248caac9af8af662d342e9cd2027a9d46c30bd565057f |
| tools | asana_get_task | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_task | task_id | 54cce24b9fc29455ac3e4176308928e73a2af483eac0a870aff7c9c1828f0f2e |
| tools | asana_get_task_stories | description | 9d5f2feea90a3046c65f4c56c11320c2175ae95707678117061b3a82a0c89239 |
| tools | asana_get_task_stories | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_task_stories | task_id | 3dc6c20c528c6d4968e59790f5f2a339ff0a0a59b30755189b6ebc0f6f5cde48 |
| tools | asana_get_tasks_for_tag | description | a999946fc3dba65bc12315fe1a8acb0de1f38ab80d400acf3e650427b620e920 |
| tools | asana_get_tasks_for_tag | limit | 959b6a6d1a0174ab07754999fa557be7476b33f5f1faeffb58e0cd2be53805c1 |
| tools | asana_get_tasks_for_tag | offset | d13d8b72ea3e2b6408e90178f39e7a3c8846dd7945a655918b83640160f73a5c |
| tools | asana_get_tasks_for_tag | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_get_tasks_for_tag | opt_pretty | c6f5338b66c9b8e5e1ac79d470615416cf56cfa89660e8cd880f5cc2ed14e9eb |
| tools | asana_get_tasks_for_tag | tag_gid | 8b8acc5ca48cc7a8100e7801ebf27b5b66754aebba4e67d0f6fed2859d247a5e |
| tools | asana_list_workspaces | description | 8161bb783b898dbae5c7923ed647800435e2cc21946a2d1cf25dd5c2d86f93eb |
| tools | asana_list_workspaces | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_search_projects | description | 464076832aa6aa0d18287e6ab64eabbc0e7d289e1b10d854968da7294ff94217 |
| tools | asana_search_projects | archived | f43ae20b80d17f8d7c5fe27dfa6f62efb78adf356122b55c714e44d8014a16e6 |
| tools | asana_search_projects | name_pattern | ca3f077301d162cffb8fb2aa4e1450e7bf253b52df36ed17f09a7f8c6dfadbbb |
| tools | asana_search_projects | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_search_projects | workspace | 0dd39fd3a709675b50a1b00477aff61b08b0db83dfc027a52b0279200ac2234a |
| tools | asana_search_tasks | description | d069ea32d7ab496cf2d2566974981ece2e2f7c1942f3dc687c116a0cc7df6b97 |
| tools | asana_search_tasks | assigned_by_any | 7eb49f2f42318bdc2f5872a6f995917f0a36fd5c79d202ba574bec33dda306f5 |
| tools | asana_search_tasks | assigned_by_not | 7e0e0b47086d406881d46a556abba2ce7ae150f08b4d23624b8fbfe41196433b |
| tools | asana_search_tasks | assignee_any | 7eb49f2f42318bdc2f5872a6f995917f0a36fd5c79d202ba574bec33dda306f5 |
| tools | asana_search_tasks | assignee_not | 7e0e0b47086d406881d46a556abba2ce7ae150f08b4d23624b8fbfe41196433b |
| tools | asana_search_tasks | commented_on_by_not | 7e0e0b47086d406881d46a556abba2ce7ae150f08b4d23624b8fbfe41196433b |
| tools | asana_search_tasks | completed | 9720bebca6767230aea9f38bd0d3846d7bcc6376830023ba4325513494520b4b |
| tools | asana_search_tasks | completed_at_after | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | completed_at_before | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | completed_on | b2ea66c98d136cd7f6a9e9a2cfed4ab6006c65fc844f13641c361c1f1bbd3660 |
| tools | asana_search_tasks | completed_on_after | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | completed_on_before | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | created_at_after | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | created_at_before | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | created_by_any | 7eb49f2f42318bdc2f5872a6f995917f0a36fd5c79d202ba574bec33dda306f5 |
| tools | asana_search_tasks | created_by_not | 7e0e0b47086d406881d46a556abba2ce7ae150f08b4d23624b8fbfe41196433b |
| tools | asana_search_tasks | created_on | b2ea66c98d136cd7f6a9e9a2cfed4ab6006c65fc844f13641c361c1f1bbd3660 |
| tools | asana_search_tasks | created_on_after | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | created_on_before | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | custom_fields | a6f8007a9660510f54b81df8bb01d7659151b257815ec8e8e8d2264cfeb0bd15 |
| tools | asana_search_tasks | due_at_after | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | due_at_before | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | due_on | b2ea66c98d136cd7f6a9e9a2cfed4ab6006c65fc844f13641c361c1f1bbd3660 |
| tools | asana_search_tasks | due_on_after | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | due_on_before | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | followers_not | 7e0e0b47086d406881d46a556abba2ce7ae150f08b4d23624b8fbfe41196433b |
| tools | asana_search_tasks | has_attachment | c023e91560f82865e3834dde9b17a855757168eafdc7716c0aadfd5bc0faf9f8 |
| tools | asana_search_tasks | is_blocked | 56390970f1d4e0bad13e8632ead9f2b2d7356d01506621f2eeebcaab6022152d |
| tools | asana_search_tasks | is_blocking | 0e93a058455d31e32609346a4b8dddfaee8d1488287c6182903743eed22356d8 |
| tools | asana_search_tasks | is_subtask | 1e60777fede3609187f61baa7ae9593f4e0b86bf15ff718fba359baece981197 |
| tools | asana_search_tasks | liked_by_not | 7e0e0b47086d406881d46a556abba2ce7ae150f08b4d23624b8fbfe41196433b |
| tools | asana_search_tasks | modified_at_after | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | modified_at_before | 85186527dbf79d5fb3301accef0f977e3933572fb73159de7a3a0308e24af8ac |
| tools | asana_search_tasks | modified_on | b2ea66c98d136cd7f6a9e9a2cfed4ab6006c65fc844f13641c361c1f1bbd3660 |
| tools | asana_search_tasks | modified_on_after | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | modified_on_before | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | opt_fields | 9dda551c97262cd3016e2f2352c352c6a64ffa383d9a2e75b785dee100cd5bed |
| tools | asana_search_tasks | portfolios_any | 5588b55a4dd61f97a68b00dab07b85eec74893087cb3c6db9b2da6c5b93397d1 |
| tools | asana_search_tasks | projects_all | 3b200bd46607d4b1ea3b3601d179ac1ba2ed2074fcaf7b702774bc22e70d40d2 |
| tools | asana_search_tasks | projects_any | 09658d727d1add565727de338ef0f8094f4d86017726a74aba6c1765058e413c |
| tools | asana_search_tasks | projects_not | 8c53877577fd80639448cb8b7412adb2c8f02b1b3c48a372a966d5b938bccb95 |
| tools | asana_search_tasks | resource_subtype | 904584f6130300c6fe85249cd560a86bfddcaa39c45bf85db07eb1f87fc41948 |
| tools | asana_search_tasks | sections_all | 6a115c53de765b526795d041048a6599096d7136cc7c9f11405fbd6d15ec7ec6 |
| tools | asana_search_tasks | sections_any | b0c0d1d99369d6b3fc2ac5c927b4d33281276263df09b0e2940f3aa3cf1045f4 |
| tools | asana_search_tasks | sections_not | 99019184b6c9e090d51b7ad25d9d6c777a65f23cd254033c49e786078d7b07fe |
| tools | asana_search_tasks | sort_ascending | e2049d5ff04f98eef7e4d4a76f062ec03a1d7467a7ba41a90f44d72a0f9f1357 |
| tools | asana_search_tasks | sort_by | 487dbf27e7bdaed5e46aa0ca5130e6f54e5c0f1488bec54bb3181dab46110ec9 |
| tools | asana_search_tasks | start_on | b2ea66c98d136cd7f6a9e9a2cfed4ab6006c65fc844f13641c361c1f1bbd3660 |
| tools | asana_search_tasks | start_on_after | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | start_on_before | dda0a3bed416c36d4b2f2aea7a6558d86db2066a27590a378991bd9f3bab5969 |
| tools | asana_search_tasks | tags_all | 3a8d464c1917e4dd20aadfe4b56e127638b8c047ef6351fec6c509beb0120ee7 |
| tools | asana_search_tasks | tags_any | 4787f362850668edbdf18264a52c9be93ad553b2eb9fc16d40d18ff8ff8e4d4b |
| tools | asana_search_tasks | tags_not | 46857065c1ea5bc5382fe474c8c13a941b053f946807680788c01534f54b0d61 |
| tools | asana_search_tasks | teams_any | bf4ccaf927f111a9bc76ad674d9ebb07792c8505441a9ba5d3bf6a82dd782861 |
| tools | asana_search_tasks | text | 748f32e5653b7c6cd34fbf7be7cfd373339bff16de6425988c7fd31744c8106a |
| tools | asana_search_tasks | workspace | 0dd39fd3a709675b50a1b00477aff61b08b0db83dfc027a52b0279200ac2234a |
| tools | asana_set_parent_for_task | description | 517838aca71239a89a56ea48cfbea66c51f39b22c881d42369d1bc9f0ef483c9 |
| tools | asana_set_parent_for_task | task_id | 0c546230157d8d353dc93d0c606ce1ef47d16d192c533d7f5efa4eb9bef30278 |
| tools | asana_update_task | description | 55acdd57cf92287df9615b4eb836ff5b88e8bf29d519fa474fc3db9d1cecf917 |
| tools | asana_update_task | assignee | 291ab7fb273fa80e304076aae06a751d66ffe1770afa9f2d9a167cbdaf0d700d |
| tools | asana_update_task | completed | c7c47805ccd82a7e5a1c6f5ac0523a1d584e1a88aa1e84f7c1d9fff556d87337 |
| tools | asana_update_task | custom_fields | f0d14e376ebca9bb027f0238cf0cd8aef43ee4a9b777dd396bb7fd838a9283cd |
| tools | asana_update_task | due_on | 6a569b80a885c5808a66ebf91561b18833ce62db833558a6dcaf164c62a76947 |
| tools | asana_update_task | name | 23e72497d26ddb6a18577e62545e66f969a34a2905a09f0efc95dd2d3b473a76 |
| tools | asana_update_task | notes | 1a871a5bce1bdcd95995e43e2ef966bf1cbcd123382ddb0e653c39b17f5953f6 |
| tools | asana_update_task | resource_subtype | 5fe76412323c750c22bcb1ea9eb80b417084ed611989ba580a3467519cd04bde |
| tools | asana_update_task | task_id | 89c51c47dc8dfac0cf94f02036017a773c8911e0a6176bfb0174d4ec125b5d87 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
