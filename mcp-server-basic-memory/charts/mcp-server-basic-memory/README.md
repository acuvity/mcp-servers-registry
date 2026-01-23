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


# What is mcp-server-basic-memory?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-basic-memory/0.17.7?logo=docker&logoColor=fff&label=0.17.7)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory)
[![PyPI](https://img.shields.io/badge/0.17.7-3775A9?logo=pypi&logoColor=fff&label=basic-memory)](https://pypi.org/project/basic-memory/)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-basic-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22memory%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-basic-memory%3A0.17.7%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Local-first knowledge management combining Zettelkasten with knowledge graphs

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from basic-memory original [sources](https://pypi.org/project/basic-memory/).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-basic-memory/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/charts/mcp-server-basic-memory/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure basic-memory run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Basic Machines <hello@basic-machines.co> ](https://pypi.org/project/basic-memory/) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ basic-memory ](https://pypi.org/project/basic-memory/)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ basic-memory ](https://pypi.org/project/basic-memory/)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/charts/mcp-server-basic-memory)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.17.7`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-basic-memory:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-basic-memory:1.0.0-0.17.7`

---

# Table of Contents
- [Storage requirements](#chart-storage-requirements)
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

# Chart storage requirements

This chart will be deployed as a `StatefulSet` as the server requires access to persistent storage.

You will have to configure the storage settings for:
  - `storage.memory.class` with a proper storage class
  - `storage.memory.size` with a proper storage size

# Chart settings requirements

This chart requires some mandatory information to be installed.

**Optional Environment variables**:
  - `HOME="/data"` environment variable can be changed with `env.HOME="/data"`
  - `BASIC_MEMORY_HOME="/data"` environment variable can be changed with `env.BASIC_MEMORY_HOME="/data"`

# How to install


Install will helm

```console
helm install mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-basic-memory
```

From there your MCP server mcp-server-basic-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-basic-memory` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-basic-memory
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
  mcp-server-scope: standalone
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
  memory:
    class:
    size:
```

Configures additional volumes and persistent storage:
- **volumes**: arbitrary Kubernetes `volume` entries to attach.
- **volumeMounts**: mount points inside containers.
- **storage**: iterates `package.storage` entries:
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-basic-memory` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (17)
<details>
<summary>delete_note</summary>

**Description**:

```
Delete a note by title or permalink
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | not set | Yes
| project | any | not set | No
</details>
<details>
<summary>read_content</summary>

**Description**:

```
Read a file's raw content by path or permalink
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
| project | any | not set | No
</details>
<details>
<summary>build_context</summary>

**Description**:

```
Build context from a memory:// URI to continue conversations naturally.

    Use this to follow up on previous discussions or explore related topics.

    Memory URL Format:
    - Use paths like "folder/note" or "memory://folder/note"
    - Pattern matching: "folder/*" matches all notes in folder
    - Valid characters: letters, numbers, hyphens, underscores, forward slashes
    - Avoid: double slashes (//), angle brackets (<>), quotes, pipes (|)
    - Examples: "specs/search", "projects/basic-memory", "notes/*"

    Timeframes support natural language like:
    - "2 days ago", "last week", "today", "3 months ago"
    - Or standard formats like "7d", "24h"
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | any | not set | No
| max_related | integer | not set | No
| page | integer | not set | No
| page_size | integer | not set | No
| project | any | not set | No
| timeframe | any | not set | No
| url | string | not set | Yes
</details>
<details>
<summary>recent_activity</summary>

**Description**:

```
Get recent activity for a project or across all projects.

    Timeframe supports natural language formats like:
    - "2 days ago"
    - "last week"
    - "yesterday"
    - "today"
    - "3 weeks ago"
    Or standard formats like "7d"
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | integer | not set | No
| project | any | not set | No
| timeframe | string | not set | No
| type | any | not set | No
</details>
<details>
<summary>search_notes</summary>

**Description**:

```
Search across all content in the knowledge base with advanced syntax support.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after_date | any | not set | No
| entity_types | any | not set | No
| page | integer | not set | No
| page_size | integer | not set | No
| project | any | not set | No
| query | string | not set | Yes
| search_type | string | not set | No
| types | any | not set | No
</details>
<details>
<summary>read_note</summary>

**Description**:

```
Read a markdown note by title or permalink.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | not set | Yes
| page | integer | not set | No
| page_size | integer | not set | No
| project | any | not set | No
</details>
<details>
<summary>view_note</summary>

**Description**:

```
View a note as a formatted artifact for better readability.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | not set | Yes
| page | integer | not set | No
| page_size | integer | not set | No
| project | any | not set | No
</details>
<details>
<summary>write_note</summary>

**Description**:

```
Create or update a markdown note. Returns a markdown formatted summary of the semantic content.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| folder | string | not set | Yes
| note_type | string | not set | No
| project | any | not set | No
| tags | any | not set | No
| title | string | not set | Yes
</details>
<details>
<summary>canvas</summary>

**Description**:

```
Create an Obsidian canvas file to visualize concepts and connections.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| edges | array | not set | Yes
| folder | string | not set | Yes
| nodes | array | not set | Yes
| project | any | not set | No
| title | string | not set | Yes
</details>
<details>
<summary>list_directory</summary>

**Description**:

```
List directory contents with filtering and depth control.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | integer | not set | No
| dir_name | string | not set | No
| file_name_glob | any | not set | No
| project | any | not set | No
</details>
<details>
<summary>edit_note</summary>

**Description**:

```
Edit an existing markdown note using various operations like append, prepend, find_replace, or replace_section.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| expected_replacements | integer | not set | No
| find_text | any | not set | No
| identifier | string | not set | Yes
| operation | string | not set | Yes
| project | any | not set | No
| section | any | not set | No
</details>
<details>
<summary>move_note</summary>

**Description**:

```
Move a note to a new location, updating database and maintaining links.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination_path | string | not set | Yes
| identifier | string | not set | Yes
| project | any | not set | No
</details>
<details>
<summary>list_memory_projects</summary>

**Description**:

```
List all available projects with their status.

Shows all Basic Memory projects that are available for MCP operations.
Use this tool to discover projects when you need to know which project to use.

Use this tool:
- At conversation start when project is unknown
- When user asks about available projects
- Before any operation requiring a project

After calling:
- Ask user which project to use
- Remember their choice for the session

Returns:
    Formatted list of projects with session management guidance

Example:
    list_memory_projects()
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_memory_project</summary>

**Description**:

```
Create a new Basic Memory project.

Creates a new project with the specified name and path. The project directory
will be created if it doesn't exist. Optionally sets the new project as default.

Args:
    project_name: Name for the new project (must be unique)
    project_path: File system path where the project will be stored
    set_default: Whether to set this project as the default (optional, defaults to False)

Returns:
    Confirmation message with project details

Example:
    create_memory_project("my-research", "~/Documents/research")
    create_memory_project("work-notes", "/home/user/work", set_default=True)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_name | string | not set | Yes
| project_path | string | not set | Yes
| set_default | boolean | not set | No
</details>
<details>
<summary>delete_project</summary>

**Description**:

```
Delete a Basic Memory project.

Removes a project from the configuration and database. This does NOT delete
the actual files on disk - only removes the project from Basic Memory's
configuration and database records.

Args:
    project_name: Name of the project to delete

Returns:
    Confirmation message about project deletion

Example:
    delete_project("old-project")

Warning:
    This action cannot be undone. The project will need to be re-added
    to access its content through Basic Memory again.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_name | string | not set | Yes
</details>
<details>
<summary>search</summary>

**Description**:

```
Search for content across the knowledge base
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | not set | Yes
</details>
<details>
<summary>fetch</summary>

**Description**:

```
Fetch the full contents of a search result document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| ai assistant guide | text/plain | memory://ai_assistant_guide | - |

</details>

## 📝 Prompts (3)
<details>
<summary>continue_conversation</summary>

**Description**:

```
Continue a previous conversation
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| topic | Topic or keyword to search for

Provide as a JSON string matching the following schema: {"anyOf":[{"type":"string"},{"type":"null"}],"description":"Topic or keyword to search for"} |No |
| timeframe | How far back to look for activity (e.g. '1d', '1 week')

Provide as a JSON string matching the following schema: {"anyOf":[{"type":"string"},{"type":"null"}],"description":"How far back to look for activity (e.g. '1d', '1 week')"} |No |
<details>
<summary>recent_activity</summary>

**Description**:

```
Get recent activity from a specific project or across all projects
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| timeframe | How far back to look for activity (e.g. '1d', '1 week')

Provide as a JSON string matching the following schema: {"description":"How far back to look for activity (e.g. '1d', '1 week')","type":"string"} |No |
| project | Specific project to get activity from (None for discovery across all projects)

Provide as a JSON string matching the following schema: {"anyOf":[{"type":"string"},{"type":"null"}],"description":"Specific project to get activity from (None for discovery across all projects)"} |No |
<details>
<summary>search_knowledge_base</summary>

**Description**:

```
Search across all content in basic-memory
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| query | not set |Yes |
| timeframe | How far back to search (e.g. '1d', '1 week')

Provide as a JSON string matching the following schema: {"anyOf":[{"type":"string"},{"type":"null"}],"description":"How far back to search (e.g. '1d', '1 week')"} |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | continue_conversation | description | 08f57034421ff1f069d1c1f6dd0dd640b9982a6ba21a5b2442953cb1b5dd6efa |
| prompts | continue_conversation | timeframe | 79053544f5f692a4029a29d441eddc792330a24eed26004f06c12d7b32892129 |
| prompts | continue_conversation | topic | d05c28ddcc33f478c5ea800d88601aa1dc1286c9dfb64213688006964612eb4e |
| prompts | recent_activity | description | a4ad3c0b4b9cfbc89c2bb0612ad7e1a6a45eca1653dee91498a45d2c58e6c6fd |
| prompts | recent_activity | project | 8ea7ece6387b242003bb4480b908a4501dd0546108b767af5f9c3a4f3caaeaa1 |
| prompts | recent_activity | timeframe | 4279066c7bbd242c4e7277c1a5643b6e1b546053ddacb0dac0f43015cda145ff |
| prompts | search_knowledge_base | description | dcd0e4296554bc417239afd10b686e82c4879c842c3a7c60a2288ad0152513e3 |
| prompts | search_knowledge_base | query | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | search_knowledge_base | timeframe | 3843dff545d4aae893892b8df4c5307eaecaca0314f37ac06061ea52cf78b968 |
| tools | build_context | description | 5a9db2017895c78083f90b9ab28d58605bc3d09d310a60869e9a602002d79e2e |
| tools | canvas | description | c739f799c4f54a0beebbbba387862e5370f4e715f36b65d0e523b3fe664d759c |
| tools | create_memory_project | description | 00d04c2aec156813a221a9e012152062b53fe5c01037c829e4e8805ec3fde06d |
| tools | delete_note | description | b92bd108ffa7b65b4ac92c9f75167080771a08e3e9a78dd6ec3fabde085802b7 |
| tools | delete_project | description | c3d6ffc05720bc4d2413c20a5f73ad917e6954e03b8ec7b3ba4f1975fc933c8e |
| tools | edit_note | description | 7e70b1ab505a2e06e8da48ad7b4368890e8d86778fd9465d88e02bc0c43fc556 |
| tools | fetch | description | 20a68f82bddb07ce389cac0cb2fe30d5db15aee31a8bc46f68b3ca3bcd9237f5 |
| tools | list_directory | description | 8eaf254f8c67f5e7396f90b2a2942e9d47c64860e8b0261bca07de9c5b118d64 |
| tools | list_memory_projects | description | 42d00f25c24b949a0abe56a14ae5a4a377b53110013bab2752b255d3ea631f9a |
| tools | move_note | description | cdc522815f6900fadbdd8fa11ded0afde844bca74753141970fb06972f2beead |
| tools | read_content | description | 5b184094eabd23821254f0608ad35de1570fd776906e9ff822020cd68d129921 |
| tools | read_note | description | 5d503b64dafb1601312dd1780eb5fbdb5d7988f7d1ce090545c3fb033c0bec77 |
| tools | recent_activity | description | 0768babdcbb8ce8f57c9a197eb183147d4e6bd8825a3a705931b83478171ec90 |
| tools | search | description | 3706ec9b490cce0c17f4fca6c321e217e0a41571df2b3a71396534ae1ead083b |
| tools | search_notes | description | 58fb30dcbae336b4aba77cf67870411f4b92a4dd94aac9e62de72f13ec2ed765 |
| tools | view_note | description | 7cb3581bfc58d06d48b06d0e5ff77a8528b44729996ae403a134cfc8b1316303 |
| tools | write_note | description | 3fb632ad40400235da2eae016e76b13f699cd2206aca615729e8ee85653ec98f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
