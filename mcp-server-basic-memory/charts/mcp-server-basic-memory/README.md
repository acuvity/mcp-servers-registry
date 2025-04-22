

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


# What is mcp-server-basic-memory?

[![Helm](https://img.shields.io/badge/v1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/0.12.3?logo=docker&logoColor=fff&label=0.12.3)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/tags/0.12.3)
[![PyPI](https://img.shields.io/badge/0.12.3-3775A9?logo=pypi&logoColor=fff&label=basic-memory)](https://pypi.org/project/basic-memory/)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** Local-first knowledge management combining Zettelkasten with knowledge graphs

> [!NOTE]
> `basic-memory` has been repackaged by Acuvity from its original [sources](https://pypi.org/project/basic-memory/).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure basic-memory run reliably and safely.

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
  - [Charts](https://github.com/acuvity/mcp-servers-registry/mcp-server-basic-memory/charts/mcp-server-basic-memory)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/mcp-server-basic-memory/docker/Dockerfile)

**Current supported version:**
  - charts: `v1.0.0`
  - container: `0.12.3`

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
helm install helm install mcp-server-basic-memory oci://docker.io/acuvity/mcp-server-basic-memory --version v1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-basic-memory --version v1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-basic-memory --version v1.0.0
````
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
args:
  - mcp
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

## 🧰 Tools (9)
<details>
<summary>delete_note</summary>

**Description**:

```
Delete a note by title or permalink
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | <no value> | Yes
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
| path | string | <no value> | Yes
</details>
<details>
<summary>build_context</summary>

**Description**:

```
Build context from a memory:// URI to continue conversations naturally.
    
    Use this to follow up on previous discussions or explore related topics.
    Timeframes support natural language like:
    - "2 days ago"
    - "last week" 
    - "today"
    - "3 months ago"
    Or standard formats like "7d", "24h"
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| depth | <no value> | <no value> | No
| max_related | integer | <no value> | No
| page | integer | <no value> | No
| page_size | integer | <no value> | No
| timeframe | <no value> | <no value> | No
| url | string | <no value> | Yes
</details>
<details>
<summary>recent_activity</summary>

**Description**:

```
Get recent activity from across the knowledge base.

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
| depth | integer | <no value> | No
| max_related | integer | <no value> | No
| page | integer | <no value> | No
| page_size | integer | <no value> | No
| timeframe | string | <no value> | No
| type | <no value> | <no value> | No
</details>
<details>
<summary>search_notes</summary>

**Description**:

```
Search across all content in the knowledge base.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after_date | <no value> | <no value> | No
| entity_types | <no value> | <no value> | No
| page | integer | <no value> | No
| page_size | integer | <no value> | No
| query | string | <no value> | Yes
| search_type | string | <no value> | No
| types | <no value> | <no value> | No
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
| identifier | string | <no value> | Yes
| page | integer | <no value> | No
| page_size | integer | <no value> | No
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
| content | string | <no value> | Yes
| folder | string | <no value> | Yes
| tags | string | <no value> | No
| title | string | <no value> | Yes
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
| edges | array | <no value> | Yes
| folder | string | <no value> | Yes
| nodes | array | <no value> | Yes
| title | string | <no value> | Yes
</details>
<details>
<summary>project_info</summary>

**Description**:

```
Get information and statistics about the current Basic Memory project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| ai assistant guide | text/plain | memory://ai_assistant_guide | <no value> |

</details>

## 📝 Prompts (3)
<details>
<summary>Continue Conversation</summary>

**Description**:

```
Continue a previous conversation
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| topic | Topic or keyword to search for | <no value> |
| timeframe | How far back to look for activity (e.g. '1d', '1 week') | <no value> |
<details>
<summary>Share Recent Activity</summary>

**Description**:

```
Get recent activity from across the knowledge base
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| timeframe | How far back to look for activity (e.g. '1d', '1 week') | <no value> |
<details>
<summary>Search Knowledge Base</summary>

**Description**:

```
Search across all content in basic-memory
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| query | <no value> | true |
| timeframe | How far back to search (e.g. '1d', '1 week') | <no value> |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | Continue Conversation | description | 08f57034421ff1f069d1c1f6dd0dd640b9982a6ba21a5b2442953cb1b5dd6efa |
| prompts | Continue Conversation | timeframe | cd9af00423b977d8f501edaeef3d43f42a323778bbbcc0900c4d88b6a4f9354e |
| prompts | Continue Conversation | topic | d8cb6ba6d70a65d763ba5f3f38b7f24ffee35f1f32c0fb1d5bfe095ba9f2d327 |
| prompts | Search Knowledge Base | description | dcd0e4296554bc417239afd10b686e82c4879c842c3a7c60a2288ad0152513e3 |
| prompts | Search Knowledge Base | query | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | Search Knowledge Base | timeframe | ac891e951bb4167b6fafdd14fdac08a1dcf761aacef7f3add86de2000a8223fb |
| prompts | Share Recent Activity | description | acaf99888843d7d2c0243f8bf67259929179ab71579a4af5a16571f3485475f7 |
| prompts | Share Recent Activity | timeframe | cd9af00423b977d8f501edaeef3d43f42a323778bbbcc0900c4d88b6a4f9354e |
| tools | build_context | description | 5e8820de852b3082413d3bd44c6d0b5764cea766cadfcac66876f4b49e604614 |
| tools | canvas | description | c739f799c4f54a0beebbbba387862e5370f4e715f36b65d0e523b3fe664d759c |
| tools | delete_note | description | b92bd108ffa7b65b4ac92c9f75167080771a08e3e9a78dd6ec3fabde085802b7 |
| tools | project_info | description | 80e50af2790edd8a0228a515f76a18d540cb04542b3f5fa91037917a6ae13847 |
| tools | read_content | description | 5b184094eabd23821254f0608ad35de1570fd776906e9ff822020cd68d129921 |
| tools | read_note | description | 5d503b64dafb1601312dd1780eb5fbdb5d7988f7d1ce090545c3fb033c0bec77 |
| tools | recent_activity | description | 8b43acabdd7bc9e4ab6398f1f27b28203fb5df0314d7f0888946136d40f548d5 |
| tools | search_notes | description | fcaec1323a397ec1b89c8d50efb4cf4af054f0574d569452599c927231594adc |
| tools | write_note | description | 3fb632ad40400235da2eae016e76b13f699cd2206aca615729e8ee85653ec98f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
