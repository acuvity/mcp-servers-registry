

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


# What is mcp-server-memory?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-memory?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-memory/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-memory/tags)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-memory)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for enabling memory for Claude through a knowledge graph

> [!NOTE]
> `@modelcontextprotocol/server-memory` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-memory run reliably and safely.

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
  - [ Anthropic, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @modelcontextprotocol/server-memory ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-memory ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

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
  - `MEMORY_FILE_PATH="/data/default.json"` environment variable can be changed with `env.MEMORY_FILE_PATH="/data/default.json"`

# How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-memory/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-memory --version <version>
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-memory --version <version>
````

Install will helm

```console
helm install helm install mcp-server-memory oci://docker.io/acuvity/mcp-server-memory --version <version>
```

From there your MCP server mcp-server-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-memory` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-memory
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-memory` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
<summary>create_entities</summary>

**Description**:

```
Create multiple new entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entities | array | <no value> | Yes
</details>
<details>
<summary>create_relations</summary>

**Description**:

```
Create multiple new relations between entities in the knowledge graph. Relations should be in active voice
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | <no value> | Yes
</details>
<details>
<summary>add_observations</summary>

**Description**:

```
Add new observations to existing entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| observations | array | <no value> | Yes
</details>
<details>
<summary>delete_entities</summary>

**Description**:

```
Delete multiple entities and their associated relations from the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entityNames | array | An array of entity names to delete | Yes
</details>
<details>
<summary>delete_observations</summary>

**Description**:

```
Delete specific observations from entities in the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| deletions | array | <no value> | Yes
</details>
<details>
<summary>delete_relations</summary>

**Description**:

```
Delete multiple relations from the knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | An array of relations to delete | Yes
</details>
<details>
<summary>read_graph</summary>

**Description**:

```
Read the entire knowledge graph
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>search_nodes</summary>

**Description**:

```
Search for nodes in the knowledge graph based on a query
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The search query to match against entity names, types, and observation content | Yes
</details>
<details>
<summary>open_nodes</summary>

**Description**:

```
Open specific nodes in the knowledge graph by their names
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| names | array | An array of entity names to retrieve | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_observations | description | f66d1982a935c25deae16641b447a894687858da5f4e56a4ffd5eded9f15287b |
| tools | create_entities | description | 5d2cd1d3e5d4ea6fd952e9568d41dd54e18c1c5a611daffe1c0399ebc57444e1 |
| tools | create_relations | description | eeb160c5595ea67cee737ea4d34dcf3d22b3d316e107d1edcf02d1dc71727f37 |
| tools | delete_entities | description | 4e8ad2271cd9cfd21a213070f051534e2fb5c6723d7f5d2eed86c9a2f41b05c2 |
| tools | delete_entities | entityNames | a927153ab95010896fc74cf8f26a9c7bc3e840e7aaf9fc7f15866c3525873ab2 |
| tools | delete_observations | description | bae5684867bc99aa4c62c3cb29dccb386983e7575a910a8be7d13ea023aafd80 |
| tools | delete_relations | description | 1b07436348ac9732db58c69ed4db4dbebed012fd263851e1ee4e35e86fe0968e |
| tools | delete_relations | relations | 16642cf152c4f981edf60e0064e4fa10410158457a438a63b60c21c1c4beb5c9 |
| tools | open_nodes | description | 0a799b2e13cab0744fe6b8dd3dbacf7e04753376fdf0adb9d9b6821ad853eded |
| tools | open_nodes | names | 7275b2ac1cb2f632b23e78c872c589a8489cda3a5306f3b399dce23ca813e3ca |
| tools | read_graph | description | 1dfb0bb4dcfe39f92a8a0464153263a3d836524a3c8fd9ff3f73be5ecb2a098c |
| tools | search_nodes | description | cdd54c52fcef34587fc903df13b58b02371a9fb2390cab93d0eeabd229c479f3 |
| tools | search_nodes | query | 2be985b738ac91d8f1e6039cc46c99b96b49b912c19eefccf337c0fc89173cff |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
