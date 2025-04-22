

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


# What is mcp-server-google-maps?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-google-maps?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-google-maps)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for using the Google Maps API

> [!NOTE]
> `@modelcontextprotocol/server-google-maps` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-google-maps run reliably and safely.

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
  - [ @modelcontextprotocol/server-google-maps ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-google-maps ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

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
  - `GOOGLE_MAPS_API_KEY` secret to be set as secrets.GOOGLE_MAPS_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-google-maps --version <version>
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-google-maps --version <version>
````

Install will helm

```console
helm install helm install mcp-server-google-maps oci://docker.io/acuvity/mcp-server-google-maps --version <version>
```

From there your MCP server mcp-server-google-maps will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-google-maps` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-google-maps
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-google-maps` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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

## 🧰 Tools (7)
<details>
<summary>maps_geocode</summary>

**Description**:

```
Convert an address into geographic coordinates
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The address to geocode | Yes
</details>
<details>
<summary>maps_reverse_geocode</summary>

**Description**:

```
Convert coordinates into an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| latitude | number | Latitude coordinate | Yes
| longitude | number | Longitude coordinate | Yes
</details>
<details>
<summary>maps_search_places</summary>

**Description**:

```
Search for places using Google Places API
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| location | object | Optional center point for the search | No
| query | string | Search query | Yes
| radius | number | Search radius in meters (max 50000) | No
</details>
<details>
<summary>maps_place_details</summary>

**Description**:

```
Get detailed information about a specific place
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| place_id | string | The place ID to get details for | Yes
</details>
<details>
<summary>maps_distance_matrix</summary>

**Description**:

```
Calculate travel distance and time for multiple origins and destinations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destinations | array | Array of destination addresses or coordinates | Yes
| mode | string | Travel mode (driving, walking, bicycling, transit) | No
| origins | array | Array of origin addresses or coordinates | Yes
</details>
<details>
<summary>maps_elevation</summary>

**Description**:

```
Get elevation data for locations on the earth
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| locations | array | Array of locations to get elevation for | Yes
</details>
<details>
<summary>maps_directions</summary>

**Description**:

```
Get directions between two points
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | Ending point address or coordinates | Yes
| mode | string | Travel mode (driving, walking, bicycling, transit) | No
| origin | string | Starting point address or coordinates | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | maps_directions | description | be6edc95fb62438faec05e86835dc456919392d8cf18526c951c7a08a4313958 |
| tools | maps_directions | destination | 2df250de879f7966a9a78785f234cd66b5e147e87cbe9235d5c7ecbef8114710 |
| tools | maps_directions | mode | fd11df1d8e93e808e44de93385fbb9ac0c42538e437d75eda08274e8f3656043 |
| tools | maps_directions | origin | 3b406abd35291a57c8bc98bfafc14dd5d385826e32a0b18d60e73e12c339867b |
| tools | maps_distance_matrix | description | e7862ed22fd55bcb4f38ff942ab0e152ed48f7586dd721e853a658560ce3f4e7 |
| tools | maps_distance_matrix | destinations | 603580b8ba0838fa89d01745f70e3ca800f38d37edfc34345e7d924027512541 |
| tools | maps_distance_matrix | mode | fd11df1d8e93e808e44de93385fbb9ac0c42538e437d75eda08274e8f3656043 |
| tools | maps_distance_matrix | origins | 6e86b75f528b3da9d842ea051020b59ca37b9cbdaa15159304c29211064f087f |
| tools | maps_elevation | description | 81010e93681dd9f4bb9bdd2b85b6f39f81d21e646380ddf4d590470a0ee2a2a5 |
| tools | maps_elevation | locations | 69af1eac3164bb92e5f241a90143aa9211a0b3993a465dd7f852aa0714d358da |
| tools | maps_geocode | description | a2385eab251b9571f1077b9635182b2de477beb3cdcc6e55984676e2f15b190a |
| tools | maps_geocode | address | 939c8b85e25ecceaeff4e531c5bc982d4be3d0d55ec91a2f17112bce002b1d57 |
| tools | maps_place_details | description | aa55b1ece847bf2602c7105930e3b77aeeff6001ab9b0228948124d493276746 |
| tools | maps_place_details | place_id | a31d452f480641a67d14ebb9211a132acae6e656a87dee7619a6ab95357140ef |
| tools | maps_reverse_geocode | description | 54a9f75c9bdf1a133afa572717edfe37c98fe7320d2a8cf716523347bd5fe84d |
| tools | maps_reverse_geocode | latitude | 104f84a6e60f6931e5dae557844d219c4399aac6977371a1fe478e03225ac37a |
| tools | maps_reverse_geocode | longitude | d1ee91527f594ffba2e15f4474146840c27810eb1b7b3637df3c35da6614fe88 |
| tools | maps_search_places | description | fe1f5391f114826110e251991e5b7cee4b0140d408eceb7601e6f70d3baf596b |
| tools | maps_search_places | location | 078c6550e737ec47a7b41ca7625466380af519f70e3b14f3f5ea97097a8e9bd6 |
| tools | maps_search_places | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | maps_search_places | radius | b990286c4cbfb7fff848cf8a4a0588fd0ae823356374dada25f39106e8cee86e |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
