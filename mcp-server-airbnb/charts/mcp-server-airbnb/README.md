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


# What is mcp-server-airbnb?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-airbnb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-airbnb/0.1.1?logo=docker&logoColor=fff&label=0.1.1)](https://hub.docker.com/r/acuvity/mcp-server-airbnb)
[![PyPI](https://img.shields.io/badge/0.1.1-3775A9?logo=pypi&logoColor=fff&label=@openbnb/mcp-server-airbnb)](https://github.com/openbnb-org/mcp-server-airbnb)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-airbnb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-airbnb%3A0.1.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides tools to search Airbnb and get listing details.

> [!NOTE]
> `@openbnb/mcp-server-airbnb` has been repackaged by Acuvity from OpenBnB original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @openbnb/mcp-server-airbnb run reliably and safely.

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
  - [ OpenBnB ](https://github.com/openbnb-org/mcp-server-airbnb) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @openbnb/mcp-server-airbnb ](https://github.com/openbnb-org/mcp-server-airbnb)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @openbnb/mcp-server-airbnb ](https://github.com/openbnb-org/mcp-server-airbnb)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-airbnb/charts/mcp-server-airbnb)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-airbnb/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.1`

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
helm install helm install mcp-server-airbnb oci://docker.io/acuvity/mcp-server-airbnb --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-airbnb --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-airbnb --version 1.0.0
````
From there your MCP server mcp-server-airbnb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-airbnb` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-airbnb
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-airbnb` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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

## 🧰 Tools (2)
<details>
<summary>airbnb_search</summary>

**Description**:

```
Search for Airbnb listings with various filters and pagination. Provide direct links to the user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| adults | number | Number of adults | No
| checkin | string | Check-in date (YYYY-MM-DD) | No
| checkout | string | Check-out date (YYYY-MM-DD) | No
| children | number | Number of children | No
| cursor | string | Base64-encoded string used for Pagination | No
| ignoreRobotsText | boolean | Ignore robots.txt rules for this request | No
| infants | number | Number of infants | No
| location | string | Location to search for (city, state, etc.) | Yes
| maxPrice | number | Maximum price for the stay | No
| minPrice | number | Minimum price for the stay | No
| pets | number | Number of pets | No
| placeId | string | Google Maps Place ID (overrides the location parameter) | No
</details>
<details>
<summary>airbnb_listing_details</summary>

**Description**:

```
Get detailed information about a specific Airbnb listing. Provide direct links to the user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| adults | number | Number of adults | No
| checkin | string | Check-in date (YYYY-MM-DD) | No
| checkout | string | Check-out date (YYYY-MM-DD) | No
| children | number | Number of children | No
| id | string | The Airbnb listing ID | Yes
| ignoreRobotsText | boolean | Ignore robots.txt rules for this request | No
| infants | number | Number of infants | No
| pets | number | Number of pets | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | airbnb_listing_details | description | 011db1da885610c9ac150e09ce15eaf2e1f466584906e8433b5a3497b79ef2c2 |
| tools | airbnb_listing_details | adults | e3da24f237679dc886393c4e256478b4ae4e2c695fd52c0f3239192031e3e8ed |
| tools | airbnb_listing_details | checkin | 54b67c841748044da6293c79ec45c182ba21377265d19842876136f470ecfaa5 |
| tools | airbnb_listing_details | checkout | 0d4cb2c5f7d2c47ed411d36986309799530a5ebfbf0ec2bc857c871365e0c980 |
| tools | airbnb_listing_details | children | 03678d5d4426e53c30eff8b3047d065f4e73e75226f40ba123024ea4ca197afb |
| tools | airbnb_listing_details | id | 655303f29b828171fd010ca1e56ee9a94cb55a38e05dfb4682dffe689223b54e |
| tools | airbnb_listing_details | ignoreRobotsText | 6cf8001889632ce9f32c02310db220717a5188c752a514d05ef3d0949bf1b62b |
| tools | airbnb_listing_details | infants | 17ab8ac5a1141ae2a690e32ea9b3df319a537a6171ad2f37685ddc6618e5616b |
| tools | airbnb_listing_details | pets | 6a6267a8ad8a5bbf9949d67eb93b31d73a81c4b2a287bbd3a889db2877b74b64 |
| tools | airbnb_search | description | c23c74d664b028a3c6c30a147149b343118e0570b4e8e8397e2899fb986e216b |
| tools | airbnb_search | adults | e3da24f237679dc886393c4e256478b4ae4e2c695fd52c0f3239192031e3e8ed |
| tools | airbnb_search | checkin | 54b67c841748044da6293c79ec45c182ba21377265d19842876136f470ecfaa5 |
| tools | airbnb_search | checkout | 0d4cb2c5f7d2c47ed411d36986309799530a5ebfbf0ec2bc857c871365e0c980 |
| tools | airbnb_search | children | 03678d5d4426e53c30eff8b3047d065f4e73e75226f40ba123024ea4ca197afb |
| tools | airbnb_search | cursor | 0f0bb366c5993fb1bad2c211fd27708aabbc88361489a19baae280df249cda9b |
| tools | airbnb_search | ignoreRobotsText | 6cf8001889632ce9f32c02310db220717a5188c752a514d05ef3d0949bf1b62b |
| tools | airbnb_search | infants | 17ab8ac5a1141ae2a690e32ea9b3df319a537a6171ad2f37685ddc6618e5616b |
| tools | airbnb_search | location | 5cd613963f0b0eefabeef72af5dc4f138831ab0801a7c3d0d6648c882f71a352 |
| tools | airbnb_search | maxPrice | a73a7d9b6103846a3985ada00a4093618e0418e2908bb0f045b010ca7464b9f7 |
| tools | airbnb_search | minPrice | a115d39d586b0d5e16d20fa7178f379b2b4a4ea085415bbf8ac218a2dcc1b2fb |
| tools | airbnb_search | pets | 6a6267a8ad8a5bbf9949d67eb93b31d73a81c4b2a287bbd3a889db2877b74b64 |
| tools | airbnb_search | placeId | ff40c86a746c7cdd4bfbc26b95818ec905cbc5a29361414f9d1b90cad97c8cf1 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
