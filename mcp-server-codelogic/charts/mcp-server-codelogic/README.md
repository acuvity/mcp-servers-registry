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


# What is mcp-server-codelogic?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-codelogic/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-codelogic/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-codelogic)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=codelogic-mcp-server)](https://github.com/CodeLogicIncEngineering/codelogic-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-codelogic&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CODELOGIC_PASSWORD%22%2C%22-e%22%2C%22CODELOGIC_SERVER_HOST%22%2C%22-e%22%2C%22CODELOGIC_USERNAME%22%2C%22-e%22%2C%22CODELOGIC_WORKSPACE_NAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-codelogic%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** CodeLogic, provides access to code dependency analytics, risk analysis, and impact assessment.

> [!NOTE]
> `codelogic-mcp-server` has been repackaged by Acuvity from garrmark <mgarrison@codelogic.com> original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure codelogic-mcp-server run reliably and safely.

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
  - [ garrmark <mgarrison@codelogic.com> ](https://github.com/CodeLogicIncEngineering/codelogic-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ codelogic-mcp-server ](https://github.com/CodeLogicIncEngineering/codelogic-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ codelogic-mcp-server ](https://github.com/CodeLogicIncEngineering/codelogic-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codelogic/charts/mcp-server-codelogic)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codelogic/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.2`

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
  - `CODELOGIC_PASSWORD` secret to be set as secrets.CODELOGIC_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `CODELOGIC_SERVER_HOST` environment variable to be set by env.CODELOGIC_SERVER_HOST
  - `CODELOGIC_USERNAME` environment variable to be set by env.CODELOGIC_USERNAME
  - `CODELOGIC_WORKSPACE_NAME` environment variable to be set by env.CODELOGIC_WORKSPACE_NAME

# How to install


Install will helm

```console
helm install helm install mcp-server-codelogic oci://docker.io/acuvity/mcp-server-codelogic --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-codelogic --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-codelogic --version 1.0.0
````
From there your MCP server mcp-server-codelogic will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-codelogic` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-codelogic
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-codelogic` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
<summary>codelogic-method-impact</summary>

**Description**:

```
Analyze impacts of modifying a specific method within a given class or type.
Recommended workflow:
1. Use this tool before implementing code changes
2. Run the tool against methods or functions that are being modified
3. Carefully review the impact analysis results to understand potential downstream effects
Particularly crucial when AI-suggested modifications are being considered.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| class | string | Name of the class containing the method | Yes
| method | string | Name of the method being analyzed | Yes
</details>
<details>
<summary>codelogic-database-impact</summary>

**Description**:

```
Analyze impacts between code and database entities.
Recommended workflow:
1. Use this tool before implementing code or database changes
2. Search for the relevant database entity
3. Review the impact analysis to understand which code depends on this database object and vice versa
Particularly crucial when AI-suggested modifications are being considered or when modifying SQL code.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entity_type | string | Type of database entity to search for (column, table, or view) | Yes
| name | string | Name of the database entity to search for | Yes
| table_or_view | string | Name of the table or view containing the column (required for columns only) | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | codelogic-database-impact | description | f48459b988da5079d2220ff245204fc40634a9313e4c8783107c225bfbcf5f02 |
| tools | codelogic-database-impact | entity_type | 2139681d1f2e210166a59e9049b11b136e5ab85e8eaa67dfdc7a5078812054a9 |
| tools | codelogic-database-impact | name | 081923b3b72d2652e6476544625527e727081b2aa2fbfd0c57cb916d1ae854bb |
| tools | codelogic-database-impact | table_or_view | 0bba0c4ce5aa807b3021084eea3dc74ce75f35be2ca3f345f361c74040b809d9 |
| tools | codelogic-method-impact | description | e767fb6af204b05579f09d8fcb302a7145192e493e021a69119cf32fbbe41d1b |
| tools | codelogic-method-impact | class | 8cc8837c6c870dfb903fd3d96471ae47592063ab69eaac12e51ec16a239fe162 |
| tools | codelogic-method-impact | method | dace788853d631ad14730083354d93374b2ad2141c7830e197fe982485969d09 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
