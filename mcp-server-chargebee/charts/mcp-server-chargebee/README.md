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


# What is mcp-server-chargebee?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chargebee/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chargebee/0.0.2?logo=docker&logoColor=fff&label=0.0.2)](https://hub.docker.com/r/acuvity/mcp-server-chargebee)
[![PyPI](https://img.shields.io/badge/0.0.2-3775A9?logo=pypi&logoColor=fff&label=@chargebee/mcp)](https://github.com/chargebee/agentkit/tree/main/modelcontextprotocol)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chargebee&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-chargebee%3A0.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with Chargebee

> [!NOTE]
> `@chargebee/mcp` has been repackaged by Acuvity from Chargebee, Inc. original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @chargebee/mcp run reliably and safely.

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
  - [ Chargebee, Inc. ](https://github.com/chargebee/agentkit/tree/main/modelcontextprotocol) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @chargebee/mcp ](https://github.com/chargebee/agentkit/tree/main/modelcontextprotocol)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @chargebee/mcp ](https://github.com/chargebee/agentkit/tree/main/modelcontextprotocol)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chargebee/charts/mcp-server-chargebee)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chargebee/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.0.2`

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
helm install helm install mcp-server-chargebee oci://docker.io/acuvity/mcp-server-chargebee --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-chargebee --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-chargebee --version 1.0.0
````
From there your MCP server mcp-server-chargebee will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-chargebee` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-chargebee
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-chargebee` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
<summary>chargebee_documentation_search</summary>

**Description**:

```

Do not use this tool for code generation. For code generation use "chargebee_code_planner" tool. 
This tool will take in parameters about integrating with Chargebee in their application, then search and retrieve relevant Chargebee documentation content.

It takes the following arguments:
- query (string): The user query to search an answer for in the Chargebee documentation.
- language (enum): The programming language for the documentation. Check the user's application language.
- userRequest (string): User's original request to you.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| language | string | The programming language for the documentation. Check the user's application language. | No
| query | string | The user query to search an answer for in the Chargebee documentation. | Yes
| userRequest | string | User's original request to you. | No
</details>
<details>
<summary>chargebee_code_planner</summary>

**Description**:

```

Always use this tool to get the accurate integeration code guide for Chargebee.
This tool will take in parameters about integrating with Chargebee in their application and generates a integration workflow along with the code snippets.

It takes the following arguments:
- goal (string): What is the user's goal?
- language (enum): Programming language the code to be generated in. Check the user's application language.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| goal | string | What is the user's goal? | Yes
| language | string | Programming language the code to be generated in. Check the user's application language. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | chargebee_code_planner | description | 4eca3e4c2e78c54c82bb5eb48f37510f336891d641899c91e9bf3f8e34b78b48 |
| tools | chargebee_code_planner | goal | 04cbd92e8f07a0311c6e815da09c2e24c7e4abd77bf55affd2bb6c5dc71b5ced |
| tools | chargebee_code_planner | language | 9ae7d3f0fa66607de9b4c660cdc526cc9d4faab6dde1eefb1922fad53c0e28c4 |
| tools | chargebee_documentation_search | description | ce67701be188ea7e41d9271b80dbf7fca5530f6631bc78c49338feef1adfc04a |
| tools | chargebee_documentation_search | language | 711806bbd9d838d0515c6c0273b3b7a8875ecb2fcfe4266500f95ac14d7626e0 |
| tools | chargebee_documentation_search | query | 40f9fa844f1e83d00fb229b79b454bf69221c6776cb9c2ae4045cee94d9db378 |
| tools | chargebee_documentation_search | userRequest | e3b43cfb33e9457b7026f1e31dab19d04f0f6370eff5ddc7b26409ec213c5c0f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
