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
  </a>
</p>


# What is mcp-server-aws-memcached?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-memcached/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-memcached/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-aws-memcached)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=awslabs.memcached-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-memcached/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-memcached&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22MEMCACHED_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-memcached%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with Amazon ElastiCache Memcached through secure connections

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.memcached-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-memcached/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/charts/mcp-server-aws-memcached/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.memcached-mcp-server run reliably and safely.

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
<summary>🛡️ Runtime Security and Guardrails</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Guardrails

#### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

#### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

#### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

#### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

#### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

#### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

### Enable guardrails

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need.

| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |

Example: add `-e GUARDRAILS="secrets-redaction sensitive-pattern-detection"` to enable those guardrails.

## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, define `BASIC_AUTH_SECRET` environment variable with a shared secret.

Example: add `-e BASIC_AUTH_SECRET="supersecret"` to enable the basic authentication.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, seaofawareness <utkarshshah@gmail.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.memcached-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.memcached-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/memcached-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/charts/mcp-server-aws-memcached)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-memcached/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-memcached:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-memcached:1.0.0-1.0.2`

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
  - `MEMCACHED_HOST` environment variable to be set by env.MEMCACHED_HOST

**Optional Environment variables**:
  - `MEMCACHED_PORT="11211"` environment variable can be changed with `env.MEMCACHED_PORT="11211"`
  - `MEMCACHED_TIMEOUT="1"` environment variable can be changed with `env.MEMCACHED_TIMEOUT="1"`
  - `MEMCACHED_CONNECT_TIMEOUT="5"` environment variable can be changed with `env.MEMCACHED_CONNECT_TIMEOUT="5"`
  - `MEMCACHED_RETRY_TIMEOUT="1"` environment variable can be changed with `env.MEMCACHED_RETRY_TIMEOUT="1"`
  - `MEMCACHED_MAX_RETRIES="3"` environment variable can be changed with `env.MEMCACHED_MAX_RETRIES="3"`
  - `MEMCACHED_USE_TLS=""` environment variable can be changed with `env.MEMCACHED_USE_TLS=""`
  - `MEMCACHED_TLS_CERT_PATH=""` environment variable can be changed with `env.MEMCACHED_TLS_CERT_PATH=""`
  - `MEMCACHED_TLS_KEY_PATH=""` environment variable can be changed with `env.MEMCACHED_TLS_KEY_PATH=""`
  - `MEMCACHED_TLS_CA_CERT_PATH=""` environment variable can be changed with `env.MEMCACHED_TLS_CA_CERT_PATH=""`
  - `MEMCACHED_TLS_VERIFY="true"` environment variable can be changed with `env.MEMCACHED_TLS_VERIFY="true"`

# How to install


Install will helm

```console
helm install mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-memcached
```

From there your MCP server mcp-server-aws-memcached will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-memcached` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-memcached
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-memcached` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-memcached oci://docker.io/acuvity/mcp-server-aws-memcached --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (22)
<details>
<summary>cache_get</summary>

**Description**:

```
Get a value from the cache.

    Args:
        key: The key to retrieve

    Returns:
        Value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>cache_gets</summary>

**Description**:

```
Get a value and its CAS token from the cache.

    Args:
        key: The key to retrieve

    Returns:
        Value and CAS token or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>cache_get_many</summary>

**Description**:

```
Get multiple values from the cache.

    Args:
        keys: List of keys to retrieve

    Returns:
        Dictionary of key-value pairs or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_get_multi</summary>

**Description**:

```
Get multiple values from the cache (alias for get_many).

    Args:
        keys: List of keys to retrieve

    Returns:
        Dictionary of key-value pairs or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_set</summary>

**Description**:

```
Set a value in the cache.

    Args:
        key: The key to set
        value: The value to store
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_cas</summary>

**Description**:

```
Set a value using CAS (Check And Set).

    Args:
        key: The key to set
        value: The value to store
        cas: CAS token from gets()
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cas | integer | not set | Yes
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_set_many</summary>

**Description**:

```
Set multiple values in the cache.

    Args:
        mapping: Dictionary of key-value pairs
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| mapping | object | not set | Yes
</details>
<details>
<summary>cache_set_multi</summary>

**Description**:

```
Set multiple values in the cache (alias for set_many).

    Args:
        mapping: Dictionary of key-value pairs
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| mapping | object | not set | Yes
</details>
<details>
<summary>cache_add</summary>

**Description**:

```
Add a value to the cache only if the key doesn't exist.

    Args:
        key: The key to add
        value: The value to store
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_replace</summary>

**Description**:

```
Replace a value in the cache only if the key exists.

    Args:
        key: The key to replace
        value: The new value
        expire: Optional expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | any | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>cache_append</summary>

**Description**:

```
Append a string to an existing value.

    Args:
        key: The key to append to
        value: String to append

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | string | not set | Yes
</details>
<details>
<summary>cache_prepend</summary>

**Description**:

```
Prepend a string to an existing value.

    Args:
        key: The key to prepend to
        value: String to prepend

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | string | not set | Yes
</details>
<details>
<summary>cache_delete</summary>

**Description**:

```
Delete a value from the cache.

    Args:
        key: The key to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>cache_delete_many</summary>

**Description**:

```
Delete multiple values from the cache.

    Args:
        keys: List of keys to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_delete_multi</summary>

**Description**:

```
Delete multiple values from the cache (alias for delete_many).

    Args:
        keys: List of keys to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keys | array | not set | Yes
</details>
<details>
<summary>cache_incr</summary>

**Description**:

```
Increment a counter in the cache.

    Args:
        key: The key to increment
        value: Amount to increment by (default 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | integer | not set | No
</details>
<details>
<summary>cache_decr</summary>

**Description**:

```
Decrement a counter in the cache.

    Args:
        key: The key to decrement
        value: Amount to decrement by (default 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | integer | not set | No
</details>
<details>
<summary>cache_touch</summary>

**Description**:

```
Update the expiration time for a key.

    Args:
        key: The key to update
        expire: New expiration time in seconds

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire | integer | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>cache_stats</summary>

**Description**:

```
Get cache statistics.

    Args:
        args: Optional list of stats to retrieve

    Returns:
        Statistics or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| args | any | not set | No
</details>
<details>
<summary>cache_flush_all</summary>

**Description**:

```
Flush all cache entries.

    Args:
        delay: Optional delay in seconds before flushing

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| delay | integer | not set | No
</details>
<details>
<summary>cache_quit</summary>

**Description**:

```
Close the connection to the cache server.

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>cache_version</summary>

**Description**:

```
Get the version of the cache server.

    Returns:
        Version string or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | cache_add | description | 81f280f8d222199eeae9759dc3fcb5aed6efd7b697341d9e6d0502b6a5fe18da |
| tools | cache_append | description | 01631b0ad0ff6caf5dd7f2ed5d1e92940332e063ed9bf750d4dfa54bac41570f |
| tools | cache_cas | description | 59cf334eb2d467ffef7c22edf0529fea828a9c41a7e039021a6fae2b2a0727a9 |
| tools | cache_decr | description | fd784b4bd4dead1c91b4162f5d75e11b3769353765f0fa6901f275af61b4c0ef |
| tools | cache_delete | description | 01915385c6c89099c143c470bc11cd659576bac2741874813cc9cb98a7e11b2a |
| tools | cache_delete_many | description | 71746fd743c8b3e6114bba07f1eef689807859133b4b47b2f9294708f5324c5d |
| tools | cache_delete_multi | description | db1f86f259bab25a0ae690eaf72604f3cd52a444e0150e635ab586e5613a7f72 |
| tools | cache_flush_all | description | e894ed489862c6fde5cc7a1e449f49f67dd08cdf4f7f3f0a38ec65ba5520c81b |
| tools | cache_get | description | 07eb96e697fd6ca9ad6cd62d8b51814ba6d817e06957e29bc0618396d73af5e0 |
| tools | cache_get_many | description | fabbf6e51f142a1069fe132d889bce23ef46d3402b7cbbe744ca0a68b3d8d7ff |
| tools | cache_get_multi | description | 0462aecde4a078f2c360843feb113673c0480aec675c457c5ef0926ba32c771f |
| tools | cache_gets | description | d7be7ba2998a38b9bc95e79e7bc81fe75d2bcce37db6451e4f404e5a5461d65a |
| tools | cache_incr | description | 60382566a20be4d3ff7d314625b5683338965ea06905850defe055db5d971ec3 |
| tools | cache_prepend | description | a1455092720fd85777064b648ad1633e353c14bfc244b402ffe9dcde7d17cd88 |
| tools | cache_quit | description | 66d334197f33b112c62902ec5355b8b74cac9270930e88c7f802f9a2c04b4e66 |
| tools | cache_replace | description | 7009a3726e86bfc5c7d16ab52090377c1959fa37bced12ca50e7eb9d08be2faa |
| tools | cache_set | description | 51acc097b7eeb8807f285cfcf8b8f34436fdafd71bdbcd56dad327e2b7c25f2c |
| tools | cache_set_many | description | a297bba815d083cd47de6914d1c7d90ddf68aa39fb2d1320846603be238cec1b |
| tools | cache_set_multi | description | 9dec89dd2fed544cf87483b282eb15704f8abc6f1fdadb4294b80a46078dde7a |
| tools | cache_stats | description | 730cde3a76b996323740f2817b48638d5e33a37dbd07cd28090a1d1ed2768faa |
| tools | cache_touch | description | d8bec5113bebbbaf0bc6039929a7c6707f0579d636b8076ad3e7c69a81ec3f3b |
| tools | cache_version | description | eba7a88ca8724f8fb3a494e168b940672dd8e4edded6ba575738400d1a24e23b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
