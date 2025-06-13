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


# What is mcp-server-aws-valkey?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-valkey/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-valkey/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-aws-valkey)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=awslabs.valkey-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/valkey-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-valkey/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-valkey&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22VALKEY_PWD%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-valkey%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AWS MCP server for Valkey datastores with ElastiCache/MemoryDB support and data operations

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.valkey-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/valkey-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-valkey/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-valkey/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-valkey/charts/mcp-server-aws-valkey/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.valkey-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-valkey/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, seaofawareness <utkarshshah@gmail.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/valkey-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.valkey-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/valkey-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.valkey-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/valkey-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-valkey/charts/mcp-server-aws-valkey)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-valkey/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-valkey:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-valkey:1.0.0-1.0.2`

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
  - `VALKEY_PWD` secret to be set as secrets.VALKEY_PWD either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `VALKEY_HOST="127.0.0.1"` environment variable can be changed with `env.VALKEY_HOST="127.0.0.1"`
  - `VALKEY_PORT="6379"` environment variable can be changed with `env.VALKEY_PORT="6379"`
  - `VALKEY_USERNAME=""` environment variable can be changed with `env.VALKEY_USERNAME=""`
  - `VALKEY_USE_SSL="false"` environment variable can be changed with `env.VALKEY_USE_SSL="false"`
  - `VALKEY_CERT_REQS="required"` environment variable can be changed with `env.VALKEY_CERT_REQS="required"`
  - `VALKEY_CA_PATH=""` environment variable can be changed with `env.VALKEY_CA_PATH=""`
  - `VALKEY_SSL_KEYFILE=""` environment variable can be changed with `env.VALKEY_SSL_KEYFILE=""`
  - `VALKEY_SSL_CERTFILE=""` environment variable can be changed with `env.VALKEY_SSL_CERTFILE=""`
  - `VALKEY_CA_CERTS=""` environment variable can be changed with `env.VALKEY_CA_CERTS=""`
  - `VALKEY_CLUSTER_MODE="false"` environment variable can be changed with `env.VALKEY_CLUSTER_MODE="false"`

# How to install


Install will helm

```console
helm install mcp-server-aws-valkey oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-valkey oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-valkey
```

From there your MCP server mcp-server-aws-valkey will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-valkey` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-valkey
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-valkey` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-valkey oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-valkey oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-valkey oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-valkey oci://docker.io/acuvity/mcp-server-aws-valkey --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (105)
<details>
<summary>bitmap_set</summary>

**Description**:

```
Set the bit at offset to value.

    Args:
        key: The name of the bitmap key
        offset: The bit offset (0-based)
        value: The bit value (0 or 1)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| offset | integer | not set | Yes
| value | integer | not set | Yes
</details>
<details>
<summary>bitmap_get</summary>

**Description**:

```
Get the bit value at offset.

    Args:
        key: The name of the bitmap key
        offset: The bit offset (0-based)

    Returns:
        Bit value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| offset | integer | not set | Yes
</details>
<details>
<summary>bitmap_count</summary>

**Description**:

```
Count the number of set bits (1) in a range.

    Args:
        key: The name of the bitmap key
        start: Start offset (inclusive, optional)
        end: End offset (inclusive, optional)

    Returns:
        Count of set bits or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end | any | not set | No
| key | string | not set | Yes
| start | any | not set | No
</details>
<details>
<summary>bitmap_pos</summary>

**Description**:

```
Find positions of bits set to a specific value.

    Args:
        key: The name of the bitmap key
        bit: Bit value to search for (0 or 1)
        start: Start offset (inclusive, optional)
        end: End offset (inclusive, optional)
        count: Maximum number of positions to return (optional)

    Returns:
        List of positions or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| bit | integer | not set | Yes
| count | any | not set | No
| end | any | not set | No
| key | string | not set | Yes
| start | any | not set | No
</details>
<details>
<summary>hash_set</summary>

**Description**:

```
Set field in hash.

    Args:
        key: The name of the key
        field: The field name
        value: The value to set

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| field | string | not set | Yes
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>hash_set_multiple</summary>

**Description**:

```
Set multiple fields in hash.

    Args:
        key: The name of the key
        mapping: Dictionary of field-value pairs

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| mapping | object | not set | Yes
</details>
<details>
<summary>hash_set_if_not_exists</summary>

**Description**:

```
Set field in hash only if it does not exist.

    Args:
        key: The name of the key
        field: The field name
        value: The value to set

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| field | string | not set | Yes
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>hash_get</summary>

**Description**:

```
Get field from hash.

    Args:
        key: The name of the key
        field: The field name

    Returns:
        Field value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| field | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>hash_get_all</summary>

**Description**:

```
Get all fields and values from hash.

    Args:
        key: The name of the key

    Returns:
        Dictionary of field-value pairs or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>hash_exists</summary>

**Description**:

```
Check if field exists in hash.

    Args:
        key: The name of the key
        field: The field name

    Returns:
        Boolean result or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| field | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>hash_increment</summary>

**Description**:

```
Increment field value in hash.

    Args:
        key: The name of the key
        field: The field name
        amount: Amount to increment by (default: 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | any | not set | No
| field | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>hash_keys</summary>

**Description**:

```
Get all field names from hash.

    Args:
        key: The name of the key

    Returns:
        List of field names or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>hash_length</summary>

**Description**:

```
Get number of fields in hash.

    Args:
        key: The name of the key

    Returns:
        Number of fields or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>hash_random_field</summary>

**Description**:

```
Get random field(s) from hash.

    Args:
        key: The name of the key
        count: Number of fields to return (optional)

    Returns:
        Random field(s) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>hash_random_field_with_values</summary>

**Description**:

```
Get random field(s) with their values from hash.

    Args:
        key: The name of the key
        count: Number of field-value pairs to return

    Returns:
        Random field-value pairs or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | integer | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>hash_strlen</summary>

**Description**:

```
Get length of field value in hash.

    Args:
        key: The name of the key
        field: The field name

    Returns:
        Length of field value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| field | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>hash_values</summary>

**Description**:

```
Get all values from hash.

    Args:
        key: The name of the key

    Returns:
        List of values or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>hll_add</summary>

**Description**:

```
Add one element to a HyperLogLog.

    Args:
        key: The name of the HyperLogLog key
        element: One element to add

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| element | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>hll_count</summary>

**Description**:

```
Get the estimated cardinality of a HyperLogLog.

    Args:
        key: The name of the HyperLogLog key

    Returns:
        Estimated cardinality or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>json_set</summary>

**Description**:

```
Set the JSON value at path.

    Args:
        key: The name of the key
        path: The path in the JSON document (e.g., "$.name" or "." for root)
        value: The value to set
        nx: Only set if path doesn't exist
        xx: Only set if path exists

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| nx | boolean | not set | No
| path | string | not set | Yes
| value | any | not set | Yes
| xx | boolean | not set | No
</details>
<details>
<summary>json_get</summary>

**Description**:

```
Get the JSON value at path.

    Args:
        key: The name of the key
        path: The path in the JSON document (optional, defaults to root)
        indent: Number of spaces for indentation (optional)
        newline: Add newlines in formatted output (optional)
        space: Add spaces in formatted output (optional)

    Returns:
        JSON value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| indent | any | not set | No
| key | string | not set | Yes
| newline | any | not set | No
| path | any | not set | No
| space | any | not set | No
</details>
<details>
<summary>json_type</summary>

**Description**:

```
Get the type of JSON value at path.

    Args:
        key: The name of the key
        path: The path in the JSON document (optional, defaults to root)

    Returns:
        JSON type or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | any | not set | No
</details>
<details>
<summary>json_numincrby</summary>

**Description**:

```
Increment the number at path by value.

    Args:
        key: The name of the key
        path: The path in the JSON document
        value: The increment value (integer or float)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>json_nummultby</summary>

**Description**:

```
Multiply the number at path by value.

    Args:
        key: The name of the key
        path: The path in the JSON document
        value: The multiplier value (integer or float)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>json_strappend</summary>

**Description**:

```
Append a string to the string at path.

    Args:
        key: The name of the key
        path: The path in the JSON document
        value: The string to append

    Returns:
        New string length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
| value | string | not set | Yes
</details>
<details>
<summary>json_strlen</summary>

**Description**:

```
Get the length of string at path.

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        String length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_arrappend</summary>

**Description**:

```
Append values to the array at path.

    Args:
        key: The name of the key
        path: The path in the JSON document
        *values: One or more values to append

    Returns:
        New array length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
| values | any | not set | Yes
</details>
<details>
<summary>json_arrindex</summary>

**Description**:

```
Get the index of value in array at path.

    Args:
        key: The name of the key
        path: The path in the JSON document
        value: The value to search for
        start: Start offset (optional)
        stop: Stop offset (optional)

    Returns:
        Index or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
| start | any | not set | No
| stop | any | not set | No
| value | any | not set | Yes
</details>
<details>
<summary>json_arrlen</summary>

**Description**:

```
Get the length of array at path.

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        Array length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_arrpop</summary>

**Description**:

```
Pop a value from the array at path and index.

    Args:
        key: The name of the key
        path: The path in the JSON document
        index: The index to pop from (-1 for last element)

    Returns:
        Popped value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | integer | not set | No
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_arrtrim</summary>

**Description**:

```
Trim array at path to include only elements within range.

    Args:
        key: The name of the key
        path: The path in the JSON document
        start: Start index (inclusive)
        stop: Stop index (inclusive)

    Returns:
        New array length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
| start | integer | not set | Yes
| stop | integer | not set | Yes
</details>
<details>
<summary>json_objkeys</summary>

**Description**:

```
Get the keys in the object at path.

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        List of keys or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_objlen</summary>

**Description**:

```
Get the number of keys in the object at path.

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        Number of keys or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_toggle</summary>

**Description**:

```
Toggle boolean value at path.

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        New boolean value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_clear</summary>

**Description**:

```
Clear container at path (array or object).

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>json_del</summary>

**Description**:

```
Delete value at path.

    Args:
        key: The name of the key
        path: The path in the JSON document

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>list_append</summary>

**Description**:

```
Append value to list.

    Args:
        key: The name of the key
        value: The value to append

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>list_prepend</summary>

**Description**:

```
Prepend value to list.

    Args:
        key: The name of the key
        value: The value to prepend

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>list_append_multiple</summary>

**Description**:

```
Append multiple values to list.

    Args:
        key: The name of the key
        values: List of values to append

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| values | array | not set | Yes
</details>
<details>
<summary>list_prepend_multiple</summary>

**Description**:

```
Prepend multiple values to list.

    Args:
        key: The name of the key
        values: List of values to prepend

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| values | array | not set | Yes
</details>
<details>
<summary>list_get</summary>

**Description**:

```
Get value at index from list.

    Args:
        key: The name of the key
        index: The index (0-based, negative indices supported)

    Returns:
        Value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | integer | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>list_set</summary>

**Description**:

```
Set value at index in list.

    Args:
        key: The name of the key
        index: The index (0-based, negative indices supported)
        value: The value to set

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | integer | not set | Yes
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>list_range</summary>

**Description**:

```
Get range of values from list.

    Args:
        key: The name of the key
        start: Start index (inclusive, default 0)
        stop: Stop index (inclusive, default -1 for end)

    Returns:
        List of values or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| start | integer | not set | No
| stop | integer | not set | No
</details>
<details>
<summary>list_trim</summary>

**Description**:

```
Trim list to specified range.

    Args:
        key: The name of the key
        start: Start index (inclusive)
        stop: Stop index (inclusive)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| start | integer | not set | Yes
| stop | integer | not set | Yes
</details>
<details>
<summary>list_length</summary>

**Description**:

```
Get length of list.

    Args:
        key: The name of the key

    Returns:
        Length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>list_pop_left</summary>

**Description**:

```
Pop value(s) from left of list.

    Args:
        key: The name of the key
        count: Number of values to pop (optional)

    Returns:
        Value(s) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>list_pop_right</summary>

**Description**:

```
Pop value(s) from right of list.

    Args:
        key: The name of the key
        count: Number of values to pop (optional)

    Returns:
        Value(s) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>list_position</summary>

**Description**:

```
Find position(s) of value in list.

    Args:
        key: The name of the key
        value: Value to search for
        rank: Match the Nth occurrence (optional)
        count: Return this many matches (optional)
        maxlen: Limit search to first N elements (optional)

    Returns:
        Position(s) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
| maxlen | any | not set | No
| rank | any | not set | No
| value | any | not set | Yes
</details>
<details>
<summary>list_move</summary>

**Description**:

```
Move element from one list to another.

    Args:
        source: Source list key
        destination: Destination list key
        wherefrom: Where to pop from ("LEFT" or "RIGHT")
        whereto: Where to push to ("LEFT" or "RIGHT")

    Returns:
        Moved value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | not set | Yes
| source | string | not set | Yes
| wherefrom | string | not set | No
| whereto | string | not set | No
</details>
<details>
<summary>list_insert_before</summary>

**Description**:

```
Insert value before pivot in list.

    Args:
        key: The name of the key
        pivot: The pivot value
        value: The value to insert

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| pivot | any | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>list_insert_after</summary>

**Description**:

```
Insert value after pivot in list.

    Args:
        key: The name of the key
        pivot: The pivot value
        value: The value to insert

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| pivot | any | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>list_remove</summary>

**Description**:

```
Remove occurrences of value from list.

    Args:
        key: The name of the key
        value: Value to remove
        count: Number of occurrences to remove (0 for all, positive for left-to-right, negative for right-to-left)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | integer | not set | No
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>delete</summary>

**Description**:

```
Delete a Valkey key.

    Args:
        key (str): The key to delete.

    Returns:
        str: Confirmation message or an error message.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>type</summary>

**Description**:

```
Returns the string representation of the type of the value stored at key.

    Args:
        key (str): The key to check.

    Returns:
        str: The type of key, or none when key doesn't exist
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>expire</summary>

**Description**:

```
Set an expiration time for a Redis key.

    Args:
        name: The Redis key.
        expire_seconds: Time in seconds after which the key should expire.

    Returns:
        A success message or an error message.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expire_seconds | integer | not set | Yes
| name | string | not set | Yes
</details>
<details>
<summary>rename</summary>

**Description**:

```
Renames a Redis key from old_key to new_key.

    Args:
        old_key (str): The current name of the Redis key to rename.
        new_key (str): The new name to assign to the key.

    Returns:
        Dict[str, Any]: A dictionary containing the result of the operation.
            On success: {"status": "success", "message": "..."}
            On error: {"error": "..."}
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| new_key | string | not set | Yes
| old_key | string | not set | Yes
</details>
<details>
<summary>dbsize</summary>

**Description**:

```
Get the number of keys stored in the Valkey database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>info</summary>

**Description**:

```
Get Valkey server information and statistics.

    Args:
        section: The section of the info command (default, memory, cpu, etc.).

    Returns:
        A dictionary of server information or an error message.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| section | string | not set | No
</details>
<details>
<summary>client_list</summary>

**Description**:

```
Get a list of connected clients to the Valkey server.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>set_add</summary>

**Description**:

```
Add member to set.

    Args:
        key: The name of the key
        member: Member to add

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| member | string | not set | Yes
</details>
<details>
<summary>set_remove</summary>

**Description**:

```
Remove member from set.

    Args:
        key: The name of the key
        member: Member to remove

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| member | string | not set | Yes
</details>
<details>
<summary>set_pop</summary>

**Description**:

```
Remove and return random member(s) from set.

    Args:
        key: The name of the key
        count: Number of members to pop (optional)

    Returns:
        Popped member(s) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>set_move</summary>

**Description**:

```
Move member from one set to another.

    Args:
        source: Source set key
        destination: Destination set key
        member: Member to move

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | not set | Yes
| member | any | not set | Yes
| source | string | not set | Yes
</details>
<details>
<summary>set_cardinality</summary>

**Description**:

```
Get number of members in set.

    Args:
        key: The name of the key

    Returns:
        Number of members or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>set_members</summary>

**Description**:

```
Get all members in set.

    Args:
        key: The name of the key

    Returns:
        List of members or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>set_random_member</summary>

**Description**:

```
Get random member(s) from set without removing.

    Args:
        key: The name of the key
        count: Number of members to return (optional)

    Returns:
        Random member(s) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>set_contains</summary>

**Description**:

```
Check if member exists in set.

    Args:
        key: The name of the key
        member: Member to check

    Returns:
        Boolean result or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| member | any | not set | Yes
</details>
<details>
<summary>sorted_set_add</summary>

**Description**:

```
Add member-score pairs to sorted set.

    Args:
        key: The name of the key
        mapping: Dictionary of member-score pairs

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| mapping | object | not set | Yes
</details>
<details>
<summary>sorted_set_add_incr</summary>

**Description**:

```
Add member to sorted set or increment its score.

    Args:
        key: The name of the key
        member: The member to add/update
        score: Score to add to existing score (or initial score)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| member | any | not set | Yes
| score | number | not set | Yes
</details>
<details>
<summary>sorted_set_remove</summary>

**Description**:

```
Remove member(s) from sorted set.

    Args:
        key: The name of the key
        *members: Members to remove

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| members | any | not set | Yes
</details>
<details>
<summary>sorted_set_remove_by_rank</summary>

**Description**:

```
Remove members by rank range.

    Args:
        key: The name of the key
        start: Start rank (inclusive)
        stop: Stop rank (inclusive)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| start | integer | not set | Yes
| stop | integer | not set | Yes
</details>
<details>
<summary>sorted_set_remove_by_score</summary>

**Description**:

```
Remove members by score range.

    Args:
        key: The name of the key
        min_score: Minimum score (inclusive)
        max_score: Maximum score (inclusive)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| max_score | number | not set | Yes
| min_score | number | not set | Yes
</details>
<details>
<summary>sorted_set_remove_by_lex</summary>

**Description**:

```
Remove members by lexicographical range.

    Args:
        key: The name of the key
        min_lex: Minimum value (inclusive)
        max_lex: Maximum value (inclusive)

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| max_lex | string | not set | Yes
| min_lex | string | not set | Yes
</details>
<details>
<summary>sorted_set_cardinality</summary>

**Description**:

```
Get number of members in sorted set.

    Args:
        key: The name of the key
        min_score: Minimum score (optional)
        max_score: Maximum score (optional)

    Returns:
        Number of members or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| max_score | any | not set | No
| min_score | any | not set | No
</details>
<details>
<summary>sorted_set_score</summary>

**Description**:

```
Get score of member in sorted set.

    Args:
        key: The name of the key
        member: The member to get score for

    Returns:
        Score or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| member | any | not set | Yes
</details>
<details>
<summary>sorted_set_rank</summary>

**Description**:

```
Get rank of member in sorted set.

    Args:
        key: The name of the key
        member: The member to get rank for
        reverse: If True, get rank in reverse order (highest first)

    Returns:
        Rank or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| member | any | not set | Yes
| reverse | boolean | not set | No
</details>
<details>
<summary>sorted_set_range</summary>

**Description**:

```
Get range of members from sorted set.

    Args:
        key: The name of the key
        start: Start index (inclusive)
        stop: Stop index (inclusive)
        withscores: Include scores in result
        reverse: Return results in reverse order

    Returns:
        List of members (with scores if requested) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| reverse | boolean | not set | No
| start | integer | not set | No
| stop | integer | not set | No
| withscores | boolean | not set | No
</details>
<details>
<summary>sorted_set_range_by_score</summary>

**Description**:

```
Get range of members by score.

    Args:
        key: The name of the key
        min_score: Minimum score (inclusive)
        max_score: Maximum score (inclusive)
        withscores: Include scores in result
        reverse: Return results in reverse order
        offset: Number of members to skip
        count: Maximum number of members to return

    Returns:
        List of members (with scores if requested) or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
| max_score | number | not set | Yes
| min_score | number | not set | Yes
| offset | any | not set | No
| reverse | boolean | not set | No
| withscores | boolean | not set | No
</details>
<details>
<summary>sorted_set_range_by_lex</summary>

**Description**:

```
Get range of members by lexicographical order.

    Args:
        key: The name of the key
        min_lex: Minimum value (inclusive)
        max_lex: Maximum value (inclusive)
        reverse: Return results in reverse order
        offset: Number of members to skip
        count: Maximum number of members to return

    Returns:
        List of members or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
| max_lex | string | not set | Yes
| min_lex | string | not set | Yes
| offset | any | not set | No
| reverse | boolean | not set | No
</details>
<details>
<summary>sorted_set_popmin</summary>

**Description**:

```
Remove and return members with lowest scores.

    Args:
        key: The name of the key
        count: Number of members to pop (optional)

    Returns:
        Popped members with scores or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>sorted_set_popmax</summary>

**Description**:

```
Remove and return members with highest scores.

    Args:
        key: The name of the key
        count: Number of members to pop (optional)

    Returns:
        Popped members with scores or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>stream_add</summary>

**Description**:

```
Add entry to stream.

    Args:
        key: The name of the key
        field_dict: Dictionary of field-value pairs
        id: Entry ID (default "*" for auto-generation)
        maxlen: Maximum length of stream (optional)
        approximate: Whether maxlen is approximate

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| approximate | boolean | not set | No
| field_dict | object | not set | Yes
| id | string | not set | No
| key | string | not set | Yes
| maxlen | any | not set | No
</details>
<details>
<summary>stream_delete</summary>

**Description**:

```
Delete entries from stream.

    Args:
        key: The name of the key
        id: Entry ID to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>stream_trim</summary>

**Description**:

```
Trim stream to specified length.

    Args:
        key: The name of the key
        maxlen: Maximum length to trim to
        approximate: Whether maxlen is approximate

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| approximate | boolean | not set | No
| key | string | not set | Yes
| maxlen | integer | not set | Yes
</details>
<details>
<summary>stream_length</summary>

**Description**:

```
Get length of stream.

    Args:
        key: The name of the key

    Returns:
        Length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>stream_range</summary>

**Description**:

```
Get range of entries from stream.

    Args:
        key: The name of the key
        start: Start ID (default "-" for beginning)
        end: End ID (default "+" for end)
        count: Maximum number of entries to return
        reverse: Return entries in reverse order

    Returns:
        List of entries or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | any | not set | No
| end | string | not set | No
| key | string | not set | Yes
| reverse | boolean | not set | No
| start | string | not set | No
</details>
<details>
<summary>stream_read</summary>

**Description**:

```
Read entries from stream.

    Args:
        key: The name of the key
        count: Maximum number of entries to return
        block: Milliseconds to block (optional)
        last_id: Last ID received (default "$" for new entries only)

    Returns:
        List of entries or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block | any | not set | No
| count | any | not set | No
| key | string | not set | Yes
| last_id | string | not set | No
</details>
<details>
<summary>stream_group_create</summary>

**Description**:

```
Create consumer group.

    Args:
        key: The name of the key
        group_name: Name of consumer group
        id: ID to start reading from (default "$" for new entries only)
        mkstream: Create stream if it doesn't exist

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| group_name | string | not set | Yes
| id | string | not set | No
| key | string | not set | Yes
| mkstream | boolean | not set | No
</details>
<details>
<summary>stream_group_destroy</summary>

**Description**:

```
Destroy consumer group.

    Args:
        key: The name of the key
        group_name: Name of consumer group

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| group_name | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>stream_group_set_id</summary>

**Description**:

```
Set consumer group's last delivered ID.

    Args:
        key: The name of the key
        group_name: Name of consumer group
        id: ID to set as last delivered

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| group_name | string | not set | Yes
| id | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>stream_group_delete_consumer</summary>

**Description**:

```
Delete consumer from group.

    Args:
        key: The name of the key
        group_name: Name of consumer group
        consumer_name: Name of consumer to delete

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| consumer_name | string | not set | Yes
| group_name | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>stream_read_group</summary>

**Description**:

```
Read entries from stream as part of consumer group.

    Args:
        key: The name of the key
        group_name: Name of consumer group
        consumer_name: Name of this consumer
        count: Maximum number of entries to return
        block: Milliseconds to block (optional)
        noack: Don't require acknowledgment

    Returns:
        List of entries or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block | any | not set | No
| consumer_name | string | not set | Yes
| count | any | not set | No
| group_name | string | not set | Yes
| key | string | not set | Yes
| noack | boolean | not set | No
</details>
<details>
<summary>stream_info</summary>

**Description**:

```
Get information about stream.

    Args:
        key: The name of the key

    Returns:
        Stream information or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>stream_info_groups</summary>

**Description**:

```
Get information about consumer groups.

    Args:
        key: The name of the key

    Returns:
        Consumer groups information or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>stream_info_consumers</summary>

**Description**:

```
Get information about consumers in group.

    Args:
        key: The name of the key
        group_name: Name of consumer group

    Returns:
        Consumers information or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| group_name | string | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>string_set</summary>

**Description**:

```
Set string value.

    Args:
        key: The name of the key
        value: The value to set
        ex: Expire time in seconds
        px: Expire time in milliseconds
        nx: Only set if key does not exist
        xx: Only set if key exists
        keepttl: Retain the time to live associated with the key

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ex | any | not set | No
| keepttl | boolean | not set | No
| key | string | not set | Yes
| nx | boolean | not set | No
| px | any | not set | No
| value | any | not set | Yes
| xx | boolean | not set | No
</details>
<details>
<summary>string_get</summary>

**Description**:

```
Get string value.

    Args:
        key: The name of the key

    Returns:
        Value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>string_append</summary>

**Description**:

```
Append to string value.

    Args:
        key: The name of the key
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
<summary>string_get_range</summary>

**Description**:

```
Get substring.

    Args:
        key: The name of the key
        start: Start index (inclusive)
        end: End index (inclusive)

    Returns:
        Substring or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end | integer | not set | Yes
| key | string | not set | Yes
| start | integer | not set | Yes
</details>
<details>
<summary>string_get_set</summary>

**Description**:

```
Set new value and return old value.

    Args:
        key: The name of the key
        value: New value to set

    Returns:
        Old value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | any | not set | Yes
</details>
<details>
<summary>string_increment</summary>

**Description**:

```
Increment integer value.

    Args:
        key: The name of the key
        amount: Amount to increment by (default 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | integer | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>string_increment_float</summary>

**Description**:

```
Increment float value.

    Args:
        key: The name of the key
        amount: Amount to increment by

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | not set | Yes
| key | string | not set | Yes
</details>
<details>
<summary>string_decrement</summary>

**Description**:

```
Decrement integer value.

    Args:
        key: The name of the key
        amount: Amount to decrement by (default 1)

    Returns:
        New value or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | integer | not set | No
| key | string | not set | Yes
</details>
<details>
<summary>string_length</summary>

**Description**:

```
Get string length.

    Args:
        key: The name of the key

    Returns:
        Length or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>string_set_range</summary>

**Description**:

```
Overwrite part of string.

    Args:
        key: The name of the key
        offset: Position to start overwriting
        value: String to write

    Returns:
        Success message or error message
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| offset | integer | not set | Yes
| value | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | bitmap_count | description | 46e06ee971778d4ca55ed1fc26ebe28df052a5bba7190814a0567c389ae27020 |
| tools | bitmap_get | description | 1b622e991e495f2e9afaebec0268f9b0e50c91bc15fdd6d6877c898e560d5d74 |
| tools | bitmap_pos | description | 9550686091728b717b36e733a366258885d5092f7c4c2c276f5ab86d96bb0ec1 |
| tools | bitmap_set | description | eaf638eb75a5eb264ea126cbd42c3c7643ba7128547e4b25eec5dfdc3f4fc2d2 |
| tools | client_list | description | c9577d6e39a1db48abaf5bae1b4ae63295c47b1746c8cbf5b6c5a1c758333df2 |
| tools | dbsize | description | a91dfd374756386f46c6a5db72a46a1563f8bc209e9d8823a9f85e8fc3e75708 |
| tools | delete | description | 5f5bb787056fcc4bb5eb863f36f9ee3db5233725b66ca0c2c424108a8e1f249c |
| tools | expire | description | aab5216c41dd1ed8a50a8fbb2168f6a05170378f17159b17cdc8e8dd3dcd7daa |
| tools | hash_exists | description | 1f8ee08bc251ea14a4960f26a102a901369a50fb2178cdddc8f42f1f322b91ff |
| tools | hash_get | description | 80baf31bea7a23a9902ffc6c9a5948709a23fe71a908c88cdf4a328e815d75a7 |
| tools | hash_get_all | description | af4334a64f2cfcc98cbd0fa95fcf1b4a44a973f4f26a2bf765cd58d04038730d |
| tools | hash_increment | description | 3f4e4617fcb1ce31cfab3c44d4f207db59501a1b38c916c733119dbf1a6ede60 |
| tools | hash_keys | description | c155dbac559fd6f388a71964e57414207436b41867c88548598050c77503d23e |
| tools | hash_length | description | fad1d18fe6febb01f3ea254ce98e455148fe8dab746bda98214a914b2f638ab4 |
| tools | hash_random_field | description | 4f3b6f49ef2c399b535477a20afbe50cf7598d5f69343fcc22073eb365392648 |
| tools | hash_random_field_with_values | description | 8466e7c7437cc1bea119c72468781830bdbb3ccb4a493218f0171b0207e0b91d |
| tools | hash_set | description | ec5e648c207e224dd0d38b19139231d46ccf075b63202a95e1eee72ebe153bb3 |
| tools | hash_set_if_not_exists | description | 5cea42a5ece6eef02abbcc267ea88467a6dac87c932aeec8723154c5d62aebed |
| tools | hash_set_multiple | description | de4699dbb3a945f4ecb00ab73f10ff362b72f55ab9396acd5a0dc3c79fbfe2be |
| tools | hash_strlen | description | b2dddf896451f0622e4a7c961a63f3132732ed3126979250a154ceca774894ac |
| tools | hash_values | description | e4c3260f7edca38f4a03a4355465fdfbd48f0ee35461b68f87f1e4e645d78b44 |
| tools | hll_add | description | 5580d329e752ceebddd27e6ccafeff4373024cb99e39b8948a328bc5480ef32e |
| tools | hll_count | description | b51ad559fb762cb1d7288599bc2ada05a879143211af15cd4b91f42f93b10892 |
| tools | info | description | 205900f2ab65ddff317fc8cadb51c6c358e9cf4ba54ced8df44a59eaeb7517a2 |
| tools | json_arrappend | description | 47eebec082fc4ae7969b711b68da1ae6ea38dc59e1942fcec8a23bdd8ec7e82c |
| tools | json_arrindex | description | 24be6a2bc7bfa545acce04a3a448e2325c1189ccd38fe78e94ee1fc03038b8df |
| tools | json_arrlen | description | f9424ef47bdf674365a1f2a6758556e32cddf28e0c634319fcedc7cd8994835c |
| tools | json_arrpop | description | fe79d1960ef54016ddcc17e3a26fac10c35d002092e3915c6b7335360f65173d |
| tools | json_arrtrim | description | da88ec41b7f0cc0ad4df011ad077c3707a3454d9e1e9399f4252719161247b9f |
| tools | json_clear | description | 87f670750d611bc1c6018579e1866c42ae82ca5cdc30032c4fd76e2b548f0b84 |
| tools | json_del | description | 2e428a63dedbf2c09e9dfaac9daef4492a0905c08fc73de0de14109c10fca37b |
| tools | json_get | description | fce58d776c10705f60e06c13d008f371d1116a25e1ad22b1b6dc02d78c5236a4 |
| tools | json_numincrby | description | 54929022c84550beb2f86a119f947bdbe9ddc4fc3d4d3586b94fd1f2b5a3b38e |
| tools | json_nummultby | description | c9de4a0df2ab7003ec645325235075e880d8e5a0446e9ac94bd40be77f5dbaf9 |
| tools | json_objkeys | description | 2a65bde38291e920451d420cdbbcdc9eb0d03cfd80bd5573931f024cc35f4444 |
| tools | json_objlen | description | be5fc504daa1bf48e3f6fbd033a131227b5d0e72e0d3b31d9300f39dd97b217c |
| tools | json_set | description | 4cb4d75e3b86087fbde4d445590ab6b53b11bb5f70b848bf3098a06ddbb4fbc9 |
| tools | json_strappend | description | 34d7814766a40b378b45f612289ab6ba28a754ffef8b373ad48dcc7811015374 |
| tools | json_strlen | description | 0e9aa54c10991495416cd212c1df17cb209640f8c57b194537aa80a63cdf7aa2 |
| tools | json_toggle | description | c3ce1a657eea66de5bcb172304b4b898182a2569eb244fea134776df942f331b |
| tools | json_type | description | fee39440d8d37c7a09aca65415fbe7283882a4d5f883003a30bc638dd1ae1681 |
| tools | list_append | description | 917af44de7d8e74def4a6c180ac2034a25bb962d173617d837306bd5489bd226 |
| tools | list_append_multiple | description | c8921972bd8867d376e1a7169275fd9facd512d75c574b8056572b9fae050658 |
| tools | list_get | description | 8f148729573448feddc2c89591df2854257e160af315bb14a2887d9a07887ab6 |
| tools | list_insert_after | description | 6b4d6e8a7db0f88d1ad44b75abf6319e39b5d7c441c63d1c0a31bd9f93da7563 |
| tools | list_insert_before | description | 81f9cfabe661e241e90e3856640d3115c7b32a21a3d9ee8618c182bdfabfe285 |
| tools | list_length | description | 060297b76a88fd82f0bb1034825711531e6941fa78c962cd64fadf807f8837a7 |
| tools | list_move | description | 35057555f10c0c3123ab276c770d25cc03a887d357a3183b8bc3de231b7c10a9 |
| tools | list_pop_left | description | 9a35872f299959c4b4dfb1b791e19c1dc7a344fc7a761133f75fbf9aae3d1b8a |
| tools | list_pop_right | description | f9c1d7d9768321d12b5a2b9c59c41d61c7c732d1dc8ead03e497029f4223951c |
| tools | list_position | description | 04bdfb0c828db5ac34fba6775a2f6b680b0e11828e507246c98060bfd171bab3 |
| tools | list_prepend | description | be260602335551e80b4ac6243ac424cecb4e4da979ac7c1c39c1a81484107da6 |
| tools | list_prepend_multiple | description | d40cea7868c68d4703cb16f1d93eaaa84febef5a8f6fc5d0c1c7486cc51f275d |
| tools | list_range | description | c108930c08f21507b75468f8d592a590ecb824d6f69d16c7e7840772d5a047ac |
| tools | list_remove | description | eb2f4d60cdb1e5f09ff7e89fecb512247ca4176883520e5da8bf2d8d567ce1e2 |
| tools | list_set | description | 38dafaba96b061532f86159b018ca5219ecd80d1405aa8ab9d021f7f2ee6b82f |
| tools | list_trim | description | 68c0285352642790a4c2b5316ed337f37f5fd60f4cd63fe51546cda3747d62ec |
| tools | rename | description | d7ef1e83e46ab8ec8616c54afc03cd23a3232bd427acdfc5239743430e7ba64d |
| tools | set_add | description | 76ff0c5ffc7b3a825f9c8d4cd8ab03331fed5dc2e55a23ca2fc2392e70daa5b4 |
| tools | set_cardinality | description | 7f00e89bc9e9373a1e8023396c87ce9c6528d4c7b614f67649571c9cb59fd009 |
| tools | set_contains | description | 5824eb7a7cac53be4a63d432131dc403932e105da63ca746d678d0499d2e59d6 |
| tools | set_members | description | 455bf2a794e4005d18ad39f84aef6bb83d77654e80aa0ed3b945fb2f52c50d59 |
| tools | set_move | description | ff8e422dc5b53feeab0c2a459947161f1bb7108f7ad49a59a2f1ce52b43121c8 |
| tools | set_pop | description | 6510c732adb0a5660d9902eea51807dcc3c6da9169e12f9606f5cc50b08e2238 |
| tools | set_random_member | description | 838b53913b8ea9883acea6db4b5a81b8c83a5ca4a14b19a5adbc82d857039362 |
| tools | set_remove | description | 16755da49b874969d003f20841648b662f68723def6284e570273e022bc6eb89 |
| tools | sorted_set_add | description | 007b8f9fcc348edcd2324b9d2add09c4218b65a87cb9c98bb3e21cb7f3d3389f |
| tools | sorted_set_add_incr | description | 06013b91db06f6a5be1c6b8382867e737c05bdfe0dc481a00b01921e6b2dd636 |
| tools | sorted_set_cardinality | description | f2309e350d3efc58538a219e99594a9b2c4a0733461d2e9f32ab8cb905ba18b1 |
| tools | sorted_set_popmax | description | a135d11a6b6d60facb11db3e27173193705df33858c5347552988ff515e783ab |
| tools | sorted_set_popmin | description | f9d0c55528ec21e55a6310e8188c656aa271457da4586502ebfadd4ba8b332a9 |
| tools | sorted_set_range | description | ee759a2ecbc644436d563a5dde5747eb2246cb006895ed64c93d6a0193e3d9f4 |
| tools | sorted_set_range_by_lex | description | 6741aa30a8208c5d45a78f584f1c897960d1aea01cdbfc1c7b097c70fe9c0b80 |
| tools | sorted_set_range_by_score | description | b38de4f22166836f1ab8c65f94e05e1d08086b587e3d340d9a1e25633c91757b |
| tools | sorted_set_rank | description | 75e83cb368d1fa7a6969c7e90178651375174dab15e59ad8c7b6667920024f8a |
| tools | sorted_set_remove | description | a8d728c0c45f2d6c95d63e291c7651b1f10f5f7f5917791b4ab7041203d74cdf |
| tools | sorted_set_remove_by_lex | description | cd0e6894cb055f0a2e0cc132bb77e656b58038abb76451e9a2980e71154f989d |
| tools | sorted_set_remove_by_rank | description | 6a55238e8ea7364d4f782ecc14e36c2b18aa300ec21202682230ca4069faf54f |
| tools | sorted_set_remove_by_score | description | 4edb2cd12de704315b154326f9f9223f5226a3b7def4c4fe09698fb92eecc8de |
| tools | sorted_set_score | description | fc8cd1b38d40652fda0c3cb8c67d4f9441082f9b1053be1e740d8770b28a01da |
| tools | stream_add | description | 7415338ac428aa74de902b9fc64cee07fdc4921aa2b7aa937959fb432bdc98f8 |
| tools | stream_delete | description | 88635b19653635a5c48ee1864d4da787a3b1e7b59ec85c33b49347579d5e2711 |
| tools | stream_group_create | description | d6d9cb70774e89e1cf55826f6f9c000c1dc9c8108a5ae7a6ae071c4b8bcda7df |
| tools | stream_group_delete_consumer | description | 0a147e3a94244e8454102dc9b0a0690cc92d0dfbbaee6155c67c0757835bdd37 |
| tools | stream_group_destroy | description | 8de133b153078aa3b38ccb44af8805fe146f43e69ed19a1b6850637688afe2d4 |
| tools | stream_group_set_id | description | 067112a63e8a27726b6c7f27bda470e8c8a5e6940849b38190d59c0c8a527923 |
| tools | stream_info | description | 55e240b0a41b01e72aa4a95860a6ee48f67f553bb6eeafea54d804c0ab9ed3ab |
| tools | stream_info_consumers | description | 4bd461c4308ccbb035df02aee28877002171b6a62014971a57f6002adb4d65e6 |
| tools | stream_info_groups | description | 5f33885a2396b3394f56df8eac3b683e9785e6077551f1325424f1309b2d1bdf |
| tools | stream_length | description | 6c71139aa9c488bbfc5d09fd20fce5fb39ebe0f7d1fa1e054f650c8b74fc3da3 |
| tools | stream_range | description | b8b7758241bc187edd0eb3ffcde52dce1ccc0d20ae55ad4b1fa1b96473378da1 |
| tools | stream_read | description | 97a9ae40a00305e1fc37b586df3649e30b1e2f074efb1cbd15877f01d81c8a59 |
| tools | stream_read_group | description | 2f7903a1f349d2190fd0aee2f85c766e5975e69673e15f942b5e593fbf2a38f3 |
| tools | stream_trim | description | c5c60bfc5d03e98f4cea61bd295ba155af81094dd632ad6c92ead0510caed165 |
| tools | string_append | description | 4ec96896f31e2f1f85f393500847bc0fb843f2bc0fe1ccdf407c339d5d05566e |
| tools | string_decrement | description | cdbc6e830220e0d78168cd531019d582cd940611e851eae8e745075679f4e21a |
| tools | string_get | description | 5430b8f09ae41935207f8a85cd6e58275604c2f0258ddc7dd3ccf774ada78e85 |
| tools | string_get_range | description | 48e6371aeb6f74977325ab0a07934523b1402ba5303dd9648ce08f94b7b6299f |
| tools | string_get_set | description | 3419387831a2a26671e04be1a0fa755d31ced1c353e4a41cbe03fb44e8017c59 |
| tools | string_increment | description | d3028a0bc7a55b69dd304c5bf7225493dd2e5975ae401b090ba7eec92e387d51 |
| tools | string_increment_float | description | 752c2a82f973b3ad837a8ffcd823ecd3816b67ff397565f7e4a8f8671b253593 |
| tools | string_length | description | c9215426b56462882a34509f92d5b67e6e493f8088ff58e67690ffa675a21792 |
| tools | string_set | description | 726396797779d347083b3a39c1cf533c2fcffdcf5a3d53c487d53c546a6ef726 |
| tools | string_set_range | description | 5b113c6a0732c766628f9e860e83ae4d4f7cf8c6624af8da2a039357a38c0b51 |
| tools | type | description | 4b7a6d2d9042ab46bb1889b8fa01d8c42e9522cff8f96fd3cbcd3fa6e42a9d03 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
