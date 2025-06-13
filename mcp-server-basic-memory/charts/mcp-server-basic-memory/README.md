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


# What is mcp-server-basic-memory?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-basic-memory/0.13.5?logo=docker&logoColor=fff&label=0.13.5)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory)
[![PyPI](https://img.shields.io/badge/0.13.5-3775A9?logo=pypi&logoColor=fff&label=basic-memory)](https://pypi.org/project/basic-memory/)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-basic-memory/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-basic-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22memory%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-basic-memory%3A0.13.5%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-basic-memory/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - container: `1.0.0-0.13.5`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-basic-memory:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-basic-memory:1.0.0-0.13.5`

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

## 🧰 Tools (19)
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
| depth | integer | not set | No
| max_related | integer | not set | No
| page | integer | not set | No
| page_size | integer | not set | No
| project | any | not set | No
| timeframe | string | not set | No
| type | any | not set | No
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
<summary>sync_status</summary>

**Description**:

```
Check the status of file synchronization and background operations.
    
    Use this tool to:
    - Check if file sync is in progress or completed
    - Get detailed sync progress information  
    - Understand if your files are fully indexed
    - Get specific error details if sync operations failed
    - Monitor initial project setup and legacy migration
    
    This covers all sync operations including:
    - Initial project setup and file indexing
    - Legacy project migration to unified database
    - Ongoing file monitoring and updates
    - Background processing of knowledge graphs
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project | any | not set | No
</details>
<details>
<summary>list_memory_projects</summary>

**Description**:

```
List all available projects with their status.

    Shows all Basic Memory projects that are available, indicating which one
    is currently active and which is the default.

    Returns:
        Formatted list of projects with status indicators

    Example:
        list_projects()
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>switch_project</summary>

**Description**:

```
Switch to a different project context.

    Changes the active project context for all subsequent tool calls.
    Shows a project summary after switching successfully.

    Args:
        project_name: Name of the project to switch to

    Returns:
        Confirmation message with project summary

    Example:
        switch_project("work-notes")
        switch_project("personal-journal")
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_name | string | not set | Yes
</details>
<details>
<summary>get_current_project</summary>

**Description**:

```
Show the currently active project and basic stats.

    Displays which project is currently active and provides basic information
    about it.

    Returns:
        Current project name and basic statistics

    Example:
        get_current_project()
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>set_default_project</summary>

**Description**:

```
Set default project in config. Requires restart to take effect.

    Updates the configuration to use a different default project. This change
    only takes effect after restarting the Basic Memory server.

    Args:
        project_name: Name of the project to set as default

    Returns:
        Confirmation message about config update

    Example:
        set_default_project("work-notes")
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_name | string | not set | Yes
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
        create_project("my-research", "~/Documents/research")
        create_project("work-notes", "/home/user/work", set_default=True)
    
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

## 📚 Resources (2)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| ai assistant guide | text/plain | memory://ai_assistant_guide | - |
| project_info | text/plain | memory://project_info | - |

</details>

## 📝 Prompts (4)
<details>
<summary>Continue Conversation</summary>

**Description**:

```
Continue a previous conversation
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| topic | Topic or keyword to search for |No |
| timeframe | How far back to look for activity (e.g. '1d', '1 week') |No |
<details>
<summary>Share Recent Activity</summary>

**Description**:

```
Get recent activity from across the knowledge base
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| timeframe | How far back to look for activity (e.g. '1d', '1 week') |No |
<details>
<summary>Search Knowledge Base</summary>

**Description**:

```
Search across all content in basic-memory
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| query | not set |Yes |
| timeframe | How far back to search (e.g. '1d', '1 week') |No |
<details>
<summary>sync_status_prompt</summary>

**Description**:

```
Get sync status with recommendations for AI assistants.
    
    This prompt provides both current sync status and guidance on how
    AI assistants should respond when sync operations are in progress or completed.
    
```

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
| prompts | sync_status_prompt | description | da4cc0a9c0044eef836c0023b8a9c33d53ac046beba62f756a3587f3da1ac1bc |
| tools | build_context | description | 8864f9648ebb192186da87418b06d8d7a200eedfb7762ecd67e4a29fa85a8867 |
| tools | canvas | description | c739f799c4f54a0beebbbba387862e5370f4e715f36b65d0e523b3fe664d759c |
| tools | create_memory_project | description | d3cbed6ef409f038824079681857e09fc92573440b22b618f6393bfc01f3824d |
| tools | delete_note | description | b92bd108ffa7b65b4ac92c9f75167080771a08e3e9a78dd6ec3fabde085802b7 |
| tools | delete_project | description | e684a0bd482c60d1ba3ee7bc935cf30436d56ad267f9b20d9b257e9c3722912a |
| tools | edit_note | description | 7e70b1ab505a2e06e8da48ad7b4368890e8d86778fd9465d88e02bc0c43fc556 |
| tools | get_current_project | description | ec25ce3bd6c3f91340b4761b2976bbf17caa41d64f5660fd40edd781c07a86a5 |
| tools | list_directory | description | 8eaf254f8c67f5e7396f90b2a2942e9d47c64860e8b0261bca07de9c5b118d64 |
| tools | list_memory_projects | description | 944ac1e2c55826b72ca7fd53fc1c16dfe77ef71945500ecebc9756bf723c7c52 |
| tools | move_note | description | cdc522815f6900fadbdd8fa11ded0afde844bca74753141970fb06972f2beead |
| tools | read_content | description | 5b184094eabd23821254f0608ad35de1570fd776906e9ff822020cd68d129921 |
| tools | read_note | description | 5d503b64dafb1601312dd1780eb5fbdb5d7988f7d1ce090545c3fb033c0bec77 |
| tools | recent_activity | description | 8b43acabdd7bc9e4ab6398f1f27b28203fb5df0314d7f0888946136d40f548d5 |
| tools | search_notes | description | fcaec1323a397ec1b89c8d50efb4cf4af054f0574d569452599c927231594adc |
| tools | set_default_project | description | 25c20445c664c4a3459c6188cd63e33b69219d984641f916d4c118ddd9a2877f |
| tools | switch_project | description | 096b246c8d498cf080f5c936ffc13d14d21cea89e6f768b82d81aea3071ab5b4 |
| tools | sync_status | description | 00b145ea43da92d1e768bbdcb203a9104369d88d55314c30a0970c3edd03499c |
| tools | view_note | description | 7cb3581bfc58d06d48b06d0e5ff77a8528b44729996ae403a134cfc8b1316303 |
| tools | write_note | description | 3fb632ad40400235da2eae016e76b13f699cd2206aca615729e8ee85653ec98f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
