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


# What is mcp-server-chroma?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chroma/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chroma/0.2.2?logo=docker&logoColor=fff&label=0.2.2)](https://hub.docker.com/r/acuvity/mcp-server-chroma)
[![PyPI](https://img.shields.io/badge/0.2.2-3775A9?logo=pypi&logoColor=fff&label=chroma-mcp)](https://github.com/chroma-core/chroma-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-chroma/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chroma&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHROMA_CLIENT_TYPE%22%2C%22-e%22%2C%22CHROMA_DATABASE%22%2C%22-e%22%2C%22CHROMA_HOST%22%2C%22-e%22%2C%22CHROMA_PORT%22%2C%22-e%22%2C%22CHROMA_TENANT%22%2C%22docker.io%2Facuvity%2Fmcp-server-chroma%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Embedding database for LLM applications with advanced search capabilities.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from chroma-mcp original [sources](https://github.com/chroma-core/chroma-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-chroma/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/charts/mcp-server-chroma/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure chroma-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Author ](https://github.com/chroma-core/chroma-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ chroma-mcp ](https://github.com/chroma-core/chroma-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ chroma-mcp ](https://github.com/chroma-core/chroma-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/charts/mcp-server-chroma)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chroma/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-chroma:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-chroma:1.0.0-0.2.2`

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

**Optional Secrets**:
  - `CHROMA_API_KEY` secret to be set as secrets.CHROMA_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `CHROMA_CLIENT_TYPE` environment variable to be set by env.CHROMA_CLIENT_TYPE
  - `CHROMA_DATABASE` environment variable to be set by env.CHROMA_DATABASE
  - `CHROMA_HOST` environment variable to be set by env.CHROMA_HOST
  - `CHROMA_PORT` environment variable to be set by env.CHROMA_PORT
  - `CHROMA_TENANT` environment variable to be set by env.CHROMA_TENANT

**Optional Environment variables**:
  - `CHROMA_CUSTOM_AUTH_CREDENTIALS=""` environment variable can be changed with `env.CHROMA_CUSTOM_AUTH_CREDENTIALS=""`
  - `CHROMA_DATA_DIR=""` environment variable can be changed with `env.CHROMA_DATA_DIR=""`
  - `CHROMA_SSL=""` environment variable can be changed with `env.CHROMA_SSL=""`

# How to install


Install will helm

```console
helm install mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-chroma
```

From there your MCP server mcp-server-chroma will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-chroma` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-chroma
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-chroma` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-chroma oci://docker.io/acuvity/mcp-server-chroma --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>chroma_list_collections</summary>

**Description**:

```
List all collection names in the Chroma database with pagination support.
    
    Args:
        limit: Optional maximum number of collections to return
        offset: Optional number of collections to skip before returning results
    
    Returns:
        List of collection names
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
</details>
<details>
<summary>chroma_create_collection</summary>

**Description**:

```
Create a new Chroma collection with configurable HNSW parameters.
    
    Args:
        collection_name: Name of the collection to create
        space: Distance function used in HNSW index. Options: 'l2', 'ip', 'cosine'
        ef_construction: Size of the dynamic candidate list for constructing the HNSW graph
        ef_search: Size of the dynamic candidate list for searching the HNSW graph
        max_neighbors: Maximum number of neighbors to consider during HNSW graph construction
        num_threads: Number of threads to use during HNSW construction
        batch_size: Number of elements to batch together during index construction
        sync_threshold: Number of elements to process before syncing index to disk
        resize_factor: Factor to resize the index by when it's full
        embedding_function_name: Name of the embedding function to use. Options: 'default', 'cohere', 'openai', 'jina', 'voyageai', 'ollama', 'roboflow'
        metadata: Optional metadata dict to add to the collection
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| batch_size | any | not set | No
| collection_name | string | not set | Yes
| ef_construction | any | not set | No
| ef_search | any | not set | No
| embedding_function_name | any | not set | No
| max_neighbors | any | not set | No
| metadata | any | not set | No
| num_threads | any | not set | No
| resize_factor | any | not set | No
| space | any | not set | No
| sync_threshold | any | not set | No
</details>
<details>
<summary>chroma_peek_collection</summary>

**Description**:

```
Peek at documents in a Chroma collection.
    
    Args:
        collection_name: Name of the collection to peek into
        limit: Number of documents to peek at
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| limit | integer | not set | No
</details>
<details>
<summary>chroma_get_collection_info</summary>

**Description**:

```
Get information about a Chroma collection.
    
    Args:
        collection_name: Name of the collection to get info about
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_get_collection_count</summary>

**Description**:

```
Get the number of documents in a Chroma collection.
    
    Args:
        collection_name: Name of the collection to count
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_modify_collection</summary>

**Description**:

```
Modify a Chroma collection's name or metadata.
    
    Args:
        collection_name: Name of the collection to modify
        new_name: Optional new name for the collection
        new_metadata: Optional new metadata for the collection
        ef_search: Size of the dynamic candidate list for searching the HNSW graph
        num_threads: Number of threads to use during HNSW construction
        batch_size: Number of elements to batch together during index construction
        sync_threshold: Number of elements to process before syncing index to disk
        resize_factor: Factor to resize the index by when it's full
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| batch_size | any | not set | No
| collection_name | string | not set | Yes
| ef_search | any | not set | No
| new_metadata | any | not set | No
| new_name | any | not set | No
| num_threads | any | not set | No
| resize_factor | any | not set | No
| sync_threshold | any | not set | No
</details>
<details>
<summary>chroma_delete_collection</summary>

**Description**:

```
Delete a Chroma collection.
    
    Args:
        collection_name: Name of the collection to delete
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
</details>
<details>
<summary>chroma_add_documents</summary>

**Description**:

```
Add documents to a Chroma collection.
    
    Args:
        collection_name: Name of the collection to add documents to
        documents: List of text documents to add
        metadatas: Optional list of metadata dictionaries for each document
        ids: Optional list of IDs for the documents
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| documents | array | not set | Yes
| ids | any | not set | No
| metadatas | any | not set | No
</details>
<details>
<summary>chroma_query_documents</summary>

**Description**:

```
Query documents from a Chroma collection with advanced filtering.
    
    Args:
        collection_name: Name of the collection to query
        query_texts: List of query texts to search for
        n_results: Number of results to return per query
        where: Optional metadata filters using Chroma's query operators
               Examples:
               - Simple equality: {"metadata_field": "value"}
               - Comparison: {"metadata_field": {"$gt": 5}}
               - Logical AND: {"$and": [{"field1": {"$eq": "value1"}}, {"field2": {"$gt": 5}}]}
               - Logical OR: {"$or": [{"field1": {"$eq": "value1"}}, {"field1": {"$eq": "value2"}}]}
        where_document: Optional document content filters
        include: List of what to include in response. By default, this will include documents, metadatas, and distances.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| include | array | not set | No
| n_results | integer | not set | No
| query_texts | array | not set | Yes
| where | any | not set | No
| where_document | any | not set | No
</details>
<details>
<summary>chroma_get_documents</summary>

**Description**:

```
Get documents from a Chroma collection with optional filtering.
    
    Args:
        collection_name: Name of the collection to get documents from
        ids: Optional list of document IDs to retrieve
        where: Optional metadata filters using Chroma's query operators
               Examples:
               - Simple equality: {"metadata_field": "value"}
               - Comparison: {"metadata_field": {"$gt": 5}}
               - Logical AND: {"$and": [{"field1": {"$eq": "value1"}}, {"field2": {"$gt": 5}}]}
               - Logical OR: {"$or": [{"field1": {"$eq": "value1"}}, {"field1": {"$eq": "value2"}}]}
        where_document: Optional document content filters
        include: List of what to include in response. By default, this will include documents, and metadatas.
        limit: Optional maximum number of documents to return
        offset: Optional number of documents to skip before returning results
    
    Returns:
        Dictionary containing the matching documents, their IDs, and requested includes
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| ids | any | not set | No
| include | array | not set | No
| limit | any | not set | No
| offset | any | not set | No
| where | any | not set | No
| where_document | any | not set | No
</details>
<details>
<summary>chroma_update_documents</summary>

**Description**:

```
Update documents in a Chroma collection.

    Args:
        collection_name: Name of the collection to update documents in
        ids: List of document IDs to update (required)
        embeddings: Optional list of new embeddings for the documents.
                    Must match length of ids if provided.
        metadatas: Optional list of new metadata dictionaries for the documents.
                   Must match length of ids if provided.
        documents: Optional list of new text documents.
                   Must match length of ids if provided.

    Returns:
        A confirmation message indicating the number of documents updated.

    Raises:
        ValueError: If 'ids' is empty or if none of 'embeddings', 'metadatas',
                    or 'documents' are provided, or if the length of provided
                    update lists does not match the length of 'ids'.
        Exception: If the collection does not exist or if the update operation fails.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| documents | any | not set | No
| embeddings | any | not set | No
| ids | array | not set | Yes
| metadatas | any | not set | No
</details>
<details>
<summary>chroma_delete_documents</summary>

**Description**:

```
Delete documents from a Chroma collection.

    Args:
        collection_name: Name of the collection to delete documents from
        ids: List of document IDs to delete

    Returns:
        A confirmation message indicating the number of documents deleted.

    Raises:
        ValueError: If 'ids' is empty
        Exception: If the collection does not exist or if the delete operation fails.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_name | string | not set | Yes
| ids | array | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | chroma_add_documents | description | fb4fc8a59779eeeeeae7ce6f3266a183514eb78b0671fc13b636328c3c7656b7 |
| tools | chroma_create_collection | description | 5f3175ec903416f64d78427694c1b273eff494104b05c0aa0d7f4efa496f70a5 |
| tools | chroma_delete_collection | description | a361003969b79e83a7d12f01a90673e38583b856951806d565b8d99a2b54c4ef |
| tools | chroma_delete_documents | description | 23ab4256014ccae612288d23ff8838af64c2f56391dc7851c570da81aade2987 |
| tools | chroma_get_collection_count | description | 33047599d472f45af90fa29d9eacb603f25e1dbb6d1e1d4fad63dda4d868efe8 |
| tools | chroma_get_collection_info | description | bcde301a84c843b111bc751d56fc858b3dabd659be1336f7acf95522dcf81e1c |
| tools | chroma_get_documents | description | 684820343977ed4618f5d3e8dcade8a185f3eb3d91a10af45dc8edf73cfa8b98 |
| tools | chroma_list_collections | description | f38afda8f178cd3962a2d3d56ababd022794917ab7369d1b704ef6f774dc58bb |
| tools | chroma_modify_collection | description | 554eb2c50155a2973d81efe74728befea9bf94a8d553c75854ee945050eb4754 |
| tools | chroma_peek_collection | description | 9f2ddf70df5250db4c74e7576cb64a067997c6cf5659401d00481d280135a9ca |
| tools | chroma_query_documents | description | 9284071e209e0ffc7566fa8fc14746dd34b310e186f0a0439b23e135cb6f8220 |
| tools | chroma_update_documents | description | 038dbe7bb4d878805ac4552b9c62b8687e94954391a6ed95259b5029049de95d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
