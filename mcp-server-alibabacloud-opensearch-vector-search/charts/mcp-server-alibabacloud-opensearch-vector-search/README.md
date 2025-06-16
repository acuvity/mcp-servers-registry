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


# What is mcp-server-alibabacloud-opensearch-vector-search?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-opensearch-vector-search/545d264?logo=docker&logoColor=fff&label=545d264)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search)
[![GitHUB](https://img.shields.io/badge/545d264-3775A9?logo=github&logoColor=fff&label=aliyun/alibabacloud-opensearch-mcp-server)](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-vector-search/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-opensearch-vector-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_USERNAME%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_PASSWORD%22%2C%22-e%22%2C%22OPENSEARCH_VECTOR_INSTANCE_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-opensearch-vector-search%3A545d264%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Universal interface between AI Agents and OpenSearch Vector.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from aliyun/alibabacloud-opensearch-mcp-server original [sources](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-opensearch-vector-search/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure aliyun/alibabacloud-opensearch-mcp-server run reliably and safely.

## 🔐 Key Security Features

### 📦 Isolated Immutable Sandbox

| Feature                   | Description                                                                                                            |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| Isolated Execution        | All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.         |
| Non-root by Default       | Enforces least-privilege principles, minimizing the impact of potential security breaches.                              |
| Read-only Filesystem      | Ensures runtime immutability, preventing unauthorized modification.                                                     |
| Version Pinning           | Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.                  |
| CVE Scanning              | Continuously scans images for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation. |
| SBOM & Provenance         | Delivers full supply chain transparency by embedding metadata and traceable build information.                          |
| Container Signing (Cosign) | Implements image signing using [Cosign](https://github.com/sigstore/cosign) to ensure integrity and authenticity of container images.                             |

### 🛡️ Runtime Security and Guardrails

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `resource integrity`             | Embeds a hash of all exposed resources to ensure their authenticity and prevent unauthorized modifications, guarding against supply chain attacks and dynamic alterations of tool metadata. |
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |
| `basic authentication`           | Enables the configuration of a shared secret to restrict unauthorized access to the MCP server and ensure only approved clients can connect. |

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

> [!NOTE]
> By default, all guardrails except `resource integrity` are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ aliyun ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ aliyun/alibabacloud-opensearch-mcp-server ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ aliyun/alibabacloud-opensearch-mcp-server ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/opensearch-vector-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/charts/mcp-server-alibabacloud-opensearch-vector-search)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-vector-search/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-545d264`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search:1.0.0-545d264`

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
  - `OPENSEARCH_VECTOR_PASSWORD` secret to be set as secrets.OPENSEARCH_VECTOR_PASSWORD either by `.value` or from existing with `.valueFrom`

**Optional Secrets**:
  - `AISEARCH_API_KEY` secret to be set as secrets.AISEARCH_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `OPENSEARCH_VECTOR_USERNAME` environment variable to be set by env.OPENSEARCH_VECTOR_USERNAME
  - `OPENSEARCH_VECTOR_INSTANCE_ID` environment variable to be set by env.OPENSEARCH_VECTOR_INSTANCE_ID

**Optional Environment variables**:
  - `OPENSEARCH_VECTOR_INDEX_NAME=""` environment variable can be changed with `env.OPENSEARCH_VECTOR_INDEX_NAME=""`
  - `AISEARCH_ENDPOINT=""` environment variable can be changed with `env.AISEARCH_ENDPOINT=""`

# How to install


Install will helm

```console
helm install mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-alibabacloud-opensearch-vector-search
```

From there your MCP server mcp-server-alibabacloud-opensearch-vector-search will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-opensearch-vector-search` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-alibabacloud-opensearch-vector-search
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-alibabacloud-opensearch-vector-search` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-alibabacloud-opensearch-vector-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-vector-search --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (6)
<details>
<summary>simple_search</summary>

**Description**:

```
Perform a similarity search based on either a text query or a vector. If the input is text, it will be converted into a vector using the specified embedding model.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| embedding_model | string | Embedding model for text queries. Supported: `ops-text-embedding-001`、`ops-text-embedding-zh-001`、`ops-text-embedding-en-001`、`ops-text-embedding-002` | No
| filter | any | Additional filtering criteria. | No
| namespace | any | Namespace for filtering results. | No
| need_sparse_vector | boolean | Whether to include sparse vector data in the search. | No
| query | any | Search query, can be either a text string or a list of floats representing a vector. | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
</details>
<details>
<summary>query_by_ids</summary>

**Description**:

```
Perform a simple search based on key ids.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ids | array | List of ids to query | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
</details>
<details>
<summary>inference_query</summary>

**Description**:

```
Perform a simple search based on text after configuring EmbeddingModel in OpenSearch Console.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The text to query | Yes
| namespace | any | The namespace of the target table in OpenSearch Vector. | No
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
</details>
<details>
<summary>multi_query</summary>

**Description**:

```
Perform a multi search based on vectors.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
| vector_list | array | A list of dense vectors to be used for the multi-vector similarity search. | Yes
</details>
<details>
<summary>mix_query_with_sparse_vector</summary>

**Description**:

```
Perform a complex search based on a single dense vector and a sparse vector.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sparse_ids | array | A list of token IDs representing the indices of the sparse vector. | Yes
| sparse_values | array | A list of corresponding weights for each token ID in sparse_ids, forming the sparse vector. | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
| vector | array | A dense vector used as the primary query vector for similarity search. | Yes
</details>
<details>
<summary>mix_query_with_text</summary>

**Description**:

```
Perform a complex search based on a single dense vector and a text.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | A text query for similarity search. | Yes
| table_name | string | The name of the target table in OpenSearch Vector. | Yes
| vector | array | A dense vector for similarity search. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | inference_query | description | 46ec7dbe526f2f38d4f0be6e52d31e7b2088caff963b759de349dc04957087f1 |
| tools | inference_query | content | 3a9e67b7734e83063d056290633ca6d9f7d7bf6070fae6cbfb279a75fda5e099 |
| tools | inference_query | namespace | c5f3f8aeea4f98fedfdf82f13463d9a1a2fd9645a94baeabaa30b9c9b74f5609 |
| tools | inference_query | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | mix_query_with_sparse_vector | description | 90c71900bc568809689f449dcc3a8449fc3847d0e196ca237cf9dd5eaa465bc0 |
| tools | mix_query_with_sparse_vector | sparse_ids | 594a9f49a20a1647000229942298b16c09a49b1940c47377a8474a78dd77c022 |
| tools | mix_query_with_sparse_vector | sparse_values | 196cc8b6c9d410285838c3f480cfb363900e6011533dfe20b9bc76603df36938 |
| tools | mix_query_with_sparse_vector | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | mix_query_with_sparse_vector | vector | 9f4908a3cd51420bae5215d7be70280bc232f8de18a4c299bf9ae47595619dc1 |
| tools | mix_query_with_text | description | ecdc3576c1e7744051bee3604ca3c778a8150c4a9bc8f43a78c41ccb3bb231f9 |
| tools | mix_query_with_text | content | 7a662e4676b262d0e259a679a08b7fc35144f28ae8db9408d294ae5e7ae32ae4 |
| tools | mix_query_with_text | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | mix_query_with_text | vector | 02ceae19226395b6f4bddc8b96143a651c3a93b4e69e70bdd8c52c4fab7941e2 |
| tools | multi_query | description | 68186a60caa990bc5efb1987e03545258b5405983ca7e0f804ec31d9ab8bc6bb |
| tools | multi_query | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | multi_query | vector_list | c12b44c7640b8394d36b0f0a042d06b9500e5a9562796b45f4303ef43042325d |
| tools | query_by_ids | description | 64d3cd22f258ce2fd3fe7fb09213bbf61b79f100c12142dbab8ac496b3423cfc |
| tools | query_by_ids | ids | ee8044588b3879214257c2302e201c3a61b83f1401a4df9e8bc7d8d7375d03db |
| tools | query_by_ids | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |
| tools | simple_search | description | 5107a7b75309bd2218d85484bf5ae384ba5127a09ddbb27cda056687d3ca8eff |
| tools | simple_search | embedding_model | 17cecb6e7d5767adb8025db25cc2be514b88e144654b7a7b643d7ca2be9e4e5c |
| tools | simple_search | filter | 699dbab22e9da5f117ac730b2bfb2aab3ce65c6e4a495b7d6adef3acbc2f631f |
| tools | simple_search | namespace | a2735052645d07d9e3daac15c818c027ed5c487789ad2eda55b83382a79f7890 |
| tools | simple_search | need_sparse_vector | ece41e6b7a00b1ddd535724f039408e9db21d57eacba26a37f720df3fcc38c8b |
| tools | simple_search | query | 7e0534f864ebd7b073fe3c37ea3b3f59daaf5ad7a9cd6cf3afc266bc4cd71983 |
| tools | simple_search | table_name | 89446506972d8f2c1e548380df335b1b47b68db871fef473d70b85cfa1d36601 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
