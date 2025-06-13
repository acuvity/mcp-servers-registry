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


# What is mcp-server-alibabacloud-opensearch-ai-search?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-ai-search/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-opensearch-ai-search/545d264?logo=docker&logoColor=fff&label=545d264)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-ai-search)
[![GitHUB](https://img.shields.io/badge/545d264-3775A9?logo=github&logoColor=fff&label=aliyun/alibabacloud-opensearch-mcp-server)](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/aisearch-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-opensearch-ai-search/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-opensearch-ai-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AISEARCH_API_KEY%22%2C%22-e%22%2C%22AISEARCH_ENDPOINT%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-opensearch-ai-search%3A545d264%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Universal interface between AI Agents and OpenSearch AI Search Platform.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from aliyun/alibabacloud-opensearch-mcp-server original [sources](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/aisearch-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-opensearch-ai-search/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-ai-search/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-ai-search/charts/mcp-server-alibabacloud-opensearch-ai-search/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure aliyun/alibabacloud-opensearch-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-ai-search/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ aliyun ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/aisearch-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ aliyun/alibabacloud-opensearch-mcp-server ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/aisearch-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ aliyun/alibabacloud-opensearch-mcp-server ](https://github.com/aliyun/alibabacloud-opensearch-mcp-server/tree/HEAD/aisearch-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-ai-search/charts/mcp-server-alibabacloud-opensearch-ai-search)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-opensearch-ai-search/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-545d264`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search:1.0.0-545d264`

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
  - `AISEARCH_API_KEY` secret to be set as secrets.AISEARCH_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `AISEARCH_ENDPOINT` environment variable to be set by env.AISEARCH_ENDPOINT

# How to install


Install will helm

```console
helm install mcp-server-alibabacloud-opensearch-ai-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-alibabacloud-opensearch-ai-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-alibabacloud-opensearch-ai-search
```

From there your MCP server mcp-server-alibabacloud-opensearch-ai-search will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-opensearch-ai-search` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-alibabacloud-opensearch-ai-search
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-alibabacloud-opensearch-ai-search` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-alibabacloud-opensearch-ai-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-alibabacloud-opensearch-ai-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-alibabacloud-opensearch-ai-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-alibabacloud-opensearch-ai-search oci://docker.io/acuvity/mcp-server-alibabacloud-opensearch-ai-search --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>document_analyze</summary>

**Description**:

```
提供非结构化文档解析服务，将 PDF、DOC、DOCX、HTML、TXT 等文档解析为结构化数据格式，支持提取论文、书籍或知识库文档的标题、分段、文本、表格、图片等内容。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | 用户需要提供待处理文件的地址或路径 | Yes
| file_type | string | 待处理文件类型，支持以下格式：`pdf`, `doc`, `docx`, `html`, `txt` | Yes
| mode | string | 文件来源模式，支持以下选项：`url`, `local` | Yes
</details>
<details>
<summary>image_analyze</summary>

**Description**:

```
提供图片内容解析服务，支持以下能力：
- 基于多模态大模型对图片内容进行理解与描述；
- 使用 OCR 技术识别图片中的文字内容；
- 解析结果可用于图片检索、问答等场景。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | 待处理图片的地址或路径 | Yes
| mode | string | 文件来源模式，支持以下选项：`url`, `local` | Yes
</details>
<details>
<summary>document_split</summary>

**Description**:

```
提供通用文档切片服务，支持基于以下方式进行内容切分：
- 文档语义；
- 段落结构；
- 自定义规则。

适用于提升后续文档处理及检索效率，输出的切片树还可在检索召回时进行上下文补全。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | 待切分的原始文档内容 | Yes
| content_type | string | 文档内容类型，支持：`text`、`html`、`markdown` | No
| max_chunk_size | integer | 单个切片最大长度 | No
| need_sentence | boolean | 是否需要按句子粒度切分 | No
</details>
<details>
<summary>text_embedding</summary>

**Description**:

```
提供将文本数据转化为稠密向量（dense vector）的服务，支持多种语言、输入长度和输出维度的文本向量模型，适用于以下场景：
- 信息检索；
- 文本分类；
- 相似性比较。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| embedding_model | string | 文本向量化模型，可选值：`ops-text-embedding-001`、`ops-text-embedding-zh-001`、`ops-text-embedding-en-001`、`ops-text-embedding-002` | No
| input_type | string | 输入文本类型，可选值：`query`或`document` | No
| text_list | array | 待向量化的文本列表，每次最多支持 32 条，最少 1 条。若超过上限需分批调用。 | Yes
</details>
<details>
<summary>text_sparse_embedding</summary>

**Description**:

```
提供将文本数据转化为稀疏向量（sparse vector）的服务。稀疏向量具有更小的存储空间，适用于以下场景：
- 表达关键词及其词频信息；
- 与稠密向量结合进行混合检索；
- 提升最终检索效果。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| input_type | string | 输入文本类型，可选值：`query`或`document` | No
| text_list | array | 待稀疏向量化的文本列表，每次最多支持 32 条，最少 1 条。若超过上限需分批调用。 | Yes
</details>
<details>
<summary>rerank</summary>

**Description**:

```
提供 Query 与文档的相关性排序服务，在 RAG 及搜索场景中使用。通过该服务可按相关性对文档进行重排序并返回结果，从而有效提升检索准确率及大模型生成内容的相关性。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docs | array | 待排序的文档列表，将根据与查询的相关性重新排序 | Yes
| query | string | 用户输入的查询语句或问题 | Yes
| top_k | integer | 返回的相关性最高的文档数量 | No
</details>
<details>
<summary>web_search</summary>

**Description**:

```
提供联网搜索服务，用于在私有知识库无法回答用户问题时进行拓展检索。通过该服务可获取互联网上的最新信息，补充知识来源，并结合大语言模型生成更丰富、准确的回答。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | 用户输入的查询语句或问题 | Yes
</details>
<details>
<summary>query_analyze</summary>

**Description**:

```
提供 Query 内容分析服务，基于大语言模型与 NLP 技术，支持以下功能：
- 用户查询意图识别；
- 相似问题自动扩展；
- 查询内容改写与归一化。

适用于提升 RAG 场景下的检索与问答效果。

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | 用户输入的查询语句或问题 | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | document_analyze | description | dc3a4d22a33f01921afd322670e8276ee26fc19e575f5edf37c561e5c0e92253 |
| tools | document_analyze | file_path | 1f503d3e885c4516d9fb634fd3eea968f6619c5965a61a57e61cf09db2924090 |
| tools | document_analyze | file_type | 9325f1b65bd16f3d3188c45ce665bcd840e6c3617ca5670c271c3e7e1aa1c6eb |
| tools | document_analyze | mode | 1c264cd9575403e17501ef87fbd31ef6369440a2cca0234663f10b7335b2d582 |
| tools | document_split | description | 50a5d21952f3ebb83a6a8090faafe804333ecd61c1ff657e4aea397120ac4475 |
| tools | document_split | content | 3c825adbd15cc444feb9e0206b9d2218d25d8dbe6fc5e5c941b5531aad23f2a3 |
| tools | document_split | content_type | 982218f5a51ed3780b37154e855274c20cca89a0ff3e0adc1fe2e1c0d6643176 |
| tools | document_split | max_chunk_size | 6c42527262ec4deaea23e2c9ca135fefc8e3405c5080ba35634d51981f532856 |
| tools | document_split | need_sentence | 19087babf37119de8151f8b8317931e9aa5f4e215be0a24bb239a97de92371dc |
| tools | image_analyze | description | 74f745a5b47c7104020c7069a6fe2014bc2513b06ec1fed33e833b3a93d6a664 |
| tools | image_analyze | file_path | 433e69980a90bcba03d151c5540fde5d8f42218a590bf58abe548337f92ed7e3 |
| tools | image_analyze | mode | 1c264cd9575403e17501ef87fbd31ef6369440a2cca0234663f10b7335b2d582 |
| tools | query_analyze | description | 167cec8b4f6b9ff48c090c9c43f69c89c2e80cd441a472cf84c511db10b8cb12 |
| tools | query_analyze | query | 1f773e9ec5965be20522e6d02a4677548d3c6b2d1ba67c147ee7df690991592d |
| tools | rerank | description | f9c5965a2977facfd6f4e0673ca23a5436a3abc5c251ffb9178dbe866946028e |
| tools | rerank | docs | d8eb66df4eb3d7ab129e7d720eb9354a129aa2c201726dfa908f74fc125d730a |
| tools | rerank | query | 1f773e9ec5965be20522e6d02a4677548d3c6b2d1ba67c147ee7df690991592d |
| tools | rerank | top_k | c642c72a1fca00b6b6942ee18a9e15ff93d4684e8ca5a06d2aa0c8c638f83843 |
| tools | text_embedding | description | c5d0f406aeebcb72f08233a4740b3d53a0093832673f7affb982b20275a34410 |
| tools | text_embedding | embedding_model | 076bbe69caa0d8990d5f7e2a1f79e52c27e3c2f4c89571425342db1d3296c44a |
| tools | text_embedding | input_type | e4a0391557e608041fff6d77bedeba27847a25ec7cdfcd5a8fd91a3a60b091ee |
| tools | text_embedding | text_list | 508e7f12b47846657984b143645545af8e7685e7740e9a75e96923ea07462b39 |
| tools | text_sparse_embedding | description | 2c298239bea78bbf9e4e716ff83246e04a86938d4861b8406d2b48b3968a0ab6 |
| tools | text_sparse_embedding | input_type | e4a0391557e608041fff6d77bedeba27847a25ec7cdfcd5a8fd91a3a60b091ee |
| tools | text_sparse_embedding | text_list | 8f064caa0e1f72f18aa4cc64bc26812aa372ea9f38f20240643aeefa0f0a5efe |
| tools | web_search | description | 96a5d62a22e2a8f50fb97621636120b50eda58e1ed3875855a0fcfabd5910865 |
| tools | web_search | query | 1f773e9ec5965be20522e6d02a4677548d3c6b2d1ba67c147ee7df690991592d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
