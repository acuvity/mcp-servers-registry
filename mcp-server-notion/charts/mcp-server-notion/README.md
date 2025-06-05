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


# What is mcp-server-notion?
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-notion/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-notion/1.8.1?logo=docker&logoColor=fff&label=1.8.1)](https://hub.docker.com/r/acuvity/mcp-server-notion)
[![PyPI](https://img.shields.io/badge/1.8.1-3775A9?logo=pypi&logoColor=fff&label=@notionhq/notion-mcp-server)](https://github.com/makenotion/notion-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-notion/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-notion&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OPENAPI_MCP_HEADERS%22%2C%22docker.io%2Facuvity%2Fmcp-server-notion%3A1.8.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Interacting with Notion API.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @notionhq/notion-mcp-server original [sources](https://github.com/makenotion/notion-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-notion/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/charts/mcp-server-notion/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @notionhq/notion-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ @notionhq ](https://github.com/makenotion/notion-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @notionhq/notion-mcp-server ](https://github.com/makenotion/notion-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @notionhq/notion-mcp-server ](https://github.com/makenotion/notion-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/charts/mcp-server-notion)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-notion/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.8.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-notion:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-notion:1.0.0-1.8.1`

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
  - `OPENAPI_MCP_HEADERS` secret to be set as secrets.OPENAPI_MCP_HEADERS either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-notion
```

From there your MCP server mcp-server-notion will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-notion` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-notion
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-notion` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-notion oci://docker.io/acuvity/mcp-server-notion --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>API-get-user</summary>

**Description**:

```
Retrieve a user
Error Responses:
400: 400
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user_id | string | not set | Yes
</details>
<details>
<summary>API-get-users</summary>

**Description**:

```
List all users
Error Responses:
400: 400
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| start_cursor | string | If supplied, this endpoint will return a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-get-self</summary>

**Description**:

```
Retrieve your token's bot user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>API-post-database-query</summary>

**Description**:

```
Query a database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| archived | boolean | not set | No
| database_id | string | Identifier for a Notion database. | Yes
| filter | object | When supplied, limits which pages are returned based on the [filter conditions](ref:post-database-query-filter). | No
| filter_properties | array | A list of page property value IDs associated with the database. Use this param to limit the response to a specific page property value or values for pages that meet the `filter` criteria. | No
| in_trash | boolean | not set | No
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| sorts | array | When supplied, orders the results based on the provided [sort criteria](ref:post-database-query-sort). | No
| start_cursor | string | When supplied, returns a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-post-search</summary>

**Description**:

```
Search by title
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter | object | A set of criteria, `value` and `property` keys, that limits the results to either only pages or only databases. Possible `value` values are `"page"` or `"database"`. The only supported `property` value is `"object"`. | No
| page_size | integer | The number of items from the full list to include in the response. Maximum: `100`. | No
| query | string | The text that the API compares page and database titles against. | No
| sort | object | A set of criteria, `direction` and `timestamp` keys, that orders the results. The **only** supported timestamp value is `"last_edited_time"`. Supported `direction` values are `"ascending"` and `"descending"`. If `sort` is not provided, then the most recently edited results are returned first. | No
| start_cursor | string | A `cursor` value returned in a previous response that If supplied, limits the response to results starting after the `cursor`. If not supplied, then the first page of results is returned. Refer to [pagination](https://developers.notion.com/reference/intro#pagination) for more details. | No
</details>
<details>
<summary>API-get-block-children</summary>

**Description**:

```
Retrieve block children
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | Identifier for a [block](ref:block) | Yes
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| start_cursor | string | If supplied, this endpoint will return a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-patch-block-children</summary>

**Description**:

```
Append block children
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | The ID of the existing block that the new block should be appended after. | No
| block_id | string | Identifier for a [block](ref:block). Also accepts a [page](ref:page) ID. | Yes
| children | array | Child content to append to a container block as an array of [block objects](ref:block) | Yes
</details>
<details>
<summary>API-retrieve-a-block</summary>

**Description**:

```
Retrieve a block
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | Identifier for a Notion block | Yes
</details>
<details>
<summary>API-update-a-block</summary>

**Description**:

```
Update a block
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| archived | boolean | Set to true to archive (delete) a block. Set to false to un-archive (restore) a block. | No
| block_id | string | Identifier for a Notion block | Yes
| type | object | The [block object `type`](ref:block#block-object-keys) value with the properties to be updated. Currently only `text` (for supported block types) and `checked` (for `to_do` blocks) fields can be updated. | No
</details>
<details>
<summary>API-delete-a-block</summary>

**Description**:

```
Delete a block
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | Identifier for a Notion block | Yes
</details>
<details>
<summary>API-retrieve-a-page</summary>

**Description**:

```
Retrieve a page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filter_properties | string | A list of page property value IDs associated with the page. Use this param to limit the response to a specific page property value or values. To retrieve multiple properties, specify each page property ID. For example: `?filter_properties=iAk8&filter_properties=b7dh`. | No
| page_id | string | Identifier for a Notion page | Yes
</details>
<details>
<summary>API-patch-page</summary>

**Description**:

```
Update page properties
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| archived | boolean | not set | No
| cover | object | A cover image for the page. Only [external file objects](https://developers.notion.com/reference/file-object) are supported. | No
| icon | object | A page icon for the page. Supported types are [external file object](https://developers.notion.com/reference/file-object) or [emoji object](https://developers.notion.com/reference/emoji-object). | No
| in_trash | boolean | Set to true to delete a block. Set to false to restore a block. | No
| page_id | string | The identifier for the Notion page to be updated. | Yes
| properties | object | The property values to update for the page. The keys are the names or IDs of the property and the values are property values. If a page property ID is not included, then it is not changed. | No
</details>
<details>
<summary>API-post-page</summary>

**Description**:

```
Create a page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| children | array | The content to be rendered on the new page, represented as an array of [block objects](https://developers.notion.com/reference/block). | No
| cover | string | The cover image of the new page, represented as a [file object](https://developers.notion.com/reference/file-object). | No
| icon | string | The icon of the new page. Either an [emoji object](https://developers.notion.com/reference/emoji-object) or an [external file object](https://developers.notion.com/reference/file-object).. | No
| parent | object | not set | Yes
| properties | object | not set | Yes
</details>
<details>
<summary>API-create-a-database</summary>

**Description**:

```
Create a database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| parent | object | not set | Yes
| properties | object | Property schema of database. The keys are the names of properties as they appear in Notion and the values are [property schema objects](https://developers.notion.com/reference/property-schema-object). | Yes
| title | array | not set | No
</details>
<details>
<summary>API-update-a-database</summary>

**Description**:

```
Update a database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_id | string | identifier for a Notion database | Yes
| description | array | An array of [rich text objects](https://developers.notion.com/reference/rich-text) that represents the description of the database that is displayed in the Notion UI. If omitted, then the database description remains unchanged. | No
| properties | object | Property schema of database. The keys are the names of properties as they appear in Notion and the values are [property schema objects](https://developers.notion.com/reference/property-schema-object). | No
| title | array | An array of [rich text objects](https://developers.notion.com/reference/rich-text) that represents the title of the database that is displayed in the Notion UI. If omitted, then the database title remains unchanged. | No
</details>
<details>
<summary>API-retrieve-a-database</summary>

**Description**:

```
Retrieve a database
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_id | string | An identifier for the Notion database. | Yes
</details>
<details>
<summary>API-retrieve-a-page-property</summary>

**Description**:

```
Retrieve a page property item
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page_id | string | Identifier for a Notion page | Yes
| page_size | integer | For paginated properties. The max number of property item objects on a page. The default size is 100 | No
| property_id | string | Identifier for a page [property](https://developers.notion.com/reference/page#all-property-values) | Yes
| start_cursor | string | For paginated properties. | No
</details>
<details>
<summary>API-retrieve-a-comment</summary>

**Description**:

```
Retrieve comments
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| block_id | string | Identifier for a Notion block or page | Yes
| page_size | integer | The number of items from the full list desired in the response. Maximum: 100 | No
| start_cursor | string | If supplied, this endpoint will return a page of results starting after the cursor provided. If not supplied, this endpoint will return the first page of results. | No
</details>
<details>
<summary>API-create-a-comment</summary>

**Description**:

```
Create comment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| parent | object | The page that contains the comment | Yes
| rich_text | array | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | API-create-a-comment | description | 1cf44abde6508ae75f3c866eba8a08eb24a74c5dad94f813c09415892844a9f1 |
| tools | API-create-a-comment | parent | 80ad2857740577e2077ef3c462fe8409dbe228a6cdfbb8c9a4c9d25ca7f2965e |
| tools | API-create-a-database | description | 0c4d32832f46802e297eafb102362f820aee2e6f0177fa9dc6d6ee757b9c0380 |
| tools | API-create-a-database | properties | 4ae18f5cbb0402c238429b0a84c46840de281c628a8dbb587811f28cbfe1c321 |
| tools | API-delete-a-block | description | ff8c9f2e015f6e739de171932d2524e290bc8ea79b5b1f654c2203569fd1db23 |
| tools | API-delete-a-block | block_id | 4282659befb77e742b5cc853f28d0fba3c013371b1d5a7cd24a13568b31f7b37 |
| tools | API-get-block-children | description | da3023fae08d3eeb47ca99d24d773168c09b2505b9eea9a33650cadd3c45f68c |
| tools | API-get-block-children | block_id | 9bcbe2492facf78a4ee18c89806c40c35a87ad4b530c3170a1ff39a880906371 |
| tools | API-get-block-children | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-get-block-children | start_cursor | e5b52e5e2e4b1f29ff2ef0055327c55856d7f55609fe52f8b1f69eaa29530469 |
| tools | API-get-self | description | f85e198803128737113544ba6f34b54ee768ac7efb522f84f42a3cc31aedcc37 |
| tools | API-get-user | description | 727869918a2bb6ceed20bc01ba4fb145450664ff250ac9a0d260e83a69fc4bd2 |
| tools | API-get-users | description | 7f8a2d0b73f3ce289a62c88574d19f11d293a676b3bbc8147a8111972108e7b7 |
| tools | API-get-users | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-get-users | start_cursor | e5b52e5e2e4b1f29ff2ef0055327c55856d7f55609fe52f8b1f69eaa29530469 |
| tools | API-patch-block-children | description | 9bb75c455eec4f782777a8eb1d4ae66ff1405fc116075870ad15cf7d4142dcb1 |
| tools | API-patch-block-children | after | c727e3b91d2dc39ec83c92b70bda36145409cdfac6fd8dfd73c53be124071343 |
| tools | API-patch-block-children | block_id | 1ac2e0616787fd6470faf44a932a32dc5ae7ecfb910a07316ff2c1c7322ac23e |
| tools | API-patch-block-children | children | 44d9344314eeef73a29c1b254f18b3b88a25123298f00a082863c6ff6c14cb47 |
| tools | API-patch-page | description | 725ffb46cb4484d0b6db71d621c028e51ee043f97b2413299991fc40c4d61706 |
| tools | API-patch-page | cover | b9815ef939d225a191cfc788e43ae4b549a433471b3fb166e5b20d2a497cdf14 |
| tools | API-patch-page | icon | 58eb56d386c18050173f6394c736007572828633a894fe88e905e12aa6210d79 |
| tools | API-patch-page | in_trash | ab3e9fe89322e3da72f39f596f2033bbec59a0098bf9f0aa672e5c5dddf2aaeb |
| tools | API-patch-page | page_id | b5930097fd9390bac535ec99ebbfaa2927d17bcae8f871695278547f8e7cf346 |
| tools | API-patch-page | properties | 8b7dfc8b81ca3f2eac312bf89b6eb8ef8dc60d95c91523b7f1c07057f1b861f4 |
| tools | API-post-database-query | description | aa89e5751799ff61d77270aae00c6ef47fcd596d025126006c76e8a3d1bc9c4b |
| tools | API-post-database-query | database_id | 5c72ef7b2808ccbea1aba31b1f3ab37a4e29cfe686640c1e2a24f26ffb12b37e |
| tools | API-post-database-query | filter | ec833085bb176f402f35ee780c049727af1bc363ad3daaccf3949747d372b280 |
| tools | API-post-database-query | filter_properties | d99874beb7ac9824a1c917e9d0d75414d40df7a9c39d1c07d23888dfdfdd4a31 |
| tools | API-post-database-query | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-post-database-query | sorts | f6657dbb20e7728c34cfb77ebabe93c11f4ebdb40b436d4d937079a3f95b3253 |
| tools | API-post-database-query | start_cursor | f806e2c7f95944c3b62944aa634647138e5b0fac2ce899ae534b6443b186cb7f |
| tools | API-post-page | description | b682233a5002907c4bc71179c53d6a8665ef446828d3b49cebc2295a1db3315b |
| tools | API-post-page | children | dfef3332fc212d5de83488a378ef5f656620690071b9a4c1bf89224c47117eda |
| tools | API-post-page | cover | b39fea223aa71d6c736f6bdc458887d85629de1450078a67e4f4708fe4407e97 |
| tools | API-post-page | icon | 28975513a8ec2f9437200f6012de26619dc902c7133691c102cfe1c43956549c |
| tools | API-post-search | description | 6b5b4c14c7630a2ab91fa1e874d92664c976b51469742d93591fd0b49bc2953c |
| tools | API-post-search | filter | 32dd86a94fe9cf223fa7fe8f4a203ade4151ff9d914041d82e57f27c2625a3cc |
| tools | API-post-search | page_size | ceafdaab204f34d7a79ce05c88b6d698aeee428066057f7512ad1d8c965c14aa |
| tools | API-post-search | query | 4880cdf43451479ef98bf8b0ea9611ddc4c9db89d15387c01da46a2d3893095b |
| tools | API-post-search | sort | 564929275340d84a24f9382adf6a7cf751fa71f4f38a814ce43dedd9f7713f97 |
| tools | API-post-search | start_cursor | 9f0b7de41237ccb79a242da38187fe4acd22c3e69684ece5dad353404c6c62e1 |
| tools | API-retrieve-a-block | description | 0eee5d7cbca7bb7d3af0e294f295a6aebf0a25cdd857388c662293238f73b2ce |
| tools | API-retrieve-a-block | block_id | 4282659befb77e742b5cc853f28d0fba3c013371b1d5a7cd24a13568b31f7b37 |
| tools | API-retrieve-a-comment | description | 338c62fbb4fe8309e148e93a54bde82311c970ecd81cb51ba17d52a748aa0d0a |
| tools | API-retrieve-a-comment | block_id | 800e6bacf259e4f525e1c2e5cb8e67f361d1b5bc0c35a68d38d218e5645a889f |
| tools | API-retrieve-a-comment | page_size | c8d012f8541c3b71b11b5012afa60f8f495889a85bfbcee9cdbabde3531d743e |
| tools | API-retrieve-a-comment | start_cursor | e5b52e5e2e4b1f29ff2ef0055327c55856d7f55609fe52f8b1f69eaa29530469 |
| tools | API-retrieve-a-database | description | 518ea41f01b56703f518c40cb76a88942803b6049734fcd23835c3614e10d4df |
| tools | API-retrieve-a-database | database_id | c057256c3e7db65d8daced3de4624c82885902d6778442730f7db17690da6c08 |
| tools | API-retrieve-a-page | description | a06af6b3d748466cd0ede9733c78709ffc04af5881d322c9547320c236b1318d |
| tools | API-retrieve-a-page | filter_properties | aaa1e89cb9d79b8b24fed89244939f50bca965a928ccd3bd95fe18c7c483634b |
| tools | API-retrieve-a-page | page_id | 28634ab8051c0c0b0b533b0830f92e6bea11a3d772ba30db5161f58ea95f68b4 |
| tools | API-retrieve-a-page-property | description | 63709857408947091c44c5536e44267574ddebe6568b91debf9b5545f5101c70 |
| tools | API-retrieve-a-page-property | page_id | 28634ab8051c0c0b0b533b0830f92e6bea11a3d772ba30db5161f58ea95f68b4 |
| tools | API-retrieve-a-page-property | page_size | 231332689fcc3e6a74772c04121a1778539e4e7a54856a84b86bbeeb11b04fc6 |
| tools | API-retrieve-a-page-property | property_id | 864a243ef35b8ea5e3d0db2712a8a7ade53550c732678977cc84697000695214 |
| tools | API-retrieve-a-page-property | start_cursor | b274bf0ccad01fb37e4fc3ce317fd9d19e33f37f16349f2f61d246dbab289d14 |
| tools | API-update-a-block | description | fa8813d7c2db87b4833d9583f764f50b810c24cfe7cd6a3931f82fda2d83b98c |
| tools | API-update-a-block | archived | 9507894f6773eba55065ea07d3b4b65014523432442a3bbd5f11242764637bba |
| tools | API-update-a-block | block_id | 4282659befb77e742b5cc853f28d0fba3c013371b1d5a7cd24a13568b31f7b37 |
| tools | API-update-a-block | type | ed6d041bbe1c6569f88f0c4cab0b8021625770aa7651f19e04896ed880b89920 |
| tools | API-update-a-database | description | 8fa57e069d31ba547c5d8d0da2867ffc414c672f042002bdc498777fb98afc59 |
| tools | API-update-a-database | database_id | 2d152e5d3c566d4a653a5af8b8bcc554f46581fb025168a32a8f1515ef16663b |
| tools | API-update-a-database | description | dc6c429d7ab536b920ff1e2d2286cc8272c8372a818cc07307a9c53fd44492e1 |
| tools | API-update-a-database | properties | 4ae18f5cbb0402c238429b0a84c46840de281c628a8dbb587811f28cbfe1c321 |
| tools | API-update-a-database | title | 71fa38328b1a805076688217254acab10f33be6346bdb01ca992d3472102ce5d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
