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


# What is mcp-server-webflow?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-webflow/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-webflow/0.6.0?logo=docker&logoColor=fff&label=0.6.0)](https://hub.docker.com/r/acuvity/mcp-server-webflow)
[![PyPI](https://img.shields.io/badge/0.6.0-3775A9?logo=pypi&logoColor=fff&label=webflow-mcp-server)](https://github.com/webflow/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-webflow/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-webflow&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22WEBFLOW_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-webflow%3A0.6.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Enables AI agents to interact with Webflow APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from webflow-mcp-server original [sources](https://github.com/webflow/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-webflow/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/charts/mcp-server-webflow/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure webflow-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/webflow/mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ webflow-mcp-server ](https://github.com/webflow/mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ webflow-mcp-server ](https://github.com/webflow/mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/charts/mcp-server-webflow)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-webflow/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.6.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-webflow:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-webflow:1.0.0-0.6.0`

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
  - `WEBFLOW_TOKEN` secret to be set as secrets.WEBFLOW_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-webflow
```

From there your MCP server mcp-server-webflow will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-webflow` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-webflow
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-webflow` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-webflow oci://docker.io/acuvity/mcp-server-webflow --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (32)
<details>
<summary>ask_webflow_ai</summary>

**Description**:

```
Ask Webflow AI about anything related to Webflow API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | not set | Yes
</details>
<details>
<summary>collections_list</summary>

**Description**:

```
List all CMS collections in a site. Returns collection metadata including IDs, names, and schemas.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>collections_get</summary>

**Description**:

```
Get detailed information about a specific CMS collection including its schema and field definitions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
</details>
<details>
<summary>collections_create</summary>

**Description**:

```
Create a new CMS collection in a site with specified name and schema.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request | object | not set | Yes
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>collection_fields_create_static</summary>

**Description**:

```
Create a new static field in a CMS collection (e.g., text, number, date, etc.).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collection_fields_create_option</summary>

**Description**:

```
Create a new option field in a CMS collection with predefined choices.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collection_fields_create_reference</summary>

**Description**:

```
Create a new reference field in a CMS collection that links to items in another collection.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collection_fields_update</summary>

**Description**:

```
Update properties of an existing field in a CMS collection.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| field_id | string | Unique identifier for the Field. | Yes
| request | object | Request schema to update collection field metadata. | Yes
</details>
<details>
<summary>collections_items_create_item_live</summary>

**Description**:

```
Create and publish new items in a CMS collection directly to the live site.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_update_items_live</summary>

**Description**:

```
Update and publish existing items in a CMS collection directly to the live site.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_list_items</summary>

**Description**:

```
List items in a CMS collection with optional filtering and sorting.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cmsLocaleId | string | Unique identifier for the locale of the CMS Item. | No
| collection_id | string | Unique identifier for the Collection. | Yes
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| name | string | Name of the field. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| slug | string | URL structure of the Item in your site. Note: Updates to an item slug will break all links referencing the old slug. | No
| sortBy | string | Field to sort the items by. Allowed values: lastPublished, name, slug. | No
| sortOrder | string | Order to sort the items by. Allowed values: asc, desc. | No
</details>
<details>
<summary>collections_items_create_item</summary>

**Description**:

```
Create new items in a CMS collection as drafts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | not set | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_update_items</summary>

**Description**:

```
Update existing items in a CMS collection as drafts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| request | object | not set | Yes
</details>
<details>
<summary>collections_items_publish_items</summary>

**Description**:

```
Publish draft items in a CMS collection to make them live.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection_id | string | Unique identifier for the Collection. | Yes
| itemIds | array | Array of item IDs to be published. | Yes
</details>
<details>
<summary>collections_items_delete_item</summary>

**Description**:

```
Delete an item in a CMS collection. Items will only be deleted in the primary locale unless a cmsLocaleId is included in the request. 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cmsLocaleIds | string | Unique identifier for the locale of the CMS Item. | No
| collection_id | string | Unique identifier for the Collection. | Yes
| itemId | string | Item ID to be deleted. | Yes
</details>
<details>
<summary>components_list</summary>

**Description**:

```
List all components in a site. Returns component metadata including IDs, names, and versions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>components_get_content</summary>

**Description**:

```
Get the content structure and data for a specific component including text, images, and nested components.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| component_id | string | Unique identifier for the Component. | Yes
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>components_update_content</summary>

**Description**:

```
Update content on a component in secondary locales by modifying text nodes and property overrides.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| component_id | string | Unique identifier for the Component. | Yes
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | Yes
| nodes | array | not set | Yes
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>components_get_properties</summary>

**Description**:

```
Get component properties including default values and configuration for a specific component.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| component_id | string | Unique identifier for the Component. | Yes
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>components_update_properties</summary>

**Description**:

```
Update component properties for localization to customize behavior in different languages.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| component_id | string | Unique identifier for the Component. | Yes
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | Yes
| properties | array | Array of properties to update for this component. | Yes
| site_id | string | Unique identifier for the Site. | Yes
</details>
<details>
<summary>pages_list</summary>

**Description**:

```
List all pages within a site. Returns page metadata including IDs, titles, and slugs.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| site_id | string | The site’s unique ID, used to list its pages. | Yes
</details>
<details>
<summary>pages_get_metadata</summary>

**Description**:

```
Get metadata for a specific page including SEO settings, Open Graph data, and page status (draft/published).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>pages_update_page_settings</summary>

**Description**:

```
Update page settings including SEO metadata, Open Graph data, slug, and publishing status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | object | not set | Yes
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>pages_get_content</summary>

**Description**:

```
Get the content structure and data for a specific page including all elements and their properties.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of records to be returned (max limit: 100) | No
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | No
| offset | number | Offset used for pagination if the results have more than limit records. | No
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>pages_update_static_content</summary>

**Description**:

```
Update content on a static page in secondary locales by modifying text nodes and property overrides.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| localeId | string | Unique identifier for a specific locale. Applicable when using localization. | Yes
| nodes | array | not set | Yes
| page_id | string | Unique identifier for the page. | Yes
</details>
<details>
<summary>site_registered_scripts_list</summary>

**Description**:

```
List all registered scripts for a site. To apply a script to a site or page, first register it via the Register Script endpoints, then apply it using the relevant Site or Page endpoints.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>site_applied_scripts_list</summary>

**Description**:

```
Get all scripts applied to a site by the App. To apply a script to a site or page, first register it via the Register Script endpoints, then apply it using the relevant Site or Page endpoints.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>add_inline_site_script</summary>

**Description**:

```
Register an inline script for a site. Inline scripts are limited to 2000 characters. 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request | object | Request schema to register an inline script for a site. | Yes
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>delete_all_site_scripts</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | not set | Yes
</details>
<details>
<summary>sites_list</summary>

**Description**:

```
List all sites accessible to the authenticated user. Returns basic site information including site ID, name, and last published date.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>sites_get</summary>

**Description**:

```
Get detailed information about a specific site including its settings, domains, and publishing status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| site_id | string | Unique identifier for the site. | Yes
</details>
<details>
<summary>sites_publish</summary>

**Description**:

```
Publish a site to specified domains. This will make the latest changes live on the specified domains.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customDomains | array | Array of custom domains to publish the site to. | No
| publishToWebflowSubdomain | boolean | Whether to publish to the Webflow subdomain. | No
| site_id | string | Unique identifier for the site. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_inline_site_script | description | da4ad46026aff6c1441513d12afdfd7f0d735ac69b77f117abe1acaea4ac1a95 |
| tools | add_inline_site_script | request | aa102df180b52825def499e4fe43678565faa9b5d49fb7f252c89e645f251e25 |
| tools | add_inline_site_script | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | ask_webflow_ai | description | 85f6b0e69c5883d64bb75e42ac2fe025397ba097e8fe5ab98066c4cf55f60d84 |
| tools | collection_fields_create_option | description | 62a672e665513acde53ce1a510df12fc2e7f7689f9a3bb18fd1bd15f224fe285 |
| tools | collection_fields_create_option | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_create_reference | description | bef40d710120c44326c891a239d241cd71673f253f09f04272f442d865e80957 |
| tools | collection_fields_create_reference | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_create_static | description | ba8c9655fc6d1fcdca20a3ccb99563c489f0926a60791c733e24085e50f8005c |
| tools | collection_fields_create_static | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_update | description | 9b2bd3f2e812c999d93db7c3a6fe04f90a5285e1d74144030b69deaf12270ae9 |
| tools | collection_fields_update | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collection_fields_update | field_id | ae4d9ca9be1202b3aa55e265518c58fe345fbb73d09b64ad2a02f91fd4a47bb4 |
| tools | collection_fields_update | request | 8c2ca159b99a3327d48f1a044b8a51d937b17363e29fddc22112f521bdf43648 |
| tools | collections_create | description | 6f8c2d10f17e8b3bf111d0fa51c9965a11b554b0ca3ced2d5efc39b3e425d1e2 |
| tools | collections_create | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | collections_get | description | 8dc2b780368dc65efbc4a296c22a24e8574001aeb4ae3e24d7eef434ba11a615 |
| tools | collections_get | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_create_item | description | 7e4ba46da466f9cbb3c98b14775d0aaa16bc699072bb5c6e1fe414137689a26c |
| tools | collections_items_create_item_live | description | c34348e4d6324531de00ad31fb0cd8853047260672eaa9af5f19a3c13af7d1af |
| tools | collections_items_create_item_live | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_delete_item | description | 1a0c3cf174193bce310f0aedfa97e5e361a05cd452634df04c590764842d21ba |
| tools | collections_items_delete_item | cmsLocaleIds | 2c80366881f730cbfdd6a5a84e297d080fb9b122f5d862e7d93907291ddf73c3 |
| tools | collections_items_delete_item | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_delete_item | itemId | 93b52bccace2b195765c4741576378311e1a6dc3a7e9d99a54eb3d2f38d4db83 |
| tools | collections_items_list_items | description | 53f750ec5891295e8c14703fde1be5ef65153477a59d56e58d5affbb11cc98b3 |
| tools | collections_items_list_items | cmsLocaleId | 2c80366881f730cbfdd6a5a84e297d080fb9b122f5d862e7d93907291ddf73c3 |
| tools | collections_items_list_items | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_list_items | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | collections_items_list_items | name | 7d2df8838eff32f65b6f7c489a378fa2cd3644d368476d0e47fc16ed5766e92c |
| tools | collections_items_list_items | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | collections_items_list_items | slug | 49d7fede96b1d9e1ba74f82ac8c8ba4042b748b58f164bc5c27108a4a416a1c4 |
| tools | collections_items_list_items | sortBy | 5eaec853a1daebd92184126702156f4a18f7c2c5570b730ce0fef3e9f931ba98 |
| tools | collections_items_list_items | sortOrder | ba6d082117b479734c4dce7f7201f26a31aa5144bd51b840f64b45ade5ff95e9 |
| tools | collections_items_publish_items | description | 770b23bbb398e3161554349f34af62684369a285f1cca171aaa54695a88019fd |
| tools | collections_items_publish_items | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_publish_items | itemIds | 41b108aec95f8e6903de0af0b611968f0b934721ad353e47297cc1d05a027074 |
| tools | collections_items_update_items | description | 0c2b38b1977b3b0b275c9e3e7896c55b7061575e062f74843564711490ea9c62 |
| tools | collections_items_update_items | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_items_update_items_live | description | 00f101eab1a826bbc3c594a42fae7948d4175cbbb8946dae7ea4111d7e439566 |
| tools | collections_items_update_items_live | collection_id | 66d4114e3cddf0a95068c7be63e8966d91e952f972207e7a31beb949190c7a6b |
| tools | collections_list | description | 180e254b26e6204a9c607ca35cd5b77bd5d0f3b2d6421e0cb1308a9628d3e032 |
| tools | collections_list | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | components_get_content | description | 1ef232c201a63dab696a5be177dfe94ebfbc5b452991e49ad7d0f88c127ab118 |
| tools | components_get_content | component_id | 912431579ec24d5b2a47d973b48cd5f674b83aae0ca3bf5aa3fd0bb703813641 |
| tools | components_get_content | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | components_get_content | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | components_get_content | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | components_get_content | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | components_get_properties | description | 1d9010a3cfb9570bf68181fb7f6239a4fe667948f34e1a64421732e04c66ea5b |
| tools | components_get_properties | component_id | 912431579ec24d5b2a47d973b48cd5f674b83aae0ca3bf5aa3fd0bb703813641 |
| tools | components_get_properties | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | components_get_properties | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | components_get_properties | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | components_get_properties | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | components_list | description | f7230c69688c0b8cc65a7d19bd4e1684d6acdf73a467d5ed1de55e5062b80d82 |
| tools | components_list | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | components_list | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | components_list | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | components_update_content | description | b7b3a3fce9aeca852fd04da7cd67648baa646e735abbf48f130a563347d5b189 |
| tools | components_update_content | component_id | 912431579ec24d5b2a47d973b48cd5f674b83aae0ca3bf5aa3fd0bb703813641 |
| tools | components_update_content | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | components_update_content | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | components_update_properties | description | 6ff350bd9e89ade29efcdfa3c8567bf9a66f06dba09f4273ed9e21136856df78 |
| tools | components_update_properties | component_id | 912431579ec24d5b2a47d973b48cd5f674b83aae0ca3bf5aa3fd0bb703813641 |
| tools | components_update_properties | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | components_update_properties | properties | a80075dc14678a794348edfdde3d5f2d7d4ac154d385d30fc8806df501cd30ec |
| tools | components_update_properties | site_id | 093137d76773f00522f69fe5d1d79d3f7189422258e583dd0fb7ddb13528f614 |
| tools | delete_all_site_scripts | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | pages_get_content | description | effc85cda69758932ff15da05b2058f56f8c281d4ec570932e4e18e744ef8a46 |
| tools | pages_get_content | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | pages_get_content | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_get_content | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | pages_get_content | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | pages_get_metadata | description | fe6591dc6226af8c68550b3fa1fc33ca48aefe0a391030ccdfa42fd8e2e826c5 |
| tools | pages_get_metadata | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_get_metadata | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | pages_list | description | acdb1a75cfe59d3c84d2d4fe37a0cf0d16d204b927253fd8a2039a4ec375424c |
| tools | pages_list | limit | 9146b99529c5390536212dc3047f99237c2a9402947460621fca401c975971f0 |
| tools | pages_list | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_list | offset | 013a5e06eec0d5bb7168a7e6e0bdc90458bd75b6b108a41e2e8ac255b60af65d |
| tools | pages_list | site_id | 1add0001e1327e44b502de21faf1f7d001ad50c2d3ac250ed54e83c650f66a27 |
| tools | pages_update_page_settings | description | cb85ebb21f2a2d5d3a0a85614f3095d8a3ea9cf88518004e1cfd4cc913962624 |
| tools | pages_update_page_settings | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_update_page_settings | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | pages_update_static_content | description | b2acdb4ed19d91fb06e288f976ba927547715bdfc6dc30604cdb138f43ce5ee3 |
| tools | pages_update_static_content | localeId | d2d12c4615bc4314a64f68a62885839a4ec8340cede10c10e342f95fedf106f6 |
| tools | pages_update_static_content | page_id | 5b478ff3d1213d27fa9d28ca41910e9c282e9f54d3883d799532a1bf75275158 |
| tools | site_applied_scripts_list | description | 7f84d7cba120774d342ab8f4cba857c2bfe0dd1c6be3ccd367abca9c159e810a |
| tools | site_applied_scripts_list | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | site_registered_scripts_list | description | 7ff87b19559b7c7f4977b7d9b0a368dd23d08f48adacd2b8093672bd4e6acc34 |
| tools | site_registered_scripts_list | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | sites_get | description | 5b82168721ca142a8df5b4bca54e4f6447d518a729e62291e0d8bbd8a13a5cb6 |
| tools | sites_get | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |
| tools | sites_list | description | 35adeea1cc0ffb3caf7a994028ed2cd993f7a465721bd59263558b1475bc113f |
| tools | sites_publish | description | 3d55371074f85622832e649d4e5c38b88ed2643f12ee1172d5116c3960faa4f1 |
| tools | sites_publish | customDomains | 18fbd2084e46f0039226e64c99f75c9250c1f422135d86eb7f67a794d9de7ede |
| tools | sites_publish | publishToWebflowSubdomain | f5362553c613f1672e8cd06f80b846ce5c5c234243670b590fce486cea5d89c4 |
| tools | sites_publish | site_id | c012e27d6f83f7433a656f22db20bee7dd830a37e94f37cc6378935ada9243a3 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
