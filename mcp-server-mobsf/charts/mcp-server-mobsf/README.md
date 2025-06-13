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


# What is mcp-server-mobsf?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-mobsf/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-mobsf/1.0.0?logo=docker&logoColor=fff&label=1.0.0)](https://hub.docker.com/r/acuvity/mcp-server-mobsf)
[![PyPI](https://img.shields.io/badge/1.0.0-3775A9?logo=pypi&logoColor=fff&label=mobsf-mcp)](https://github.com/cyproxio/mcp-for-security/tree/HEAD/mobsf-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-mobsf/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-mobsf&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22MOBSF_URL%22%2C%22-e%22%2C%22MOBSF_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-mobsf%3A1.0.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Mobile application security testing framework for Android, iOS, and Windows applications

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mobsf-mcp original [sources](https://github.com/cyproxio/mcp-for-security/tree/HEAD/mobsf-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-mobsf/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mobsf/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mobsf/charts/mcp-server-mobsf/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mobsf-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mobsf/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ nkcc-apk ](https://github.com/cyproxio/mcp-for-security/tree/HEAD/mobsf-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mobsf-mcp ](https://github.com/cyproxio/mcp-for-security/tree/HEAD/mobsf-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mobsf-mcp ](https://github.com/cyproxio/mcp-for-security/tree/HEAD/mobsf-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mobsf/charts/mcp-server-mobsf)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-mobsf/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-mobsf:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-mobsf:1.0.0-1.0.0`

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
  - `MOBSF_API_KEY` secret to be set as secrets.MOBSF_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `MOBSF_URL` environment variable to be set by env.MOBSF_URL

# How to install


Install will helm

```console
helm install mcp-server-mobsf oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-mobsf oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-mobsf
```

From there your MCP server mcp-server-mobsf will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-mobsf` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-mobsf
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-mobsf` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-mobsf oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-mobsf oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-mobsf oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-mobsf oci://docker.io/acuvity/mcp-server-mobsf --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (71)
<details>
<summary>uploadFile</summary>

**Description**:

```
Upload a mobile application file (APK, IPA, or APPX) to MobSF for security analysis. This is the first step before scanning and must be done prior to using other analysis functions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file | string | Upload file path | Yes
</details>
<details>
<summary>getScanLogs</summary>

**Description**:

```
Retrieve detailed scan logs for a previously analyzed mobile application using its hash value. These logs contain information about the scanning process and any issues encountered.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash file to getting scan logs | Yes
</details>
<details>
<summary>getJsonReport</summary>

**Description**:

```
Generate and retrieve a comprehensive security analysis report in JSON format for a scanned mobile application. This report includes detailed findings about security vulnerabilities, permissions, API calls, and other security-relevant information.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash file to getting scan logs | Yes
</details>
<details>
<summary>getJsonReportSection</summary>

**Description**:

```
Get a specific section of the MobSF JSON report by hash and section name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
| section | string | Section name, e.g. permissions, android_api, security_analysis, etc. | Yes
</details>
<details>
<summary>getJsonReportSections</summary>

**Description**:

```
Get all top-level section names of the MobSF JSON report.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getRecentScans</summary>

**Description**:

```
Retrieve a list of recently performed security scans on the MobSF server, showing mobile applications that have been analyzed, their statuses, and basic scan information.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for result | Yes
| pageSize | number | Page size for result | Yes
</details>
<details>
<summary>searchScanResult</summary>

**Description**:

```
Search scan results by hash, app name, package name, or file name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Hash, app name, package name, or file name to search | Yes
</details>
<details>
<summary>deleteScan</summary>

**Description**:

```
Delete scan results by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan to delete | Yes
</details>
<details>
<summary>getScorecard</summary>

**Description**:

```
Get MobSF Application Security Scorecard by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan to get scorecard | Yes
</details>
<details>
<summary>generatePdfReport</summary>

**Description**:

```
Generate PDF security report by hash. Returns PDF as base64 string.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan to generate PDF report | Yes
</details>
<details>
<summary>viewSource</summary>

**Description**:

```
View source files by hash, file path, and type.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file | string | Relative file path | Yes
| hash | string | Hash of the scan | Yes
| type | string | File type (apk/ipa/studio/eclipse/ios) | Yes
</details>
<details>
<summary>getScanTasks</summary>

**Description**:

```
Get scan tasks queue (async scan queue must be enabled).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>compareApps</summary>

**Description**:

```
Compare scan results by two hashes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash1 | string | First scan hash | Yes
| hash2 | string | Second scan hash to compare with | Yes
</details>
<details>
<summary>suppressByRule</summary>

**Description**:

```
Suppress findings by rule id.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
| rule | string | Rule id | Yes
| type | string | code or manifest | Yes
</details>
<details>
<summary>suppressByFiles</summary>

**Description**:

```
Suppress findings by files.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
| rule | string | Rule id | Yes
| type | string | code | Yes
</details>
<details>
<summary>listSuppressions</summary>

**Description**:

```
View suppressions associated with a scan.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>deleteSuppression</summary>

**Description**:

```
Delete suppressions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
| kind | string | rule or file | Yes
| rule | string | Rule id | Yes
| type | string | code or manifest | Yes
</details>
<details>
<summary>listAllHashes</summary>

**Description**:

```
Get all report MD5 hash values.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for result | Yes
| pageSize | number | Page size for result | Yes
</details>
<details>
<summary>getJsonSection_version</summary>

**Description**:

```
Get the 'version' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_title</summary>

**Description**:

```
Get the 'title' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_file_name</summary>

**Description**:

```
Get the 'file_name' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_app_name</summary>

**Description**:

```
Get the 'app_name' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_app_type</summary>

**Description**:

```
Get the 'app_type' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_size</summary>

**Description**:

```
Get the 'size' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_md5</summary>

**Description**:

```
Get the 'md5' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_sha1</summary>

**Description**:

```
Get the 'sha1' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_sha256</summary>

**Description**:

```
Get the 'sha256' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_package_name</summary>

**Description**:

```
Get the 'package_name' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_main_activity</summary>

**Description**:

```
Get the 'main_activity' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_exported_activities</summary>

**Description**:

```
Get the 'exported_activities' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_browsable_activities</summary>

**Description**:

```
Get the 'browsable_activities' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_activities</summary>

**Description**:

```
Get the 'activities' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_receivers</summary>

**Description**:

```
Get the 'receivers' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_providers</summary>

**Description**:

```
Get the 'providers' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_services</summary>

**Description**:

```
Get the 'services' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_libraries</summary>

**Description**:

```
Get the 'libraries' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_target_sdk</summary>

**Description**:

```
Get the 'target_sdk' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_max_sdk</summary>

**Description**:

```
Get the 'max_sdk' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_min_sdk</summary>

**Description**:

```
Get the 'min_sdk' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_version_name</summary>

**Description**:

```
Get the 'version_name' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_version_code</summary>

**Description**:

```
Get the 'version_code' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_permissions</summary>

**Description**:

```
Get the 'permissions' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_malware_permissions</summary>

**Description**:

```
Get the 'malware_permissions' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_certificate_analysis</summary>

**Description**:

```
Get the 'certificate_analysis' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_manifest_analysis</summary>

**Description**:

```
Get the 'manifest_analysis' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_network_security</summary>

**Description**:

```
Get the 'network_security' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_binary_analysis</summary>

**Description**:

```
Get the 'binary_analysis' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_file_analysis</summary>

**Description**:

```
Get the 'file_analysis' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_android_api</summary>

**Description**:

```
Get the 'android_api' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_code_analysis</summary>

**Description**:

```
Get the 'code_analysis' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_niap_analysis</summary>

**Description**:

```
Get the 'niap_analysis' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_permission_mapping</summary>

**Description**:

```
Get the 'permission_mapping' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_urls</summary>

**Description**:

```
Get the 'urls' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_domains</summary>

**Description**:

```
Get the 'domains' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_emails</summary>

**Description**:

```
Get the 'emails' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_strings</summary>

**Description**:

```
Get the 'strings' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_firebase_urls</summary>

**Description**:

```
Get the 'firebase_urls' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_exported_count</summary>

**Description**:

```
Get the 'exported_count' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_apkid</summary>

**Description**:

```
Get the 'apkid' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_behaviour</summary>

**Description**:

```
Get the 'behaviour' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_trackers</summary>

**Description**:

```
Get the 'trackers' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_playstore_details</summary>

**Description**:

```
Get the 'playstore_details' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_secrets</summary>

**Description**:

```
Get the 'secrets' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_logs</summary>

**Description**:

```
Get the 'logs' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_sbom</summary>

**Description**:

```
Get the 'sbom' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_average_cvss</summary>

**Description**:

```
Get the 'average_cvss' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_appsec</summary>

**Description**:

```
Get the 'appsec' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_virus_total</summary>

**Description**:

```
Get the 'virus_total' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_base_url</summary>

**Description**:

```
Get the 'base_url' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_dwd_dir</summary>

**Description**:

```
Get the 'dwd_dir' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>
<details>
<summary>getJsonSection_host_os</summary>

**Description**:

```
Get the 'host_os' section of the MobSF JSON report by hash.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hash | string | Hash of the scan | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | compareApps | description | 1881000ad1e0959631b483811b8b07e98e2b89f37ed517fc50c4c1a42409413f |
| tools | compareApps | hash1 | 982ee25bd0c3debe635e6332950d3cfc1d90f6bf37fdbe54238060df20c68594 |
| tools | compareApps | hash2 | e40c193fe8256bbf3e2c03d495efaba912a3e0ed863447eb2eff108cef1a4fa4 |
| tools | deleteScan | description | 70debd6cb8fff3159bc587868e4e14231324e34393ec26d030898bff0e1406f1 |
| tools | deleteScan | hash | 2157e189f33b789ae7c02387f294919c25f3a8c7064865e57e1b4c6f27eea913 |
| tools | deleteSuppression | description | 04f3661dff1ed5383aaeee96e78657617987d2592b3fb0f12b7f7830c71ecf1a |
| tools | deleteSuppression | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | deleteSuppression | kind | ee3bf862063eedf10b743ef5f1686b5b4067b36507c27e7bb6f0ee4e9e1019fe |
| tools | deleteSuppression | rule | 579427be0c7c82df83e316ea70819adec8380edd13cdeec057c1de5291edf621 |
| tools | deleteSuppression | type | b19b8ceb18354df775bb6180e81afaee7339e15c26c80b1f98c0bf192b3b6b96 |
| tools | generatePdfReport | description | b5367a526b066d60d423ecb9311038cf9a3b779949b2e3f113dfb6bbf3525c95 |
| tools | generatePdfReport | hash | bf5cdad0a7d0b7749451a6bbdd422c1a0ac27f086c3577633e6f850d5817b9bc |
| tools | getJsonReport | description | d6894375b60e2ff9ea93d97d6cfec9781dc2c7eb652f8943e127f7124ae4551a |
| tools | getJsonReport | hash | 35034ab692aef253d19c321ec8542b3c5e1f2a9ec0a6610dddf6909bd9c5c024 |
| tools | getJsonReportSection | description | cb249f3f4fa676b6ef765c43388c91f2bd1ee77b126b923b8ea4e531bd556a9f |
| tools | getJsonReportSection | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonReportSection | section | 070700b3968cbc0387ea45337636664d5f822e2fa363c6d271c62dcda6c5a184 |
| tools | getJsonReportSections | description | d7b01213798d15df0cc7e541f9c1b4ebd2b3bf677f52db37567a1006f9062fc1 |
| tools | getJsonReportSections | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_activities | description | 7a86474527246a2eb2010cdcd75f1792b6f04f5ad0635a2bef138549c200cc03 |
| tools | getJsonSection_activities | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_android_api | description | 0c3ee7a2b36b6d52baa57050186681f512df9f76acb86db56ab7749fa7828340 |
| tools | getJsonSection_android_api | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_apkid | description | 049c3f76fc3debe0cc5e32977e51c1ff129a30b0101a74c7f2f405235f76f206 |
| tools | getJsonSection_apkid | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_app_name | description | 5bc286d687f1f72e7d4e4118a5a5436a1bc2e836ee1d2f731fc5628684955dc4 |
| tools | getJsonSection_app_name | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_app_type | description | 650d09492c37144e8cccb29e7e0599ad1b8ed6d81e874510a8f92dafd335eaed |
| tools | getJsonSection_app_type | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_appsec | description | 3e2921eb450a6b7ffb1b7364387df28de748e340a6a9c7c0d7f7159280effa9b |
| tools | getJsonSection_appsec | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_average_cvss | description | 75b26e2b4d40d2e5c515d074c53cc4b0bf993e3e6f2dd460212471a52506d5f2 |
| tools | getJsonSection_average_cvss | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_base_url | description | 8c2a1fcc24de8c39aa1ae9bfe5d51b6ea1913da61baf7cdfadd32af49aa7dc0a |
| tools | getJsonSection_base_url | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_behaviour | description | 5f450421468480a8ab84707e5945d5b1744c2e4f37c08fa250c77cebb7f1b215 |
| tools | getJsonSection_behaviour | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_binary_analysis | description | 424dc04eea086e2922a0fc8a73ce817be4bcad0fa1cc574a509aa62063bb5baf |
| tools | getJsonSection_binary_analysis | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_browsable_activities | description | cbced8f3f582c1d168a78f367df6a5b342d906d9abcaf89a48d2c37b86111beb |
| tools | getJsonSection_browsable_activities | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_certificate_analysis | description | a089543b6bc88058d767a1e9eff2ac1a354f72751335c706e4b1e6ebd2f252e9 |
| tools | getJsonSection_certificate_analysis | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_code_analysis | description | caea20ab5a2bab01ea6b6b0e4ccb525b1ab025187708cc80409c435d7e7251b5 |
| tools | getJsonSection_code_analysis | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_domains | description | 13bb5ffb87fed0cded4bfe1f0d9d60452f73551f061fd99dea2e277a9e6a7e67 |
| tools | getJsonSection_domains | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_dwd_dir | description | c6700b4da4449f58cbf428595f219516a2c697bc0e99518ef81586f77b91dff8 |
| tools | getJsonSection_dwd_dir | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_emails | description | c398d8c0fad284c514340bce288c43abd49dfed2b0d7bde0ec90befa276a7114 |
| tools | getJsonSection_emails | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_exported_activities | description | 95a1a1f68a75acd2353a4467bba415074a780fdbed5813b3627be99d84005944 |
| tools | getJsonSection_exported_activities | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_exported_count | description | 233c664dc54a8e8652be34b3643d127cfb4924bb3df7c24fbe695578a4457f17 |
| tools | getJsonSection_exported_count | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_file_analysis | description | 3c6221a3bf3ae1f7f8901e359e45067fbfbf22d1671080767b22a2c418d411c9 |
| tools | getJsonSection_file_analysis | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_file_name | description | f54a1eebffe971348693e87d7c8028ae682fb870302164b8effb73f99a3d282b |
| tools | getJsonSection_file_name | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_firebase_urls | description | 72bdf580d5a42a9b2ca9ccc11062e9f107b0e3180289b78ca6881745d85594d9 |
| tools | getJsonSection_firebase_urls | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_host_os | description | db69ab4903dc4920d253b633e272bfaedeb481352330e793c09ea78482e54eae |
| tools | getJsonSection_host_os | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_libraries | description | 16eff0a474011fc8bb37cbf9ad038499f52e5904d2c9c5533205334f3697cb88 |
| tools | getJsonSection_libraries | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_logs | description | f999a3d635533d91fd44da34eceb1e09a2bfe85b17832523d35d6e95056bc196 |
| tools | getJsonSection_logs | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_main_activity | description | 176bbacda2aeb52cdbcb40a03b46f2850eacf79bb540e9b474cb643145d19dde |
| tools | getJsonSection_main_activity | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_malware_permissions | description | 029e010742b6d24cada728447abedff27c908c2339b54a43257fbd121abdf4af |
| tools | getJsonSection_malware_permissions | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_manifest_analysis | description | 21d5276af6984920bfef118f0d4fe25b812244744443c15f330a1e7d0a02740d |
| tools | getJsonSection_manifest_analysis | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_max_sdk | description | 60c4d56b900128e626cef777095122b63bcf8276d065d463ec429e23745240c4 |
| tools | getJsonSection_max_sdk | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_md5 | description | 33261ece7fe98406364e843a50c559a747fb3f6e0845f445fa2582e301c3191f |
| tools | getJsonSection_md5 | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_min_sdk | description | 066be3ed9b63d6a2ff19c521a63a8531d94228c3e7d90b315bcaa06590212b11 |
| tools | getJsonSection_min_sdk | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_network_security | description | 05a25a24a527b9d62c3218a3f8085d4e6bdb5a0d62e56819bae7af1ba9b09d26 |
| tools | getJsonSection_network_security | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_niap_analysis | description | fc6c33fef7a6555e9a96ec8d985d86e8b79fd044734fbbdc22ef1d51c74695cf |
| tools | getJsonSection_niap_analysis | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_package_name | description | c9450c1dc05a003e8c70e02d2ebc014ad3e231491ffc2a1b76f869f67c38330c |
| tools | getJsonSection_package_name | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_permission_mapping | description | 50eef434ae221361ac00d4f01f299ff1052268457398f484e4b54198a85cbb0a |
| tools | getJsonSection_permission_mapping | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_permissions | description | 4612e174653f4f766a94c19b1fdb722b8f8dbd8f8ddc2ca44e9ddb341ac3c41f |
| tools | getJsonSection_permissions | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_playstore_details | description | 223a06795395d320d52def589a69838998b2decaae54b0de0179cf3a4700ddbf |
| tools | getJsonSection_playstore_details | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_providers | description | 3059b3a82b1d6f127a45c55286a2ee930769a9de226cf88b1e1ae0906dab3a18 |
| tools | getJsonSection_providers | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_receivers | description | d1a48c1e41495253e6add670683011aa9467a61e8249d8c3cc2e40dbb8d72372 |
| tools | getJsonSection_receivers | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_sbom | description | 79f076e13eb8c7ffde24881c8e29256321818fb072dbd81306c88bc7bf90deb3 |
| tools | getJsonSection_sbom | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_secrets | description | f7fff2340b56fcdd0f978b7facfc0d9af6022214eab100005907e384aa0fe55c |
| tools | getJsonSection_secrets | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_services | description | bfdaf659be74188711ce201fe7af0ba1dbbef71d85c127aeda0a1d5081185a9f |
| tools | getJsonSection_services | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_sha1 | description | 417baa7f58bb6a91015f1682a38bddba45d818133ffc2fe75dc5bc4cfb85c302 |
| tools | getJsonSection_sha1 | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_sha256 | description | 2a11343447933daceb28d5ac13111d1681baf4952d24482b4070f2c679db3007 |
| tools | getJsonSection_sha256 | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_size | description | e7c12cc711b2b186d69d415a6418daf65c7b9444718665a01dec84093e25a855 |
| tools | getJsonSection_size | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_strings | description | d9d5cd480531ab3407699e49f9836cb8c33e6897278359693be0ec174dac3894 |
| tools | getJsonSection_strings | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_target_sdk | description | a8dc898117e952eee74ff4db5639b88dc7303e1a61caec22b18941c4770da322 |
| tools | getJsonSection_target_sdk | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_title | description | 97d208b7306deb8f643e21255ed2e5506362e2c5da7dc20d6f9412591d4945d0 |
| tools | getJsonSection_title | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_trackers | description | 6d592bb36b1759d84ba99d059a7f67fd70411b9ed50c75a3686054156e814691 |
| tools | getJsonSection_trackers | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_urls | description | d62b37c55df2530017841329fd1977dc763c00a346ac564bfd7101d518fc9a28 |
| tools | getJsonSection_urls | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_version | description | 48601fcd0469bf6c79dca8a067471058ae1bc1dbd24eb2f959b455258baf590d |
| tools | getJsonSection_version | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_version_code | description | 32de2642d7cbdc11a427fdbaa1f0227f8ccd856d85b596cd7477a2cdd84d167a |
| tools | getJsonSection_version_code | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_version_name | description | 37c8894c42b93b0eb1dfa09b42c2575eb2078efcfb755ced233fe0fed9e31370 |
| tools | getJsonSection_version_name | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getJsonSection_virus_total | description | 1d7cdf6bb4c1cedc6a572ceea5adbf1f8a0d342e453a553f93fa8a6cb7d3b073 |
| tools | getJsonSection_virus_total | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | getRecentScans | description | 95a72752c27850e168b4ceca0a4365de7b9e9fd9515e6309a20898bd32519351 |
| tools | getRecentScans | page | dae274736d7cb4800c5b61f0eda4e950367d2b0ac45164cffe3b393dc8306a97 |
| tools | getRecentScans | pageSize | 1b7ed5a105ddb0f72ecd4baf4d7723302d3eac584e1b4ac970894471e9d3fa60 |
| tools | getScanLogs | description | 55a7eff11f81061c353ff6a7e0618bd2a144eebe81da8fff989e6322f921e298 |
| tools | getScanLogs | hash | 35034ab692aef253d19c321ec8542b3c5e1f2a9ec0a6610dddf6909bd9c5c024 |
| tools | getScanTasks | description | f9fde44d1a0810b3b096b57263ab43e6b2f7984c9c3451ae115b9e684e72ff6a |
| tools | getScorecard | description | 135e0778dd05e7df3cee6102a7884aafb1601b51b3719ab9a5b8d02d0beb9a79 |
| tools | getScorecard | hash | 400076ec61d8dabfb9b5eaae19401b10d2a2c6d5bca4284d63080732c4b10a57 |
| tools | listAllHashes | description | ea97a8d6ae79a2d56f777e92369144845a66e5989685b807d188e91308acc735 |
| tools | listAllHashes | page | dae274736d7cb4800c5b61f0eda4e950367d2b0ac45164cffe3b393dc8306a97 |
| tools | listAllHashes | pageSize | 1b7ed5a105ddb0f72ecd4baf4d7723302d3eac584e1b4ac970894471e9d3fa60 |
| tools | listSuppressions | description | 0b2b7eca29fb241e26699874965a6c8fcdd0b7b42146acc4ece2a66d45b444a1 |
| tools | listSuppressions | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | searchScanResult | description | ec7cadcc140c5be45297b3e70f584a1537f89ad0d091717b898ba2f21efd3b07 |
| tools | searchScanResult | query | d9aa3cd54756924f8f140c71544d3483c20e4389a2121501e646fef7790f8dc4 |
| tools | suppressByFiles | description | 7e6abda267b2f4200e6d715f22f716883565cb2087b7a10438d0eb7501946207 |
| tools | suppressByFiles | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | suppressByFiles | rule | 579427be0c7c82df83e316ea70819adec8380edd13cdeec057c1de5291edf621 |
| tools | suppressByFiles | type | 5694d08a2e53ffcae0c3103e5ad6f6076abd960eb1f8a56577040bc1028f702b |
| tools | suppressByRule | description | 5b1a14242f5af30f828634cca3fc9251ffbda7b880ecf708a46fddc1d23e3e94 |
| tools | suppressByRule | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | suppressByRule | rule | 579427be0c7c82df83e316ea70819adec8380edd13cdeec057c1de5291edf621 |
| tools | suppressByRule | type | b19b8ceb18354df775bb6180e81afaee7339e15c26c80b1f98c0bf192b3b6b96 |
| tools | uploadFile | description | 6dbb1e547d9639fbac2f49305cd83a1f5e1c73c5662a45e55fdb7777c3debd4a |
| tools | uploadFile | file | 0b27ab5da5c155bb3098e1657b0f1038c33a695ca347baeb8f6b2b8ba7e30d41 |
| tools | viewSource | description | f60268e4dcf1bef5100761e4285c69addb53f5fce5d01e0670251de1d97a18fe |
| tools | viewSource | file | fe3af7d48c219c5cbb977b178e21b27d7da1dda09a5b74e1e3e001198c820aeb |
| tools | viewSource | hash | daa51bf873c05fda27e61a3e6da55d4fb86b21b9b53053f24c30b290f06c85e8 |
| tools | viewSource | type | 7e78dc2f41d4f83a369b64c10b602f75b76649aec106f20184d450212346599d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
