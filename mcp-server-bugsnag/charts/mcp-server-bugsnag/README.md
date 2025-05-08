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


# What is mcp-server-bugsnag?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-bugsnag/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-bugsnag/1.1.0?logo=docker&logoColor=fff&label=1.1.0)](https://hub.docker.com/r/acuvity/mcp-server-bugsnag)
[![PyPI](https://img.shields.io/badge/1.1.0-3775A9?logo=pypi&logoColor=fff&label=bugsnag-mcp-server)](https://github.com/tgeselle/bugsnag-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bugsnag&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BUGSNAG_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-bugsnag%3A1.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** An MCP server for interacting with Bugsnag.

> [!NOTE]
> `mcp-server-bugsnag` has been packaged by Acuvity from bugsnag-mcp-server original [sources](https://github.com/tgeselle/bugsnag-mcp).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure bugsnag-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a built-in Rego policy that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Gardrails

### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

## Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

</details>

> [!NOTE]
> All guardrails start disabled. You can switch each one on or off individually, so you only activate the protections your environment requires.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Author ](https://github.com/tgeselle/bugsnag-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ bugsnag-mcp-server ](https://github.com/tgeselle/bugsnag-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ bugsnag-mcp-server ](https://github.com/tgeselle/bugsnag-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bugsnag/charts/mcp-server-bugsnag)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bugsnag/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.1.0`

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
  - `BUGSNAG_API_KEY` secret to be set as secrets.BUGSNAG_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-bugsnag
```

From there your MCP server mcp-server-bugsnag will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-bugsnag` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-bugsnag
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-bugsnag` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-bugsnag oci://docker.io/acuvity/mcp-server-bugsnag --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>list_organizations</summary>

**Description**:

```
List available Bugsnag organizations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_projects</summary>

**Description**:

```
List projects in an organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organization_id | string | Bugsnag organization ID | Yes
</details>
<details>
<summary>list_errors</summary>

**Description**:

```
List errors in a project with filtering options
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of errors to return | No
| project_id | string | Bugsnag project ID | Yes
| sort | string | Sort order for errors | No
| status | string | Filter by error status | No
</details>
<details>
<summary>view_error</summary>

**Description**:

```
Get detailed information about a specific error
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| error_id | string | Bugsnag error ID | Yes
</details>
<details>
<summary>list_error_events</summary>

**Description**:

```
List events (occurrences) for a specific error
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| error_id | string | Bugsnag error ID | Yes
| limit | number | Maximum number of events to return | No
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>view_latest_event</summary>

**Description**:

```
View the latest event for an error
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| error_id | string | Bugsnag error ID | Yes
</details>
<details>
<summary>view_event</summary>

**Description**:

```
View detailed information about a specific event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>view_stacktrace</summary>

**Description**:

```
Extract and format stacktrace information from an event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| include_code | boolean | Include source code context if available | No
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>view_exception_chain</summary>

**Description**:

```
View the full chain of exceptions for an event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| project_id | string | Bugsnag project ID | Yes
</details>
<details>
<summary>search_issues</summary>

**Description**:

```
Search for issues using various criteria
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_version | string | Filter by app version | No
| error_class | string | Filter by error class | No
| project_id | string | Bugsnag project ID | Yes
| query | string | Search query | No
</details>
<details>
<summary>view_tabs</summary>

**Description**:

```
View all event data tabs including app, device, user, request, breadcrumbs, metadata, and stacktrace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_id | string | Bugsnag event ID | Yes
| include_code | boolean | Include source code context in stacktrace if available | No
| project_id | string | Bugsnag project ID | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | list_error_events | description | 95ac8451451be25e3b7e27dac898fa642c66b1700c5cdf484468c9ddbb973ee6 |
| tools | list_error_events | error_id | 9f4225714bc44a8c55c2813c4140538451ad9f31ef7be2671a52519ba55b05bb |
| tools | list_error_events | limit | 638a93c649b59360158a5be8a53da904c181d6c7911ba09da7b827febdc1c939 |
| tools | list_error_events | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | list_errors | description | 343fde21d5ef61a6def43d08570a90cc3e320223c0702c7ace02ec6f68c6848c |
| tools | list_errors | limit | c6a4ce4be531e8abe4e8cf45c39169cafbf40248b465ca2a8f5b76d1d31592b3 |
| tools | list_errors | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | list_errors | sort | b26b0f86e0464ed8865f56f254fea435956e331f85685cb7c7ab5a7f4f35906f |
| tools | list_errors | status | bdb568d58ab98a5c2fd8342c9b0f4f14b673ffabdd64033485a42a46e2acefaa |
| tools | list_organizations | description | 8afc1eab04f56a9b4fdf6305f377aa96240e555e8e3916b5b8695b373ea713b1 |
| tools | list_projects | description | a25a925729c7debbd803810b21c2559d9ae36906eb9000e8f65d48f625ccfca2 |
| tools | list_projects | organization_id | 8f90850f7f18622ceb36614e8c069c8dd8353d2d1d5cba2a7faa2be3fc6534f2 |
| tools | search_issues | description | d6bcfe5083b67eb6fa9ed186eaffc68c733cd532fe7d062e852d4df759e565b6 |
| tools | search_issues | app_version | fc9f6edcf3a7752f37fb69ee272f675c87e5f10fe7d02bd10b548ffd383b5985 |
| tools | search_issues | error_class | 34f1e02240bd200e89ad6994eb8d45d58f7226eb43b99030c159ca938aee3f9a |
| tools | search_issues | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | search_issues | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | view_error | description | dbe777675200bd5b7f376ca368e5e6a81a5fdce885d7f9b24cbc26c2f1bf87db |
| tools | view_error | error_id | 9f4225714bc44a8c55c2813c4140538451ad9f31ef7be2671a52519ba55b05bb |
| tools | view_event | description | 9eafe212e950a93be6089d71b93bad82cd952c3a63659002bede4f533a4ac51d |
| tools | view_event | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_event | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | view_exception_chain | description | 5f53457b2818ea05716ee8d3bf8064834fa19c8834d03e0e4cfdede2dedd3b9f |
| tools | view_exception_chain | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_exception_chain | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | view_latest_event | description | 1a2b42bbe55740f8c673eb2ce2040f3879974eb35b9049362d8c37cc05a04c2f |
| tools | view_latest_event | error_id | 9f4225714bc44a8c55c2813c4140538451ad9f31ef7be2671a52519ba55b05bb |
| tools | view_stacktrace | description | 34478499b6a4bd894d494bb0169d647958ea4d7e8d001fcad3f9a0c9e462fadc |
| tools | view_stacktrace | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_stacktrace | include_code | eb3d98dc6c160ca4d6f25a2ca54a91832bf9cebfedb9520ff0fb3a0e7302e308 |
| tools | view_stacktrace | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |
| tools | view_tabs | description | f7b2ea218184ab7be36e4c5064e4778fbfafd3f3e54b50ee5110ddf66e6547b9 |
| tools | view_tabs | event_id | aceb675ffe3fd6e9b5e401f5ffab6d3bc764f755c62e6f0c0497c85caef4d98c |
| tools | view_tabs | include_code | 09329bf315973856f11d898f676bd20fb93bc07e9e120232af626f0bfb41fabd |
| tools | view_tabs | project_id | 1d6aef646d3e586b39cef35615f094d8b6afced62f9037125c7d77245b5bc9bb |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
