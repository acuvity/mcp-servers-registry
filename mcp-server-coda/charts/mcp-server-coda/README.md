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


# What is mcp-server-coda?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-coda/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-coda/1.4.1?logo=docker&logoColor=fff&label=1.4.1)](https://hub.docker.com/r/acuvity/mcp-server-coda)
[![PyPI](https://img.shields.io/badge/1.4.1-3775A9?logo=pypi&logoColor=fff&label=coda-mcp)](https://github.com/orellazri/coda-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-coda/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-coda&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_KEY%22%2C%22-e%22%2C%22DOC_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-coda%3A1.4.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for Coda.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from coda-mcp original [sources](https://github.com/orellazri/coda-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-coda/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/charts/mcp-server-coda/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure coda-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/orellazri/coda-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ coda-mcp ](https://github.com/orellazri/coda-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ coda-mcp ](https://github.com/orellazri/coda-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/charts/mcp-server-coda)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-coda/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.4.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-coda:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-coda:1.0.0-1.4.1`

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
  - `API_KEY` secret to be set as secrets.API_KEY either by `.value` or from existing with `.valueFrom`
  - `DOC_ID` secret to be set as secrets.DOC_ID either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-coda
```

From there your MCP server mcp-server-coda will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-coda` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-coda
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-coda` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-coda oci://docker.io/acuvity/mcp-server-coda --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>coda_list_documents</summary>

**Description**:

```
List or search available documents
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The query to search for documents by - optional | No
</details>
<details>
<summary>coda_list_pages</summary>

**Description**:

```
List pages in the current document with pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document to list pages from | Yes
| limit | integer | The number of pages to return - optional, defaults to 25 | No
| nextPageToken | string | The token need to get the next page of results, returned from a previous call to this tool - optional | No
</details>
<details>
<summary>coda_create_page</summary>

**Description**:

```
Create a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content of the page to create - optional | No
| docId | string | The ID of the document to create the page in | Yes
| name | string | The name of the page to create | Yes
| parentPageId | string | The ID of the parent page to create this page under - optional | No
</details>
<details>
<summary>coda_get_page_content</summary>

**Description**:

```
Get the content of a page as markdown
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to get the content of | Yes
| pageIdOrName | string | The ID or name of the page to get the content of | Yes
</details>
<details>
<summary>coda_peek_page</summary>

**Description**:

```
Peek into the beginning of a page and return a limited number of lines
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to peek into | Yes
| numLines | integer | The number of lines to return from the start of the page - usually 30 lines is enough | Yes
| pageIdOrName | string | The ID or name of the page to peek into | Yes
</details>
<details>
<summary>coda_replace_page_content</summary>

**Description**:

```
Replace the content of a page with new markdown content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content to replace the page with | Yes
| docId | string | The ID of the document that contains the page to replace the content of | Yes
| pageIdOrName | string | The ID or name of the page to replace the content of | Yes
</details>
<details>
<summary>coda_append_page_content</summary>

**Description**:

```
Append new markdown content to the end of a page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | The markdown content to append to the page | Yes
| docId | string | The ID of the document that contains the page to append the content to | Yes
| pageIdOrName | string | The ID or name of the page to append the content to | Yes
</details>
<details>
<summary>coda_duplicate_page</summary>

**Description**:

```
Duplicate a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to duplicate | Yes
| newName | string | The name of the new page | Yes
| pageIdOrName | string | The ID or name of the page to duplicate | Yes
</details>
<details>
<summary>coda_rename_page</summary>

**Description**:

```
Rename a page in the current document
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| docId | string | The ID of the document that contains the page to rename | Yes
| newName | string | The new name of the page | Yes
| pageIdOrName | string | The ID or name of the page to rename | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | coda_append_page_content | description | d6eb83d5da34ae32ee47e049bfde75b03ca3a7b48c59a3195bb611f69629728c |
| tools | coda_append_page_content | content | 5a10ac2f054a77da9b7959abb4bacdb04cb96dec1697272b5ac8dcd8fb270172 |
| tools | coda_append_page_content | docId | 1a07d4ed809f2c4aa63a55d5635be7ae2eb8c87f3125e6cbc118ba7029879b44 |
| tools | coda_append_page_content | pageIdOrName | 2953a62ac23fd91570996571f459640e50db43ba7acfb27295ce332f276a9205 |
| tools | coda_create_page | description | cc5fb25691258d75039b01e76e47c55ca99243a51ca0a1ca8316d5f9ecf4642e |
| tools | coda_create_page | content | 22bd8cb205205d5c8826180ff748095de56dad85b69aa7d9f3e425e6d7e8f0f8 |
| tools | coda_create_page | docId | 158955c02c5aa26b184216129353a385eedf2b9368448e0b1284ca8482ca5d6a |
| tools | coda_create_page | name | 9200c858ffe87b34c08415c39d7e1111124dc7fbbe8bf606365936cf08fabdb8 |
| tools | coda_create_page | parentPageId | 23e66e983618974de73266d5421c75eedfbbd1884d0a89592ac5b383e1f03031 |
| tools | coda_duplicate_page | description | 4c2496f1d91db963e00ce499c6a64ce127e3e1789f51b7674d9053fc9f11c627 |
| tools | coda_duplicate_page | docId | f0e631f8b92b861f822ef892433ac345f70335c69c96664ae274235830198794 |
| tools | coda_duplicate_page | newName | 8cc9888bfa04926d724ebdfd4283bf915e056c54d7b9568b8c2c0409b00558d7 |
| tools | coda_duplicate_page | pageIdOrName | 23b139479cb7b4beb87d1d9833534d7c323f2db9feb871a75c81fb3abdb58ff4 |
| tools | coda_get_page_content | description | 6e954360c948036e80de20759d8e143ca665cdc6375a04d22b7fe7e79c411277 |
| tools | coda_get_page_content | docId | 48184f2c0fe56bd400f727989f61e00d5d90719df619680dce19a97250cc6039 |
| tools | coda_get_page_content | pageIdOrName | 2660e996c27d04bf1e63551dcf2f49e3414bb72b0a97bf7fce8220bd324b64bf |
| tools | coda_list_documents | description | 71001f60d122cd04f582806689df55db58e556c49e795cfe2006c2b06436ea07 |
| tools | coda_list_documents | query | 3327b3fff59e43d93c8a98177fb17ef6251f8317ed1678dfa0e4a71a89a0ddd4 |
| tools | coda_list_pages | description | 1a8a31861ee35219e4f5f8c8e509efd7987d5a01634fe30c4e33a8a15e534e5a |
| tools | coda_list_pages | docId | 4b9ffcb8819b499cd57463e3e4924724e339c33e09512dcc9abde242099ae041 |
| tools | coda_list_pages | limit | dae9aac415696897b6bf809a8667827bd19d2f208cbcf2604edbfbd76a008efd |
| tools | coda_list_pages | nextPageToken | 5e0ac137194647315f21041aa4015dcac246f338c92938f77b01f8b6b5a80e6c |
| tools | coda_peek_page | description | 7a20ab6508a28ca5ba7008abf98d712e28169db94ff7316f0c2b4b0920d2d2cc |
| tools | coda_peek_page | docId | 88dfaff1fc79e5925d00d140af6bea4710522da7c4a3552f9cabf6742d540031 |
| tools | coda_peek_page | numLines | 8ea4b7fa145c6b5c9f1fda9a7799f76910e69e71212b3f437176093668262ac7 |
| tools | coda_peek_page | pageIdOrName | 50a796ac4b6752c9ec6570e9ca6062a15ec7428a0af9baa93fa2c6f2deceada0 |
| tools | coda_rename_page | description | 037a2e1ce43e2a3eb82f6b3aa83f5e9dafdce96ffaa5186702482bf458a194b6 |
| tools | coda_rename_page | docId | 15a4d415486234c3dd1fda9950b465d5bc886abb98e870c59ada67d6e3e52d3c |
| tools | coda_rename_page | newName | 47633c3d0d36d0564492d812ff19826f72d7b172b3eacad87b98f8246491662a |
| tools | coda_rename_page | pageIdOrName | ffb5e62092ae083458b493ad20c66b6f1277f4a3bf8d35715baf351163449b8f |
| tools | coda_replace_page_content | description | 159be8ca055b41aafbe9770117c4f1579a454f2baaba9b20f33682d5273bcc5c |
| tools | coda_replace_page_content | content | d18f6633054b57d9534e835c3be08e87ef9588cb7127e43e4f0b51449683b75c |
| tools | coda_replace_page_content | docId | 275717187e2b1e8c33652fd85af2b65b81bf4e22580e0a8b905bede2cff0eca1 |
| tools | coda_replace_page_content | pageIdOrName | 54bbde434915298761a0e41ef26c250776e2129a4dc3e682586ca51f8bbc0c3b |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
