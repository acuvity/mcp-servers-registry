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


# What is mcp-server-browser-kit?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browser-kit/5.0.1?logo=docker&logoColor=fff&label=5.0.1)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit)
[![PyPI](https://img.shields.io/badge/5.0.1-3775A9?logo=pypi&logoColor=fff&label=@mcp-browser-kit/server)](https://github.com/ndthanhdev/mcp-browser-kit)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browser-kit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-browser-kit%3A5.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** An MCP Server for interacting with manifest v2 compatible browsers.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @mcp-browser-kit/server original [sources](https://github.com/ndthanhdev/mcp-browser-kit).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-browser-kit/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/charts/mcp-server-browser-kit/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @mcp-browser-kit/server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/ndthanhdev/mcp-browser-kit) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @mcp-browser-kit/server ](https://github.com/ndthanhdev/mcp-browser-kit)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @mcp-browser-kit/server ](https://github.com/ndthanhdev/mcp-browser-kit)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/charts/mcp-server-browser-kit)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-5.0.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-browser-kit:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-browser-kit:1.0.0-5.0.1`

---

# Table of Contents
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

# How to install


Install will helm

```console
helm install mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-browser-kit
```

From there your MCP server mcp-server-browser-kit will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-browser-kit` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-browser-kit
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
  mcp-server-scope: native
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-browser-kit` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-browser-kit oci://docker.io/acuvity/mcp-server-browser-kit --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>getBasicBrowserContext</summary>

**Description**:

```
🌐 GET BROWSER CONTEXT - CRITICAL FIRST STEP BEFORE USING ANY OTHER TOOLS!
* This tool MUST be called first to initialize browser automation and get essential data.
* Returns data structure with:
  - tabs: Array of browser tabs with properties like id, url, title, and active status
  - manifestVersion: Version of extension manifest format supported by the browser
* Each tab includes a unique tabId required for all other tool operations
* The active tab (marked with 'active: true') is typically your target for automation
* The manifestVersion determines which browser features and extension capabilities are available
* Different browsers support different manifest versions, affecting available tools and API access
* Standard workflow:
  1) getBasicBrowserContext → get browser state and tabId
  2) Analyze page content based on your goal and manifest version:
     - If interaction is required (clicking, filling forms, etc.):
       · For Manifest Version 2: Use captureActiveTab for visual context or getReadableElements for element identification
       · For other Manifest Versions: Use only getReadableElements for element identification
     - If no interaction is required (just reading page content):
       · Use getInnerText to extract all visible text from the page
  3) Interact using click/fill/enter tools with the obtained tabId
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>captureActiveTab</summary>

**Description**:

```

📷 Captures a screenshot of the active browser tab
* Use this tool after calling getBasicBrowserContext to obtain visual context of the current page
* The screenshot helps you see what the browser is displaying to the user
* No parameters are needed as it automatically captures the active tab
* Returns an image with width, height, and data in base64 format
* Workflow: 1) getBasicBrowserContext → 2) captureActiveTab → 3) interact with elements
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>getInnerText</summary>

**Description**:

```
📝 Extracts all text content from the current web page
* Retrieves all visible text from the active tab
* Requires the tabId obtained from getBasicBrowserContext
* Use this to analyze the page content without visual elements
* Returns a string containing all the text on the page
* Useful for getting a quick overview of page content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID to extract text from | Yes
</details>
<details>
<summary>getReadableElements</summary>

**Description**:

```
🔍 Lists all interactive elements on the page with their text
* Returns a list of elements with their index, HTML tag, and text content
* Requires the tabId obtained from getBasicBrowserContext
* Each element is returned as [index, tag, text]
* Use the index to interact with elements through click or fill operations
* Helps you identify which elements can be interacted with by their text
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID to extract elements from | Yes
</details>
<details>
<summary>clickOnViewableElement</summary>

**Description**:

```
👆 Clicks on an element at specific X,Y coordinates
* Use this to click on elements by their position on the screen
* Requires tabId from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureActiveTab screenshot dimensions
* Useful when you know the visual position of an element
* Parameters: tabId, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID of the active tab | Yes
| x | number | X coordinate (pixels) of the element to click | Yes
| y | number | Y coordinate (pixels) of the element to click | Yes
</details>
<details>
<summary>fillTextToViewableElement</summary>

**Description**:

```
⌨️ Types text into an input field at specific X,Y coordinates
* Use this to enter text into form fields by their position
* Requires tabId from getBasicBrowserContext, x,y coordinates, and the text to enter
* Coordinates are based on the captureActiveTab screenshot dimensions
* First clicks at the specified position, then types the provided text
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnViewableElement with that button
* If no submit button is visible, use hitEnterOnViewableElement instead
* Parameters: tabId, x, y, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID of the active tab | Yes
| value | string | Text to enter into the input field | Yes
| x | number | X coordinate (pixels) of the input element | Yes
| y | number | Y coordinate (pixels) of the input element | Yes
</details>
<details>
<summary>hitEnterOnViewableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element at specific X,Y coordinates
* Use this to trigger actions like form submission or button clicks
* Requires tabId from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureActiveTab screenshot dimensions
* Parameters: tabId, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabId | string | Tab ID of the active tab | Yes
| x | number | X coordinate (pixels) of the input element | Yes
| y | number | Y coordinate (pixels) of the input element | Yes
</details>
<details>
<summary>clickOnReadableElement</summary>

**Description**:

```
🔘 Clicks on an element identified by its index from getReadableElements
* Use this to click on elements after identifying them by their text
* Requires tabId from getBasicBrowserContext and index from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the index, then use this tool
* Parameters: tabId, index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Element index from getReadableElements | Yes
| tabId | string | Tab ID to target | Yes
</details>
<details>
<summary>fillTextToReadableElement</summary>

**Description**:

```
✏️ Types text into an input field identified by its index from getReadableElements
* Use this to enter text into form fields identified by their text
* Requires tabId from getBasicBrowserContext, index from getReadableElements, and text to enter
* Works with text inputs, textareas, and other editable elements
* First call getReadableElements to get the index, then use this tool
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnReadableElement with that button
* If no submit button is visible, use hitEnterOnReadableElement instead
* Parameters: tabId, index, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Element index from getReadableElements | Yes
| tabId | string | Tab ID to target | Yes
| value | string | Text to enter into the input field | Yes
</details>
<details>
<summary>hitEnterOnReadableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element identified by its index from getReadableElements
* Use this to trigger actions like form submission or button clicks
* Requires tabId from getBasicBrowserContext and index from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the index, then use this tool
* Parameters: tabId, index
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index | number | Element index from getReadableElements | Yes
| tabId | string | Tab ID to target | Yes
</details>
<details>
<summary>invokeJsFn</summary>

**Description**:

```
⚙️ Executes custom JavaScript code in the context of the web page
* Use this for advanced operations not covered by other tools
* Requires tabId from getBasicBrowserContext and JavaScript code to execute
* The code should be the body of a function that returns a value
* Example: 'return document.title;' to get the page title
* Gives you full flexibility for custom browser automation
* Parameters: tabId, fnBodyCode (JavaScript code as string)
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fnBodyCode | string | JavaScript function body to execute in page context | Yes
| tabId | string | Tab ID to run JavaScript in | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | captureActiveTab | description | af2fce241e21a76efa4e308a4e0063945e0b1752cb63e107a28e2a5031313851 |
| tools | clickOnReadableElement | description | 0438df73af4298fd9ec61c2247a0194f476bb8897d5ed905c174e4aad43176c2 |
| tools | clickOnReadableElement | index | 00ce0f742d8f01096ec9c784fdc8602c4c23d2c6892a28f66da5be7b339602b4 |
| tools | clickOnReadableElement | tabId | ab47f3937da53de3304fcdc69fc699789b345e543a90bff7f350152c4cbec94e |
| tools | clickOnViewableElement | description | 7aa07ce61e8fb1ea991061d521b95bb4dc12b3d883e02a5de0c01a55a5156976 |
| tools | clickOnViewableElement | tabId | cdbb31fdde2736d3de4f8ad98c1cfacbd2480c4d36538ef4b17087ed9a85b1dd |
| tools | clickOnViewableElement | x | 59b39337c4a10dcfead421def1e8e8c734c8359009c377b78f2b00e765e3831a |
| tools | clickOnViewableElement | y | 2c8254757572058da51b836876a7d89ff7784fe35c4d44a83da57be0cba46aa5 |
| tools | fillTextToReadableElement | description | 131ce07e5e32af2472619d8e9d496c901d5ea91f9eb509306f5f0e30a22b6fa4 |
| tools | fillTextToReadableElement | index | 00ce0f742d8f01096ec9c784fdc8602c4c23d2c6892a28f66da5be7b339602b4 |
| tools | fillTextToReadableElement | tabId | ab47f3937da53de3304fcdc69fc699789b345e543a90bff7f350152c4cbec94e |
| tools | fillTextToReadableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | description | e575ce47b46f93cdaaba248d3cc71958ab0bbd1bf744f31ccc05f0b581abd8d7 |
| tools | fillTextToViewableElement | tabId | cdbb31fdde2736d3de4f8ad98c1cfacbd2480c4d36538ef4b17087ed9a85b1dd |
| tools | fillTextToViewableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | x | 9ff70902c61f20d5928afc1078266d27bfae4e9a7f6bb0bd047907297e01d640 |
| tools | fillTextToViewableElement | y | 1e12d399a5a2b45739d01e30f9085c451692a8cfc68c3b25ae317573a6c649f4 |
| tools | getBasicBrowserContext | description | fbaacf1500b361281d9a9317b0b9d831596d4add5657fb3373efc931386e91c6 |
| tools | getInnerText | description | 533f548f87b146e20d054aa3dc6bcda97e79ddfb22a19fe4f5aee630647dc38d |
| tools | getInnerText | tabId | 46915f32fdbc787d332e2d237392bdd37e28a82bb9e132c4cc58b202bc9528fb |
| tools | getReadableElements | description | 4d48b9ab52fd816fbdd12d8b3c37236d187d4fd86fd4a91e6bcfef6b0e1215ed |
| tools | getReadableElements | tabId | 77da1d8b6cc995c38f0b0558fa9212aa7bdcd7ec325b556349dde7a53d4ec534 |
| tools | hitEnterOnReadableElement | description | d2d465c9904dee4b69dfb1504a65bfa3b42c6b01b32a8963e8ccc2331b021dc8 |
| tools | hitEnterOnReadableElement | index | 00ce0f742d8f01096ec9c784fdc8602c4c23d2c6892a28f66da5be7b339602b4 |
| tools | hitEnterOnReadableElement | tabId | ab47f3937da53de3304fcdc69fc699789b345e543a90bff7f350152c4cbec94e |
| tools | hitEnterOnViewableElement | description | 22a380bd11cb1e39f302a6a94452901bb2f5ecc0decb4d9ae038cc18997bc56a |
| tools | hitEnterOnViewableElement | tabId | cdbb31fdde2736d3de4f8ad98c1cfacbd2480c4d36538ef4b17087ed9a85b1dd |
| tools | hitEnterOnViewableElement | x | 9ff70902c61f20d5928afc1078266d27bfae4e9a7f6bb0bd047907297e01d640 |
| tools | hitEnterOnViewableElement | y | 1e12d399a5a2b45739d01e30f9085c451692a8cfc68c3b25ae317573a6c649f4 |
| tools | invokeJsFn | description | 2c31aecf416b17b6875d32778025efffd41943254f213a806892117f0d0633f3 |
| tools | invokeJsFn | fnBodyCode | 32bb4de35be8ab9939cd4881e9390f4702545ad99169cceddbe70fcb1efbc8ab |
| tools | invokeJsFn | tabId | 7cf618734c4a34ebe0999b4bea3fc172c6f7f07710d924d9e3df406aa946f1fb |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
