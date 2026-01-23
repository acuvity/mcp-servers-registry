<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://acuvity.ai/wp-content/uploads/2025/09/1.-Acuvity-Logo-Black-scaled-e1758135197226.png" height="90" alt="Acuvity logo"/>
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
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browser-kit/6.0.0?logo=docker&logoColor=fff&label=6.0.0)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit)
[![PyPI](https://img.shields.io/badge/6.0.0-3775A9?logo=pypi&logoColor=fff&label=@mcp-browser-kit/server)](https://github.com/ndthanhdev/mcp-browser-kit)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browser-kit/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browser-kit&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-browser-kit%3A6.0.0%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browser-kit#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - container: `1.0.0-6.0.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-browser-kit:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-browser-kit:1.0.0-6.0.0`

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

## 🧰 Tools (14)
<details>
<summary>getBasicBrowserContext</summary>

**Description**:

```
🌐 GET BROWSER CONTEXT - CRITICAL FIRST STEP BEFORE USING ANY OTHER TOOLS!
* This tool MUST be called first to initialize browser automation and get essential data.
* Returns data structure with:
  - tabs: Array of browser tabs with properties like id, url, title, and active status
  - manifestVersion: Version of extension manifest format supported by the browser
* Each tab includes a unique tabKey required for all other tool operations
* The active tab (marked with 'active: true') is typically your target for automation
* The manifestVersion determines which browser features and extension capabilities are available
* Different browsers support different manifest versions, affecting available tools and API access
* Standard workflow:
  1) getBasicBrowserContext → get browser state and tabKey
  2) Analyze page content based on your goal and manifest version:
     - If interaction is required (clicking, filling forms, etc.):
       · For Manifest Version 2: Use captureTab for visual context or getReadableElements for element identification
       · For other Manifest Versions: Use only getReadableElements for element identification
     - If no interaction is required (just reading page content):
       · Use getReadableText to extract all visible text from the page
  3) Interact using click/fill/enter tools with the obtained tabKey
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>captureTab</summary>

**Description**:

```
📷 Captures a screenshot of a browser tab
* Use this tool after calling getBasicBrowserContext to obtain visual context of the page
* The screenshot helps you see what the browser is displaying to the user
* Requires tabKey from getBasicBrowserContext
* Returns an image with width, height, and data in base64 format
* Workflow: 1) getBasicBrowserContext → 2) captureTab → 3) interact with elements
* Parameters: tabKey
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>invokeJsFn</summary>

**Description**:

```
⚙️ Executes custom JavaScript code in the context of the web page
* Use this for advanced operations not covered by other tools
* Requires tabKey from getBasicBrowserContext and JavaScript code to execute
* The code should be the body of a function that returns a value
* Example: 'return document.title;' to get the page title
* Gives you full flexibility for custom browser automation
* Parameters: tabKey, fnBodyCode (JavaScript code as string)
* NOTE: This feature is only available in browsers supporting Manifest Version 2
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| fnBodyCode | string | Function body code to execute in page context | Yes
| tabKey | string | Tab key to run JavaScript in | Yes
</details>
<details>
<summary>openTab</summary>

**Description**:

```
🌐 Opens a new browser tab with the specified URL
* Use this to navigate to a new page in a new tab
* Requires windowKey from getBasicBrowserContext and the URL to open
* Returns the tabKey of the newly created tab which you can use for further operations
* The new tab will be created in the specified browser window
* After opening, you may need to wait a moment for the page to load
* Parameters: windowKey, url
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | URL to open in the new tab | Yes
| windowKey | string | Window key where the new tab should open | Yes
</details>
<details>
<summary>closeTab</summary>

**Description**:

```
🗑️ Closes a specific browser tab
* Use this to close a tab when you're done with it or need to clean up
* Requires tabKey from getBasicBrowserContext
* The tab will be permanently closed and cannot be recovered
* Be careful not to close the tab you're currently working with
* Parameters: tabKey
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>getSelection</summary>

**Description**:

```
📋 Gets the current text selection in the browser tab
* Use this to retrieve text that the user has selected on the page
* Requires tabKey from getBasicBrowserContext
* Returns information about the selected text including the text content itself
* Useful for capturing user selections or verifying what text is highlighted
* Returns empty selection if nothing is currently selected
* Parameters: tabKey
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>getReadableText</summary>

**Description**:

```
📝 Extracts all text content from the current web page
* Retrieves all visible text from the active tab
* Requires the tabKey obtained from getBasicBrowserContext
* Use this to analyze the page content without visual elements
* Returns a string containing all the text on the page
* Useful for getting a quick overview of page content
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>getReadableElements</summary>

**Description**:

```
🔍 Lists all interactive elements on the page with their text
* Returns a list of elements with their path, role, and text content
* Requires the tabKey obtained from getBasicBrowserContext
* Each element is returned as [path, accessibleRole, accessibleText]
* Use the path as readablePath to interact with elements through click or fill operations
* Helps you identify which elements can be interacted with by their text
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>clickOnViewableElement</summary>

**Description**:

```
👆 Clicks on an element at specific X,Y coordinates
* Use this to click on elements by their position on the screen
* Requires tabKey from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureTab screenshot dimensions
* Useful when you know the visual position of an element
* Parameters: tabKey, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key of the active tab | Yes
| x | number | X coordinate (pixels) | Yes
| y | number | Y coordinate (pixels) | Yes
</details>
<details>
<summary>fillTextToViewableElement</summary>

**Description**:

```
⌨️ Types text into an input field at specific X,Y coordinates
* Use this to enter text into form fields by their position
* Requires tabKey from getBasicBrowserContext, x,y coordinates, and the text to enter
* Coordinates are based on the captureTab screenshot dimensions
* First clicks at the specified position, then types the provided text
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnViewableElement with that button
* If no submit button is visible, use hitEnterOnViewableElement instead
* Parameters: tabKey, x, y, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key of the active tab | Yes
| value | string | Text to enter into the input field | Yes
| x | number | X coordinate (pixels) | Yes
| y | number | Y coordinate (pixels) | Yes
</details>
<details>
<summary>hitEnterOnViewableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element at specific X,Y coordinates
* Use this to trigger actions like form submission or button clicks
* Requires tabKey from getBasicBrowserContext and x,y coordinates from the screenshot
* Coordinates are based on the captureTab screenshot dimensions
* Parameters: tabKey, x, y
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| tabKey | string | Tab key of the active tab | Yes
| x | number | X coordinate (pixels) | Yes
| y | number | Y coordinate (pixels) | Yes
</details>
<details>
<summary>clickOnReadableElement</summary>

**Description**:

```
🔘 Clicks on an element identified by its readablePath from getReadableElements
* Use this to click on elements after identifying them by their text
* Requires tabKey from getBasicBrowserContext and readablePath from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the readablePath, then use this tool
* Parameters: tabKey, readablePath
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readablePath | string | Readable path from getReadableElements | Yes
| tabKey | string | Tab key to target | Yes
</details>
<details>
<summary>fillTextToReadableElement</summary>

**Description**:

```
✏️ Types text into an input field identified by its readablePath from getReadableElements
* Use this to enter text into form fields identified by their text
* Requires tabKey from getBasicBrowserContext, readablePath from getReadableElements, and text to enter
* Works with text inputs, textareas, and other editable elements
* First call getReadableElements to get the readablePath, then use this tool
* After filling text, check for associated submit-like buttons (submit, search, send, etc.)
* If submit button is visible, use clickOnReadableElement with that button
* If no submit button is visible, use hitEnterOnReadableElement instead
* Parameters: tabKey, readablePath, value (text to enter)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readablePath | string | Readable path from getReadableElements | Yes
| tabKey | string | Tab key to target | Yes
| value | string | Text to enter into the input field | Yes
</details>
<details>
<summary>hitEnterOnReadableElement</summary>

**Description**:

```
↵ Hits the Enter key on an element identified by its readablePath from getReadableElements
* Use this to trigger actions like form submission or button clicks
* Requires tabKey from getBasicBrowserContext and readablePath from getReadableElements
* More reliable than coordinate-based clicking for dynamic layouts
* First call getReadableElements to get the readablePath, then use this tool
* Parameters: tabKey, readablePath
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| readablePath | string | Readable path from getReadableElements | Yes
| tabKey | string | Tab key to target | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | captureTab | description | 152fb60c5e1ca8d698be64696826fadfd3011e3d6506bf10ae25eb54849f25f8 |
| tools | captureTab | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | clickOnReadableElement | description | 74103a94e481633340bf37de9227c79583b672b71474b3002c17c71be6428304 |
| tools | clickOnReadableElement | readablePath | a821ee6279e49d0e8612bd5b956e9d9d068310896baa044a2360a013e05ba670 |
| tools | clickOnReadableElement | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | clickOnViewableElement | description | d299973fae685829743762c47e7dc7e834c91cc118a8144677ea0a5843c97d39 |
| tools | clickOnViewableElement | tabKey | 1905d1d81df0a9cc7ad121903f7ce900212d89c7a0a61302e3024eb7fdc818cc |
| tools | clickOnViewableElement | x | 99e485969ccfcf64b1a19ba66225ab59a10fd001381f06eb985c786f11aa5dc7 |
| tools | clickOnViewableElement | y | 352255b47c2dd55fc1ba4cc33ee8e6ee31ac9bea2904356cf45a843cea4eb010 |
| tools | closeTab | description | 7688fa4da5c6e071bc02f9de5ea358ba1f154f88c74b92a3c03c698766b10fb9 |
| tools | closeTab | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | fillTextToReadableElement | description | d4a19ba1806b2bf8c0d22fef01a727c9f20fd89550ad15d3880d69eceaac3a8e |
| tools | fillTextToReadableElement | readablePath | a821ee6279e49d0e8612bd5b956e9d9d068310896baa044a2360a013e05ba670 |
| tools | fillTextToReadableElement | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | fillTextToReadableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | description | 0faa5e473ac318b0523b870006ae95c2fd188218cc397fd5653d30c7c5c1bfc9 |
| tools | fillTextToViewableElement | tabKey | 1905d1d81df0a9cc7ad121903f7ce900212d89c7a0a61302e3024eb7fdc818cc |
| tools | fillTextToViewableElement | value | e80240577aae2f2bc8b5b22933a8196469ab650feff9be5b30353e8116f3233b |
| tools | fillTextToViewableElement | x | 99e485969ccfcf64b1a19ba66225ab59a10fd001381f06eb985c786f11aa5dc7 |
| tools | fillTextToViewableElement | y | 352255b47c2dd55fc1ba4cc33ee8e6ee31ac9bea2904356cf45a843cea4eb010 |
| tools | getBasicBrowserContext | description | 0efa36a8e491b8af1859fc7d3043445c97f044800c76d53244571bb51ff660b7 |
| tools | getReadableElements | description | 83421405f70f23e7e0d6360813246c2affa9b147946490d9e912e6c58c318e3d |
| tools | getReadableElements | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | getReadableText | description | 953ad929cd5f3bd90e24269390db34df662f1c6ca596b6c7982cb5a9986c16e6 |
| tools | getReadableText | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | getSelection | description | 003adda1508fb36bca5fd64a1615e2b6e6be59121f9127905bd359674dbda16b |
| tools | getSelection | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | hitEnterOnReadableElement | description | 72f368e61a6bebbb9c449c5acb16847750b21034df5666c0b95c5d42276a95cc |
| tools | hitEnterOnReadableElement | readablePath | a821ee6279e49d0e8612bd5b956e9d9d068310896baa044a2360a013e05ba670 |
| tools | hitEnterOnReadableElement | tabKey | 9d91cd630f74f39d726bde359288463d19041a66100dc90594335713137e52b7 |
| tools | hitEnterOnViewableElement | description | 9497ea9d06fc3c06782c3ebcf659c262b5e73d48b42024f8542be786cef91b9a |
| tools | hitEnterOnViewableElement | tabKey | 1905d1d81df0a9cc7ad121903f7ce900212d89c7a0a61302e3024eb7fdc818cc |
| tools | hitEnterOnViewableElement | x | 99e485969ccfcf64b1a19ba66225ab59a10fd001381f06eb985c786f11aa5dc7 |
| tools | hitEnterOnViewableElement | y | 352255b47c2dd55fc1ba4cc33ee8e6ee31ac9bea2904356cf45a843cea4eb010 |
| tools | invokeJsFn | description | 346a3964a9981ab3a17b524d04e6a37546211aa6877326ee1cc4c513d383e737 |
| tools | invokeJsFn | fnBodyCode | 94e3e04f3d9fb5007d21cc65151c5c06fd599343b91a4a9ddc0825c698d3e5d0 |
| tools | invokeJsFn | tabKey | 38d6163316bb484cc05e0fabdef1292b391cb04ac7450fc0c56082586c28afdc |
| tools | openTab | description | 48fd5fe3b54a97ffa89790256789639d05029426ddad4955d5ba8a778df4569f |
| tools | openTab | url | c5c97556e9cbd94912bf77a26557f0783744994e813a89ef4d4b6c049087ff69 |
| tools | openTab | windowKey | 860d4f0888ac2e7d876f8a178933dcb83417b2a8cbc46a3fb973886ca31b0a13 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
