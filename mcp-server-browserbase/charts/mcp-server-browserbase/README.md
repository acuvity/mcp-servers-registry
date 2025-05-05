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
</p>


# What is mcp-server-browserbase?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browserbase/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browserbase/0.5.1?logo=docker&logoColor=fff&label=0.5.1)](https://hub.docker.com/r/acuvity/mcp-server-browserbase)
[![PyPI](https://img.shields.io/badge/0.5.1-3775A9?logo=pypi&logoColor=fff&label=@browserbasehq/mcp-browserbase)](https://github.com/browserbase/mcp-server-browserbase)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserbase&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERBASE_API_KEY%22%2C%22-e%22%2C%22BROWSERBASE_PROJECT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserbase%3A0.5.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Automate browser interactions in the cloud (e.g. web navigation, data extraction, form filling).

> [!NOTE]
> `@browserbasehq/mcp-browserbase` has been repackaged by Acuvity from Anthropic, PBC original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @browserbasehq/mcp-browserbase run reliably and safely.

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
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails that protect MCP server integrity and detect suspicious behaviors in real-time.:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions - or call arguments - reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognised tokens formats with `[REDACTED]` in outbound content.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Anthropic, PBC ](https://github.com/browserbase/mcp-server-browserbase) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @browserbasehq/mcp-browserbase ](https://github.com/browserbase/mcp-server-browserbase)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @browserbasehq/mcp-browserbase ](https://github.com/browserbase/mcp-server-browserbase)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/charts/mcp-server-browserbase)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserbase/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.5.1`

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
  - `BROWSERBASE_API_KEY` secret to be set as secrets.BROWSERBASE_API_KEY either by `.value` or from existing with `.valueFrom`
  - `BROWSERBASE_PROJECT_ID` secret to be set as secrets.BROWSERBASE_PROJECT_ID either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install helm install mcp-server-browserbase oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-browserbase --version 1.0.0
````
From there your MCP server mcp-server-browserbase will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-browserbase` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-browserbase
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
args:
```

Passes arbitrary command‑line arguments into the container.


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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-browserbase` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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

  # Policier configuration
  policer:
    # Instruct to enforce policies if enabled
    # otherwise it will jsut log the verdict as a warning
    # message in logs
    enforce: false
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

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>browserbase_create_session</summary>

**Description**:

```
Create a new cloud browser session using Browserbase
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>browserbase_close_session</summary>

**Description**:

```
Close a browser session on Browserbase
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | not set | Yes
</details>
<details>
<summary>browserbase_navigate</summary>

**Description**:

```
Navigate to a URL
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>browserbase_screenshot</summary>

**Description**:

```
Take a screenshot of the current page or a specific element
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | Height in pixels (default: 600) | No
| name | string | Name for the screenshot | Yes
| selector | string | CSS selector for element to screenshot | No
| width | number | Width in pixels (default: 800) | No
</details>
<details>
<summary>browserbase_click</summary>

**Description**:

```
Click an element on the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for element to click | Yes
</details>
<details>
<summary>browserbase_fill</summary>

**Description**:

```
Fill out an input field
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for input field | Yes
| value | string | Value to fill | Yes
</details>
<details>
<summary>browserbase_evaluate</summary>

**Description**:

```
Execute JavaScript in the browser console
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| script | string | JavaScript code to execute | Yes
</details>
<details>
<summary>browserbase_get_content</summary>

**Description**:

```
Extract all content from the current page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | Optional CSS selector to get content from specific elements (default: returns whole page) | No
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Browser console logs | text/plain | console://logs | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | browserbase_click | description | 0f5e4e9a2e49b9860eacc68a7dc5312c71ab2f83be1734dcddbc8ce31fc7d82b |
| tools | browserbase_click | selector | a6922769712660b619584746585d94b11a460d199e2cb84957988b6f9f7cd3bf |
| tools | browserbase_close_session | description | be033dac5747af43f17a5e254bd24af517866cab1af756a72549b19d9292a250 |
| tools | browserbase_create_session | description | 56bdd0db0c370258b7b7ef2d4604f7602a46d68d3f7cdae47dcf8bb48305c774 |
| tools | browserbase_evaluate | description | 0d3a0f5f637a3ca339c8c9bef048bb7db6e97e99b3e930af4f90036cf0ae0eac |
| tools | browserbase_evaluate | script | 4b891a8ea8149f7f674a0058530d3027453331b59fdc8dd937f97530abe2917d |
| tools | browserbase_fill | description | 9092ab55b68d8d48b44cd4637d7c45d295489784406d1d0b2811c64eb390c12e |
| tools | browserbase_fill | selector | 9b2fd4f2a301cda1ab585f8de553e53bf5907a4b15ee68f56f075d6e57464d23 |
| tools | browserbase_fill | value | 11d5ebd4e421f3e0f32524bf28a9c06bfce4a5f82b89ad49f4636dce92377c8f |
| tools | browserbase_get_content | description | 6105d7f8013e0ad9af3aeaeb5638755ccc8337aeb2e402ea526aead14e030569 |
| tools | browserbase_get_content | selector | cf9b6a9a4d253d7e4cbb921429945fcc70861aebf48bd8c8a0e6c61201352ade |
| tools | browserbase_navigate | description | 5e517ac29796df4781d6e8f8b3be061cc694f0c8e027f40e42ce0739e887b1d5 |
| tools | browserbase_screenshot | description | 5e3558916850d55baa3a9b5dfaec0755a8c16f6bcd03be7a78aadbc65745da85 |
| tools | browserbase_screenshot | height | 0e240884937c1dc91c541aaeceb007bb3bb0994e396a1652edb748fa6198615d |
| tools | browserbase_screenshot | name | 28c1b883362fcf9a1205e2015271212cbc322322343879408bd5b191917b3379 |
| tools | browserbase_screenshot | selector | aa5efe3a86a6ab130c1c81e671113a8be57294dedf3bbde39fe0088fea2c14d5 |
| tools | browserbase_screenshot | width | d10864eef69042788f00ea5522b84a05480ff9a1479b27cc6cdfa409a2304060 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
