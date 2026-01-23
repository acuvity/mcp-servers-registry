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


# What is mcp-server-line-bot?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-line-bot/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-line-bot/0.4.2?logo=docker&logoColor=fff&label=0.4.2)](https://hub.docker.com/r/acuvity/mcp-server-line-bot)
[![PyPI](https://img.shields.io/badge/0.4.2-3775A9?logo=pypi&logoColor=fff&label=@line/line-bot-mcp-server)](https://github.com/line/line-bot-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-line-bot/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-line-bot&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHANNEL_ACCESS_TOKEN%22%2C%22-e%22%2C%22DESTINATION_USER_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-line-bot%3A0.4.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connects AI Agent to LINE for messaging interactions.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @line/line-bot-mcp-server original [sources](https://github.com/line/line-bot-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-line-bot/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/charts/mcp-server-line-bot/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @line/line-bot-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Author ](https://github.com/line/line-bot-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @line/line-bot-mcp-server ](https://github.com/line/line-bot-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @line/line-bot-mcp-server ](https://github.com/line/line-bot-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/charts/mcp-server-line-bot)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-line-bot/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.4.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-line-bot:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-line-bot:1.0.0-0.4.2`

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
  - `CHANNEL_ACCESS_TOKEN` secret to be set as secrets.CHANNEL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`
  - `DESTINATION_USER_ID` secret to be set as secrets.DESTINATION_USER_ID either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-line-bot
```

From there your MCP server mcp-server-line-bot will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-line-bot` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-line-bot
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-line-bot` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-line-bot oci://docker.io/acuvity/mcp-server-line-bot --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>push_text_message</summary>

**Description**:

```
Push a simple text message to a user via LINE. Use this for sending plain text messages without formatting.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
| userId | string | The user ID to receive a message. Defaults to DESTINATION_USER_ID. | No
</details>
<details>
<summary>push_flex_message</summary>

**Description**:

```
Push a highly customizable flex message to a user via LINE. Supports both bubble (single container) and carousel (multiple swipeable bubbles) layouts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
| userId | string | The user ID to receive a message. Defaults to DESTINATION_USER_ID. | No
</details>
<details>
<summary>broadcast_text_message</summary>

**Description**:

```
Broadcast a simple text message via LINE to all users who have followed your LINE Official Account. Use this for sending plain text messages without formatting. Please be aware that this message will be sent to all users.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
</details>
<details>
<summary>broadcast_flex_message</summary>

**Description**:

```
Broadcast a highly customizable flex message via LINE to all users who have added your LINE Official Account. Supports both bubble (single container) and carousel (multiple swipeable bubbles) layouts. Please be aware that this message will be sent to all users.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | object | not set | Yes
</details>
<details>
<summary>get_profile</summary>

**Description**:

```
Get detailed profile information of a LINE user including display name, profile picture URL, status message and language.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| userId | string | The user ID to get a profile. Defaults to DESTINATION_USER_ID. | No
</details>
<details>
<summary>get_message_quota</summary>

**Description**:

```
Get the message quota and consumption of the LINE Official Account. This shows the monthly message limit and current usage.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_rich_menu_list</summary>

**Description**:

```
Get the list of rich menus associated with your LINE Official Account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>delete_rich_menu</summary>

**Description**:

```
Delete a rich menu from your LINE Official Account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| richMenuId | string | The ID of the rich menu to delete. | Yes
</details>
<details>
<summary>set_rich_menu_default</summary>

**Description**:

```
Set a rich menu as the default rich menu.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| richMenuId | string | The ID of the rich menu to set as default. | Yes
</details>
<details>
<summary>cancel_rich_menu_default</summary>

**Description**:

```
Cancel the default rich menu.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_rich_menu</summary>

**Description**:

```
Create a rich menu based on the given actions. Generate and upload a rich menu image based on the given action. This rich menu will be registered as the default.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| actions | array | The actions of the rich menu. | Yes
| chatBarText | string | Text displayed in the chat bar and this is also used as name of the rich menu to create | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | broadcast_flex_message | description | 375ffde87d672553fec772b66a897b10465d90cd26fa546489090ccc3ba88c74 |
| tools | broadcast_text_message | description | 6a7cee7032cbb044108c51358ff821abf09938c87a00c6f9ef9df70f848fdc91 |
| tools | cancel_rich_menu_default | description | 5665fffb4bd328740228f593ceaa04b8838575e8489c1b9db3eebf27eefa9993 |
| tools | create_rich_menu | description | 58e5d0152ff327ce0fae3570dd9a50bd559c5da433320f8c6e04cab4cbd21112 |
| tools | create_rich_menu | actions | 9f6675aafdca62783849a1dfd72d064d2cc7276b9833c236318076f2ba50cc80 |
| tools | create_rich_menu | chatBarText | 6ba84bd6cc9b53d9afe786af0b6c2a57fda5df0f414429849e53b6d41de9b6f6 |
| tools | delete_rich_menu | description | 9354a24cd221401fe051d2738db054192319efb3b6d293f348cf5e9a27a3e434 |
| tools | delete_rich_menu | richMenuId | 2d411290063b03c03efe1a704b011a2391040b3f116a1acde421819cb9327c8e |
| tools | get_message_quota | description | 9edfcab24cb244f0063332ca4117ffed55fb8de1b61c2735079b8bd5bfad0634 |
| tools | get_profile | description | 35f893ef7edcac5026b3bd2f7d5b9953827b7ad6484a2ec2d63e94dd5872625a |
| tools | get_profile | userId | ab51e75da45824d3fdaf17ed8b9a48dd5790587d762fafabfb91d93b7e28fb45 |
| tools | get_rich_menu_list | description | 615b67d830bc1ad3702a55c10fbf5317854b49be42b7dcf7d6ff0860bd8b950f |
| tools | push_flex_message | description | 3f7f8a97ee448ca4c7467dfb44ce2476225ae1d5e66dce76a1dd5e1591cc77ae |
| tools | push_flex_message | userId | ae3ba3776baad8eeb0f3eb9d13eaecf069294ebbff803dd13f7a7f1557cb04e4 |
| tools | push_text_message | description | 65e328795468a461ca52572caddd9320ef1afb238961594dcc04a122e73a5d1c |
| tools | push_text_message | userId | ae3ba3776baad8eeb0f3eb9d13eaecf069294ebbff803dd13f7a7f1557cb04e4 |
| tools | set_rich_menu_default | description | 0b133223247370c03fbd51ef4881660aa52ce6326e76bb2d689b123a12df36d5 |
| tools | set_rich_menu_default | richMenuId | f42e7823d6c9a7c04afafce460535cca4bbd2912680aefb43095a669105b99df |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
