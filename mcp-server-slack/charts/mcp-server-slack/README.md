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


# What is mcp-server-slack?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-slack/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-slack/2025.4.25?logo=docker&logoColor=fff&label=2025.4.25)](https://hub.docker.com/r/acuvity/mcp-server-slack)
[![PyPI](https://img.shields.io/badge/2025.4.25-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-slack)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-slack&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22SLACK_BOT_TOKEN%22%2C%22-e%22%2C%22SLACK_TEAM_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-slack%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for interacting with Slack

> [!NOTE]
> `@modelcontextprotocol/server-slack` has been repackaged by Acuvity from Anthropic, PBC original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-slack run reliably and safely.

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
  - [ Anthropic, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @modelcontextprotocol/server-slack ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-slack ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/charts/mcp-server-slack)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-slack/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-2025.4.25`

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
  - `SLACK_BOT_TOKEN` secret to be set as secrets.SLACK_BOT_TOKEN either by `.value` or from existing with `.valueFrom`
  - `SLACK_TEAM_ID` secret to be set as secrets.SLACK_TEAM_ID either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install helm install mcp-server-slack oci://docker.io/acuvity/mcp-server-slack --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-slack --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-slack --version 1.0.0
````
From there your MCP server mcp-server-slack will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-slack` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-slack
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-slack` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
<summary>slack_list_channels</summary>

**Description**:

```
List public or pre-defined channels in the workspace with pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Pagination cursor for next page of results | No
| limit | number | Maximum number of channels to return (default 100, max 200) | No
</details>
<details>
<summary>slack_post_message</summary>

**Description**:

```
Post a new message to a Slack channel
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel to post to | Yes
| text | string | The message text to post | Yes
</details>
<details>
<summary>slack_reply_to_thread</summary>

**Description**:

```
Reply to a specific message thread in Slack
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel containing the thread | Yes
| text | string | The reply text | Yes
| thread_ts | string | The timestamp of the parent message in the format '1234567890.123456'. Timestamps in the format without the period can be converted by adding the period such that 6 numbers come after it. | Yes
</details>
<details>
<summary>slack_add_reaction</summary>

**Description**:

```
Add a reaction emoji to a message
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel containing the message | Yes
| reaction | string | The name of the emoji reaction (without ::) | Yes
| timestamp | string | The timestamp of the message to react to | Yes
</details>
<details>
<summary>slack_get_channel_history</summary>

**Description**:

```
Get recent messages from a channel
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel | Yes
| limit | number | Number of messages to retrieve (default 10) | No
</details>
<details>
<summary>slack_get_thread_replies</summary>

**Description**:

```
Get all replies in a message thread
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| channel_id | string | The ID of the channel containing the thread | Yes
| thread_ts | string | The timestamp of the parent message in the format '1234567890.123456'. Timestamps in the format without the period can be converted by adding the period such that 6 numbers come after it. | Yes
</details>
<details>
<summary>slack_get_users</summary>

**Description**:

```
Get a list of all users in the workspace with their basic profile information
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Pagination cursor for next page of results | No
| limit | number | Maximum number of users to return (default 100, max 200) | No
</details>
<details>
<summary>slack_get_user_profile</summary>

**Description**:

```
Get detailed profile information for a specific user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user_id | string | The ID of the user | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | slack_add_reaction | description | 1f62c0d2156feeea70ab2bb08899b0eea724921708ef1f842d5a3274b8a42242 |
| tools | slack_add_reaction | channel_id | 83651ca4b8296fa718d4acdfeb6cae2c112c95a79d72305e997bf788de804f4f |
| tools | slack_add_reaction | reaction | dde7c05968061cac6874c1977ced5368e35ef7faf132ecbe4581e793abf9ba7d |
| tools | slack_add_reaction | timestamp | 6bf125bd35ca506a4fcdde9d16cda3475862d295770c69c704fe5e21a62397de |
| tools | slack_get_channel_history | description | b43638ece46444f140ef4ee2bcc7361a2a2e45234c3bd1d02b08a2a6562d3bd8 |
| tools | slack_get_channel_history | channel_id | 73a4a19c15485e6ad000420b9a6f6520294a9f79e68febad4f62f408c5243e5b |
| tools | slack_get_channel_history | limit | 4054928c311253594c8a19a24c514c4a702aa5da1f8109f514e7340cd6c3a043 |
| tools | slack_get_thread_replies | description | f25a9302b989e9d86f701d431e0e5dfce1cf769429eea022e7f13e22888d93cf |
| tools | slack_get_thread_replies | channel_id | c8d1977d3c00d46ff3c2f206a9d17540dc173cf435ab4ad2a0fcbbaa53174b98 |
| tools | slack_get_thread_replies | thread_ts | e7d2dff0b6b5d4cb27ad3c927afc91e9bf54e44f67468519d23e81625423645f |
| tools | slack_get_user_profile | description | 24e26221d8494e92eee5dfd7c12e4ec57595f985c5873c89b2885cd5f1154b59 |
| tools | slack_get_user_profile | user_id | f0e13cca2694f31a174eb5bb798a4b5b187952d31bad9d14bcb1167d057e24f0 |
| tools | slack_get_users | description | 064d8ff96ee3ebc5262414bcf8d7a3569e50309fa1f47c86e8a504bd380a1bb9 |
| tools | slack_get_users | cursor | af663f140c35780ea36be96fa602b310c84c5373bd95d8f7e98e2fdb474d5061 |
| tools | slack_get_users | limit | a0f951f54f777c4126ec2111eeb7387dddd999ace45b68d2ba653a89f25d8db2 |
| tools | slack_list_channels | description | 20dcdc291e18a09e8ac35a4335082ec4394a452d18cfff2626d5a57158ef234b |
| tools | slack_list_channels | cursor | af663f140c35780ea36be96fa602b310c84c5373bd95d8f7e98e2fdb474d5061 |
| tools | slack_list_channels | limit | fa1df8a77e411a4caea75403c307b517794b232c64c461f5d72b2ba2aed7755e |
| tools | slack_post_message | description | d105b99a6bf981dd4dd7cde32c4b8d33778f41b55d598babca8eba58e0897708 |
| tools | slack_post_message | channel_id | 0160eabae43220452e6637867cbf32654460cdc34924d4c5181e600a08adc2c5 |
| tools | slack_post_message | text | c8aa0df1dbb20587482804936252b53a17db6330c1e42a8889aaeb687ca40a33 |
| tools | slack_reply_to_thread | description | a304e8edbaf0870a55d4d3c33ca6433ddd6ed10eae67ba538ce678da6a520c3a |
| tools | slack_reply_to_thread | channel_id | c8d1977d3c00d46ff3c2f206a9d17540dc173cf435ab4ad2a0fcbbaa53174b98 |
| tools | slack_reply_to_thread | text | 63318714e118e032285fa4f42f874e1b848ce97f3c96b0b429c88bcc3d68e4a3 |
| tools | slack_reply_to_thread | thread_ts | e7d2dff0b6b5d4cb27ad3c927afc91e9bf54e44f67468519d23e81625423645f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
