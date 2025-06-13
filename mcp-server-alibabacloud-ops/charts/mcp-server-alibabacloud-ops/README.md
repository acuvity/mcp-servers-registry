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


# What is mcp-server-alibabacloud-ops?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-ops/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibabacloud-ops/0.8.9?logo=docker&logoColor=fff&label=0.8.9)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-ops)
[![PyPI](https://img.shields.io/badge/0.8.9-3775A9?logo=pypi&logoColor=fff&label=alibaba-cloud-ops-mcp-server)](https://github.com/aliyun/alibaba-cloud-ops-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-alibabacloud-ops/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibabacloud-ops&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_ID%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibabacloud-ops%3A0.8.9%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Alibaba Cloud integration, supporting ECS, Cloud Monitor, OOS and widely used cloud products.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from alibaba-cloud-ops-mcp-server original [sources](https://github.com/aliyun/alibaba-cloud-ops-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibabacloud-ops/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-ops/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-ops/charts/mcp-server-alibabacloud-ops/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure alibaba-cloud-ops-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-ops/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Zheng Dayu <dayu.zdy@alibaba-inc.com> ](https://github.com/aliyun/alibaba-cloud-ops-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ alibaba-cloud-ops-mcp-server ](https://github.com/aliyun/alibaba-cloud-ops-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ alibaba-cloud-ops-mcp-server ](https://github.com/aliyun/alibaba-cloud-ops-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-ops/charts/mcp-server-alibabacloud-ops)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibabacloud-ops/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.8.9`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-ops:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-alibabacloud-ops:1.0.0-0.8.9`

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
  - `ALIBABA_CLOUD_ACCESS_KEY_ID` secret to be set as secrets.ALIBABA_CLOUD_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `ALIBABA_CLOUD_ACCESS_KEY_SECRET` secret to be set as secrets.ALIBABA_CLOUD_ACCESS_KEY_SECRET either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-alibabacloud-ops oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-alibabacloud-ops oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-alibabacloud-ops
```

From there your MCP server mcp-server-alibabacloud-ops will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibabacloud-ops` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-alibabacloud-ops
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-alibabacloud-ops` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-alibabacloud-ops oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-alibabacloud-ops oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-alibabacloud-ops oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-alibabacloud-ops oci://docker.io/acuvity/mcp-server-alibabacloud-ops --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (34)
<details>
<summary>OOS_RunCommand</summary>

**Description**:

```
批量在多台ECS实例上运行云助手命令，适用于需要同时管理多台ECS实例的场景，如应用程序管理和资源标记操作等。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Command | string | Content of the command executed on the ECS instance | Yes
| CommandType | string | The type of command executed on the ECS instance, optional value：RunShellScript，RunPythonScript，RunPerlScript，RunBatScript，RunPowerShellScript | No
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_StartInstances</summary>

**Description**:

```
批量启动ECS实例，适用于需要同时管理和启动多台ECS实例的场景，例如应用部署和高可用性场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_StopInstances</summary>

**Description**:

```
批量停止ECS实例，适用于需要同时管理和停止多台ECS实例的场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ForeceStop | boolean | Is forced shutdown required | No
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_RebootInstances</summary>

**Description**:

```
批量重启ECS实例，适用于需要同时管理和重启多台ECS实例的场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ForeceStop | boolean | Is forced shutdown required | No
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_RunInstances</summary>

**Description**:

```
批量创建ECS实例，适用于需要同时创建多台ECS实例的场景，例如应用部署和高可用性场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Amount | integer | Number of ECS instances | No
| ImageId | string | Image ID | Yes
| InstanceName | string | Instance Name | No
| InstanceType | string | Instance Type | Yes
| RegionId | string | AlibabaCloud region ID | No
| SecurityGroupId | string | SecurityGroup ID | Yes
| VSwitchId | string | VSwitch ID | Yes
</details>
<details>
<summary>OOS_ResetPassword</summary>

**Description**:

```
批量修改ECS实例的密码，请注意，本操作将会重启ECS实例
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| Password | string | The password of the ECS instance must be 8-30 characters and must contain only the following characters: lowercase letters, uppercase letters, numbers, and special characters only.（）~！@#$%^&*-_+=（40：<>，？/ | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_ReplaceSystemDisk</summary>

**Description**:

```
批量替换ECS实例的系统盘，更换操作系统
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ImageId | string | Image ID | Yes
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_StartRDSInstances</summary>

**Description**:

```
批量启动RDS实例，适用于需要同时管理和启动多台RDS实例的场景，例如应用部署和高可用性场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_StopRDSInstances</summary>

**Description**:

```
批量停止RDS实例，适用于需要同时管理和停止多台RDS实例的场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud RDS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OOS_RebootRDSInstances</summary>

**Description**:

```
批量重启RDS实例，适用于需要同时管理和重启多台RDS实例的场景。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud RDS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetCpuUsageData</summary>

**Description**:

```
获取ECS实例的CPU使用率数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetCpuLoadavgData</summary>

**Description**:

```
获取CPU一分钟平均负载指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetCpuloadavg5mData</summary>

**Description**:

```
获取CPU五分钟平均负载指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetCpuloadavg15mData</summary>

**Description**:

```
获取CPU十五分钟平均负载指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetMemUsedData</summary>

**Description**:

```
获取内存使用量指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetMemUsageData</summary>

**Description**:

```
获取内存利用率指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetDiskUsageData</summary>

**Description**:

```
获取磁盘利用率指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetDiskTotalData</summary>

**Description**:

```
获取磁盘分区总容量指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>CMS_GetDiskUsedData</summary>

**Description**:

```
获取磁盘分区使用量指标数据
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| InstanceIds | array | AlibabaCloud ECS instance ID List | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OSS_ListBuckets</summary>

**Description**:

```
列出指定区域的所有OSS存储空间。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Prefix | string | AlibabaCloud OSS Bucket Name prefix | No
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OSS_ListObjects</summary>

**Description**:

```
获取指定OSS存储空间中的所有文件信息。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| BucketName | string | AlibabaCloud OSS Bucket Name | Yes
| Prefix | string | AlibabaCloud OSS Bucket Name prefix | No
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>OSS_PutBucket</summary>

**Description**:

```
创建一个新的OSS存储空间。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| BucketName | string | AlibabaCloud OSS Bucket Name | Yes
| DataRedundancyType | string | The data disaster recovery type of AlibabaCloud OSS Bucket, LRS (default): Locally redundant LRS, which stores your data redundantly on different storage devices in the same availability zone. ZRS: Intra-city redundant ZRS, which uses a multi-availability zone (AZ) mechanism to store your data redundantly in three availability zones in the same region. | No
| RegionId | string | AlibabaCloud region ID | No
| StorageClass | string | The Storage Type of AlibabaCloud OSS Bucket, The value range is as follows: Standard (default): standard storage, IA: infrequent access, Archive: archive storage, ColdArchive: cold archive storage, DeepColdArchive: deep cold archive storage | No
</details>
<details>
<summary>OSS_DeleteBucket</summary>

**Description**:

```
删除指定的OSS存储空间。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| BucketName | string | AlibabaCloud OSS Bucket Name | Yes
| RegionId | string | AlibabaCloud region ID | No
</details>
<details>
<summary>ECS_DescribeInstances</summary>

**Description**:

```
本接口支持根据不同请求条件查询实例列表，并关联查询实例的详细信息。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| AdditionalAttributes | array | 实例其他属性列表。 参数类型: array,参数示例：META_OPTIONS | No
| DeviceAvailable | boolean | >该参数正在邀测中，暂不支持使用。 参数类型: boolean,参数示例：false | No
| DryRun | boolean | 是否只预检此次请求。取值范围：

- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DryRunOperation。  
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。 

默认值：false。 参数类型: boolean,参数示例：false | No
| EipAddresses | array | 实例的弹性公网IP列表。当InstanceNetworkType=vpc时该参数生效，取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  参数类型: string,参数示例：["42.1.1.**", "42.1.2.**", … "42.1.10.**"] | No
| HpcClusterId | string | 实例所在的HPC集群ID。 参数类型: string,参数示例：hpc-bp67acfmxazb4p**** | No
| HttpEndpoint | string | 是否启用实例元数据的访问通道。取值范围：
- enabled：启用。
- disabled：禁用。

默认值：enabled。
>有关实例元数据的更多信息，请参见[实例元数据概述](~~49122~~)。 参数类型: string,参数示例：enabled | No
| HttpPutResponseHopLimit | integer | >该参数暂未开放使用。 参数类型: integer,参数示例：0 | No
| HttpTokens | string | 访问实例元数据时是否强制使用加固模式（IMDSv2）。取值范围：
- optional：不强制使用。
- required：强制使用。设置该取值后，普通模式无法访问实例元数据。

默认值：optional。
>有关访问实例元数据模式的更多信息，请参见[实例元数据访问模式](~~150575~~)。 参数类型: string,参数示例：optional | No
| ImageId | string | 镜像ID。 参数类型: string,参数示例：m-bp67acfmxazb4p**** | No
| InnerIpAddresses | string | 经典网络类型实例的内网IP列表。当InstanceNetworkType=classic时生效，取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  参数类型: string,参数示例：["10.1.1.1", "10.1.2.1", … "10.1.10.1"] | No
| InstanceChargeType | string | 实例的计费方式。取值范围： 
         
- PostPaid：按量付费。 
- PrePaid：包年包月。 参数类型: string,参数示例：PostPaid | No
| InstanceIds | array | 实例ID。取值可以由多个实例ID组成一个JSON数组，最多支持100个ID，ID之间用半角逗号（,）隔开。  参数类型: string,参数示例：["i-bp67acfmxazb4p****", "i-bp67acfmxazb4p****", … "i-bp67acfmxazb4p****"] | No
| InstanceName | string | 实例名称，支持使用通配符*进行模糊搜索。  参数类型: string,参数示例：Test | No
| InstanceNetworkType | string | 实例网络类型。取值范围：

- classic：经典网络。
- vpc：专有网络VPC。 参数类型: string,参数示例：vpc | No
| InstanceType | string | 实例的规格。 参数类型: string,参数示例：ecs.g5.large | No
| InstanceTypeFamily | string | 实例的规格族。 参数类型: string,参数示例：ecs.g5 | No
| InternetChargeType | string | 公网带宽计费方式。取值范围：

- PayByBandwidth：按固定带宽计费。
- PayByTraffic：按使用流量计费。

> **按使用流量计费**模式下的出入带宽峰值都是带宽上限，不作为业务承诺指标。当出现资源争抢时，带宽峰值可能会受到限制。如果您的业务需要有带宽的保障，请使用**按固定带宽计费**模式。 参数类型: string,参数示例：PayByTraffic | No
| IoOptimized | boolean | 是否是I/O优化型实例。取值范围：

- true：是。
- false：否。 参数类型: boolean,参数示例：true | No
| Ipv6Address | array | 为弹性网卡指定的IPv6地址。 参数类型: array,参数示例： | No
| KeyPairName | string | 实例使用的SSH密钥对名称。 参数类型: string,参数示例：KeyPairNameTest | No
| LockReason | string | 资源被锁定的原因。取值范围：

- financial：因欠费被锁定。

- security：因安全原因被锁定。

- Recycling：抢占式实例的待释放锁定状态。

- dedicatedhostfinancial：因为专有宿主机欠费导致ECS实例被锁定。

- refunded：因退款被锁定。 参数类型: string,参数示例：security | No
| MaxResults | integer | 分页查询时每页行数。最大值为100。

默认值：

- 当不设置值或设置的值小于10时，默认值为10。
- 当设置的值大于100时，默认值为100。 参数类型: integer,参数示例：10 | No
| NeedSaleCycle | boolean | >该参数正在邀测中，暂不支持使用。 参数类型: boolean,参数示例：false | No
| NextToken | string | 查询凭证（Token），取值为上一次API调用返回的`NextToken`参数值。 参数类型: string,参数示例：caeba0bbb2be03f84eb48b699f0a4883 | No
| PageNumber | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 参数类型: integer,参数示例：1 | No
| PageSize | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 参数类型: integer,参数示例：10 | No
| PrivateIpAddresses | array | VPC网络类型实例的私有IP。当InstanceNetworkType=vpc时生效，取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  参数类型: string,参数示例：["172.16.1.1", "172.16.2.1", … "172.16.10.1"] | No
| PublicIpAddresses | array | 实例的公网IP列表。取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  参数类型: string,参数示例：["42.1.1.**", "42.1.2.**", … "42.1.10.**"] | No
| RdmaIpAddresses | string | HPC实例的RDMA网络IP。 参数类型: string,参数示例：10.10.10.102 | No
| RegionId | string | 实例所属的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 实例所在的企业资源组ID。使用该参数过滤资源时，资源数量不能超过1000个。

>不支持默认资源组过滤。 参数类型: string,参数示例：rg-bp67acfmxazb4p**** | No
| SecurityGroupId | string | 实例所属的安全组。 参数类型: string,参数示例：sg-bp67acfmxazb4p**** | No
| Status | string | 实例状态。取值范围： 

- Pending：创建中。
- Running：运行中。
- Starting：启动中。
- Stopping：停止中。
- Stopped：已停止。 参数类型: string,参数示例：Running | No
| Tag | array | 标签列表。 参数类型: array,参数示例： | No
| VSwitchId | string | 交换机ID。 参数类型: string,参数示例：vsw-bp67acfmxazb4p**** | No
| VpcId | string | 专有网络VPC ID。 参数类型: string,参数示例：v-bp67acfmxazb4p**** | No
| ZoneId | string | 可用区ID。 参数类型: string,参数示例：cn-hangzhou-g | No
</details>
<details>
<summary>ECS_DescribeRegions</summary>

**Description**:

```
根据计费方式、资源类型等参数查询地域信息列表。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| AcceptLanguage | string | 根据汉语、英语和日语筛选返回结果。更多详情，请参见[RFC 7231](https://tools.ietf.org/html/rfc7231)。取值范围：  
         
- zh-CN：简体中文。
- zh-TW：繁体中文。
- en-US：英文。
- ja：日文。
- fr：法语。
- de：德语。
- ko：韩语。

默认值：zh-CN。 参数类型: string,参数示例：zh-CN | No
| InstanceChargeType | string | 实例的计费方式，更多信息，请参见[计费概述](~~25398~~)。取值范围：

- PrePaid：包年包月。此时，请确认自己的账号支持余额支付或者信用支付，否则将报错InvalidPayMethod。
- PostPaid：按量付费。
- SpotWithPriceLimit：设置上限价格。
- SpotAsPriceGo：系统自动出价，最高按量付费价格。

默认值：PostPaid。 参数类型: string,参数示例：PrePaid | No
| RegionId | string | 地域ID | No
| ResourceType | string | 资源类型。取值范围：

-  instance：ECS实例。
-  disk：磁盘。
-  reservedinstance：预留实例券。
-  scu：存储容量单位包。

默认值：instance。 参数类型: string,参数示例：instance | No
</details>
<details>
<summary>ECS_DescribeZones</summary>

**Description**:

```
根据地域ID、计费方式等参数查询可用区信息列表。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| AcceptLanguage | string | 根据汉语、英语和日语筛选返回结果。更多信息，请参见[RFC 7231](https://tools.ietf.org/html/rfc7231)。取值范围：  
         
- zh-CN：简体中文。
- zh-TW：繁体中文。
- en-US：英文。
- ja：日文。
- fr：法语。
- de：德语。
- ko：韩语。

默认值：zh-CN。 参数类型: string,参数示例：zh-CN | No
| InstanceChargeType | string | 可用区里支持的资源计费方式。更多信息，请参见[计费概述](~~25398~~)。取值范围： 

- PrePaid：包年包月。
- PostPaid：按量付费。

默认值：PostPaid。 参数类型: string,参数示例：PostPaid | No
| RegionId | string | 可用区所在的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 参数类型: string,参数示例：cn-hangzhou | Yes
| SpotStrategy | string | 按量付费实例的竞价策略。当`InstanceChargeType=PostPaid`时，您可以传入该参数。更多信息，请参见[抢占式实例](~~52088~~)。取值范围：
         
- NoSpot：正常按量付费实例。
- SpotWithPriceLimit：设置上限价格的抢占式实例。
- SpotAsPriceGo：系统自动出价，最高按量付费价格。

默认值：NoSpot。 参数类型: string,参数示例：NoSpot | No
| Verbose | boolean | 是否展示详细信息。

- true：展示。
- false：不展示。

默认值：true。 参数类型: boolean,参数示例：false | No
</details>
<details>
<summary>ECS_DescribeAccountAttributes</summary>

**Description**:

```
查询您在一个阿里云地域下能创建的ECS资源配额。包括您能创建的安全组数量、弹性网卡数量、按量付费vCPU核数、抢占式实例vCPU核数、按量付费云盘总容量配额、专用宿主机数量、网络类型以及账号是否已完成实名认证。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| AttributeName | array | 查询某类资源在指定地域下的使用配额，N的取值范围为1~8。取值范围：

- instance-network-type：可选择的网络类型。
- max-security-groups：安全组数量。
- max-elastic-network-interfaces：弹性网卡的数量。
- max-postpaid-instance-vcpu-count：按量付费实例的vCPU核数上限。
- max-spot-instance-vcpu-count：抢占式实例vCPU核数上限。
- used-postpaid-instance-vcpu-count：已使用按量付费实例的vCPU核数。
- used-spot-instance-vcpu-count：已使用抢占式实例vCPU核数。
- max-postpaid-yundisk-capacity：用作数据盘的按量付费云盘的总容量上限。（该参数值已弃用）
- used-postpaid-yundisk-capacity：已使用的用作数据盘的按量付费云盘容量。（该参数值已弃用）
- max-dedicated-hosts：专用宿主机数量。
- supported-postpaid-instance-types：按量付费I/O优化实例规格。
- max-axt-command-count：云助手命令的数量。
- max-axt-invocation-daily：每天可以执行的云助手命令次数。
- real-name-authentication：账号是否完成了实名认证。

    > 您只有完成了实名认证才可以在中国内地地域中创建ECS实例。
- max-cloud-assistant-activation-count：可创建的云助手托管实例激活码数量上限。

默认值为空。 参数类型: array,参数示例：max-security-groups | No
| RegionId | string | 地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。  参数类型: string,参数示例：cn-hangzhou | Yes
| ZoneId | string | 可用区ID。 参数类型: string,参数示例：cn-hangzhou-b | No
</details>
<details>
<summary>ECS_DescribeAvailableResource</summary>

**Description**:

```
查询可用区的资源库存状态。您可以在某一可用区创建实例（RunInstances）或者修改实例规格（ModifyInstanceSpec）时查询该可用区的资源库存状态。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Cores | integer | 实例规格的vCPU内核数目。取值参见[实例规格族](~~25378~~)。

当DestinationResource取值为InstanceType时，Cores才为有效参数。  参数类型: integer,参数示例：2 | No
| DataDiskCategory | string | 数据盘类型。取值范围： 
         
- cloud：普通云盘。
- cloud_efficiency：高效云盘。
- cloud_ssd：SSD云盘。
- ephemeral_ssd：本地SSD盘。
- cloud_essd：ESSD云盘。
- cloud_auto：ESSD AutoPL云盘。
<props="china">
- cloud_essd_entry：ESSD Entry云盘。
</props> 参数类型: string,参数示例：cloud_ssd | No
| DedicatedHostId | string | 专有宿主机ID。 参数类型: string,参数示例：dh-bp165p6xk2tlw61e**** | No
| DestinationResource | string | 要查询的资源类型。取值范围： 
         
- Zone：可用区。
- IoOptimized：I/O优化。
- InstanceType：实例规格。
- Network：网络类型。
- ddh：专有宿主机。
- SystemDisk：系统盘。
- DataDisk：数据盘。

>当DestinationResource取值为`SystemDisk`时，由于系统盘受实例规格限制，此时必须传入InstanceType。

参数DestinationResource的取值方式请参见本文中的**接口说明**。 参数类型: string,参数示例：InstanceType | Yes
| InstanceChargeType | string | 资源的计费方式。更多信息，请参见[计费概述](~~25398~~)。取值范围： 
       
- PrePaid：包年包月。  
- PostPaid：按量付费。

默认值：PostPaid。 参数类型: string,参数示例：PrePaid | No
| InstanceType | string | 实例规格。更多信息，请参见[实例规格族](~~25378~~)，您也可以调用[DescribeInstanceTypes](~~25620~~)接口获得最新的规格表。

参数InstanceType的取值方式请参见本文开头的**接口说明**。 参数类型: string,参数示例：ecs.g5.large | No
| IoOptimized | string | 是否为I/O优化实例。取值范围： 
         
- none：非I/O优化实例。
- optimized：I/O优化实例。


默认值：optimized。 参数类型: string,参数示例：optimized | No
| Memory | number | 实例规格的内存大小，单位为GiB。取值参见[实例规格族](~~25378~~)。

当DestinationResource取值为InstanceType时，Memory才为有效参数。  参数类型: number,参数示例：8.0 | No
| NetworkCategory | string | 网络类型。取值范围： 
        
- vpc：专有网络。
- classic：经典网络。
          参数类型: string,参数示例：vpc | No
| RegionId | string | 目标地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceType | string | 资源类型。取值范围：

- instance：ECS实例。
- disk：云盘。
- reservedinstance：预留实例券。
- ddh：专有宿主机。 参数类型: string,参数示例：instance | No
| Scope | string | 预留实例券的范围。取值范围：
         
- Region：地域级别。
- Zone：可用区级别。 参数类型: string,参数示例：Region | No
| SpotDuration | integer | 抢占式实例的保留时长，单位为小时。 默认值：1。取值范围：
- 1：创建后阿里云会保证实例运行1小时不会被自动释放；超过1小时后，系统会自动比较出价与市场价格、检查资源库存，来决定实例的持有和回收。
- 0：创建后，阿里云不保证实例运行1小时，系统会自动比较出价与市场价格、检查资源库存，来决定实例的持有和回收。

实例回收前5分钟阿里云会通过ECS系统事件向您发送通知。抢占式实例按秒计费，建议您结合具体任务执行耗时来选择合适的保留时长。

> 当`InstanceChargeType`取值为`PostPaid`，并且`SpotStrategy`值为`SpotWithPriceLimit`或`SpotAsPriceGo`时该参数生效。 参数类型: integer,参数示例：1 | No
| SpotStrategy | string | 按量付费实例的竞价策略。取值范围： 
         
- NoSpot：正常按量付费实例。
- SpotWithPriceLimit：设置上限价格的抢占式实例。
- SpotAsPriceGo：系统自动出价，最高按量付费价格。

默认值：NoSpot。

当参数`InstanceChargeType`取值为`PostPaid`时，参数`SpotStrategy`才有效。 参数类型: string,参数示例：NoSpot | No
| SystemDiskCategory | string | 系统盘类型。取值范围： 
         
- cloud：普通云盘。
- cloud_efficiency：高效云盘。
- cloud_ssd：SSD云盘。
- ephemeral_ssd：本地SSD盘。
- cloud_essd：ESSD云盘。
- cloud_auto：ESSD AutoPL云盘。
<props="china">
- cloud_essd_entry：ESSD Entry云盘。
</props>

默认值：cloud_efficiency。

> 参数ResourceType取值为instance、DestinationResource取值为DataDisk时，参数SystemDiskCategory是必选参数。如果未传递参数值，则以默认值生效。 参数类型: string,参数示例：cloud_ssd | No
| ZoneId | string | 可用区ID。

默认值：无。返回该地域（`RegionId`）下所有可用区符合查询条件的资源。 参数类型: string,参数示例：cn-hangzhou-e | No
</details>
<details>
<summary>ECS_DescribeImages</summary>

**Description**:

```
指定ImageId、镜像被使用场景、Filter过滤等参数，查询您可以使用的镜像资源列表。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ActionType | string | 镜像需要被使用到的场景。取值范围：

- CreateEcs（默认）：创建实例。
- ChangeOS：更换系统盘/更换操作系统。 参数类型: string,参数示例：CreateEcs | No
| Architecture | string | 镜像的体系架构。取值范围：

- i386。
- x86_64。
- arm64。 参数类型: string,参数示例：i386 | No
| DryRun | boolean | 是否只预检此次请求。
         
- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DryRunOperation。  
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。 

默认值：false。 参数类型: boolean,参数示例：false | No
| Filter | array | 查询资源时的筛选条件列表。 参数类型: array,参数示例： | No
| ImageFamily | string | 镜像族系名称，查询镜像时可通过设置该参数来过滤当前族系对应的镜像。

默认值：空。
> 阿里云官方镜像关联的镜像族系信息请参见[公共镜像概述](~~108393~~)。 参数类型: string,参数示例：hangzhou-daily-update | No
| ImageId | string | 镜像ID。

<details>
<summary>镜像ID的命名规则</summary>

- 公共镜像：以操作系统版本号、架构、语言和发布日期命名。例如，Windows Server 2008 R2企业版、64位英文系统的镜像ID为win2008r2_64_ent_sp1_en-us_40G_alibase_20190318.vhd。

- 自定义镜像、共享镜像、云市场镜像、社区镜像的镜像：以m开头。

</details> 参数类型: string,参数示例：m-bp1g7004ksh0oeuc**** | No
| ImageName | string | 镜像名称。支持模糊搜索。 参数类型: string,参数示例：testImageName | No
| ImageOwnerAlias | string | 镜像来源。取值范围：

- system：阿里云官方提供的，且不是通过云市场发布的镜像，和控制台中的“公共镜像”概念不同。
- self：您创建的自定义镜像。
- others：包含共享镜像（其他阿里云用户直接共享给您的镜像）和社区镜像（任意阿里云用户将其自定义镜像完全公开共享后的镜像）。您需要注意：
    - 查找社区镜像时，IsPublic必须为true。
    - 查找共享镜像时，IsPublic需要设置为false或者不传值。
- marketplace：阿里云或者第三方供应商ISV在云市场发布的镜像，需要和ECS一起购买。请自行留意云市场镜像的收费详情。

默认值：空。

>空表示返回取值为system、self以及others的结果。 参数类型: string,参数示例：self | No
| ImageOwnerId | integer | 镜像所属的阿里云账号ID。该参数仅在查询共享镜像以及社区镜像时生效。

 参数类型: integer,参数示例：20169351435666**** | No
| InstanceType | string | 为指定的实例规格查询可以使用的镜像。 参数类型: string,参数示例：ecs.g5.large | No
| IsPublic | boolean | 是否查询已发布的社区镜像。取值范围：

- true：查询已发布的社区镜像。当您指定该参数值为true时，ImageOwnerAlias必须为others。
- false：查询除社区镜像的其他镜像类型，具体以ImageOwnerAlias参数值为准。

默认值：false。 参数类型: boolean,参数示例：false | No
| IsSupportCloudinit | boolean | 镜像是否支持cloud-init。 参数类型: boolean,参数示例：true | No
| IsSupportIoOptimized | boolean | 镜像是否可以运行在I/O优化实例上。 参数类型: boolean,参数示例：true | No
| OSType | string | 镜像的操作系统类型。取值范围：

- windows。
- linux。 参数类型: string,参数示例：linux | No
| PageNumber | integer | 镜像资源列表的页码。

起始值：1。

默认值：1。 参数类型: integer,参数示例：1 | No
| PageSize | integer | 分页查询时设置的每页行数。

最大值：100。

默认值：10。 参数类型: integer,参数示例：10 | No
| RegionId | string | 镜像所属的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 自定义镜像所在的企业资源组ID。使用该参数过滤资源时，资源数量不能超过1000个。

>不支持默认资源组过滤。 参数类型: string,参数示例：rg-bp67acfmxazb4p**** | No
| ShowExpired | boolean | 订阅型镜像是否已经超过使用期限。 参数类型: boolean,参数示例：false | No
| SnapshotId | string | 根据某一快照ID创建的自定义镜像。 参数类型: string,参数示例：s-bp17ot2q7x72ggtw**** | No
| Status | string | 查询指定状态的镜像，如果不配置此参数，默认只返回Available状态的镜像。取值范围：

- Creating：镜像正在创建中。
- Waiting：多任务排队中。
- Available（默认）：您可以使用的镜像。
- UnAvailable：您不能使用的镜像。
- CreateFailed：创建失败的镜像。
- Deprecated：已弃用的镜像。

默认值：Available。当前参数支持同时取多个值，值之间以半角逗号（,）隔开。 参数类型: string,参数示例：Available | No
| Tag | array | 标签列表。 参数类型: array,参数示例： | No
| Usage | string | 镜像是否已经运行在ECS实例中。取值范围：

- instance：镜像处于运行状态，有ECS实例使用。
- none：镜像处于闲置状态，暂无ECS实例使用。 参数类型: string,参数示例：instance | No
</details>
<details>
<summary>ECS_DescribeSecurityGroups</summary>

**Description**:

```
本接口用于查询安全组基本信息列表，支持您通过地域、安全组ID、安全组类型等不同参数查询。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| DryRun | boolean | 是否只预检此次请求。取值范围：
         
- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DryRunOperation。
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。

默认值为false。 参数类型: boolean,参数示例：false | No
| FuzzyQuery | boolean | >该参数已废弃。 参数类型: boolean,参数示例：null | No
| IsQueryEcsCount | boolean | 是否查询安全组的容量信息。传True时，返回值中的`EcsCount`和`AvailableInstanceAmount`有效。
>该参数已废弃。 参数类型: boolean,参数示例：null | No
| MaxResults | integer | 分页查询时每页的最大条目数。一旦设置该参数，即表示使用`MaxResults`与`NextToken`组合参数的查询方式。

最大值为100。

默认值为10。 参数类型: integer,参数示例：10 | No
| NetworkType | string | 安全组的网络类型。取值范围：

- vpc：专有网络。
- classic：经典网络。 参数类型: string,参数示例：vpc | No
| NextToken | string | 查询凭证（Token）。取值为上一次调用该接口返回的NextToken参数值，初次调用接口时无需设置该参数。 参数类型: string,参数示例：e71d8a535bd9cc11 | No
| PageNumber | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 参数类型: integer,参数示例：1 | No
| PageSize | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 参数类型: integer,参数示例：10 | No
| RegionId | string | 地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 安全组所在的企业资源组ID。使用该参数过滤资源时，资源数量不能超过1000个。您可以调用[ListResourceGroups](~~158855~~)查询资源组列表。

>不支持默认资源组过滤。 参数类型: string,参数示例：rg-bp67acfmxazb4p**** | No
| SecurityGroupId | string | 安全组ID。 参数类型: string,参数示例：sg-bp67acfmxazb4p**** | No
| SecurityGroupIds | array | 安全组ID列表。一次最多支持100个安全组ID，ID之间用半角逗号（,）隔开，格式为JSON数组。 参数类型: string,参数示例：["sg-bp67acfmxazb4p****", "sg-bp67acfmxazb4p****", "sg-bp67acfmxazb4p****",....] | No
| SecurityGroupName | string | 安全组名称。 参数类型: string,参数示例：SGTestName | No
| SecurityGroupType | string | 安全组类型。取值范围：
- normal：普通安全组。
- enterprise：企业安全组。

> 当不为该参数传值时，表示查询所有类型的安全组。 参数类型: string,参数示例：normal | No
| ServiceManaged | boolean | 是否为托管安全组。取值范围：

- true：是托管安全组。
- false：不是托管安全组。 参数类型: boolean,参数示例：false | No
| Tag | array | 标签列表。 参数类型: array,参数示例： | No
| VpcId | string | 安全组所在的专有网络ID。 参数类型: string,参数示例：vpc-bp67acfmxazb4p**** | No
</details>
<details>
<summary>ECS_DeleteInstances</summary>

**Description**:

```
本接口用于批量删除或者释放按量付费实例或者到期的包年包月实例，支持通过参数设置决定云盘是否释放或转换为按量付费保留。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ClientToken | string | 保证请求幂等性。从您的客户端生成一个参数值，确保不同请求间该参数值唯一。**ClientToken**只支持ASCII字符，且不能超过64个字符。更多信息，请参见[如何保证幂等性](~~25693~~)。 参数类型: string,参数示例：123e4567-e89b-12d3-a456-426655440000 | No
| DryRun | boolean | 是否只预检此次请求。

- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DRYRUN.SUCCESS。
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。

默认值：false。 参数类型: boolean,参数示例：false | No
| Force | boolean | 是否强制释放**运行中**（`Running`）的ECS实例。

- true：强制释放**运行中**（`Running`）的实例。
- false：正常释放实例，此时实例必须处于**已停止**（`Stopped`）状态。

默认值：false。
><warning>强制释放相当于断电，实例内存以及存储中的临时数据都会被擦除，无法恢复。></warning> 参数类型: boolean,参数示例：false | No
| ForceStop | boolean | 释放**运行中**（`Running`）的实例时的是否采取强制关机策略。仅当`Force=true`时生效。取值范围：

- true：强制关机并释放实例。相当于典型的断电操作，实例会直接进入资源释放流程。
><warning>强制释放相当于断电，实例内存以及存储中的临时数据都会被擦除，无法恢复。></warning>
- false：在实例释放前，系统将优先执行标准关机流程，该模式会导致实例释放动作持续几分钟。用户在操作系统关机时，配置一些业务排水动作，从而减少业务系统的噪声。

默认值：true。 参数类型: boolean,参数示例：true | No
| InstanceId | array | 实例ID数组。数组长度：1~100。 参数类型: array,参数示例：i-bp1g6zv0ce8oghu7**** | Yes
| RegionId | string | 实例所属的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 参数类型: string,参数示例：cn-hangzhou | Yes
| TerminateSubscription | boolean | 是否释放已到期的包年包月实例。

- true：释放。
- false：不释放。

默认值：false。 参数类型: boolean,参数示例：false | No
</details>
<details>
<summary>VPC_DescribeVpcs</summary>

**Description**:

```
查询已创建的VPC。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| DhcpOptionsSetId | string | DHCP选项集的ID。 参数类型: string,参数示例：dopt-o6w0df4epg9zo8isy**** | No
| DryRun | boolean | 是否只预检此次请求，取值：

- **true**：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码`DryRunOperation`。

- **false**（默认值）：发送正常请求，通过检查后返回HTTP 2xx状态码并直接查询资源状况。 参数类型: boolean,参数示例：false | No
| EnableIpv6 | boolean | 是否查询指定地域下开启IPv6网段的VPC，默认为空值（空值则不根据是否开启IPv6网段做过滤），取值：

- **false**：不开启。
- **true**：开启。 参数类型: boolean,参数示例：false | No
| IsDefault | boolean | 是否查询指定地域下的默认VPC，取值： 

- **true**（默认值）：查询指定地域下的默认VPC。  

- **false**：不查询默认VPC。  
 参数类型: boolean,参数示例：false | No
| PageNumber | integer |  列表的页码，默认值为**1**。   参数类型: integer,参数示例：1 | No
| PageSize | integer | 分页查询时每页的行数，最大值为**50**，默认值为**10**。   参数类型: integer,参数示例：10 | No
| RegionId | string | VPC所在的地域ID。 

您可以通过调用[DescribeRegions](~~448570~~)接口获取地域ID。 参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 要查询的VPC所属的资源组ID。 参数类型: string,参数示例：rg-acfmxvfvazb4p**** | No
| Tag | array | 资源的标签。 参数类型: array,参数示例： | No
| VpcId | string | VPC的ID。 

最多支持指定20个VPC ID，多个VPC的ID之间用半角逗号（,）隔开。  参数类型: string,参数示例：vpc-bp1b1xjllp3ve5yze**** | No
| VpcName | string | VPC的名称。 参数类型: string,参数示例：Vpc-1 | No
| VpcOwnerId | integer | VPC所属的阿里云账号ID。 参数类型: integer,参数示例：253460731706911258 | No
</details>
<details>
<summary>VPC_DescribeVSwitches</summary>

**Description**:

```
查询可组网的信息，内网按vswitch进行组网。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| DryRun | boolean | 是否只预检此次请求。取值：
- **true**：发送检查请求，不会创建资源（接口功能）。检查项包括是否填写了必需参数、请求格式、业务限制。如果检查不通过，则返回对应错误。如果检查通过，则返回错误码`DryRunOperation`。
- **false**（默认值）：发送正常请求，通过检查后返回HTTP 2xx状态码并直接进行操作。 参数类型: boolean,参数示例：true | No
| EnableIpv6 | boolean | 是否查询指定地域下开启IPv6网段的交换机，取值：

- **true**：查询指定地域下开启IPv6网段的交换机。

- **false**：不查询指定地域下开启IPv6网段的交换机。

如果不传入该参数，系统默认查询指定地域下的所有交换机。 参数类型: boolean,参数示例：false | No
| IsDefault | boolean | 是否查询指定地域下的默认交换机，取值： 

- **true**：查询指定地域下的默认交换机。  

- **false**：不查询指定地域下的默认交换机。  

如果不传入该参数，系统默认查询指定地域下的所有交换机。

 参数类型: boolean,参数示例：true | No
| PageNumber | integer |  列表的页码，默认值为**1**。   参数类型: integer,参数示例：1 | No
| PageSize | integer |  分页查询时每页的行数，最大值为**50**。默认值为**10**。   参数类型: integer,参数示例：10 | No
| RegionId | string | 交换机所属地域的ID。您可以通过调用[DescribeRegions](~~36063~~)接口获取地域ID。

> **RegionId**和**VpcId**参数至少输入一个。   参数类型: string,参数示例：cn-hangzhou | No
| ResourceGroupId | string | 交换机所属的资源组ID。 参数类型: string,参数示例：rg-bp67acfmxazb4ph**** | No
| RouteTableId | string | 路由表的ID。 参数类型: string,参数示例：vtb-bp145q7glnuzdvzu2**** | No
| Tag | array | 资源的标签。 参数类型: array,参数示例： | No
| VSwitchId | string | 要查询的交换机的ID。  参数类型: string,参数示例：vsw-23dscddcffvf3**** | No
| VSwitchName | string | 交换机的名称。

名称长度为1～128个字符，不能以`http://`或`https://`开头。 参数类型: string,参数示例：vSwitch | No
| VSwitchOwnerId | integer | 资源归属的阿里云账号ID。 参数类型: integer,参数示例：2546073170691**** | No
| VpcId | string | 要查询的交换机所属VPC的ID。 

> **RegionId**和**VpcId**参数至少输入一个。 参数类型: string,参数示例：vpc-25cdvfeq58pl**** | No
| ZoneId | string | 交换机所属可用区的ID。您可以通过调用[DescribeZones](~~36064~~)接口获取可用区ID。   参数类型: string,参数示例：cn-hangzhou-d | No
</details>
<details>
<summary>RDS_DescribeDBInstances</summary>

**Description**:

```
该接口用于查询RDS的实例列表。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Category | string | 实例的系列。取值：
- **Basic**：基础系列
- **HighAvailability**：高可用系列
- **cluster**：集群系列
- **serverless_basic**：Serverless 参数类型: string,参数示例：cluster | No
| ClientToken | string | 用于保证请求的幂等性，防止重复提交请求。由客户端生成该参数值，要保证在不同请求间唯一，最大值不超过64个ASCII字符，且该参数值中不能包含非ASCII字符。 参数类型: string,参数示例：ETnLKlblzczshOTUbOCz**** | No
| ConnectionMode | string | 实例的访问模式，取值：
* **Standard**：标准访问模式
* **Safe**：数据库代理模式

默认返回所有访问模式下的实例。 参数类型: string,参数示例：Standard | No
| ConnectionString | string | 实例的连接地址。通过该连接地址查询对应的实例。 参数类型: string,参数示例：rm-uf6wjk5****.mysql.rds.aliyuncs.com | No
| DBInstanceClass | string | 实例规格，详见[实例规格表](~~26312~~)。 参数类型: string,参数示例：rds.mys2.small | No
| DBInstanceId | string | 实例ID。 参数类型: string,参数示例：rm-uf6wjk5**** | No
| DBInstanceStatus | string | 实例状态，详情请参见[实例状态表](~~26315~~)。 参数类型: string,参数示例：Running | No
| DBInstanceType | string | 实例类型，取值：
* **Primary**：主实例
* **Readonly**：只读实例
* **Guard**：灾备实例
* **Temp**：临时实例

默认返回所有实例类型。 参数类型: string,参数示例：Primary | No
| DedicatedHostGroupId | string | 专属集群ID。 参数类型: string,参数示例：dhg-7a9**** | No
| DedicatedHostId | string | 专属集群内的主机ID。 参数类型: string,参数示例：i-bp**** | No
| Engine | string | 数据库类型，取值：
* **MySQL**
* **SQLServer**
* **PostgreSQL**
* **MariaDB**

默认返回所有数据库类型。 参数类型: string,参数示例：MySQL | No
| EngineVersion | string | 数据库版本。 参数类型: string,参数示例：8.0 | No
| Expired | string | 实例的过期状态，取值：
* **True**：已过期
* **False**：未过期 参数类型: string,参数示例：True | No
| Filter | string | 实例过滤条件参数及其值的JSON串 参数类型: string,参数示例：{"babelfishEnabled":"true"} | No
| InstanceLevel | integer | 是否返回实例系列（Category）信息，取值：
* **0**：不返回
* **1**：返回 参数类型: integer,参数示例：0 | No
| InstanceNetworkType | string | 实例的网络类型，取值：
* **VPC**：专有网络下的实例
* **Classic**：经典网络下的实例

默认返回所有网络类型下的实例。 参数类型: string,参数示例：Classic | No
| MaxResults | integer | 每页记录数。取值：**1~100**。

默认值：**30**。
>传入该参数，则**PageSize**和**PageNumber**参数不可用。 参数类型: integer,参数示例：30 | No
| NextToken | string | 翻页凭证。取值为上一次调用**DescribeDBInstances**接口时返回的**NextToken**参数值。如果调用结果分多页展示，再次调用接口时传入该值便可以展示下一页的内容。 参数类型: string,参数示例：o7PORW5o2TJg**** | No
| PageNumber | integer | 页码，取值：大于0且不超过Integer的最大值。

默认值：**1**。 参数类型: integer,参数示例：1 | No
| PageSize | integer | 每页记录数，取值：**1**~**100**。

默认值：**30**。 参数类型: integer,参数示例：30 | No
| PayType | string | 付费类型，取值：
* **Postpaid**：按量付费
* **Prepaid**：包年包月 参数类型: string,参数示例：Postpaid | No
| RegionId | string | 地域ID。可调用DescribeRegions获取。 参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 资源组ID。 参数类型: string,参数示例：rg-acfmy**** | No
| SearchKey | string | 可基于实例ID或者实例备注模糊搜索。 参数类型: string,参数示例：rm-uf6w | No
| Tags | string | 查询绑定有该标签的实例，包括TagKey和TagValue。单次最多支持传入5组值，格式：{"key1":"value1","key2":"value2"...}。 参数类型: string,参数示例：{"key1":"value1"} | No
| VSwitchId | string | 交换机ID。 参数类型: string,参数示例：vsw-uf6adz52c2p**** | No
| VpcId | string | VPC ID。 参数类型: string,参数示例：vpc-uf6f7l4fg90**** | No
| ZoneId | string | 可用区ID。 参数类型: string,参数示例：cn-hangzhou-a | No
| proxyId | string | 废弃参数，无需配置。 参数类型: string,参数示例：API | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | CMS_GetCpuLoadavgData | description | 41652de13b3c7c58e42e6a4492cf31b46e843206e322a9449abd05839b8c21a5 |
| tools | CMS_GetCpuLoadavgData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetCpuLoadavgData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetCpuUsageData | description | b48ee53ba21d5cda0a95da59872ad029104c842ce44ec4e82d762296f52d88e5 |
| tools | CMS_GetCpuUsageData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetCpuUsageData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetCpuloadavg15mData | description | 549b25638abfc79ee83bc07d5e7d903027d643dfa9ed9ccc6e58537021a5ddb0 |
| tools | CMS_GetCpuloadavg15mData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetCpuloadavg15mData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetCpuloadavg5mData | description | e2d6689f38908f260e174db620ee5030dc422730708276a88d86fa56c84b49c8 |
| tools | CMS_GetCpuloadavg5mData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetCpuloadavg5mData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetDiskTotalData | description | 4db1ae50ede0649ad2cb38bec3320d2f075d15a9013d752eae81fd57166034a7 |
| tools | CMS_GetDiskTotalData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetDiskTotalData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetDiskUsageData | description | 78aa3a39be7ed21f5c18757b871394dfd4ef2f89d3e8a1c458b9d6361f429e71 |
| tools | CMS_GetDiskUsageData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetDiskUsageData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetDiskUsedData | description | e226a9921aa9185b0e99598afebb8e4148b53cbfd23efe32a7b9a05f615298e6 |
| tools | CMS_GetDiskUsedData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetDiskUsedData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetMemUsageData | description | 5aac768c294daac21fdb877ee1a830914ad857c375f7145cd308cb4e493bc3dd |
| tools | CMS_GetMemUsageData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetMemUsageData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | CMS_GetMemUsedData | description | 3deb761f34fcb36343a7bc86816c4fbece4268664fe6313c0ec5e27a9fdbcb61 |
| tools | CMS_GetMemUsedData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | CMS_GetMemUsedData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | ECS_DeleteInstances | description | 1d4391135beaaf36967e0bcddd0a31bcf5927cb7a39c1bb062d6b2236e30d6c1 |
| tools | ECS_DeleteInstances | ClientToken | bac4b667b0f15b67d78030baea003bc7386765ac901d6eec4b0f3c34c7ed0bda |
| tools | ECS_DeleteInstances | DryRun | 8b2880c98fe600711dc20675773455de5e73937ed1bf50c4bfbe6db23b10cfc3 |
| tools | ECS_DeleteInstances | Force | 8cf4297826ffb03ba354875f0e4f5e66246fd5eda650a44ccccf410fec7ffc67 |
| tools | ECS_DeleteInstances | ForceStop | a55b06f1a5bdf8dc45be8fcce9ada00c491d07ec93a5dedc1b46fa9b96adf8c4 |
| tools | ECS_DeleteInstances | InstanceId | 48c9b4cfb12d358b4eaa239597a24429c4de2d22eabe91bc3ea89d125a9db223 |
| tools | ECS_DeleteInstances | RegionId | 995641f98f158eb9bf044ecf3bcbdfd27c2ab7d5f6f9abae6a9eba6358d4f412 |
| tools | ECS_DeleteInstances | TerminateSubscription | 833ee8396b32b1fb328cee2948df5302250ab70f96d07b0d13ef316648661cff |
| tools | ECS_DescribeAccountAttributes | description | 1778be5783909688e56baa9f09d33597f7c99ee1565170403be16241f30367a6 |
| tools | ECS_DescribeAccountAttributes | AttributeName | c3f4d92c7e851adeb16102f462fd6b48c3c4b1b55de09da1c9aa58aba3ac2b9a |
| tools | ECS_DescribeAccountAttributes | RegionId | 4ff89e74212de1fe9ceb33c919a960cab6874c21e25537609415f9ed76774cf8 |
| tools | ECS_DescribeAccountAttributes | ZoneId | d07659eaa42ed58c7ec2d72867c7ae99fb9e9de1835a02023683a34a87ffe538 |
| tools | ECS_DescribeAvailableResource | description | 5fa70d9722cdb8a377252c9f5f08d6f3049ea97412349445b06a1df15c500e8e |
| tools | ECS_DescribeAvailableResource | Cores | be11827f9da4395ce0d21f5836dcded503ca0a64ebafb3cd4bc42ff4bf31ac6e |
| tools | ECS_DescribeAvailableResource | DataDiskCategory | 2278475a48595c823825439eaaed230e95d844b772dcc99a63cf1e4f61ec2f87 |
| tools | ECS_DescribeAvailableResource | DedicatedHostId | 25b2c63ae5f415d0349ef1b2cbd135618632bbb563370f9e64de26bd2fbc72d7 |
| tools | ECS_DescribeAvailableResource | DestinationResource | f7a66037226e0b09ac69718cc429214e2287ff98cc024fab1b6fe856d67dd63e |
| tools | ECS_DescribeAvailableResource | InstanceChargeType | f066872f7a0eaf76a2f2c3016c873fc1c30a5e7749e2a17fc73c31a225ef371c |
| tools | ECS_DescribeAvailableResource | InstanceType | 2b184a54dac9c8979588981006899d1493254b63b19db8ff1bf9b4425af8a777 |
| tools | ECS_DescribeAvailableResource | IoOptimized | e60b3218ce1e608b8a44fa7d35a24d36cffe0874bd5b67c3d0bfa33d76d9e9c9 |
| tools | ECS_DescribeAvailableResource | Memory | 39611f2618c00789041b55928f6968d59dbb95e38d738ed1994801459c5326c3 |
| tools | ECS_DescribeAvailableResource | NetworkCategory | 9b45ad75461900b351a2a15d28e833cef665d498149856b5a4a07318116078c6 |
| tools | ECS_DescribeAvailableResource | RegionId | 9b3f584047259427f176e357a625858503cc3b62e0f5ebcde4cf837fa9d84069 |
| tools | ECS_DescribeAvailableResource | ResourceType | d0a927ab8a71c76bb899ec98672ab6952f39d2721ab33858fc80b2be0c9a1352 |
| tools | ECS_DescribeAvailableResource | Scope | 878e61006d462ebb8c4a28ab5838d42532c5d644f24429456e62c4cf55ac7aee |
| tools | ECS_DescribeAvailableResource | SpotDuration | f7ec4f9c2783e86ecf105b67dd3eef6c1d7432f435831bdcf79230c5837fcbeb |
| tools | ECS_DescribeAvailableResource | SpotStrategy | ba84fb51a0b9e7640e62bfe2aa6eef49a02793bd0d302907697dd3ec83345c72 |
| tools | ECS_DescribeAvailableResource | SystemDiskCategory | a4cc33aca1eddbbe7f5d1854b21ee737c6915d0845d0d711506870352365a12f |
| tools | ECS_DescribeAvailableResource | ZoneId | 744195ea131f085f12af223787c28f3b352572719b3d21d87a542f2f6dfea890 |
| tools | ECS_DescribeImages | description | 7b9e39af4a694e9e5d41d443d5629b647ce7fb947e0b2f2e9b6bd529a16a76a0 |
| tools | ECS_DescribeImages | ActionType | 0d0f0630c0289c1bb55b026687d70504ac762d572046daec997f17bc891d4d58 |
| tools | ECS_DescribeImages | Architecture | 0f711e44c57b959288d6f874ee6b895ec6e24f4ee5b7a24bcaf09336f80cdecb |
| tools | ECS_DescribeImages | DryRun | 81b4973ab48fd04b7470423fcb5639f1ccdd960d95949c1edb150bcd45ec6b5c |
| tools | ECS_DescribeImages | Filter | 5ebec602e2cfe9026ffe4766cf1ec75e76448f154c55d46e5245a9ba8e54c2e4 |
| tools | ECS_DescribeImages | ImageFamily | 713529548513e6e55b513369ea082e39d69a8e1f54716d7c23e4ebbef6600018 |
| tools | ECS_DescribeImages | ImageId | c94e18646bca013de72f115c72e1243846dd184bed056f5ee7e9b2ac6bb04d16 |
| tools | ECS_DescribeImages | ImageName | f0b125ba0b819f33a950838f203a11532345d7bdfa9f2f2ab01c2682d866d2c6 |
| tools | ECS_DescribeImages | ImageOwnerAlias | 0f2ca7e3e3c78d3cdd041cea33e108b4f5dadd001aa124558c08583bb6f87fa4 |
| tools | ECS_DescribeImages | ImageOwnerId | 11f31e369f18da36fdb00c991c07cd89c85829ba4e498c947e1df8f3927448c5 |
| tools | ECS_DescribeImages | InstanceType | 6cfa548234074273f38cefff812eb11c59c7d37d78e28d2992d7425135451ede |
| tools | ECS_DescribeImages | IsPublic | 48d1dd9a9a8c8de4f839eccded608a9ab8a3e9709b8ad2122cafbde767ec8e38 |
| tools | ECS_DescribeImages | IsSupportCloudinit | 3b16b22c7d66be8d48a251421ee77fcdfe3e4a29b25368d28320883d548b3c1d |
| tools | ECS_DescribeImages | IsSupportIoOptimized | 6cb4ee9ffa861a1c44eaa58dfa0c6442e8577ba246701ea69ac7e1cc34b3d131 |
| tools | ECS_DescribeImages | OSType | 2a7f445bfc8393f178838f28cd8532a8745e33851d054230de15f406327eb51f |
| tools | ECS_DescribeImages | PageNumber | 5142ef02b0ec2832c6ecabd80a05bc7911d3f21175c12265a77049482d035e8b |
| tools | ECS_DescribeImages | PageSize | d36739a3ebaac96294a663fff47bc24a3e7af19affbde6b22ff61e02de866908 |
| tools | ECS_DescribeImages | RegionId | 0e7b693aa52bd759fb115d6124729424444a6ceac5d770eb42e73a29a7ccab96 |
| tools | ECS_DescribeImages | ResourceGroupId | 7f76bbca8f5dc5d7d63c75bc05170b79c3707cf2900c07f22e02fee0ee7b722a |
| tools | ECS_DescribeImages | ShowExpired | 68d4be31cd1b9bb5d04994824f10740af927a53f5e4a1c5a4f845a28047623af |
| tools | ECS_DescribeImages | SnapshotId | d5736330c3f5438eadf635aee18b70136f76543cb815e7c47c20a5016605091b |
| tools | ECS_DescribeImages | Status | c11597fd33ae6cccf29bf5b70cbfc45a24f27b094ca658d9a65e4ab511f1d9f4 |
| tools | ECS_DescribeImages | Tag | 4e9ebf06aad244f961653a9054180cce685fa62532ba75a42b33e7020ee11925 |
| tools | ECS_DescribeImages | Usage | 1a7c063f1eee59a94814bbe075522fc59d67df0421481a948d1be1ed350a634d |
| tools | ECS_DescribeInstances | description | a28662a80361fdf89085f9d85fa5289ae7fd47ea0662ee8a203334b9128a198e |
| tools | ECS_DescribeInstances | AdditionalAttributes | 1c33b9734363179fcc72a49c66a1546408b37c2bca7a5d52758729ea33e4cd7e |
| tools | ECS_DescribeInstances | DeviceAvailable | d4d9d51c49d4699ba073a3077abd7a88398ef7264fe75ea072f286d4cd42bc72 |
| tools | ECS_DescribeInstances | DryRun | 66ff7edba883c2d94c9701fffbfea4ccf605305cb9f38be5d12ff17aeb3d4145 |
| tools | ECS_DescribeInstances | EipAddresses | 53a39329c4c508e51bd24ac79c7bfa1dc5a0061f0a28d4acac2c3b96f21dd016 |
| tools | ECS_DescribeInstances | HpcClusterId | c350de710f593180b03749704b929d7d730fb383d7162a25753ae925a89643a7 |
| tools | ECS_DescribeInstances | HttpEndpoint | 5c4e7d6792bd3fb480f8052cbfe174bf0207fd94b2ef5fdb7194c2f3cb4040b4 |
| tools | ECS_DescribeInstances | HttpPutResponseHopLimit | afc3fb46b829f5426b3e3f4bae656698a5624fea3b4fcf9f5c0be38cbf51f0dc |
| tools | ECS_DescribeInstances | HttpTokens | a9dbff4f60c34be9849087ceff267de9a1a89ec208e141fc198ab52d4d5009f6 |
| tools | ECS_DescribeInstances | ImageId | e47a4505d550400be2f81cd033661107fdab6d623a725f974d303f01993697d8 |
| tools | ECS_DescribeInstances | InnerIpAddresses | 8b623ae0cd91796926d3bbe2946c00b5ac567e8c431aa7d9d2954eff3081611e |
| tools | ECS_DescribeInstances | InstanceChargeType | f86188e8454f62570c7f606da851c114c2c034551b0053af4b194faef767403a |
| tools | ECS_DescribeInstances | InstanceIds | d32a88b6176e4174a46e020d50a9c9c056b8875812d3cd878f8006664c27abcd |
| tools | ECS_DescribeInstances | InstanceName | f7f11d97bee14df7333a70dd245398fc175ed54a430215a588938a89b4556dbf |
| tools | ECS_DescribeInstances | InstanceNetworkType | 69b39d69052a1852d66a1c2ca3fcd586deb9013f2a33ecb0ea100758cde87d4e |
| tools | ECS_DescribeInstances | InstanceType | 0e975450fea407bf2b81df64b56c2be9eb22a1c85909b87b250e91c3051ed799 |
| tools | ECS_DescribeInstances | InstanceTypeFamily | d5507cc5c0291401d6a67170905fd04eaa0f046137dfa39e0f96b1211011056e |
| tools | ECS_DescribeInstances | InternetChargeType | 1517c95eaac4e682ceaf1f337701160f2d17e0bdaa954a37dfdb65f0ece81d4e |
| tools | ECS_DescribeInstances | IoOptimized | 0fc874d90ba1c20e96e05237581af159d985d92a9a4224cc4b8b617c2a4e7fea |
| tools | ECS_DescribeInstances | Ipv6Address | 7295ee05890c2eba9ba709544c083b3f09d24170654b8864915e4f368d4c16d3 |
| tools | ECS_DescribeInstances | KeyPairName | 4a4f74a9c3120da1c0e7089f6a7eaa7eec283e081ac1c203ee075e0421e14041 |
| tools | ECS_DescribeInstances | LockReason | ece16ff324bdb01f8db81d447ee2bcb63f73aff7cab3a95c3c957832b429b03e |
| tools | ECS_DescribeInstances | MaxResults | 9647d1d7da3d2b65da6a06fad964d73a711982a7fe743730d480cbb0de0cd76e |
| tools | ECS_DescribeInstances | NeedSaleCycle | d4d9d51c49d4699ba073a3077abd7a88398ef7264fe75ea072f286d4cd42bc72 |
| tools | ECS_DescribeInstances | NextToken | f055311b338dc07a4a040108e3a16131f38e103b8981854f6e78133952ff477e |
| tools | ECS_DescribeInstances | PageNumber | 360d16a40d37ce7ac77b14df56693531c34bd765b8715449a2c5583e0e1e5ef0 |
| tools | ECS_DescribeInstances | PageSize | fc539899caace6e40bee71aca8715701f2cb8fc0d3754f0d31f46dd971e04eb5 |
| tools | ECS_DescribeInstances | PrivateIpAddresses | 9780ee9d5708812b28d04ea54289782d1477eb349f888255e4e3a913dc345169 |
| tools | ECS_DescribeInstances | PublicIpAddresses | efea5c341557f8e25d4cd650ea4db376da69054cde7afd91392311c62b1d5d8f |
| tools | ECS_DescribeInstances | RdmaIpAddresses | 18d7b645d905db68b588ae2ea0160fa0c9f2e133afce7e08268bfc876ced6825 |
| tools | ECS_DescribeInstances | RegionId | 995641f98f158eb9bf044ecf3bcbdfd27c2ab7d5f6f9abae6a9eba6358d4f412 |
| tools | ECS_DescribeInstances | ResourceGroupId | bdbc4baf50b86f2f37bcaa3576b02fcbaeb78db0a57ac96a2dc9511b4a520a6b |
| tools | ECS_DescribeInstances | SecurityGroupId | fa95b95a639efde5011d516e6b50e0aacc8dcc98d4e05508c170a0b8c34bfb00 |
| tools | ECS_DescribeInstances | Status | 10b70c9fb90b40d8ec691408a30fcdb82a246a297775bdbe8861d7aaa0b834cc |
| tools | ECS_DescribeInstances | Tag | 4e9ebf06aad244f961653a9054180cce685fa62532ba75a42b33e7020ee11925 |
| tools | ECS_DescribeInstances | VSwitchId | c0d9e910cb500e894d25ff47f64053614839d71286de5d4c3b63311cf7350a14 |
| tools | ECS_DescribeInstances | VpcId | f0f39742d72d0c83a8a5c368a149e6087e67c2f61359c84693e4f693c2102b91 |
| tools | ECS_DescribeInstances | ZoneId | 8957c7f84aaeb8e23c8fddd812fa6d6982752e67fcafb7a39f25241768123ce7 |
| tools | ECS_DescribeRegions | description | 724439e22c78a85a56a968d31a6288b6f86c13e37436e2a27d1afc0934421cc3 |
| tools | ECS_DescribeRegions | AcceptLanguage | cc8a5506b846193165fb73093c81514c563d10325c7a9e9bb21b809f8cdb1918 |
| tools | ECS_DescribeRegions | InstanceChargeType | 5a93cf6a6130b885a91422158dbacb88f77afcf7c127a6321163b0415e020c9f |
| tools | ECS_DescribeRegions | RegionId | 9503d3f99019306f9dac25f97f1cba93dfc9d40677af27024b204fa233b1c0aa |
| tools | ECS_DescribeRegions | ResourceType | efdda08c46102f77a32ed5e31db814cb69cc2f7a3299355f1110c06e73214c14 |
| tools | ECS_DescribeSecurityGroups | description | 974995f8def0cf8014a8e1a1271e3462a921755203768b6da8290db18eb45232 |
| tools | ECS_DescribeSecurityGroups | DryRun | 981eaa8d69e13fa43d80d0349c88ad7a584883b708d683ee9e4648cf1f4db25e |
| tools | ECS_DescribeSecurityGroups | FuzzyQuery | b9a8944970f46106e39528891d2a7d1a428276ca300de51a4422e90e185cb1d7 |
| tools | ECS_DescribeSecurityGroups | IsQueryEcsCount | 287f39048427101c1e03dfae8312ad259af5e605e4148a8605e5d5d67c9cdf42 |
| tools | ECS_DescribeSecurityGroups | MaxResults | bf7de2a702ef16d70ceee1de38e6acbf4e2d273bfb8e69de7975ba40f64d49aa |
| tools | ECS_DescribeSecurityGroups | NetworkType | f9a80b402b3dbf603002a0c06d162664966de8e06fcc319d264265340c97bcdc |
| tools | ECS_DescribeSecurityGroups | NextToken | 0745dbd4c674a956527d5ffabe30d36c3d373243c37eaebac02a8c6799051401 |
| tools | ECS_DescribeSecurityGroups | PageNumber | 360d16a40d37ce7ac77b14df56693531c34bd765b8715449a2c5583e0e1e5ef0 |
| tools | ECS_DescribeSecurityGroups | PageSize | fc539899caace6e40bee71aca8715701f2cb8fc0d3754f0d31f46dd971e04eb5 |
| tools | ECS_DescribeSecurityGroups | RegionId | ad85ccdb92cac3ba8b3eecd73f569063f9f9fe1d0a8f9f7ffb4ab87e3555fa2c |
| tools | ECS_DescribeSecurityGroups | ResourceGroupId | 737a15c47bf59a07fc19fd8bc369fe86fded8057af9c62f895d0ef8bdd130f3a |
| tools | ECS_DescribeSecurityGroups | SecurityGroupId | 4b04107f546ae648e916f206e6556c96050d29d67f88469e626bfabfa148f506 |
| tools | ECS_DescribeSecurityGroups | SecurityGroupIds | 64a5d0a5cdc801e7f2fa85573cad6701020ab019a87b0a6942f67509788e10b0 |
| tools | ECS_DescribeSecurityGroups | SecurityGroupName | 5bb3c23114ecb778e0a2d1e6bd5cf14d591936d84a8119474530d37b6ca5faaf |
| tools | ECS_DescribeSecurityGroups | SecurityGroupType | 0b236811fa4a301c68f60d1bdded798f3a1d2f319b1d3130ac98fd4e55afa660 |
| tools | ECS_DescribeSecurityGroups | ServiceManaged | e7c86e0179a1d4cb1999905465b017aa528ae1dce9ff89efa4ae4e0c5748a558 |
| tools | ECS_DescribeSecurityGroups | Tag | 4e9ebf06aad244f961653a9054180cce685fa62532ba75a42b33e7020ee11925 |
| tools | ECS_DescribeSecurityGroups | VpcId | 022fcaca86375ab190dffc103d15c9bc94e8606b25d258809c969e4259b59d6c |
| tools | ECS_DescribeZones | description | 7bbc1a1726ba7c9cdb6530521edc66856017ca35a14fdd557bdae0095073b751 |
| tools | ECS_DescribeZones | AcceptLanguage | ba95cfc445c7dde4be0872e107d4ed785e722f08c8ed7821e057009d55980d42 |
| tools | ECS_DescribeZones | InstanceChargeType | f7f089baaa5a71e6e42bb986cb6e4d84b6773968fdc046aa418cc0bccc3b2b92 |
| tools | ECS_DescribeZones | RegionId | b38e5cd975089502aee6b4b606ff29de96039c9314b7c7b8be9f87e90d68940b |
| tools | ECS_DescribeZones | SpotStrategy | 3460aef21b995bb88a5340104b565153fe7f3054bd6a0f1fe7be28fd19440ea3 |
| tools | ECS_DescribeZones | Verbose | 29529a50e0c9273c4558104a9067fd487661f042a3bedb6c2e9af37e68f8a705 |
| tools | OOS_RebootInstances | description | 1636357802dfb1e363bd90bccb30de5558b17fea156d78d53ed5f8ceb78ac97e |
| tools | OOS_RebootInstances | ForeceStop | 99976c8b00f8a26bad165f6035f444ed44c4283c542a33dc3120ebf2343ec92f |
| tools | OOS_RebootInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_RebootInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_RebootRDSInstances | description | 0db0233dcf7820dd57804634bce6be3e80e64bda482a14e6b92a8121f8c42bcc |
| tools | OOS_RebootRDSInstances | InstanceIds | 94c0de0e1dca546c1c7a4153d4726b0f364a642f25af1981723240e902643682 |
| tools | OOS_RebootRDSInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_ReplaceSystemDisk | description | d0d6d720f2d2b85b11cf4b8a06ab14a8dc6de15f3a1d39c12250e1e7dd1d660a |
| tools | OOS_ReplaceSystemDisk | ImageId | e780d31fde4a9a7a36431d220963181ad11dbabc44726d4ad63575646248e1b9 |
| tools | OOS_ReplaceSystemDisk | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_ReplaceSystemDisk | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_ResetPassword | description | 4a33b145e5b8d26e4c1c08e31a0b428bafb564d6eac35de3cbb2e477d039b827 |
| tools | OOS_ResetPassword | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_ResetPassword | Password | b7258dd07b9fbea8a9e69664eb9a298fc9aa37a8d5fff5fc0a2c62f70a8f711d |
| tools | OOS_ResetPassword | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_RunCommand | description | 24cff39b267e346b7083d22f58dd20b6f0c2d1c5ef110fdd561397320eac32b1 |
| tools | OOS_RunCommand | Command | b5a8cb191642b66b6c8d70c68080199c6e42397a2694cf3fdfe65c77ab9494cc |
| tools | OOS_RunCommand | CommandType | 36b1638d62b2c428d109c7d361070dab3f8b88ac88e7c0d65f8cb1175a8ae556 |
| tools | OOS_RunCommand | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_RunCommand | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_RunInstances | description | 9f242e6a3ef246a32b45c8a7b8f880823efed4773562d6f3bfa4dee58a7ba9c4 |
| tools | OOS_RunInstances | Amount | 7cbf3f2f47038f065fd18a2ae3e3209f1b9b1464ed77b1706b1d682ecf30ecd3 |
| tools | OOS_RunInstances | ImageId | e780d31fde4a9a7a36431d220963181ad11dbabc44726d4ad63575646248e1b9 |
| tools | OOS_RunInstances | InstanceName | 85d41dd35ffc946d8d382ee0c2c3b34c183e7c90eb44507d9c4b32ffb1364525 |
| tools | OOS_RunInstances | InstanceType | 894583b8fb98ecc1949d791e9581c5069ea4ee9257c8f1788aff5db4145518e5 |
| tools | OOS_RunInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_RunInstances | SecurityGroupId | aaf4294581458c5e074f518dcca8c6a8e3d2499d9327fb54f2752b84b1e29e12 |
| tools | OOS_RunInstances | VSwitchId | 59e6707b70baeb8daa22e49efab46925019d41489da4d6d5239f88741022d0bd |
| tools | OOS_StartInstances | description | 2a9f08533d2ce509b6ed4af460a44cb475cbb4880bea5f20f298a8daa3949260 |
| tools | OOS_StartInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_StartInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_StartRDSInstances | description | 1b51fcfc50e0e2ace55caf73d80caa25e29890448385dd20ff7015765b841787 |
| tools | OOS_StartRDSInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_StartRDSInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_StopInstances | description | d2ba4bde7d55993dc51809cfa260a1502278a850e1bab1413ba442c5b458cc7e |
| tools | OOS_StopInstances | ForeceStop | 99976c8b00f8a26bad165f6035f444ed44c4283c542a33dc3120ebf2343ec92f |
| tools | OOS_StopInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | OOS_StopInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OOS_StopRDSInstances | description | 77ef2436fc623a21ff2cd4ed8c0aff898698e94b7264987d1b64dfba8257deaf |
| tools | OOS_StopRDSInstances | InstanceIds | 94c0de0e1dca546c1c7a4153d4726b0f364a642f25af1981723240e902643682 |
| tools | OOS_StopRDSInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OSS_DeleteBucket | description | 34270d559b1de0ef3dded6c8a4db7089554367736c56dee5c01a26a4fa5a0efa |
| tools | OSS_DeleteBucket | BucketName | c054f7f7409e381b13900fb120a8aa9f7e39ae8d3b6d8d9d198052e02714b895 |
| tools | OSS_DeleteBucket | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OSS_ListBuckets | description | 53ef8dcd87ffe37e106c8846b6cf1eb85d4d95a99694819369e2cb26afe3833f |
| tools | OSS_ListBuckets | Prefix | 842acc0be5c86f318a10292fcd531e702d65dbbafd05f6d961975b084a9bed13 |
| tools | OSS_ListBuckets | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OSS_ListObjects | description | a857f99b9e698e92ee186ea317028030123ffc567ad4c9c9850c340144af66cb |
| tools | OSS_ListObjects | BucketName | c054f7f7409e381b13900fb120a8aa9f7e39ae8d3b6d8d9d198052e02714b895 |
| tools | OSS_ListObjects | Prefix | 842acc0be5c86f318a10292fcd531e702d65dbbafd05f6d961975b084a9bed13 |
| tools | OSS_ListObjects | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OSS_PutBucket | description | 1b263bbe06cd2619edea488fe78f781f014ab161e8c4dc384d40ef6c62f98a6b |
| tools | OSS_PutBucket | BucketName | c054f7f7409e381b13900fb120a8aa9f7e39ae8d3b6d8d9d198052e02714b895 |
| tools | OSS_PutBucket | DataRedundancyType | 1e5cd59109f4f1bc3f44a140f3b1008d946478ec731c2e6b041d8a082a671535 |
| tools | OSS_PutBucket | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | OSS_PutBucket | StorageClass | d8694c5db8c8fdfc2bf7fb7d6580ab63fb715fd130ce78aaeeb86a453529ccc9 |
| tools | RDS_DescribeDBInstances | description | e429f4c2b0f9c291b58360877af08e35f6f89cfa0c772de8fe92fbfbd2436919 |
| tools | RDS_DescribeDBInstances | Category | bae337c2c8181573291a63fb792c7189768cd0971461f62d7c0dad0df020ff50 |
| tools | RDS_DescribeDBInstances | ClientToken | d823d39e9dbbd279107f7ca2210e5eb8ac75b4dc0518ee56476e9fa303a08e20 |
| tools | RDS_DescribeDBInstances | ConnectionMode | 5bf98297c9c8935ea12b64580669e8ab79dd832cb442b9d86681777b5070eb3b |
| tools | RDS_DescribeDBInstances | ConnectionString | 6513f526917925075e8b738e017ac99b975515405a310bd6457a7ecf5ab860a5 |
| tools | RDS_DescribeDBInstances | DBInstanceClass | 96743d1157e16ba1dbc80d22e938d2fc7cd5e7382b1f6c53e7cae59d3dffac78 |
| tools | RDS_DescribeDBInstances | DBInstanceId | 02311cf8c5be64b25617da281243113e43d299a2dc0cae12806a0f6dea8d8b0b |
| tools | RDS_DescribeDBInstances | DBInstanceStatus | a4278e8c19ae81095726bb47c613a0f10c9f09b7639db7dbdcbd18e40cf61c65 |
| tools | RDS_DescribeDBInstances | DBInstanceType | f2c6386742df021aec0549864cdb2ea33ea60f1e364502e7830845fc8f746486 |
| tools | RDS_DescribeDBInstances | DedicatedHostGroupId | ff3212a0384a7c1c2af2da852cc1055e4472dcebf9a058636997415aa30793b8 |
| tools | RDS_DescribeDBInstances | DedicatedHostId | 04837ff7a8528ef93d3a943f609f13b62c7e512b3dfaa58ad2d436d77c52ee5b |
| tools | RDS_DescribeDBInstances | Engine | 4e63271d21fab4c07305bcf0e863c7cf83a928037f05354065ebaf241cb99591 |
| tools | RDS_DescribeDBInstances | EngineVersion | 47905ef3d05d72c2dd453f3a24b9d079bcad64230442ac81f66ffbd3b84d7aaa |
| tools | RDS_DescribeDBInstances | Expired | 9b91184fea6916fb8616d833e2f62d1a6f19d5bf915a580cc9982b83a85d50bd |
| tools | RDS_DescribeDBInstances | Filter | 77a58490ca9c6263a37d3c743c01337593490775dc82f6e31dd3446e2b0908ab |
| tools | RDS_DescribeDBInstances | InstanceLevel | 755ad5a857f89fe37c03d6373161dea72f9a90c3ca069b01dc69be6bc61ad3f0 |
| tools | RDS_DescribeDBInstances | InstanceNetworkType | 884c03de6b91cc5e4ff2fb7c65e04176b4295e69ca2b55db0c0c00b444051f6a |
| tools | RDS_DescribeDBInstances | MaxResults | 722fb0cf424522703d5dec8b078dd335e5f55882e5fe8811f0133151fdf39a76 |
| tools | RDS_DescribeDBInstances | NextToken | 24fa44abf7fff7fa814dae5229c582c3bba9548127de1ee122551ad1e88d1a04 |
| tools | RDS_DescribeDBInstances | PageNumber | abac8dcc027933bd2b8745797c41117532e7462148984fa8dd8cd93cd5861d65 |
| tools | RDS_DescribeDBInstances | PageSize | 4e1b665c3fc78e0b4b5a4dd30033235656b72bcae1a462563661fc8907910b93 |
| tools | RDS_DescribeDBInstances | PayType | 751cb05ea5b3d66e923d402f2c2739bd0dcea30a9015a537ae0a092985e628a4 |
| tools | RDS_DescribeDBInstances | RegionId | 346d700067bbb2adaf346574503249a9c592c39c13b88b1a3a48737daee16e2b |
| tools | RDS_DescribeDBInstances | ResourceGroupId | 19ae9d89a6b7d9068dd13d0aa3e36bae904216bfc81d0c1101b4d25213d3ee38 |
| tools | RDS_DescribeDBInstances | SearchKey | 0c8be5077823b520a0e8da0f0464449034eb1efab05ff35768459a329ed30d92 |
| tools | RDS_DescribeDBInstances | Tags | 7a0f93fb86eefb56e8eb43bbe47046098ddb5aeb40614da85e273404667d3690 |
| tools | RDS_DescribeDBInstances | VSwitchId | 9b243983c0a508f40075db19621a3ceec333005f0cd636e2fe4f23897824c76a |
| tools | RDS_DescribeDBInstances | VpcId | 1abc3b8305200a8e87b26754e7648162ebfd83c5be81a90f3eac02a5912d3eaa |
| tools | RDS_DescribeDBInstances | ZoneId | 1efa06638dc092b8b95cb1c1c4c17256807845419620d5f3334ff2661e9550a5 |
| tools | RDS_DescribeDBInstances | proxyId | 26ed81e40404ba0d9af0bc57c946bba744da4e7add1e16972fc1b899e9eb3d49 |
| tools | VPC_DescribeVSwitches | description | 590bac0ac1ceadd90b4cc06f1d9ed4f51bd69ef683902965c7fe3e00367763aa |
| tools | VPC_DescribeVSwitches | DryRun | ba7ebab9c54e97da229a9777ec89b6ad69767452906dc7798d481a7c1f52a40d |
| tools | VPC_DescribeVSwitches | EnableIpv6 | 178bc2519fe562f96c9594a77177f360d92f6a4245b71f7b1943a1a267ffa880 |
| tools | VPC_DescribeVSwitches | IsDefault | 62deaeacaef9fd7fc3173f9bd194841dcb9da78e250a619ef7e49924442ec7b7 |
| tools | VPC_DescribeVSwitches | PageNumber | 430d2ad0189728da036e47a12d9c1fcb5af20904c654eaa6e2d8e88ce1462828 |
| tools | VPC_DescribeVSwitches | PageSize | f86b3c372a6c36dea1534717aacf173c95c0886150a05a0ae30ebe4a3ba80f28 |
| tools | VPC_DescribeVSwitches | RegionId | 94513da59f9b522c15531186d5deb34629f884ede7dc818067baf58dd82b76dd |
| tools | VPC_DescribeVSwitches | ResourceGroupId | 87ef5b690b7978e4cf6886177ec97a58b26db3e73bb71c081d6289e1ae32c0fd |
| tools | VPC_DescribeVSwitches | RouteTableId | 742720bfbefdd2afcf9e5406b4be6e03d6defad05f8686bf347a32b767f885a2 |
| tools | VPC_DescribeVSwitches | Tag | b33b36370413b8091f2fd1570c71175f1c13856e62e03f4e645ac3b82ec43cee |
| tools | VPC_DescribeVSwitches | VSwitchId | bf926fc718287020dd7aff70fb73f24395e87dbdfed01df3e3709b1bcebb87dc |
| tools | VPC_DescribeVSwitches | VSwitchName | d512f46488b7439763bad2e0494cf866ad3ccd3bcbaed14bed8c3a65fd99eed2 |
| tools | VPC_DescribeVSwitches | VSwitchOwnerId | 5b6490bcf8d7e7f0405b66154bd37f25ca76eb9a7baf6bb0f87fbb000d98e26b |
| tools | VPC_DescribeVSwitches | VpcId | b70bb979aa5592ce0ffa36a3cb937c7eeb5daedcc9915f3dc8e87b4c5ee186e2 |
| tools | VPC_DescribeVSwitches | ZoneId | 9e229f39b36bfa99e7d688ed9ae1e0ce3df74e04e0eb5913d8ef1e7717ee4b64 |
| tools | VPC_DescribeVpcs | description | f06a297508d84a303b32891ebe65ca9545423bac48e9ab95ac66fb9dd5d0b9b6 |
| tools | VPC_DescribeVpcs | DhcpOptionsSetId | 50b203292ab67ec363be7c2ad16ecbdbbb393c94ca4c759a6b89db44bbf1be25 |
| tools | VPC_DescribeVpcs | DryRun | d7f631654da8a12f8e7b1671a699aede68d32cfc123678effeeaee580c845f9b |
| tools | VPC_DescribeVpcs | EnableIpv6 | 3b8ce7552ce542bead0d84606ca88b2e541c63ca37d368241ffe990c30cb5ebb |
| tools | VPC_DescribeVpcs | IsDefault | a564467489fea658abda0d70f44e226d891b71fc55b2e5174ba27eb573547e55 |
| tools | VPC_DescribeVpcs | PageNumber | 430d2ad0189728da036e47a12d9c1fcb5af20904c654eaa6e2d8e88ce1462828 |
| tools | VPC_DescribeVpcs | PageSize | 7217543ee483b2bc711cbdb30f5d02a5e64370cf868e93ec1385394d820f608c |
| tools | VPC_DescribeVpcs | RegionId | 59d325520a037c2ab61c02b93ca6347957d4dd7e3c0126214a63137c4b0b8945 |
| tools | VPC_DescribeVpcs | ResourceGroupId | aaf3f93d70f1c840d0a9c1e3bde9cd00bbaff4e3d0f5e33aaa6ed5ab8c1f38b7 |
| tools | VPC_DescribeVpcs | Tag | b33b36370413b8091f2fd1570c71175f1c13856e62e03f4e645ac3b82ec43cee |
| tools | VPC_DescribeVpcs | VpcId | 8a9cb1682ed891029be9965563d5e7411bde18f1c2a189b6d548dcb7add7b211 |
| tools | VPC_DescribeVpcs | VpcName | 76806b216ca04d9bc108664de16a2a951e5c37bfd00908879f719926a8c4054b |
| tools | VPC_DescribeVpcs | VpcOwnerId | 7f1553163d065c7bef9d31a5d4e5ba22919d5be7086a7920273f60b5b22dabcc |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
