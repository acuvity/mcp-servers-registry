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


# What is mcp-server-alibaba-cloud-ops?

[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-alibaba-cloud-ops/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-alibaba-cloud-ops/0.8.3?logo=docker&logoColor=fff&label=0.8.3)](https://hub.docker.com/r/acuvity/mcp-server-alibaba-cloud-ops)
[![PyPI](https://img.shields.io/badge/0.8.3-3775A9?logo=pypi&logoColor=fff&label=alibaba-cloud-ops-mcp-server)](https://github.com/aliyun/alibaba-cloud-ops-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-alibaba-cloud-ops&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_ID%22%2C%22-e%22%2C%22ALIBABA_CLOUD_ACCESS_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-alibaba-cloud-ops%3A0.8.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Alibaba Cloud integration, supporting ECS, Cloud Monitor, OOS and widely used cloud products.

Packaged by Acuvity from alibaba-cloud-ops-mcp-server original [sources](https://github.com/aliyun/alibaba-cloud-ops-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-alibaba-cloud-ops/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/charts/mcp-server-alibaba-cloud-ops/README.md#how-to-install)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/charts/mcp-server-alibaba-cloud-ops#minibridge) for Helm charts).


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
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/charts/mcp-server-alibaba-cloud-ops)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-alibaba-cloud-ops/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.8.3`

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
helm install mcp-server-alibaba-cloud-ops oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-alibaba-cloud-ops oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-alibaba-cloud-ops
```

From there your MCP server mcp-server-alibaba-cloud-ops will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-alibaba-cloud-ops` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-alibaba-cloud-ops
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-alibaba-cloud-ops` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-alibaba-cloud-ops oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-alibaba-cloud-ops oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-alibaba-cloud-ops oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-alibaba-cloud-ops oci://docker.io/acuvity/mcp-server-alibaba-cloud-ops --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (34)
<details>
<summary>RunCommand</summary>

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
<summary>StartInstances</summary>

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
<summary>StopInstances</summary>

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
<summary>RebootInstances</summary>

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
<summary>RunInstances</summary>

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
<summary>ResetPassword</summary>

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
<summary>ReplaceSystemDisk</summary>

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
<summary>StartRDSInstances</summary>

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
<summary>StopRDSInstances</summary>

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
<summary>RebootRDSInstances</summary>

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
<summary>GetCpuUsageData</summary>

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
<summary>GetCpuLoadavgData</summary>

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
<summary>GetCpuloadavg5mData</summary>

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
<summary>GetCpuloadavg15mData</summary>

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
<summary>GetMemUsedData</summary>

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
<summary>GetMemUsageData</summary>

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
<summary>GetDiskUsageData</summary>

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
<summary>GetDiskTotalData</summary>

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
<summary>GetDiskUsedData</summary>

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
<summary>ListBuckets</summary>

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
<summary>ListObjects</summary>

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
<summary>PutBucket</summary>

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
<summary>DeleteBucket</summary>

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
<summary>DescribeInstances</summary>

**Description**:

```
本接口支持根据不同请求条件查询实例列表，并关联查询实例的详细信息。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| AdditionalAttributes | array | 实例其他属性列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例：META_OPTIONS | No
| DeviceAvailable | boolean | >该参数正在邀测中，暂不支持使用。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| DryRun | boolean | 是否只预检此次请求。取值范围：

- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DryRunOperation。  
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。 

默认值：false。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| EipAddresses | string | 实例的弹性公网IP列表。当InstanceNetworkType=vpc时该参数生效，取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：["42.1.1.**", "42.1.2.**", … "42.1.10.**"] | No
| HpcClusterId | string | 实例所在的HPC集群ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：hpc-bp67acfmxazb4p**** | No
| HttpEndpoint | string | 是否启用实例元数据的访问通道。取值范围：
- enabled：启用。
- disabled：禁用。

默认值：enabled。
>有关实例元数据的更多信息，请参见[实例元数据概述](~~49122~~)。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：enabled | No
| HttpPutResponseHopLimit | integer | >该参数暂未开放使用。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：0 | No
| HttpTokens | string | 访问实例元数据时是否强制使用加固模式（IMDSv2）。取值范围：
- optional：不强制使用。
- required：强制使用。设置该取值后，普通模式无法访问实例元数据。

默认值：optional。
>有关访问实例元数据模式的更多信息，请参见[实例元数据访问模式](~~150575~~)。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：optional | No
| ImageId | string | 镜像ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：m-bp67acfmxazb4p**** | No
| InnerIpAddresses | string | 经典网络类型实例的内网IP列表。当InstanceNetworkType=classic时生效，取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：["10.1.1.1", "10.1.2.1", … "10.1.10.1"] | No
| InstanceChargeType | string | 实例的计费方式。取值范围： 
         
- PostPaid：按量付费。 
- PrePaid：包年包月。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：PostPaid | No
| InstanceIds | string | 实例ID。取值可以由多个实例ID组成一个JSON数组，最多支持100个ID，ID之间用半角逗号（,）隔开。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：["i-bp67acfmxazb4p****", "i-bp67acfmxazb4p****", … "i-bp67acfmxazb4p****"] | No
| InstanceName | string | 实例名称，支持使用通配符*进行模糊搜索。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Test | No
| InstanceNetworkType | string | 实例网络类型。取值范围：

- classic：经典网络。
- vpc：专有网络VPC。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc | No
| InstanceType | string | 实例的规格。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：ecs.g5.large | No
| InstanceTypeFamily | string | 实例的规格族。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：ecs.g5 | No
| InternetChargeType | string | 公网带宽计费方式。取值范围：

- PayByBandwidth：按固定带宽计费。
- PayByTraffic：按使用流量计费。

> **按使用流量计费**模式下的出入带宽峰值都是带宽上限，不作为业务承诺指标。当出现资源争抢时，带宽峰值可能会受到限制。如果您的业务需要有带宽的保障，请使用**按固定带宽计费**模式。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：PayByTraffic | No
| IoOptimized | boolean | 是否是I/O优化型实例。取值范围：

- true：是。
- false：否。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：true | No
| Ipv6Address | array | 为弹性网卡指定的IPv6地址。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| KeyPairName | string | 实例使用的SSH密钥对名称。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：KeyPairNameTest | No
| LockReason | string | 资源被锁定的原因。取值范围：

- financial：因欠费被锁定。

- security：因安全原因被锁定。

- Recycling：抢占式实例的待释放锁定状态。

- dedicatedhostfinancial：因为专有宿主机欠费导致ECS实例被锁定。

- refunded：因退款被锁定。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：security | No
| MaxResults | integer | 分页查询时每页行数。最大值为100。

默认值：

- 当不设置值或设置的值小于10时，默认值为10。
- 当设置的值大于100时，默认值为100。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| NeedSaleCycle | boolean | >该参数正在邀测中，暂不支持使用。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| NextToken | string | 查询凭证（Token），取值为上一次API调用返回的`NextToken`参数值。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：caeba0bbb2be03f84eb48b699f0a4883 | No
| PageNumber | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| PageSize | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| PrivateIpAddresses | string | VPC网络类型实例的私有IP。当InstanceNetworkType=vpc时生效，取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：["172.16.1.1", "172.16.2.1", … "172.16.10.1"] | No
| PublicIpAddresses | string | 实例的公网IP列表。取值可以由多个IP组成一个JSON数组，最多支持100个IP，IP之间用半角逗号（,）隔开。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：["42.1.1.**", "42.1.2.**", … "42.1.10.**"] | No
| RdmaIpAddresses | string | HPC实例的RDMA网络IP。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：10.10.10.102 | No
| RegionId | string | 实例所属的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 实例所在的企业资源组ID。使用该参数过滤资源时，资源数量不能超过1000个。

>不支持默认资源组过滤。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rg-bp67acfmxazb4p**** | No
| SecurityGroupId | string | 实例所属的安全组。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：sg-bp67acfmxazb4p**** | No
| Status | string | 实例状态。取值范围： 

- Pending：创建中。
- Running：运行中。
- Starting：启动中。
- Stopping：停止中。
- Stopped：已停止。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Running | No
| Tag | array | 标签列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| VSwitchId | string | 交换机ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vsw-bp67acfmxazb4p**** | No
| VpcId | string | 专有网络VPC ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：v-bp67acfmxazb4p**** | No
| ZoneId | string | 可用区ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou-g | No
</details>
<details>
<summary>DescribeRegions</summary>

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

默认值：zh-CN。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：zh-CN | No
| InstanceChargeType | string | 实例的计费方式，更多信息，请参见[计费概述](~~25398~~)。取值范围：

- PrePaid：包年包月。此时，请确认自己的账号支持余额支付或者信用支付，否则将报错InvalidPayMethod。
- PostPaid：按量付费。
- SpotWithPriceLimit：设置上限价格。
- SpotAsPriceGo：系统自动出价，最高按量付费价格。

默认值：PostPaid。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：PrePaid | No
| RegionId | string | 地域ID | No
| ResourceType | string | 资源类型。取值范围：

-  instance：ECS实例。
-  disk：磁盘。
-  reservedinstance：预留实例券。
-  scu：存储容量单位包。

默认值：instance。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：instance | No
</details>
<details>
<summary>DescribeZones</summary>

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

默认值：zh-CN。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：zh-CN | No
| InstanceChargeType | string | 可用区里支持的资源计费方式。更多信息，请参见[计费概述](~~25398~~)。取值范围： 

- PrePaid：包年包月。
- PostPaid：按量付费。

默认值：PostPaid。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：PostPaid | No
| RegionId | string | 可用区所在的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| SpotStrategy | string | 按量付费实例的竞价策略。当`InstanceChargeType=PostPaid`时，您可以传入该参数。更多信息，请参见[抢占式实例](~~52088~~)。取值范围：
         
- NoSpot：正常按量付费实例。
- SpotWithPriceLimit：设置上限价格的抢占式实例。
- SpotAsPriceGo：系统自动出价，最高按量付费价格。

默认值：NoSpot。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：NoSpot | No
| Verbose | boolean | 是否展示详细信息。

- true：展示。
- false：不展示。

默认值：true。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
</details>
<details>
<summary>DescribeAccountAttributes</summary>

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

默认值为空。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例：max-security-groups | No
| RegionId | string | 地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ZoneId | string | 可用区ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou-b | No
</details>
<details>
<summary>DescribeAvailableResource</summary>

**Description**:

```
查询可用区的资源库存状态。您可以在某一可用区创建实例（RunInstances）或者修改实例规格（ModifyInstanceSpec）时查询该可用区的资源库存状态。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| Cores | integer | 实例规格的vCPU内核数目。取值参见[实例规格族](~~25378~~)。

当DestinationResource取值为InstanceType时，Cores才为有效参数。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：2 | No
| DataDiskCategory | string | 数据盘类型。取值范围： 
         
- cloud：普通云盘。
- cloud_efficiency：高效云盘。
- cloud_ssd：SSD云盘。
- ephemeral_ssd：本地SSD盘。
- cloud_essd：ESSD云盘。
- cloud_auto：ESSD AutoPL云盘。
<props="china">
- cloud_essd_entry：ESSD Entry云盘。
</props> 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cloud_ssd | No
| DedicatedHostId | string | 专有宿主机ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：dh-bp165p6xk2tlw61e**** | No
| DestinationResource | string | 要查询的资源类型。取值范围： 
         
- Zone：可用区。
- IoOptimized：I/O优化。
- InstanceType：实例规格。
- Network：网络类型。
- ddh：专有宿主机。
- SystemDisk：系统盘。
- DataDisk：数据盘。

>当DestinationResource取值为`SystemDisk`时，由于系统盘受实例规格限制，此时必须传入InstanceType。

参数DestinationResource的取值方式请参见本文中的**接口说明**。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：InstanceType | Yes
| InstanceChargeType | string | 资源的计费方式。更多信息，请参见[计费概述](~~25398~~)。取值范围： 
       
- PrePaid：包年包月。  
- PostPaid：按量付费。

默认值：PostPaid。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：PrePaid | No
| InstanceType | string | 实例规格。更多信息，请参见[实例规格族](~~25378~~)，您也可以调用[DescribeInstanceTypes](~~25620~~)接口获得最新的规格表。

参数InstanceType的取值方式请参见本文开头的**接口说明**。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：ecs.g5.large | No
| IoOptimized | string | 是否为I/O优化实例。取值范围： 
         
- none：非I/O优化实例。
- optimized：I/O优化实例。


默认值：optimized。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：optimized | No
| Memory | number | 实例规格的内存大小，单位为GiB。取值参见[实例规格族](~~25378~~)。

当DestinationResource取值为InstanceType时，Memory才为有效参数。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: number,参数示例：8.0 | No
| NetworkCategory | string | 网络类型。取值范围： 
        
- vpc：专有网络。
- classic：经典网络。
          请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc | No
| RegionId | string | 目标地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceType | string | 资源类型。取值范围：

- instance：ECS实例。
- disk：云盘。
- reservedinstance：预留实例券。
- ddh：专有宿主机。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：instance | No
| Scope | string | 预留实例券的范围。取值范围：
         
- Region：地域级别。
- Zone：可用区级别。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Region | No
| SpotDuration | integer | 抢占式实例的保留时长，单位为小时。 默认值：1。取值范围：
- 1：创建后阿里云会保证实例运行1小时不会被自动释放；超过1小时后，系统会自动比较出价与市场价格、检查资源库存，来决定实例的持有和回收。
- 0：创建后，阿里云不保证实例运行1小时，系统会自动比较出价与市场价格、检查资源库存，来决定实例的持有和回收。

实例回收前5分钟阿里云会通过ECS系统事件向您发送通知。抢占式实例按秒计费，建议您结合具体任务执行耗时来选择合适的保留时长。

> 当`InstanceChargeType`取值为`PostPaid`，并且`SpotStrategy`值为`SpotWithPriceLimit`或`SpotAsPriceGo`时该参数生效。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| SpotStrategy | string | 按量付费实例的竞价策略。取值范围： 
         
- NoSpot：正常按量付费实例。
- SpotWithPriceLimit：设置上限价格的抢占式实例。
- SpotAsPriceGo：系统自动出价，最高按量付费价格。

默认值：NoSpot。

当参数`InstanceChargeType`取值为`PostPaid`时，参数`SpotStrategy`才有效。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：NoSpot | No
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

> 参数ResourceType取值为instance、DestinationResource取值为DataDisk时，参数SystemDiskCategory是必选参数。如果未传递参数值，则以默认值生效。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cloud_ssd | No
| ZoneId | string | 可用区ID。

默认值：无。返回该地域（`RegionId`）下所有可用区符合查询条件的资源。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou-e | No
</details>
<details>
<summary>DescribeImages</summary>

**Description**:

```
指定ImageId、镜像被使用场景、Filter过滤等参数，查询您可以使用的镜像资源列表。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ActionType | string | 镜像需要被使用到的场景。取值范围：

- CreateEcs（默认）：创建实例。
- ChangeOS：更换系统盘/更换操作系统。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：CreateEcs | No
| Architecture | string | 镜像的体系架构。取值范围：

- i386。
- x86_64。
- arm64。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：i386 | No
| DryRun | boolean | 是否只预检此次请求。
         
- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DryRunOperation。  
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。 

默认值：false。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| Filter | array | 查询资源时的筛选条件列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| ImageFamily | string | 镜像族系名称，查询镜像时可通过设置该参数来过滤当前族系对应的镜像。

默认值：空。
> 阿里云官方镜像关联的镜像族系信息请参见[公共镜像概述](~~108393~~)。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：hangzhou-daily-update | No
| ImageId | string | 镜像ID。

<details>
<summary>镜像ID的命名规则</summary>

- 公共镜像：以操作系统版本号、架构、语言和发布日期命名。例如，Windows Server 2008 R2企业版、64位英文系统的镜像ID为win2008r2_64_ent_sp1_en-us_40G_alibase_20190318.vhd。

- 自定义镜像、共享镜像、云市场镜像、社区镜像的镜像：以m开头。

</details> 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：m-bp1g7004ksh0oeuc**** | No
| ImageName | string | 镜像名称。支持模糊搜索。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：testImageName | No
| ImageOwnerAlias | string | 镜像来源。取值范围：

- system：阿里云官方提供的，且不是通过云市场发布的镜像，和控制台中的“公共镜像”概念不同。
- self：您创建的自定义镜像。
- others：包含共享镜像（其他阿里云用户直接共享给您的镜像）和社区镜像（任意阿里云用户将其自定义镜像完全公开共享后的镜像）。您需要注意：
    - 查找社区镜像时，IsPublic必须为true。
    - 查找共享镜像时，IsPublic需要设置为false或者不传值。
- marketplace：阿里云或者第三方供应商ISV在云市场发布的镜像，需要和ECS一起购买。请自行留意云市场镜像的收费详情。

默认值：空。

>空表示返回取值为system、self以及others的结果。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：self | No
| ImageOwnerId | integer | 镜像所属的阿里云账号ID。该参数仅在查询共享镜像以及社区镜像时生效。

 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：20169351435666**** | No
| InstanceType | string | 为指定的实例规格查询可以使用的镜像。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：ecs.g5.large | No
| IsPublic | boolean | 是否查询已发布的社区镜像。取值范围：

- true：查询已发布的社区镜像。当您指定该参数值为true时，ImageOwnerAlias必须为others。
- false：查询除社区镜像的其他镜像类型，具体以ImageOwnerAlias参数值为准。

默认值：false。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| IsSupportCloudinit | boolean | 镜像是否支持cloud-init。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：true | No
| IsSupportIoOptimized | boolean | 镜像是否可以运行在I/O优化实例上。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：true | No
| OSType | string | 镜像的操作系统类型。取值范围：

- windows。
- linux。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：linux | No
| PageNumber | integer | 镜像资源列表的页码。

起始值：1。

默认值：1。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| PageSize | integer | 分页查询时设置的每页行数。

最大值：100。

默认值：10。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| RegionId | string | 镜像所属的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 自定义镜像所在的企业资源组ID。使用该参数过滤资源时，资源数量不能超过1000个。

>不支持默认资源组过滤。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rg-bp67acfmxazb4p**** | No
| ShowExpired | boolean | 订阅型镜像是否已经超过使用期限。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| SnapshotId | string | 根据某一快照ID创建的自定义镜像。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：s-bp17ot2q7x72ggtw**** | No
| Status | string | 查询指定状态的镜像，如果不配置此参数，默认只返回Available状态的镜像。取值范围：

- Creating：镜像正在创建中。
- Waiting：多任务排队中。
- Available（默认）：您可以使用的镜像。
- UnAvailable：您不能使用的镜像。
- CreateFailed：创建失败的镜像。
- Deprecated：已弃用的镜像。

默认值：Available。当前参数支持同时取多个值，值之间以半角逗号（,）隔开。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Available | No
| Tag | array | 标签列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| Usage | string | 镜像是否已经运行在ECS实例中。取值范围：

- instance：镜像处于运行状态，有ECS实例使用。
- none：镜像处于闲置状态，暂无ECS实例使用。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：instance | No
</details>
<details>
<summary>DescribeSecurityGroups</summary>

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

默认值为false。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| FuzzyQuery | boolean | >该参数已废弃。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：null | No
| IsQueryEcsCount | boolean | 是否查询安全组的容量信息。传True时，返回值中的`EcsCount`和`AvailableInstanceAmount`有效。
>该参数已废弃。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：null | No
| MaxResults | integer | 分页查询时每页的最大条目数。一旦设置该参数，即表示使用`MaxResults`与`NextToken`组合参数的查询方式。

最大值为100。

默认值为10。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| NetworkType | string | 安全组的网络类型。取值范围：

- vpc：专有网络。
- classic：经典网络。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc | No
| NextToken | string | 查询凭证（Token）。取值为上一次调用该接口返回的NextToken参数值，初次调用接口时无需设置该参数。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：e71d8a535bd9cc11 | No
| PageNumber | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| PageSize | integer | > 该参数即将下线，推荐您使用NextToken与MaxResults完成分页查询操作。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| RegionId | string | 地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 安全组所在的企业资源组ID。使用该参数过滤资源时，资源数量不能超过1000个。您可以调用[ListResourceGroups](~~158855~~)查询资源组列表。

>不支持默认资源组过滤。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rg-bp67acfmxazb4p**** | No
| SecurityGroupId | string | 安全组ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：sg-bp67acfmxazb4p**** | No
| SecurityGroupIds | string | 安全组ID列表。一次最多支持100个安全组ID，ID之间用半角逗号（,）隔开，格式为JSON数组。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：["sg-bp67acfmxazb4p****", "sg-bp67acfmxazb4p****", "sg-bp67acfmxazb4p****",....] | No
| SecurityGroupName | string | 安全组名称。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：SGTestName | No
| SecurityGroupType | string | 安全组类型。取值范围：
- normal：普通安全组。
- enterprise：企业安全组。

> 当不为该参数传值时，表示查询所有类型的安全组。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：normal | No
| ServiceManaged | boolean | 是否为托管安全组。取值范围：

- true：是托管安全组。
- false：不是托管安全组。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| Tag | array | 标签列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| VpcId | string | 安全组所在的专有网络ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc-bp67acfmxazb4p**** | No
</details>
<details>
<summary>DeleteInstances</summary>

**Description**:

```
本接口用于批量删除或者释放按量付费实例或者到期的包年包月实例，支持通过参数设置决定云盘是否释放或转换为按量付费保留。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ClientToken | string | 保证请求幂等性。从您的客户端生成一个参数值，确保不同请求间该参数值唯一。**ClientToken**只支持ASCII字符，且不能超过64个字符。更多信息，请参见[如何保证幂等性](~~25693~~)。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：123e4567-e89b-12d3-a456-426655440000 | No
| DryRun | boolean | 是否只预检此次请求。

- true：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码DRYRUN.SUCCESS。
- false：发送正常请求，通过检查后返回2XX HTTP状态码并直接查询资源状况。

默认值：false。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| Force | boolean | 是否强制释放**运行中**（`Running`）的ECS实例。

- true：强制释放**运行中**（`Running`）的实例。
- false：正常释放实例，此时实例必须处于**已停止**（`Stopped`）状态。

默认值：false。
><warning>强制释放相当于断电，实例内存以及存储中的临时数据都会被擦除，无法恢复。></warning> 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| ForceStop | boolean | 释放**运行中**（`Running`）的实例时的是否采取强制关机策略。仅当`Force=true`时生效。取值范围：

- true：强制关机并释放实例。相当于典型的断电操作，实例会直接进入资源释放流程。
><warning>强制释放相当于断电，实例内存以及存储中的临时数据都会被擦除，无法恢复。></warning>
- false：在实例释放前，系统将优先执行标准关机流程，该模式会导致实例释放动作持续几分钟。用户在操作系统关机时，配置一些业务排水动作，从而减少业务系统的噪声。

默认值：true。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：true | No
| InstanceId | array | 实例ID数组。数组长度：1~100。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例：i-bp1g6zv0ce8oghu7**** | Yes
| RegionId | string | 实例所属的地域ID。您可以调用[DescribeRegions](~~25609~~)查看最新的阿里云地域列表。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| TerminateSubscription | boolean | 是否释放已到期的包年包月实例。

- true：释放。
- false：不释放。

默认值：false。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
</details>
<details>
<summary>DescribeVpcs</summary>

**Description**:

```
查询已创建的VPC。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| DhcpOptionsSetId | string | DHCP选项集的ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：dopt-o6w0df4epg9zo8isy**** | No
| DryRun | boolean | 是否只预检此次请求，取值：

- **true**：发送检查请求，不会查询资源状况。检查项包括AccessKey是否有效、RAM用户的授权情况和是否填写了必需参数。如果检查不通过，则返回对应错误。如果检查通过，会返回错误码`DryRunOperation`。

- **false**（默认值）：发送正常请求，通过检查后返回HTTP 2xx状态码并直接查询资源状况。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| EnableIpv6 | boolean | 是否查询指定地域下开启IPv6网段的VPC，默认为空值（空值则不根据是否开启IPv6网段做过滤），取值：

- **false**：不开启。
- **true**：开启。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| IsDefault | boolean | 是否查询指定地域下的默认VPC，取值： 

- **true**（默认值）：查询指定地域下的默认VPC。  

- **false**：不查询默认VPC。  
 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| PageNumber | integer |  列表的页码，默认值为**1**。   请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| PageSize | integer | 分页查询时每页的行数，最大值为**50**，默认值为**10**。   请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| RegionId | string | VPC所在的地域ID。 

您可以通过调用[DescribeRegions](~~448570~~)接口获取地域ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 要查询的VPC所属的资源组ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rg-acfmxvfvazb4p**** | No
| Tag | array | 资源的标签。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| VpcId | string | VPC的ID。 

最多支持指定20个VPC ID，多个VPC的ID之间用半角逗号（,）隔开。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc-bp1b1xjllp3ve5yze**** | No
| VpcName | string | VPC的名称。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Vpc-1 | No
| VpcOwnerId | integer | VPC所属的阿里云账号ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：253460731706911258 | No
</details>
<details>
<summary>DescribeVSwitches</summary>

**Description**:

```
查询可组网的信息，内网按vswitch进行组网。
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| DryRun | boolean | 是否只预检此次请求。取值：
- **true**：发送检查请求，不会创建资源（接口功能）。检查项包括是否填写了必需参数、请求格式、业务限制。如果检查不通过，则返回对应错误。如果检查通过，则返回错误码`DryRunOperation`。
- **false**（默认值）：发送正常请求，通过检查后返回HTTP 2xx状态码并直接进行操作。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：true | No
| EnableIpv6 | boolean | 是否查询指定地域下开启IPv6网段的交换机，取值：

- **true**：查询指定地域下开启IPv6网段的交换机。

- **false**：不查询指定地域下开启IPv6网段的交换机。

如果不传入该参数，系统默认查询指定地域下的所有交换机。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：false | No
| IsDefault | boolean | 是否查询指定地域下的默认交换机，取值： 

- **true**：查询指定地域下的默认交换机。  

- **false**：不查询指定地域下的默认交换机。  

如果不传入该参数，系统默认查询指定地域下的所有交换机。

 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: boolean,参数示例：true | No
| PageNumber | integer |  列表的页码，默认值为**1**。   请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| PageSize | integer |  分页查询时每页的行数，最大值为**50**。默认值为**10**。   请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：10 | No
| RegionId | string | 交换机所属地域的ID。您可以通过调用[DescribeRegions](~~36063~~)接口获取地域ID。

> **RegionId**和**VpcId**参数至少输入一个。   请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | No
| ResourceGroupId | string | 交换机所属的资源组ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rg-bp67acfmxazb4ph**** | No
| RouteTableId | string | 路由表的ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vtb-bp145q7glnuzdvzu2**** | No
| Tag | array | 资源的标签。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: array,参数示例： | No
| VSwitchId | string | 要查询的交换机的ID。  请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vsw-23dscddcffvf3**** | No
| VSwitchName | string | 交换机的名称。

名称长度为1～128个字符，不能以`http://`或`https://`开头。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vSwitch | No
| VSwitchOwnerId | integer | 资源归属的阿里云账号ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：2546073170691**** | No
| VpcId | string | 要查询的交换机所属VPC的ID。 

> **RegionId**和**VpcId**参数至少输入一个。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc-25cdvfeq58pl**** | No
| ZoneId | string | 交换机所属可用区的ID。您可以通过调用[DescribeZones](~~36064~~)接口获取可用区ID。   请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou-d | No
</details>
<details>
<summary>DescribeDBInstances</summary>

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
- **serverless_basic**：Serverless 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cluster | No
| ClientToken | string | 用于保证请求的幂等性，防止重复提交请求。由客户端生成该参数值，要保证在不同请求间唯一，最大值不超过64个ASCII字符，且该参数值中不能包含非ASCII字符。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：ETnLKlblzczshOTUbOCz**** | No
| ConnectionMode | string | 实例的访问模式，取值：
* **Standard**：标准访问模式
* **Safe**：数据库代理模式

默认返回所有访问模式下的实例。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Standard | No
| ConnectionString | string | 实例的连接地址。通过该连接地址查询对应的实例。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rm-uf6wjk5****.mysql.rds.aliyuncs.com | No
| DBInstanceClass | string | 实例规格，详见[实例规格表](~~26312~~)。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rds.mys2.small | No
| DBInstanceId | string | 实例ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rm-uf6wjk5**** | No
| DBInstanceStatus | string | 实例状态，详情请参见[实例状态表](~~26315~~)。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Running | No
| DBInstanceType | string | 实例类型，取值：
* **Primary**：主实例
* **Readonly**：只读实例
* **Guard**：灾备实例
* **Temp**：临时实例

默认返回所有实例类型。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Primary | No
| DedicatedHostGroupId | string | 专属集群ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：dhg-7a9**** | No
| DedicatedHostId | string | 专属集群内的主机ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：i-bp**** | No
| Engine | string | 数据库类型，取值：
* **MySQL**
* **SQLServer**
* **PostgreSQL**
* **MariaDB**

默认返回所有数据库类型。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：MySQL | No
| EngineVersion | string | 数据库版本。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：8.0 | No
| Expired | string | 实例的过期状态，取值：
* **True**：已过期
* **False**：未过期 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：True | No
| Filter | string | 实例过滤条件参数及其值的JSON串 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：{"babelfishEnabled":"true"} | No
| InstanceLevel | integer | 是否返回实例系列（Category）信息，取值：
* **0**：不返回
* **1**：返回 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：0 | No
| InstanceNetworkType | string | 实例的网络类型，取值：
* **VPC**：专有网络下的实例
* **Classic**：经典网络下的实例

默认返回所有网络类型下的实例。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Classic | No
| MaxResults | integer | 每页记录数。取值：**1~100**。

默认值：**30**。
>传入该参数，则**PageSize**和**PageNumber**参数不可用。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：30 | No
| NextToken | string | 翻页凭证。取值为上一次调用**DescribeDBInstances**接口时返回的**NextToken**参数值。如果调用结果分多页展示，再次调用接口时传入该值便可以展示下一页的内容。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：o7PORW5o2TJg**** | No
| PageNumber | integer | 页码，取值：大于0且不超过Integer的最大值。

默认值：**1**。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：1 | No
| PageSize | integer | 每页记录数，取值：**1**~**100**。

默认值：**30**。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: integer,参数示例：30 | No
| PayType | string | 付费类型，取值：
* **Postpaid**：按量付费
* **Prepaid**：包年包月 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：Postpaid | No
| RegionId | string | 地域ID。可调用DescribeRegions获取。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou | Yes
| ResourceGroupId | string | 资源组ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rg-acfmy**** | No
| SearchKey | string | 可基于实例ID或者实例备注模糊搜索。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：rm-uf6w | No
| Tags | string | 查询绑定有该标签的实例，包括TagKey和TagValue。单次最多支持传入5组值，格式：{"key1":"value1","key2":"value2"...}。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：{"key1":"value1"} | No
| VSwitchId | string | 交换机ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vsw-uf6adz52c2p**** | No
| VpcId | string | VPC ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：vpc-uf6f7l4fg90**** | No
| ZoneId | string | 可用区ID。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：cn-hangzhou-a | No
| proxyId | string | 废弃参数，无需配置。 请注意，提供参数要严格按照参数的类型和参数示例的提示，如果提到参数为String，且为一个 JSON 数组字符串，应在数组内使用单引号包裹对应的参数以避免转义问题，并在最外侧用双引号包裹以确保其是字符串，否则可能会导致参数解析错误。参数类型: string,参数示例：API | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | DeleteBucket | description | 34270d559b1de0ef3dded6c8a4db7089554367736c56dee5c01a26a4fa5a0efa |
| tools | DeleteBucket | BucketName | c054f7f7409e381b13900fb120a8aa9f7e39ae8d3b6d8d9d198052e02714b895 |
| tools | DeleteBucket | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | DeleteInstances | description | 1d4391135beaaf36967e0bcddd0a31bcf5927cb7a39c1bb062d6b2236e30d6c1 |
| tools | DeleteInstances | ClientToken | 814bc6c33f6fd7f0e903d76bb0fbe7018cdd3b30ed810f3aab80fe1532000eb2 |
| tools | DeleteInstances | DryRun | 7469d4fbd7cf75dca63eb1e68143fb71c3a672fbce06c87ff67d78fcdfd11fa2 |
| tools | DeleteInstances | Force | 350b08992d6de73662e62be33f443a6aca62a3b4c29368c7a2fbf8a0673e91ef |
| tools | DeleteInstances | ForceStop | 411bb487a1ad8e38299073d58d1a6a2033361b55ed762b6bfa672b16de800237 |
| tools | DeleteInstances | InstanceId | 50fb451eed47fe53a2d80f5beb5f29846e78b504745a94b37faa6dc3f3c1920d |
| tools | DeleteInstances | RegionId | 6a5d1879a2800d0eeee616fcbfd9e7005a98a00fd5f8a9232d5a0937887b6786 |
| tools | DeleteInstances | TerminateSubscription | a82ab64ef52e9866159c00601db876cf50f6a7fa9a10c1aa488937c903da9fd3 |
| tools | DescribeAccountAttributes | description | 1778be5783909688e56baa9f09d33597f7c99ee1565170403be16241f30367a6 |
| tools | DescribeAccountAttributes | AttributeName | a348cc2da5e480d71dc4a2ff4165ec02984e830c35dca261c49c63f54301a651 |
| tools | DescribeAccountAttributes | RegionId | b9ab0114a4c9a7cd2b8ec8b1eb907d4dff6f36a305d492b3e572609f318ad6b4 |
| tools | DescribeAccountAttributes | ZoneId | 1a41d4e11cf726a5773552d4eb04146a1406a3a368b2a18ee5938d16751c066e |
| tools | DescribeAvailableResource | description | 5fa70d9722cdb8a377252c9f5f08d6f3049ea97412349445b06a1df15c500e8e |
| tools | DescribeAvailableResource | Cores | 78eb84ca370559d3054187efaff5cef2cb31b7633b6f891161edb3483f6e3761 |
| tools | DescribeAvailableResource | DataDiskCategory | 9fac2a647d843c46f5753ecdb230996f69d057e6f572743ca239ff165562f390 |
| tools | DescribeAvailableResource | DedicatedHostId | 2c2f45d856af02e91a8801603a65795ac75b7af610bc4c8ddcd0ec64663a5ad6 |
| tools | DescribeAvailableResource | DestinationResource | 12ac4def22b17e4e12427cc7ad776d432347fef6fd3e35873ce6d55abab416dc |
| tools | DescribeAvailableResource | InstanceChargeType | 90ae3df01aa91f3eb9d7420e3f9e6093d959d24e4d80e64a44dc1c0c3fd9167b |
| tools | DescribeAvailableResource | InstanceType | 027e34adc74a7971144fae257ac37e3df97bd8adc7abec966ad3718af6b86992 |
| tools | DescribeAvailableResource | IoOptimized | d9ba1d8312c93a9015def426b521aea2511ff8742728222dfa9a00f2c6decb0f |
| tools | DescribeAvailableResource | Memory | 3d28627ae435c9f8b8064aef96dab7d37f71aad715325bf25f2f79bae760cf31 |
| tools | DescribeAvailableResource | NetworkCategory | 80e1644138843ad829eb2adcfb8119d677029dc88ebf43a2cc90a081c4baba81 |
| tools | DescribeAvailableResource | RegionId | 95e0d9498a495b05fefff184a83f3cc3fdd1abce32f861d05d39a9b9da0d6e89 |
| tools | DescribeAvailableResource | ResourceType | 798718439d1012ddcd24717a01edc6c335bef2a981b533013c152d80c8746416 |
| tools | DescribeAvailableResource | Scope | a7864765bee1e980dc4075565eee043d9f74e04e08d39ee5d6552ab3f6ccae06 |
| tools | DescribeAvailableResource | SpotDuration | de8ad7246d3c43c87336c3f7c664d8a0fc70cbd0a5d1a7383ef0d9e6d5534631 |
| tools | DescribeAvailableResource | SpotStrategy | c0c3f434229afe0d61efdefa1a50d52b894e02ff759e1b0496fe145f5915cf3d |
| tools | DescribeAvailableResource | SystemDiskCategory | c92ab519a22a9800cbae75cdb9500dacbefb8ec50629f73c1b5b152b8649104b |
| tools | DescribeAvailableResource | ZoneId | 320b909cf079389bc697d6e8acdca94c36500da90b99d1d187910e8228516a6e |
| tools | DescribeDBInstances | description | e429f4c2b0f9c291b58360877af08e35f6f89cfa0c772de8fe92fbfbd2436919 |
| tools | DescribeDBInstances | Category | d9c3cff2737cd5f2840c4d5072e6c2580b7da8ec213ea8b80887eb99711cb90f |
| tools | DescribeDBInstances | ClientToken | fc7f6f4d49179a52e00631a0667140bc5f90ab18ad37b15ef4cd3b9999aa2249 |
| tools | DescribeDBInstances | ConnectionMode | ae90af3493951595ffc0e913815359a8cecbd54bc3e68eaf1daab1766d8dff32 |
| tools | DescribeDBInstances | ConnectionString | e0c0492d7d96516460ba190be394bdd477981aba39e233adad79139afc52c672 |
| tools | DescribeDBInstances | DBInstanceClass | 2fbb3bbccc67e49814b19021f2ec53246c6f96bf5f4e85a3f64487bb3394e963 |
| tools | DescribeDBInstances | DBInstanceId | e668276910a085dbe1ee4a4a172a680897badf997eb20b4dd48f4df75a7be25b |
| tools | DescribeDBInstances | DBInstanceStatus | 3411fc1289ca5c4850de8c47d78669b976d7397fc3062e2b5b500ce5f6730445 |
| tools | DescribeDBInstances | DBInstanceType | 7fa3855f720a52b5d40cda85613d7bd3b739e367e4b50110c73eaad780af594d |
| tools | DescribeDBInstances | DedicatedHostGroupId | ad8a8360ca95b0b375903b33ec892b5a00341600d27c1ca5a9cda00c6ba5427e |
| tools | DescribeDBInstances | DedicatedHostId | 8158415b90c3d015f045818a5692ed03435a14427975bff9860caabafb6f899e |
| tools | DescribeDBInstances | Engine | a6806a270db56efb88e16e1a565f8bf6c385c04e1b2407c6b2da2042ce232d11 |
| tools | DescribeDBInstances | EngineVersion | cdca0ab63c9b467e16367a8bbed80b57a1788926dd1d9c50d9cbe5850a61885a |
| tools | DescribeDBInstances | Expired | 1a1a19e093a96d197582b7fb44363943e6107238148246ac45cbe4b9b4deab87 |
| tools | DescribeDBInstances | Filter | 34f0929c94e825b033233fc950f378511f6786715c4b00914f138736de5e3518 |
| tools | DescribeDBInstances | InstanceLevel | e0c51464b5d1ee1f728f125f008e0ddc39552a41dd1297d760e89ba8e04c9b50 |
| tools | DescribeDBInstances | InstanceNetworkType | f8ba450d5f434177f4f2fd5e399682727a8a880a31323a27e96beff4effcaa70 |
| tools | DescribeDBInstances | MaxResults | 96bed3cc2d5f6119339180e22ff66d72637d30856b25437be72c1723256858be |
| tools | DescribeDBInstances | NextToken | 2cf930b801a4041a4dbc42662a810bfdb50f54c7b548d819c4d24f9331c65e28 |
| tools | DescribeDBInstances | PageNumber | 1dc34c832dfdabe8ab427be9358c7fd8a89f1031a14ed132e08ff24d9912b269 |
| tools | DescribeDBInstances | PageSize | efb9cf1579cdad0b8159c32581575f7b0babdb893abb5179af09816f195865a1 |
| tools | DescribeDBInstances | PayType | ceb2b1c3ad63418c000404552605345c63109c988aadca8a39caf9b8b9233f44 |
| tools | DescribeDBInstances | RegionId | dd3e800c8aaedf9ba71f52d46715d387b1b80e32e804570f564d01cf3250bd0f |
| tools | DescribeDBInstances | ResourceGroupId | 27c38b65f392c80286e253c9592db80a04b76af6d56a500b5ad0599466c9027a |
| tools | DescribeDBInstances | SearchKey | bbfb1b3c85a1092ae76ae840f83d09d08d93a556fe8abca1db749a5fa8f556b0 |
| tools | DescribeDBInstances | Tags | 4576d6ccb6bcad1278dc1536797c5835c5e627ac54ff70a0ccfd8170b307cc37 |
| tools | DescribeDBInstances | VSwitchId | 34d6fdff305663795bff9ce36a93cdcb8f62e073c06268cf676089f648dbcef4 |
| tools | DescribeDBInstances | VpcId | 9c999eacaba678f0279b7027c5b3c7b50a5e47c6b8a950b48e12b5d8c2587fe0 |
| tools | DescribeDBInstances | ZoneId | b1d2ca48cb730ef3cdc40106ed9269b36baaf8526587395b4abfb31142293acc |
| tools | DescribeDBInstances | proxyId | 684c843668b31ed0ab43715899a68f445e760196bf7a9556123292d9dadd245f |
| tools | DescribeImages | description | 7b9e39af4a694e9e5d41d443d5629b647ce7fb947e0b2f2e9b6bd529a16a76a0 |
| tools | DescribeImages | ActionType | 53a7c24720c1d479d7f2fb115031c3db57faa2f99fac723be6dd8bdb08fa2c64 |
| tools | DescribeImages | Architecture | ad76ced752037180735ecc38d5a03899262371562ae4f37557df55684f65f301 |
| tools | DescribeImages | DryRun | f79f4e9618f5bdf57b9f6c5f39605864c3fcb2873c20a5a6bd5d0b9b41df5ef0 |
| tools | DescribeImages | Filter | 184be6716c115715860ff20617a4ee836f8312edf8d4f114531ad1a00ce5a887 |
| tools | DescribeImages | ImageFamily | 141cb6fa430316a249b149c696acaea746b6171d74e773361423cc961ff1b8e6 |
| tools | DescribeImages | ImageId | 82c491b7872b75e27dd0a3d598d97f5860deb816a0b6f5babdb53d5d59f59ef2 |
| tools | DescribeImages | ImageName | b18b7564d273873b0dae7eeb7864505e599e18189b155af394151419fdb58157 |
| tools | DescribeImages | ImageOwnerAlias | c167213ee5ca2aa1b0362f601c9e62bf97252cff1f98e720f62602b6379ebdd8 |
| tools | DescribeImages | ImageOwnerId | 61b209620543c24b73aae9647e8d77a708a6e7d15301d64cc702eb7074c32a50 |
| tools | DescribeImages | InstanceType | 28ee64b963dd30f95787a5f3c9c76327dd98993cf6a3a2b9e6406470178938cc |
| tools | DescribeImages | IsPublic | ebae512a94629ad801a9632dfa95bf7f95bb3c2e1dd92b9ace465bc334242b7c |
| tools | DescribeImages | IsSupportCloudinit | 36007bd5c312ecd853ab337fdd0b13ad04830440ea89455c38bd2e789b9924ed |
| tools | DescribeImages | IsSupportIoOptimized | e5a471553054cf8c929373e3a36352916b1f3da69d60ad3d71e466d507e3a271 |
| tools | DescribeImages | OSType | 8c16a37f56ca927f43cedebe09f970cc67aefa3aa7dda6b99902880e01dc42a6 |
| tools | DescribeImages | PageNumber | 3cb121d23a19a594feed00e09655228b4e6bc8daba1a6bd8103ce40435676956 |
| tools | DescribeImages | PageSize | c1649134f269ce589af015cb294e0e28ab4f7536120b220d3b4e510d5e95545c |
| tools | DescribeImages | RegionId | 5ab3d6eeafc619b429a763372591a5978a477ad1b4b1c543cf1deab41391a526 |
| tools | DescribeImages | ResourceGroupId | 5f8fd30bf9b24ee53bfdb46223d4361a9628fc0f2d4d1ece732d7170df772d46 |
| tools | DescribeImages | ShowExpired | d398cc1cd2b45da2151e9c4ba885859db8d1cb8652f81c9209f9906ff165dbe3 |
| tools | DescribeImages | SnapshotId | 274e67cceed5cd377f86b82efe03280fbf86ea00bc4d7336517fcdf021a618c1 |
| tools | DescribeImages | Status | 239bb592b776aa7f92f6cbaaa80c6243d097790bb979d994db63dfbc87478862 |
| tools | DescribeImages | Tag | 83e9e6a7dd1a07deb29ec714126d1523a03b6a10476e9ea5624b6b05a53f284d |
| tools | DescribeImages | Usage | 0bfa857e8ae1950d535ffcde29bedfb1980043091fec7bcd1622e5d926295fa7 |
| tools | DescribeInstances | description | a28662a80361fdf89085f9d85fa5289ae7fd47ea0662ee8a203334b9128a198e |
| tools | DescribeInstances | AdditionalAttributes | c59bc571a8f0dacb14fbf3574d92256e703875f361bba7c314db09d3ad45b7d3 |
| tools | DescribeInstances | DeviceAvailable | 0c2bf3c8652978daeb6b04cb431391259c1af4e71c9b07ccc45ebacd9963c3bf |
| tools | DescribeInstances | DryRun | c6e19566632ebc01d985a36eefbd073d8f67c03b7262424c18f6157b7d75f079 |
| tools | DescribeInstances | EipAddresses | b6af49b1027ca6408396705c0c0320594f6d59e3cc4f082f1ea4c7fc354e7d54 |
| tools | DescribeInstances | HpcClusterId | 516517d85db1140377b0279a6d014b390a5e369eb923d0e1e07fb45394527c2a |
| tools | DescribeInstances | HttpEndpoint | 241757000ae8deee72302f4b1075586c2b66af63d75a6a8de3a8885057f218b6 |
| tools | DescribeInstances | HttpPutResponseHopLimit | 26161f20d05f4a3459315f07f5da9e9a2530348cf87f0350c84d9dcd3f491bcf |
| tools | DescribeInstances | HttpTokens | f92cf6795143cb5b06a3c0a26b3056b488dd8cdb3b96a6945a92ff3557b91914 |
| tools | DescribeInstances | ImageId | dfa754593cb92bd75a5ac634c55947439dfef151ba1c556c6b1cb75ff413cee5 |
| tools | DescribeInstances | InnerIpAddresses | d5d61be24ca9c35e603dd950b38d4773c8953522623940b35a401b557adc8245 |
| tools | DescribeInstances | InstanceChargeType | 94c78fcd6c5deabd22854234a934f85f8c421259b0ae938f45d5d587ca4d3817 |
| tools | DescribeInstances | InstanceIds | aac06960caed43abc88f7c3167e42a48959d01231d58103f8ecb88170e35fdd0 |
| tools | DescribeInstances | InstanceName | e64fa99f23d78973ebbe8c41f3a6963c0652810b5bda6c6810f3c1e7e6d95c1a |
| tools | DescribeInstances | InstanceNetworkType | 3598ac76ec7e4a9822cfee5bcd07b615c079bfff66d5131300d8c80ed3003242 |
| tools | DescribeInstances | InstanceType | e9ebaef1f174a13cf0e9e9a21976ce4a68f5c84bcb96456117456825a707f66a |
| tools | DescribeInstances | InstanceTypeFamily | 68f6559825eec6c55ca7f9a6b55ccbc2db5bb8bef4dca0d9607c33c79987a49d |
| tools | DescribeInstances | InternetChargeType | 0603f1b46c4bbf31107394efafe57437d9943446770e3990d107524fc1be8ade |
| tools | DescribeInstances | IoOptimized | ac279345cdc22a3938da3c6d01a410f5cf4278f58e79ca1d87f23398c8c38b5b |
| tools | DescribeInstances | Ipv6Address | 0192d7c96df642dfd076f643dc4a64be8a31e60c572182d70bb7982857e1e526 |
| tools | DescribeInstances | KeyPairName | 53cfe85adebf607160a50385c0ca5a7cbcbaa11a90a17520d1f9d4b6194b0589 |
| tools | DescribeInstances | LockReason | 319ce0b8dc29c721df723aef1b8618180b055d81584021cb21cac38e2d5f9cd7 |
| tools | DescribeInstances | MaxResults | 7c80c15454c90e3d6d12aa55b372aacf5888e40e25bc0ec6dc2016df69220c81 |
| tools | DescribeInstances | NeedSaleCycle | 0c2bf3c8652978daeb6b04cb431391259c1af4e71c9b07ccc45ebacd9963c3bf |
| tools | DescribeInstances | NextToken | 85fbcd294b814eacdc4ce76377d0cdc9f80d053cf313a5b0f5de56cb4c899440 |
| tools | DescribeInstances | PageNumber | 3a4094d6d52629c5422bfa62325b52e99c9744eb655f426fd269f1a8eed4a66d |
| tools | DescribeInstances | PageSize | 8643c646198519a54a8127ea51e5f2e5a306b4f59d9447a3d0c3943ee775609a |
| tools | DescribeInstances | PrivateIpAddresses | 4699387e4d1c71632964ed3fe9d1bce7b7650a0f8448743549b42b206808314c |
| tools | DescribeInstances | PublicIpAddresses | 72a6674e47904121bf87244b3a47536aa452f8ed634825d464d37f25689c31cb |
| tools | DescribeInstances | RdmaIpAddresses | 1eaebbd14625c89a9fb47aeeb861e58467efa212d42cc9af6ba597356df93cdb |
| tools | DescribeInstances | RegionId | 6a5d1879a2800d0eeee616fcbfd9e7005a98a00fd5f8a9232d5a0937887b6786 |
| tools | DescribeInstances | ResourceGroupId | fdebc311be282aef6192bb25fb878e78a51082da67e0fa0e788509873aaeb343 |
| tools | DescribeInstances | SecurityGroupId | f4db556278275b8cf5945e31281261fdf7b60c36aa64dc22da588d526471f2c9 |
| tools | DescribeInstances | Status | b0f542f074264ecd9d7009616ada602b619fb2dc32e42319c08513a9728bedce |
| tools | DescribeInstances | Tag | 83e9e6a7dd1a07deb29ec714126d1523a03b6a10476e9ea5624b6b05a53f284d |
| tools | DescribeInstances | VSwitchId | a4ac8720603684408bd6df34d0a1e9da6ef8ac93fa9e50140176b6e15215cc8a |
| tools | DescribeInstances | VpcId | b3afe03803970f1f44a151b756e49e78faf9f52799070e3f1f4411dab59d80ae |
| tools | DescribeInstances | ZoneId | 2b9b2c49abeadb9882c1be4c01bdb9ce07e41b650be507f7d99221075fb5a56c |
| tools | DescribeRegions | description | 724439e22c78a85a56a968d31a6288b6f86c13e37436e2a27d1afc0934421cc3 |
| tools | DescribeRegions | AcceptLanguage | 97d088230fdf686e9da1d9ff0f56de8d796c8d61e3eb821829afeadfe4dc7291 |
| tools | DescribeRegions | InstanceChargeType | a0864c7ccdd8a602187897e1751400e5eb2e772cc322060909921739720c4fd1 |
| tools | DescribeRegions | RegionId | 9503d3f99019306f9dac25f97f1cba93dfc9d40677af27024b204fa233b1c0aa |
| tools | DescribeRegions | ResourceType | 0e8a62eb8f972f35fc591ec1fa7cb001bdf94996992521e5c82f12b7ab1ba7f9 |
| tools | DescribeSecurityGroups | description | 974995f8def0cf8014a8e1a1271e3462a921755203768b6da8290db18eb45232 |
| tools | DescribeSecurityGroups | DryRun | 74d2c4ffad9646f0e51c8b2b3ea6c0be1613356b0ea8dda02858acd95ae01656 |
| tools | DescribeSecurityGroups | FuzzyQuery | 55f7d10cf95f16ec5ca4616427d3d64993ba4e77bb0ae419c62683ed6f2ab840 |
| tools | DescribeSecurityGroups | IsQueryEcsCount | 74c01db2fb9da094a53dc1be019dddb6a88824401608245a87a3c481da0daa13 |
| tools | DescribeSecurityGroups | MaxResults | 938a755bec3fd3fa83eca4dfe76094c0d519998a560df53deb5032f0b3caec72 |
| tools | DescribeSecurityGroups | NetworkType | ae1f0d961754b1669ed74aca412b3b8e8559bf8d40d577e9d746faccd7a40836 |
| tools | DescribeSecurityGroups | NextToken | a90171fe22b485f5400adc59e14bf3ae4dd79c987a333e9996e273cc35d501ea |
| tools | DescribeSecurityGroups | PageNumber | 3a4094d6d52629c5422bfa62325b52e99c9744eb655f426fd269f1a8eed4a66d |
| tools | DescribeSecurityGroups | PageSize | 8643c646198519a54a8127ea51e5f2e5a306b4f59d9447a3d0c3943ee775609a |
| tools | DescribeSecurityGroups | RegionId | 2b3ec6948510eec21166d3d4909f34da19734a209512940f490d3d73d4ee86d1 |
| tools | DescribeSecurityGroups | ResourceGroupId | 750465cefb03595e10eacebad78afa598d6966086ae322ff66114e193c286716 |
| tools | DescribeSecurityGroups | SecurityGroupId | c7fcd5a9f520a601187c5a3a58e83329f09a8f27441309b356391aef945a140e |
| tools | DescribeSecurityGroups | SecurityGroupIds | bfb1068b60b0a550fdedcbc9dc65061ca3bf3993c40997b7c1312bf25ddbca25 |
| tools | DescribeSecurityGroups | SecurityGroupName | d70cdac05df945801a35355b31c5f3d2e4cf8f25f746305727620508f6d828bd |
| tools | DescribeSecurityGroups | SecurityGroupType | d0d8ec44540ef1a5cc3b5a51f19493ad1194096400da5050e9525a48ac276b97 |
| tools | DescribeSecurityGroups | ServiceManaged | 6e9d20f943f15db566ecdec50042cc8296cfa6eb0088364b6eb6638999da0af3 |
| tools | DescribeSecurityGroups | Tag | 83e9e6a7dd1a07deb29ec714126d1523a03b6a10476e9ea5624b6b05a53f284d |
| tools | DescribeSecurityGroups | VpcId | 47264274a6f7d4993132c0f1f9cb50e1ef4429d06a75153aae629fc80a5652b2 |
| tools | DescribeVSwitches | description | 590bac0ac1ceadd90b4cc06f1d9ed4f51bd69ef683902965c7fe3e00367763aa |
| tools | DescribeVSwitches | DryRun | a3a141b6e8825196032f585432b769282d842a94086f929a2ba064411ae343b6 |
| tools | DescribeVSwitches | EnableIpv6 | 536767fb1a462d50038e5f2923f6a84210c4ec059b17cb36040b81f105e6642a |
| tools | DescribeVSwitches | IsDefault | 2fe2b2526810ec6ecd1148ae0762977fdd65bf1cec49b7d105c581502ed44e31 |
| tools | DescribeVSwitches | PageNumber | c7e8e1faa08b4924d65c1d384e0931ef6931034059119c26989f7fd121133855 |
| tools | DescribeVSwitches | PageSize | 4d59809c388da72981c7cb9c1f114376da201dd91f231665a8ea9d9ffcf9eb00 |
| tools | DescribeVSwitches | RegionId | c1232da70253fa78bdef3cc8a1dc7b6670d869cdf22d1f530500f8d124dd99cd |
| tools | DescribeVSwitches | ResourceGroupId | d99a25598973b6e2e19b25f11c52a6a2722e19bef918c3cb135c2f3e13d128a7 |
| tools | DescribeVSwitches | RouteTableId | 965e34a18f6d96d8c1384981b76a7f399fae5c3510851fd16006bd43fa6cca8b |
| tools | DescribeVSwitches | Tag | 49eb82179b8af61102d151aef5887143794269e5a25ac79d12fc2e491c0e5e77 |
| tools | DescribeVSwitches | VSwitchId | e04633f6ed82b28f6e1adf2bfba6403199ae5dc09b200c7eef930073f9918f90 |
| tools | DescribeVSwitches | VSwitchName | b0b99af3fd5abb98383d8d5172a2e48a0549c6500caf4c13da18c2e8af431768 |
| tools | DescribeVSwitches | VSwitchOwnerId | 0c8463a443e52754eba4af6757917a474e0290d625b887edc9810307c80965f8 |
| tools | DescribeVSwitches | VpcId | 8fb361c6cbbce5fff2f28073122c1615439deedf3e392b604e4794d65e672a07 |
| tools | DescribeVSwitches | ZoneId | ad5773e515ddb1467216f65c04696000c15ba5944df4d66f13d97eea07166768 |
| tools | DescribeVpcs | description | f06a297508d84a303b32891ebe65ca9545423bac48e9ab95ac66fb9dd5d0b9b6 |
| tools | DescribeVpcs | DhcpOptionsSetId | 50de7756536ed0db7cd216256f4bd5b3dd9dc987754cf3f56ab9c7c8d5dd5493 |
| tools | DescribeVpcs | DryRun | 98ec7ef5ad4b9509416f57cd0c5a8ba79dba2723641ac2c434b186580e00fc0f |
| tools | DescribeVpcs | EnableIpv6 | e67b6b97148fd2daa38dc84611256bbffe3566ca1ede85ea34c50ad2dee85c1c |
| tools | DescribeVpcs | IsDefault | 13e9007f9e1a1e58083766afc3d3a97815266b32884caa05248d4ca09bc9ca29 |
| tools | DescribeVpcs | PageNumber | c7e8e1faa08b4924d65c1d384e0931ef6931034059119c26989f7fd121133855 |
| tools | DescribeVpcs | PageSize | 76495fa93b6e4c9bdc62741a2eb5ac27044c53f0a0103a7ad9908d83f230a597 |
| tools | DescribeVpcs | RegionId | 35e76f05fe51ea53c0c5423b51ef0dc32850099089a966d5479c1cefd0c920ea |
| tools | DescribeVpcs | ResourceGroupId | d7f75949f4b9316df5d7d829c258b0ab392214d311f04355055f94564862e644 |
| tools | DescribeVpcs | Tag | 49eb82179b8af61102d151aef5887143794269e5a25ac79d12fc2e491c0e5e77 |
| tools | DescribeVpcs | VpcId | 45fd611624c4aff476981012bf4ca25f1c426dc98976d23138c2ea8c49ca51ef |
| tools | DescribeVpcs | VpcName | e7975268795ab3e03e9b6084289350abf9ee90e9a760cc7cf6e8e354f6dda5f6 |
| tools | DescribeVpcs | VpcOwnerId | a1c8d09ac3654d5a4d6d6fb2ef8f3229f5904241f6b8a3c852906b4922fc32c5 |
| tools | DescribeZones | description | 7bbc1a1726ba7c9cdb6530521edc66856017ca35a14fdd557bdae0095073b751 |
| tools | DescribeZones | AcceptLanguage | 33223edd940a496b900ea5299f06561c7e5df7a5471cdf1dcdb863788de9c623 |
| tools | DescribeZones | InstanceChargeType | b0c63aaddada54c165241b016e2761da1f2e96bdfecfb40c93492eae2aaff6d3 |
| tools | DescribeZones | RegionId | f606eeb3add8cf2cf17b62ab607075f0f061ff9651d09d100ea5db550366d5bb |
| tools | DescribeZones | SpotStrategy | 8b30c268f690fca14ffa7d913ce580a25529b8df2c0a1c300707ba6a97789432 |
| tools | DescribeZones | Verbose | f083ea656023a05e342abf105e2c2af32e579a1afb5f0bbf9b4a0ffe07b27929 |
| tools | GetCpuLoadavgData | description | 41652de13b3c7c58e42e6a4492cf31b46e843206e322a9449abd05839b8c21a5 |
| tools | GetCpuLoadavgData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetCpuLoadavgData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetCpuUsageData | description | b48ee53ba21d5cda0a95da59872ad029104c842ce44ec4e82d762296f52d88e5 |
| tools | GetCpuUsageData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetCpuUsageData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetCpuloadavg15mData | description | 549b25638abfc79ee83bc07d5e7d903027d643dfa9ed9ccc6e58537021a5ddb0 |
| tools | GetCpuloadavg15mData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetCpuloadavg15mData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetCpuloadavg5mData | description | e2d6689f38908f260e174db620ee5030dc422730708276a88d86fa56c84b49c8 |
| tools | GetCpuloadavg5mData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetCpuloadavg5mData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetDiskTotalData | description | 4db1ae50ede0649ad2cb38bec3320d2f075d15a9013d752eae81fd57166034a7 |
| tools | GetDiskTotalData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetDiskTotalData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetDiskUsageData | description | 78aa3a39be7ed21f5c18757b871394dfd4ef2f89d3e8a1c458b9d6361f429e71 |
| tools | GetDiskUsageData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetDiskUsageData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetDiskUsedData | description | e226a9921aa9185b0e99598afebb8e4148b53cbfd23efe32a7b9a05f615298e6 |
| tools | GetDiskUsedData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetDiskUsedData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetMemUsageData | description | 5aac768c294daac21fdb877ee1a830914ad857c375f7145cd308cb4e493bc3dd |
| tools | GetMemUsageData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetMemUsageData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | GetMemUsedData | description | 3deb761f34fcb36343a7bc86816c4fbece4268664fe6313c0ec5e27a9fdbcb61 |
| tools | GetMemUsedData | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | GetMemUsedData | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | ListBuckets | description | 53ef8dcd87ffe37e106c8846b6cf1eb85d4d95a99694819369e2cb26afe3833f |
| tools | ListBuckets | Prefix | 842acc0be5c86f318a10292fcd531e702d65dbbafd05f6d961975b084a9bed13 |
| tools | ListBuckets | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | ListObjects | description | a857f99b9e698e92ee186ea317028030123ffc567ad4c9c9850c340144af66cb |
| tools | ListObjects | BucketName | c054f7f7409e381b13900fb120a8aa9f7e39ae8d3b6d8d9d198052e02714b895 |
| tools | ListObjects | Prefix | 842acc0be5c86f318a10292fcd531e702d65dbbafd05f6d961975b084a9bed13 |
| tools | ListObjects | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | PutBucket | description | 1b263bbe06cd2619edea488fe78f781f014ab161e8c4dc384d40ef6c62f98a6b |
| tools | PutBucket | BucketName | c054f7f7409e381b13900fb120a8aa9f7e39ae8d3b6d8d9d198052e02714b895 |
| tools | PutBucket | DataRedundancyType | 1e5cd59109f4f1bc3f44a140f3b1008d946478ec731c2e6b041d8a082a671535 |
| tools | PutBucket | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | PutBucket | StorageClass | d8694c5db8c8fdfc2bf7fb7d6580ab63fb715fd130ce78aaeeb86a453529ccc9 |
| tools | RebootInstances | description | 1636357802dfb1e363bd90bccb30de5558b17fea156d78d53ed5f8ceb78ac97e |
| tools | RebootInstances | ForeceStop | 99976c8b00f8a26bad165f6035f444ed44c4283c542a33dc3120ebf2343ec92f |
| tools | RebootInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | RebootInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | RebootRDSInstances | description | 0db0233dcf7820dd57804634bce6be3e80e64bda482a14e6b92a8121f8c42bcc |
| tools | RebootRDSInstances | InstanceIds | 94c0de0e1dca546c1c7a4153d4726b0f364a642f25af1981723240e902643682 |
| tools | RebootRDSInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | ReplaceSystemDisk | description | d0d6d720f2d2b85b11cf4b8a06ab14a8dc6de15f3a1d39c12250e1e7dd1d660a |
| tools | ReplaceSystemDisk | ImageId | e780d31fde4a9a7a36431d220963181ad11dbabc44726d4ad63575646248e1b9 |
| tools | ReplaceSystemDisk | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | ReplaceSystemDisk | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | ResetPassword | description | 4a33b145e5b8d26e4c1c08e31a0b428bafb564d6eac35de3cbb2e477d039b827 |
| tools | ResetPassword | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | ResetPassword | Password | b7258dd07b9fbea8a9e69664eb9a298fc9aa37a8d5fff5fc0a2c62f70a8f711d |
| tools | ResetPassword | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | RunCommand | description | 24cff39b267e346b7083d22f58dd20b6f0c2d1c5ef110fdd561397320eac32b1 |
| tools | RunCommand | Command | b5a8cb191642b66b6c8d70c68080199c6e42397a2694cf3fdfe65c77ab9494cc |
| tools | RunCommand | CommandType | 36b1638d62b2c428d109c7d361070dab3f8b88ac88e7c0d65f8cb1175a8ae556 |
| tools | RunCommand | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | RunCommand | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | RunInstances | description | 9f242e6a3ef246a32b45c8a7b8f880823efed4773562d6f3bfa4dee58a7ba9c4 |
| tools | RunInstances | Amount | 7cbf3f2f47038f065fd18a2ae3e3209f1b9b1464ed77b1706b1d682ecf30ecd3 |
| tools | RunInstances | ImageId | e780d31fde4a9a7a36431d220963181ad11dbabc44726d4ad63575646248e1b9 |
| tools | RunInstances | InstanceName | 85d41dd35ffc946d8d382ee0c2c3b34c183e7c90eb44507d9c4b32ffb1364525 |
| tools | RunInstances | InstanceType | 894583b8fb98ecc1949d791e9581c5069ea4ee9257c8f1788aff5db4145518e5 |
| tools | RunInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | RunInstances | SecurityGroupId | aaf4294581458c5e074f518dcca8c6a8e3d2499d9327fb54f2752b84b1e29e12 |
| tools | RunInstances | VSwitchId | 59e6707b70baeb8daa22e49efab46925019d41489da4d6d5239f88741022d0bd |
| tools | StartInstances | description | 2a9f08533d2ce509b6ed4af460a44cb475cbb4880bea5f20f298a8daa3949260 |
| tools | StartInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | StartInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | StartRDSInstances | description | 1b51fcfc50e0e2ace55caf73d80caa25e29890448385dd20ff7015765b841787 |
| tools | StartRDSInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | StartRDSInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | StopInstances | description | d2ba4bde7d55993dc51809cfa260a1502278a850e1bab1413ba442c5b458cc7e |
| tools | StopInstances | ForeceStop | 99976c8b00f8a26bad165f6035f444ed44c4283c542a33dc3120ebf2343ec92f |
| tools | StopInstances | InstanceIds | dc8d09727c649c62ceabec0598e3608c62a7c2cefc092192ecf0d7df9445aad2 |
| tools | StopInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |
| tools | StopRDSInstances | description | 77ef2436fc623a21ff2cd4ed8c0aff898698e94b7264987d1b64dfba8257deaf |
| tools | StopRDSInstances | InstanceIds | 94c0de0e1dca546c1c7a4153d4726b0f364a642f25af1981723240e902643682 |
| tools | StopRDSInstances | RegionId | ba8b5c549e2a13baa46a390ad0fbe12b6eaccef404afca5fb51a063072048449 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
