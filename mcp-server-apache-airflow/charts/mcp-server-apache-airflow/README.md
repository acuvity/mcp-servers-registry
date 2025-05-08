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


# What is mcp-server-apache-airflow?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-apache-airflow/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-apache-airflow/0.2.2?logo=docker&logoColor=fff&label=0.2.2)](https://hub.docker.com/r/acuvity/mcp-server-apache-airflow)
[![PyPI](https://img.shields.io/badge/0.2.2-3775A9?logo=pypi&logoColor=fff&label=mcp-server-apache-airflow)](https://github.com/yangkyeongmo/mcp-server-apache-airflow)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-apache-airflow&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22AIRFLOW_HOST%22%2C%22-e%22%2C%22AIRFLOW_PASSWORD%22%2C%22-e%22%2C%22AIRFLOW_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-apache-airflow%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server that connects to Apache Airflow using official client.

> [!NOTE]
> `mcp-server-apache-airflow` has been packaged by Acuvity from mcp-server-apache-airflow original [sources](https://github.com/yangkyeongmo/mcp-server-apache-airflow).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-server-apache-airflow run reliably and safely.

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
  - [ Gyeongmo Yang <me@gmyang.dev> ](https://github.com/yangkyeongmo/mcp-server-apache-airflow) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-server-apache-airflow ](https://github.com/yangkyeongmo/mcp-server-apache-airflow)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-server-apache-airflow ](https://github.com/yangkyeongmo/mcp-server-apache-airflow)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-apache-airflow/charts/mcp-server-apache-airflow)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-apache-airflow/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.2`

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
  - `AIRFLOW_PASSWORD` secret to be set as secrets.AIRFLOW_PASSWORD either by `.value` or from existing with `.valueFrom`
  - `AIRFLOW_USERNAME` secret to be set as secrets.AIRFLOW_USERNAME either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `AIRFLOW_HOST` environment variable to be set by env.AIRFLOW_HOST

# How to install


Install will helm

```console
helm install mcp-server-apache-airflow oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-apache-airflow oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-apache-airflow
```

From there your MCP server mcp-server-apache-airflow will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-apache-airflow` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-apache-airflow
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-apache-airflow` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-apache-airflow oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-apache-airflow oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-apache-airflow oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-apache-airflow oci://docker.io/acuvity/mcp-server-apache-airflow --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (65)
<details>
<summary>get_config</summary>

**Description**:

```
Get current configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| section | any | not set | No
</details>
<details>
<summary>get_value</summary>

**Description**:

```
Get a specific option from configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| option | string | not set | Yes
| section | string | not set | Yes
</details>
<details>
<summary>list_connections</summary>

**Description**:

```
List all connections
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
</details>
<details>
<summary>create_connection</summary>

**Description**:

```
Create a connection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conn_id | string | not set | Yes
| conn_type | string | not set | Yes
| extra | any | not set | No
| host | any | not set | No
| login | any | not set | No
| password | any | not set | No
| port | any | not set | No
| schema | any | not set | No
</details>
<details>
<summary>get_connection</summary>

**Description**:

```
Get a connection by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conn_id | string | not set | Yes
</details>
<details>
<summary>update_connection</summary>

**Description**:

```
Update a connection by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conn_id | string | not set | Yes
| conn_type | any | not set | No
| extra | any | not set | No
| host | any | not set | No
| login | any | not set | No
| password | any | not set | No
| port | any | not set | No
| schema | any | not set | No
</details>
<details>
<summary>delete_connection</summary>

**Description**:

```
Delete a connection by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conn_id | string | not set | Yes
</details>
<details>
<summary>test_connection</summary>

**Description**:

```
Test a connection
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conn_type | string | not set | Yes
| extra | any | not set | No
| host | any | not set | No
| login | any | not set | No
| password | any | not set | No
| port | any | not set | No
| schema | any | not set | No
</details>
<details>
<summary>fetch_dags</summary>

**Description**:

```
Fetch all DAGs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id_pattern | any | not set | No
| limit | any | not set | No
| offset | any | not set | No
| only_active | any | not set | No
| order_by | any | not set | No
| paused | any | not set | No
| tags | any | not set | No
</details>
<details>
<summary>get_dag</summary>

**Description**:

```
Get a DAG by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
</details>
<details>
<summary>get_dag_details</summary>

**Description**:

```
Get a simplified representation of DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| fields | any | not set | No
</details>
<details>
<summary>get_dag_source</summary>

**Description**:

```
Get a source code
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_token | string | not set | Yes
</details>
<details>
<summary>pause_dag</summary>

**Description**:

```
Pause a DAG by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
</details>
<details>
<summary>unpause_dag</summary>

**Description**:

```
Unpause a DAG by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
</details>
<details>
<summary>get_dag_tasks</summary>

**Description**:

```
Get tasks for DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
</details>
<details>
<summary>get_task</summary>

**Description**:

```
Get a task by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| task_id | string | not set | Yes
</details>
<details>
<summary>get_tasks</summary>

**Description**:

```
Get tasks for DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| order_by | any | not set | No
</details>
<details>
<summary>patch_dag</summary>

**Description**:

```
Update a DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| is_paused | any | not set | No
| tags | any | not set | No
</details>
<details>
<summary>patch_dags</summary>

**Description**:

```
Update multiple DAGs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id_pattern | any | not set | No
| is_paused | any | not set | No
| tags | any | not set | No
</details>
<details>
<summary>delete_dag</summary>

**Description**:

```
Delete a DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
</details>
<details>
<summary>clear_task_instances</summary>

**Description**:

```
Clear a set of task instances
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dry_run | any | not set | No
| end_date | any | not set | No
| include_downstream | any | not set | No
| include_future | any | not set | No
| include_parentdag | any | not set | No
| include_past | any | not set | No
| include_subdags | any | not set | No
| include_upstream | any | not set | No
| reset_dag_runs | any | not set | No
| start_date | any | not set | No
| task_ids | any | not set | No
</details>
<details>
<summary>set_task_instances_state</summary>

**Description**:

```
Set a state of task instances
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dry_run | any | not set | No
| execution_date | any | not set | No
| include_downstream | any | not set | No
| include_future | any | not set | No
| include_past | any | not set | No
| include_upstream | any | not set | No
| state | string | not set | Yes
| task_ids | any | not set | No
</details>
<details>
<summary>reparse_dag_file</summary>

**Description**:

```
Request re-parsing of a DAG file
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_token | string | not set | Yes
</details>
<details>
<summary>post_dag_run</summary>

**Description**:

```
Trigger a DAG by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | any | not set | No
| data_interval_end | any | not set | No
| data_interval_start | any | not set | No
| end_date | any | not set | No
| execution_date | any | not set | No
| external_trigger | any | not set | No
| last_scheduling_decision | any | not set | No
| logical_date | any | not set | No
| note | any | not set | No
| run_type | any | not set | No
| start_date | any | not set | No
</details>
<details>
<summary>get_dag_runs</summary>

**Description**:

```
Get DAG runs by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| end_date_gte | any | not set | No
| end_date_lte | any | not set | No
| execution_date_gte | any | not set | No
| execution_date_lte | any | not set | No
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
| start_date_gte | any | not set | No
| start_date_lte | any | not set | No
| state | any | not set | No
| updated_at_gte | any | not set | No
| updated_at_lte | any | not set | No
</details>
<details>
<summary>get_dag_runs_batch</summary>

**Description**:

```
List DAG runs (batch)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_ids | any | not set | No
| end_date_gte | any | not set | No
| end_date_lte | any | not set | No
| execution_date_gte | any | not set | No
| execution_date_lte | any | not set | No
| order_by | any | not set | No
| page_limit | any | not set | No
| page_offset | any | not set | No
| start_date_gte | any | not set | No
| start_date_lte | any | not set | No
| state | any | not set | No
</details>
<details>
<summary>get_dag_run</summary>

**Description**:

```
Get a DAG run by DAG ID and DAG run ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
</details>
<details>
<summary>update_dag_run_state</summary>

**Description**:

```
Update a DAG run state by DAG ID and DAG run ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| state | any | not set | No
</details>
<details>
<summary>delete_dag_run</summary>

**Description**:

```
Delete a DAG run by DAG ID and DAG run ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
</details>
<details>
<summary>clear_dag_run</summary>

**Description**:

```
Clear a DAG run
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| dry_run | any | not set | No
</details>
<details>
<summary>set_dag_run_note</summary>

**Description**:

```
Update the DagRun note
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| note | string | not set | Yes
</details>
<details>
<summary>get_upstream_dataset_events</summary>

**Description**:

```
Get dataset events for a DAG run
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
</details>
<details>
<summary>get_dag_stats</summary>

**Description**:

```
Get DAG stats
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_ids | any | not set | No
</details>
<details>
<summary>get_datasets</summary>

**Description**:

```
List datasets
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_ids | any | not set | No
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
| uri_pattern | any | not set | No
</details>
<details>
<summary>get_dataset</summary>

**Description**:

```
Get a dataset by URI
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uri | string | not set | Yes
</details>
<details>
<summary>get_dataset_events</summary>

**Description**:

```
Get dataset events
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dataset_id | any | not set | No
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
| source_dag_id | any | not set | No
| source_map_index | any | not set | No
| source_run_id | any | not set | No
| source_task_id | any | not set | No
</details>
<details>
<summary>create_dataset_event</summary>

**Description**:

```
Create dataset event
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dataset_uri | string | not set | Yes
| extra | any | not set | No
</details>
<details>
<summary>get_dag_dataset_queued_event</summary>

**Description**:

```
Get a queued Dataset event for a DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| uri | string | not set | Yes
</details>
<details>
<summary>get_dag_dataset_queued_events</summary>

**Description**:

```
Get queued Dataset events for a DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
</details>
<details>
<summary>delete_dag_dataset_queued_event</summary>

**Description**:

```
Delete a queued Dataset event for a DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| uri | string | not set | Yes
</details>
<details>
<summary>delete_dag_dataset_queued_events</summary>

**Description**:

```
Delete queued Dataset events for a DAG
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| before | any | not set | No
| dag_id | string | not set | Yes
</details>
<details>
<summary>get_dataset_queued_events</summary>

**Description**:

```
Get queued Dataset events for a Dataset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uri | string | not set | Yes
</details>
<details>
<summary>delete_dataset_queued_events</summary>

**Description**:

```
Delete queued Dataset events for a Dataset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| before | any | not set | No
| uri | string | not set | Yes
</details>
<details>
<summary>get_event_logs</summary>

**Description**:

```
List log entries from event log
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | any | not set | No
| before | any | not set | No
| dag_id | any | not set | No
| event | any | not set | No
| excluded_events | any | not set | No
| included_events | any | not set | No
| limit | any | not set | No
| map_index | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
| owner | any | not set | No
| run_id | any | not set | No
| task_id | any | not set | No
| try_number | any | not set | No
</details>
<details>
<summary>get_event_log</summary>

**Description**:

```
Get a specific log entry by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| event_log_id | integer | not set | Yes
</details>
<details>
<summary>get_import_errors</summary>

**Description**:

```
List import errors
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
</details>
<details>
<summary>get_import_error</summary>

**Description**:

```
Get a specific import error by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| import_error_id | integer | not set | Yes
</details>
<details>
<summary>get_health</summary>

**Description**:

```
Get instance status
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_version</summary>

**Description**:

```
Get version information
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_plugins</summary>

**Description**:

```
Get a list of loaded plugins
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
</details>
<details>
<summary>get_pools</summary>

**Description**:

```
List pools
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
</details>
<details>
<summary>get_pool</summary>

**Description**:

```
Get a pool by name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pool_name | string | not set | Yes
</details>
<details>
<summary>delete_pool</summary>

**Description**:

```
Delete a pool
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pool_name | string | not set | Yes
</details>
<details>
<summary>post_pool</summary>

**Description**:

```
Create a pool
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| include_deferred | any | not set | No
| name | string | not set | Yes
| slots | integer | not set | Yes
</details>
<details>
<summary>patch_pool</summary>

**Description**:

```
Update a pool
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| include_deferred | any | not set | No
| pool_name | string | not set | Yes
| slots | any | not set | No
</details>
<details>
<summary>get_task_instance</summary>

**Description**:

```
Get a task instance by DAG ID, task ID, and DAG run ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| task_id | string | not set | Yes
</details>
<details>
<summary>list_task_instances</summary>

**Description**:

```
List task instances by DAG ID and DAG run ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| duration_gte | any | not set | No
| duration_lte | any | not set | No
| end_date_gte | any | not set | No
| end_date_lte | any | not set | No
| execution_date_gte | any | not set | No
| execution_date_lte | any | not set | No
| limit | any | not set | No
| offset | any | not set | No
| pool | any | not set | No
| queue | any | not set | No
| start_date_gte | any | not set | No
| start_date_lte | any | not set | No
| state | any | not set | No
| updated_at_gte | any | not set | No
| updated_at_lte | any | not set | No
</details>
<details>
<summary>update_task_instance</summary>

**Description**:

```
Update a task instance by DAG ID, DAG run ID, and task ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| state | any | not set | No
| task_id | string | not set | Yes
</details>
<details>
<summary>list_variables</summary>

**Description**:

```
List all variables
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | any | not set | No
| offset | any | not set | No
| order_by | any | not set | No
</details>
<details>
<summary>create_variable</summary>

**Description**:

```
Create a variable
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| key | string | not set | Yes
| value | string | not set | Yes
</details>
<details>
<summary>get_variable</summary>

**Description**:

```
Get a variable by key
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>update_variable</summary>

**Description**:

```
Update a variable by key
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| key | string | not set | Yes
| value | any | not set | No
</details>
<details>
<summary>delete_variable</summary>

**Description**:

```
Delete a variable by key
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
</details>
<details>
<summary>get_xcom_entries</summary>

**Description**:

```
Get all XCom entries
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| limit | any | not set | No
| map_index | any | not set | No
| offset | any | not set | No
| task_id | string | not set | Yes
| xcom_key | any | not set | No
</details>
<details>
<summary>get_xcom_entry</summary>

**Description**:

```
Get an XCom entry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dag_id | string | not set | Yes
| dag_run_id | string | not set | Yes
| deserialize | any | not set | No
| map_index | any | not set | No
| stringify | any | not set | No
| task_id | string | not set | Yes
| xcom_key | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | clear_dag_run | description | 4354046070b51561578c99ef466ea19dcb0515daaa229e462c4386a7cd4c2c02 |
| tools | clear_task_instances | description | 6cb3386311076528e1e111fec48ba7ba9d6272ddcbee0842e85d5897d0c6ed3a |
| tools | create_connection | description | 0bbb6ccc91590ad3b5ccc58b5be349106a8c4fcfb135bc3be73f68efaf36fd97 |
| tools | create_dataset_event | description | 712b0dde5f83409380cd8e65dd799f2f1b917472cbab65bddcbcf5f64e6ee007 |
| tools | create_variable | description | bf9bb27b5b62de51397158e4ff9fe80289282b98f76991843fabf395a07d5a49 |
| tools | delete_connection | description | 2bbf083630b9a03734c9bbd1f7997076f1ec39801893f737106ff072344d4610 |
| tools | delete_dag | description | d0abeaee2ff88b4de92811697f82e838f1030ac910a090390b22cd9d0f36965f |
| tools | delete_dag_dataset_queued_event | description | 027d6ddd44e55469f34fc22375e0aba7ae75e881c5529385407d37279c8e4511 |
| tools | delete_dag_dataset_queued_events | description | b89a1d07dd4c5d2dfcdad12c36e99dfa6c4315580837dd16fa4976464cbf3928 |
| tools | delete_dag_run | description | fe394b79841f6a7b3e6dab5155e6893a463b1b7c77a3588769cb6d3dc4931354 |
| tools | delete_dataset_queued_events | description | 45d5d8ed039dc9f2c425f89b71b729ed8d6fee3fc42d19e4633990808042a539 |
| tools | delete_pool | description | 88be11669bcf1ec9a9ba0ec8a7009587b384037ee5df0a51ccfc7719c9db37e8 |
| tools | delete_variable | description | cefa78b4658d30d5e0164f96c2fe8bbedba972a7b0436da55630f6ebd85d54c1 |
| tools | fetch_dags | description | a4f11485f71e16ce440f2c0893645eb90190bd110cfd29b4e3810dc39cbc026e |
| tools | get_config | description | b51a8c7aac67f2ca12313e8f3c66d14ce3f1f64f4a730617a4608dbcb499be3b |
| tools | get_connection | description | 333cf24ab0965eb0e72ddb4dedd2f5c424b9388b1fd29cb3d914dcffd8a409b7 |
| tools | get_dag | description | e59578749b07c1cc75ff2658163f027a7f6b43de9031b738aeb2f2aaa44965d5 |
| tools | get_dag_dataset_queued_event | description | 46e2fe1f51ccfc41a06781ec7a6daa018a146cf64e711dd665014f73bdce0cd8 |
| tools | get_dag_dataset_queued_events | description | ec1c271eb027d9441d53ba775b7970390075f081db7a79d93c5b99a252f4dc45 |
| tools | get_dag_details | description | 6561a0d8a577e6b049a9401809a2ec56f12864ed78a26a34545eb65ab28df266 |
| tools | get_dag_run | description | fde9b4e4f0dbd776d5273f2772adcf0b435543a90b2e01111742bcae7e091854 |
| tools | get_dag_runs | description | 182b23431660e152f8a71e961b5744920aabcb17b574ada12062105393cfad20 |
| tools | get_dag_runs_batch | description | 02aafdb1d62528d6ab2013330e62be7257a9b2b017bded3a51b05adcfc79bac4 |
| tools | get_dag_source | description | c725e052c79a8451eb2679414280f2db5c778567dbe94ca8f68c29e36d50ba60 |
| tools | get_dag_stats | description | a191ed8c1fc019cf98d9aaed5543bbf504694721b4ea288f0514eec14849dde6 |
| tools | get_dag_tasks | description | 08e88306b652a6b146f0649293dfc45b773d21fc0c214d1f9630d4fec467a729 |
| tools | get_dataset | description | 36abad2de88b456b105641dd8987a4be4d6d3e66ee812c64f411d5b17d987730 |
| tools | get_dataset_events | description | edc1d01091203bd7259d804f362b234bfa7c7dad6f48dc2cc372a242a6e2c9a0 |
| tools | get_dataset_queued_events | description | 7c12a174df9943d4f399ba6c5c4fce5bbf30f3f4e309e32b790a2868ea903bdb |
| tools | get_datasets | description | 5125292f8ba735210dbd20d312696824f486945c9733545ed0e7c48da49c7264 |
| tools | get_event_log | description | d105c3ae8a89463fb7065f5c15126e5bf1094afd84ee8b823ef06a24cee8cc3d |
| tools | get_event_logs | description | 57891f309b7d6c509fa7319dd615f719cd17f75430f10b8c7d39e885909ab0de |
| tools | get_health | description | 1925b0571822a40efaa00581139dcd098a93cf4d281d748eb5adc548a03d7e95 |
| tools | get_import_error | description | 231b88e3f7d0832127ef4ce02767b5c42ccd5df6d4bbfbdcf9e0217bdc3f3d72 |
| tools | get_import_errors | description | cb8a429a73ff2b11ad9a00219887ef5bf9fadba85d116009e26951bbcce25a1d |
| tools | get_plugins | description | a3cee1df8ee53b6e44c82f5aaa63baa531d9efa82d3cf4c704ee32eb4438bef7 |
| tools | get_pool | description | e8a55aa2b3e5696dff0d3f024c5c9835931d9954de936971c319983a33672367 |
| tools | get_pools | description | d282fd94532ed643bfe2336feb32d1b7ce98e943958838e1452cfd37333241fd |
| tools | get_task | description | 57284e271ab85d0aa3a79389cc07b010d5288ede8ea0a924ec8db4a26b1f54de |
| tools | get_task_instance | description | 5c5f1bcd3c55f872d97b233819a1f5317ae2307e448cb99cca76103ae3cfac3d |
| tools | get_tasks | description | 08e88306b652a6b146f0649293dfc45b773d21fc0c214d1f9630d4fec467a729 |
| tools | get_upstream_dataset_events | description | 10d0f0ea8ec87d9d42908d1d6c4b5e6ceca3acaf18f4e6aaf829bf4714f8f0e7 |
| tools | get_value | description | 8913c00f1b3d45b5aa15ecc7f08b9ef6e4521739c942294bbc738469e7ea3da8 |
| tools | get_variable | description | 8e6d21a7ada0a0a000ad57af52c008e255e2306997da9e920553bb4afe746580 |
| tools | get_version | description | 861653c8336c6bd0cce9ad51989e513df204bc34fa94f8d18deede999b84cfb2 |
| tools | get_xcom_entries | description | d859012b99c744421ca43be74a58e71ab0f5aedbce711c5559274690a9bd6ed7 |
| tools | get_xcom_entry | description | 2171d8763ff973e877226d2eb0b3ced83cd9c776bfa860e1cfd392278e5b0ce0 |
| tools | list_connections | description | b1ac0a96fb6a05c6465fe7522b4ea765b3aad0470f7b31d2acb228b974d67bf0 |
| tools | list_task_instances | description | 55c871f576b201a7b070238fc5534acd73a9e20d290d299f50cb279c02e0e75d |
| tools | list_variables | description | af4942c21411bf3fe2a6da8bbfec04008bc006f1711d7c92e072b199c558a241 |
| tools | patch_dag | description | 974f246e98fd3236748572b5312977bc3444920fc990a33ffb363c47a1edcafb |
| tools | patch_dags | description | 89f22a2a8889f12cc69e58b528075bf293ea0d019f9830cc601f25e15fbe652a |
| tools | patch_pool | description | b2e4ac499e89a6d50b2eae518a2a1c26353052b4ad8bca13f83c233b32643329 |
| tools | pause_dag | description | e7cd866515057aca64da4b95977a895617c348496884e09afbf85bf7c775dcbb |
| tools | post_dag_run | description | 23f9e3fc197495e8c6394f4cf4d8bdb0062714edf3f22c669671ec4e2c757489 |
| tools | post_pool | description | d2bc23794d78b3a2317eaa0f2921d2868a50dec02390db4733ace91b570b3f81 |
| tools | reparse_dag_file | description | b6291ba45aa591464169af1a7963245a890f38571a067ffbc5abf28f3321a90b |
| tools | set_dag_run_note | description | 0f7d1ac20b86ad47e5ce235d0934c3444498252247162d68a90b50043740f2d4 |
| tools | set_task_instances_state | description | eb3bd6aa47169b1839f086dcd219fe0dd3f28fe730b84475b00269669ddae05b |
| tools | test_connection | description | 2fbafc2bffe1fc42d8ef2ae6e7c357e98bfddf3d6c3fd8c83d311aefa1d730ad |
| tools | unpause_dag | description | 0960c0dde907b5bc72ca7d7389be017acba86df5cae241a3c4e7f5e4e9bd1ee1 |
| tools | update_connection | description | c1a99341812391797d78a660b4661141d0d51c6b320c3bb15089792b74e39d67 |
| tools | update_dag_run_state | description | af5ed22195f15f7de00b4ef60e40dad888c8a9b37d19313ed3b186e4180b1bbf |
| tools | update_task_instance | description | 7036d113775eeaf2db96fe8939ea881e016eade78985dbdc8987de90165a34ca |
| tools | update_variable | description | 7d2ed2541e9834cfa6852dd84d2c12b90d1bdef4f59a3f49abf1b6738e99ff32 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
