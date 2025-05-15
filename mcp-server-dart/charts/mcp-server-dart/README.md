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


# What is mcp-server-dart?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-dart/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-dart/0.1.13?logo=docker&logoColor=fff&label=0.1.13)](https://hub.docker.com/r/acuvity/mcp-server-dart)
[![PyPI](https://img.shields.io/badge/0.1.13-3775A9?logo=pypi&logoColor=fff&label=dart-mcp-server)](https://github.com/its-dart/dart-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-dart&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DART_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-dart%3A0.1.13%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AI-powered project management server for task and document management.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from dart-mcp-server original [sources](https://github.com/its-dart/dart-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-dart/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/charts/mcp-server-dart/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure dart-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/charts/mcp-server-dart#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Dart ](https://github.com/its-dart/dart-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ dart-mcp-server ](https://github.com/its-dart/dart-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ dart-mcp-server ](https://github.com/its-dart/dart-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/charts/mcp-server-dart)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-dart/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.13`

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
  - `DART_TOKEN` secret to be set as secrets.DART_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-dart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-dart --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-dart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-dart
```

From there your MCP server mcp-server-dart will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-dart` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-dart
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-dart` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-dart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-dart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-dart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-dart oci://docker.io/acuvity/mcp-server-dart --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>get_config</summary>

**Description**:

```
Get information about the user's space, including all of the possible values that can be provided to other endpoints. This includes available assignees, dartboards, folders, statuses, tags, priorities, and sizes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_tasks</summary>

**Description**:

```
List tasks from Dart with optional filtering parameters. You can filter by assignee, status, dartboard, priority, due date, and more.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee | string | Filter by assignee name or email | No
| assignee_duid | string | Filter by assignee ID | No
| dartboard | string | Filter by dartboard title | No
| dartboard_duid | string | Filter by dartboard ID | No
| description | string | Filter by description content | No
| due_at_after | string | Filter by due date after (ISO format) | No
| due_at_before | string | Filter by due date before (ISO format) | No
| duids | string | Filter by IDs | No
| in_trash | boolean | Filter by trash status | No
| is_draft | boolean | Filter by draft status | No
| kind | string | Filter by task kind | No
| limit | number | Number of results per page | No
| offset | number | Initial index for pagination | No
| priority | string | Filter by priority | No
| size | number | Filter by task size | No
| start_at_after | string | Filter by start date after (ISO format) | No
| start_at_before | string | Filter by start date before (ISO format) | No
| status | string | Filter by status | No
| status_duid | string | Filter by status ID | No
| subscriber_duid | string | Filter by subscriber ID | No
| tag | string | Filter by tag | No
| title | string | Filter by title | No
</details>
<details>
<summary>create_task</summary>

**Description**:

```
Create a new task in Dart. You can specify title, description, status, priority, size, dates, dartboard, assignees, tags, and parent task.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee | string | Single assignee name or email (if workspace doesn't allow multiple assignees) | No
| assignees | array | Array of assignee names or emails (if workspace allows multiple assignees) | No
| dartboard | string | The title of the dartboard (project or list of tasks) | No
| description | string | A longer description of the task, which can include markdown formatting | No
| dueAt | string | The due date in ISO format (should be at 9:00am in user's timezone) | No
| parentId | string | The ID of the parent task | No
| priority | string | The priority (Critical, High, Medium, or Low) | No
| size | number | A number that represents the amount of work needed | No
| startAt | string | The start date in ISO format (should be at 9:00am in user's timezone) | No
| status | string | The status from the list of available statuses | No
| tags | array | Array of tags to apply to the task | No
| title | string | The title of the task (required) | Yes
</details>
<details>
<summary>get_task</summary>

**Description**:

```
Retrieve an existing task by its ID. Returns the task's information including title, description, status, priority, dates, and more.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The 12-character alphanumeric ID of the task | Yes
</details>
<details>
<summary>update_task</summary>

**Description**:

```
Update an existing task. You can modify any of its properties including title, description, status, priority, dates, assignees, and more.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee | string | Single assignee name or email (if workspace doesn't allow multiple assignees) | No
| assignees | array | Array of assignee names or emails (if workspace allows multiple assignees) | No
| dartboard | string | The title of the dartboard (project or list of tasks) | No
| description | string | A longer description of the task, which can include markdown formatting | No
| dueAt | string | The due date in ISO format (should be at 9:00am in user's timezone) | No
| id | string | The 12-character alphanumeric ID of the task | Yes
| parentId | string | The ID of the parent task | No
| priority | string | The priority (Critical, High, Medium, or Low) | No
| size | number | A number that represents the amount of work needed | No
| startAt | string | The start date in ISO format (should be at 9:00am in user's timezone) | No
| status | string | The status from the list of available statuses | No
| tags | array | Array of tags to apply to the task | No
| title | string | The title of the task | No
</details>
<details>
<summary>delete_task</summary>

**Description**:

```
Move an existing task to the trash, where it can be recovered if needed. Nothing else about the task will be changed.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The 12-character alphanumeric ID of the task | Yes
</details>
<details>
<summary>list_docs</summary>

**Description**:

```
List docs from Dart with optional filtering parameters. You can filter by folder, title, text content, and more.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duids | string | Filter by IDs | No
| folder | string | Filter by folder title | No
| folder_duid | string | Filter by folder ID | No
| in_trash | boolean | Filter by trash status | No
| is_draft | boolean | Filter by draft status | No
| limit | number | Number of results per page | No
| offset | number | Initial index for pagination | No
| s | string | Search by title, text, or folder title | No
| text | string | Filter by text content | No
| title | string | Filter by title | No
</details>
<details>
<summary>create_doc</summary>

**Description**:

```
Create a new doc in Dart. You can specify title, text content, and folder.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folder | string | The title of the folder to place the doc in | No
| text | string | The text content of the doc, which can include markdown formatting | No
| title | string | The title of the doc (required) | Yes
</details>
<details>
<summary>get_doc</summary>

**Description**:

```
Retrieve an existing doc by its ID. Returns the doc's information including title, text content, folder, and more.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The 12-character alphanumeric ID of the doc | Yes
</details>
<details>
<summary>update_doc</summary>

**Description**:

```
Update an existing doc. You can modify its title, text content, and folder.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folder | string | The title of the folder to place the doc in | No
| id | string | The 12-character alphanumeric ID of the doc | Yes
| text | string | The text content of the doc, which can include markdown formatting | No
| title | string | The title of the doc | No
</details>
<details>
<summary>delete_doc</summary>

**Description**:

```
Move an existing doc to the trash, where it can be recovered if needed. Nothing else about the doc will be changed.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The 12-character alphanumeric ID of the doc | Yes
</details>

## 📝 Prompts (3)
<details>
<summary>Create task</summary>

**Description**:

```
Create a new task in Dart
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| title | Title of the task |Yes |
| description | Description of the task |No |
| status | Status of the task |No |
| priority | Priority of the task |No |
| assignee | Email of the assignee |No |
<details>
<summary>Create doc</summary>

**Description**:

```
Create a new document in Dart
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| title | Title of the document |Yes |
| text | Content of the document |No |
| folder | Folder to place the document in |No |
<details>
<summary>Summarize tasks</summary>

**Description**:

```
Get a summary of tasks with optional filtering
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| status | Filter by status (e.g., 'In Progress', 'Done') |No |
| assignee | Filter by assignee email |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | Create doc | description | 26e120261c64e33507a1345997751b697981512f9e8b1c6a9a31fb07e34d4469 |
| prompts | Create doc | folder | ff0cfe502458cdc33eb56807bdd2edc1ef7e7e6a0f67d17d1d4d6a1074783e24 |
| prompts | Create doc | text | 1f635ca94b70a3f1dbcb286d28fe6aaeefa1e283f7f1407b6eed0d8802554066 |
| prompts | Create doc | title | 8b786158c36817b4f2fde082794971f19d95f4cc822a631ab90eca7b8c2751b4 |
| prompts | Create task | description | 3b228028242c33f7c61da6f05b7f0ed7c921e958b7e4a97d0a5d489ea984ad5c |
| prompts | Create task | assignee | fa8d4cb55706892d3062167bca9cd9328bd493b4faaac56daf6132c95f248f1f |
| prompts | Create task | description | e2e7e8c11e7e795951b86786622612b34e22f9f055de975624246c0b2d9be26e |
| prompts | Create task | priority | 410f5d5c4f0bc69089dc860c53bba0a6b59cc30f3f803acc3acf17cf3fc2aa51 |
| prompts | Create task | status | 6adc89820dff29ccfcd3b7921bd6e0d7d7b3e5284c82b1f2f050d5bd423391da |
| prompts | Create task | title | 5a7b0e30345d9278f0d02a45424f9556795df870afc010404e541166e56278cf |
| prompts | Summarize tasks | description | b2cf1ed67aae22ea872232332b99cff85e788c7d3fd546383827ff3e990f28b8 |
| prompts | Summarize tasks | assignee | 36d720e703520c7f238aca38ba1d1f556f179650b47225460fbc8e37b4f4779a |
| prompts | Summarize tasks | status | e68e8e219087225092436dc037c1a0e781acdd0f3dd96dc32d23a1b82934a9b0 |
| tools | create_doc | description | b1099bc1c729560ace3a50fad194e64553b4c93e6a123c680526f77a54bb4093 |
| tools | create_doc | folder | e6970c521d4f1d5516d4e75a38ad71a41aae2a6c11cbbbe09b436d570df373a5 |
| tools | create_doc | text | c06f2b86fc675d1e4d04c7b139162cc39222bdc83a04fa75130ad9a7d4a90e12 |
| tools | create_doc | title | 9cc6b9106a08ca41a40d45cabf35bb48046a5d649a292f612bf07a870f8ca516 |
| tools | create_task | description | 86105de7f2f4b65c5722494a8bc03b289f45ce29f0885a9289b074a33f50da47 |
| tools | create_task | assignee | f56457f6c5055fc6bf77bf013a6555ae0bb4f27c7a9038dd1666c9eb3a3f5be2 |
| tools | create_task | assignees | b3936aba1f174431e90c9d60e20ec5146d2200e51fb7eecabbf94002551823c2 |
| tools | create_task | dartboard | 84958dda81147cfff7ff78fe9230d1db4ae900b89c7ca7285b7e98b4b04edd44 |
| tools | create_task | description | 7c2356ba83e1aa6346e0416d087551f1cedd217150895082b8f3c2cdc360fe62 |
| tools | create_task | dueAt | d6f19a43a34649d2b8cbab579ea85b432e20345146bd16762912dce21fd76e4a |
| tools | create_task | parentId | ebaddcf284633e96b35be6aa4185b103378bdd3294606cdf1ac3cdea63adce9b |
| tools | create_task | priority | 15e467342a400af7d45bebbcdbb6033fc254b918b8aa0a19d8f2f3bbcab472d1 |
| tools | create_task | size | 640ad4fdcd185fef7b3126e4f57a0cae606da1598628fe85fcf44aa4e06132fa |
| tools | create_task | startAt | d00148212e5b0387b0dec42855c40b624c4fb875c7706c62d978fcc9a9935e82 |
| tools | create_task | status | f7e73edb7c5a9a0505b066a639e684bd0875476102240d9255db0f8b74758314 |
| tools | create_task | tags | 12cb13942f1eefa25260f7af43bc280295e46a6d44837290f34d0455a9081571 |
| tools | create_task | title | 227c4b8ffe9734ef427c8a458dc90f40e0fe23ed742c406ef750d57badeca7a4 |
| tools | delete_doc | description | 4f6e4077a8b6af7e6c8a65d246cac80088a983ea16c70617407cdac06aad7c98 |
| tools | delete_doc | id | a4c9893001a2904378a196d3e8384822a0bc98f388f411aca489656504efa261 |
| tools | delete_task | description | 841804ef33b8477ce8f7e7b3dfe3a562f008ae4113ef4506d8cb57999f1c3ff7 |
| tools | delete_task | id | 310575c03a01f518120c4b24c0e723828d57433eb1d1465c4b4357d4a2870a5d |
| tools | get_config | description | c76d1adcac4431aa70f7a6fd9644dd31d4b7997e1703178ef6e4f1a1b50750cb |
| tools | get_doc | description | 97d2618ac41e053e00f329fe070ed2968b6200748fc705ccf77371232062f309 |
| tools | get_doc | id | a4c9893001a2904378a196d3e8384822a0bc98f388f411aca489656504efa261 |
| tools | get_task | description | a9388e5a4e7ba546c128d7a24f0dc0f7a26dcce56cd076f85351ccd07507afcf |
| tools | get_task | id | 310575c03a01f518120c4b24c0e723828d57433eb1d1465c4b4357d4a2870a5d |
| tools | list_docs | description | e065ce35eaf56e76ab337c4ca52aea287a1b53359ae8c8dff87cc101405b6436 |
| tools | list_docs | duids | 273c161c10e76cb90173c32b8eda174f96f767b7ca59ec9439c667b935933001 |
| tools | list_docs | folder | 77ad23935380f926cc9ed1360f3c8a48e0b4d5ece8fd83b6b7f9de147e8140b8 |
| tools | list_docs | folder_duid | 68454b6e7f309a58bb23f524036275414be192bc5a47e8a6b288912ea1ce2470 |
| tools | list_docs | in_trash | 109c580129edd45e9db0bc8397f9c18b9418c9087123bac10a65453d22930d23 |
| tools | list_docs | is_draft | 4eca8610f40002319534f91164cef94582afe8c78289846ac041cafeda20be8d |
| tools | list_docs | limit | ac9d79bc23e286af13eb43e132623de430169d08776f2069fe25071f010de800 |
| tools | list_docs | offset | 2106ec42a90be7c699ecbeef51c4569f9d6373df685bebab58a7cd9891558a4d |
| tools | list_docs | s | 485037bab47b7046aca06f408de0d84c5d6dee2a4ef2f1b8efe19cb6738d1ade |
| tools | list_docs | text | e0b3f6719afb4e1034dffe58ea8467a2a66abbade1a89775a40712de133d9a22 |
| tools | list_docs | title | f03711f770b6fa4f885df4dec6475307cd0ca446b569b49fed44243abc6717f4 |
| tools | list_tasks | description | c70368a4d7689bd93adb8daad25687f6862ac7768024487b64ddad7a691145d7 |
| tools | list_tasks | assignee | a5fd211f871a899c6b9194c0321692b7805725ef1073e3ed36b408792b1fa671 |
| tools | list_tasks | assignee_duid | ef395ad9357aad1c0935b185bc4fb0a0598858110d05efabd3735484ca5221b9 |
| tools | list_tasks | dartboard | b2185e89450d9791c0f31fc1c0d33cf33197c20f7d240464447529b953f00f47 |
| tools | list_tasks | dartboard_duid | d9b66288a97d66a6486eda7c03b14969acb75ccd991249c705098112948d6ceb |
| tools | list_tasks | description | c963ada0d48c9816f49908a49c8df5cc102691d448c28ad6cdbe4540eaa43cd4 |
| tools | list_tasks | due_at_after | f134726aacd5a93ed1f8a1491c3a3deb1929fe370cbb80e90b4036b86cf684c5 |
| tools | list_tasks | due_at_before | 4fd8b77ffdd64af3d862a81e3c9097b24c383788d96a293b9d37f008de9fca72 |
| tools | list_tasks | duids | 273c161c10e76cb90173c32b8eda174f96f767b7ca59ec9439c667b935933001 |
| tools | list_tasks | in_trash | 109c580129edd45e9db0bc8397f9c18b9418c9087123bac10a65453d22930d23 |
| tools | list_tasks | is_draft | 4eca8610f40002319534f91164cef94582afe8c78289846ac041cafeda20be8d |
| tools | list_tasks | kind | 8e976eb25c3672f4fe60074f014ae04299a9aab06e65589d92c66a784e380df4 |
| tools | list_tasks | limit | ac9d79bc23e286af13eb43e132623de430169d08776f2069fe25071f010de800 |
| tools | list_tasks | offset | 2106ec42a90be7c699ecbeef51c4569f9d6373df685bebab58a7cd9891558a4d |
| tools | list_tasks | priority | 48b74b8f81c021ef7f3135288dc6c2f3ac0f15d6c0fa7ec4392d7fb6488efc62 |
| tools | list_tasks | size | e33e3e1f461724ec2a8f6729a86a241228ea766f60d582dd8a23921774b460df |
| tools | list_tasks | start_at_after | 64d65f4c927386dbceb7b64df8857eb77e9233622ca21b20481c11c0af76c1a9 |
| tools | list_tasks | start_at_before | acf5c3877b2fdfd280f2870afad08debbf3ffc111af01545a30ea0a13c8b6fee |
| tools | list_tasks | status | 94d5a7703a8250de4c9e24b29839ffafa5d8477efb19c56ebce83470102e6212 |
| tools | list_tasks | status_duid | 418121f1618200d91044a6ef7be84f0c6fb43557511c3069baf8a65eed938fa2 |
| tools | list_tasks | subscriber_duid | b2ce99868d686c5cf5bab858fad1c7fb75b248f8cfa8ad01ae300006ebfa9924 |
| tools | list_tasks | tag | b9274474d0990cb9063843f21ebcb42a4ee74d5875e493412eddc64666ec93bc |
| tools | list_tasks | title | f03711f770b6fa4f885df4dec6475307cd0ca446b569b49fed44243abc6717f4 |
| tools | update_doc | description | c7ba17b4437c3335bbe54563051a9d234aea1385f57f1c026a46db681b874856 |
| tools | update_doc | folder | e6970c521d4f1d5516d4e75a38ad71a41aae2a6c11cbbbe09b436d570df373a5 |
| tools | update_doc | id | a4c9893001a2904378a196d3e8384822a0bc98f388f411aca489656504efa261 |
| tools | update_doc | text | c06f2b86fc675d1e4d04c7b139162cc39222bdc83a04fa75130ad9a7d4a90e12 |
| tools | update_doc | title | 9b4e5691ecfb7c86c3dcbff44139faa6d7eceb49dfbff7ddda26a606edb200df |
| tools | update_task | description | 5af5f13cc77b37174329796a57d6a98cf48ee4d123ace451ae6217bd59dc2968 |
| tools | update_task | assignee | f56457f6c5055fc6bf77bf013a6555ae0bb4f27c7a9038dd1666c9eb3a3f5be2 |
| tools | update_task | assignees | b3936aba1f174431e90c9d60e20ec5146d2200e51fb7eecabbf94002551823c2 |
| tools | update_task | dartboard | 84958dda81147cfff7ff78fe9230d1db4ae900b89c7ca7285b7e98b4b04edd44 |
| tools | update_task | description | 7c2356ba83e1aa6346e0416d087551f1cedd217150895082b8f3c2cdc360fe62 |
| tools | update_task | dueAt | d6f19a43a34649d2b8cbab579ea85b432e20345146bd16762912dce21fd76e4a |
| tools | update_task | id | 310575c03a01f518120c4b24c0e723828d57433eb1d1465c4b4357d4a2870a5d |
| tools | update_task | parentId | ebaddcf284633e96b35be6aa4185b103378bdd3294606cdf1ac3cdea63adce9b |
| tools | update_task | priority | 15e467342a400af7d45bebbcdbb6033fc254b918b8aa0a19d8f2f3bbcab472d1 |
| tools | update_task | size | 640ad4fdcd185fef7b3126e4f57a0cae606da1598628fe85fcf44aa4e06132fa |
| tools | update_task | startAt | d00148212e5b0387b0dec42855c40b624c4fb875c7706c62d978fcc9a9935e82 |
| tools | update_task | status | f7e73edb7c5a9a0505b066a639e684bd0875476102240d9255db0f8b74758314 |
| tools | update_task | tags | 12cb13942f1eefa25260f7af43bc280295e46a6d44837290f34d0455a9081571 |
| tools | update_task | title | d8da4c4d3526af1a57622c424e319610776173949629e64383033f6f28dae876 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
