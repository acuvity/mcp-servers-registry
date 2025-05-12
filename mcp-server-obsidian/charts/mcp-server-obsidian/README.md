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


# What is mcp-server-obsidian?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-obsidian/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-obsidian/0.2.2?logo=docker&logoColor=fff&label=0.2.2)](https://hub.docker.com/r/acuvity/mcp-server-obsidian)
[![PyPI](https://img.shields.io/badge/0.2.2-3775A9?logo=pypi&logoColor=fff&label=mcp-obsidian)](https://github.com/MarkusPfundstein/mcp-obsidian)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-obsidian&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OBSIDIAN_API_KEY%22%2C%22-e%22%2C%22OBSIDIAN_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-obsidian%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Interacting with Obsidian via REST API.

Packaged by Acuvity from mcp-obsidian original [sources](https://github.com/MarkusPfundstein/mcp-obsidian).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-obsidian/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/charts/mcp-server-obsidian/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-obsidian run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/charts/mcp-server-obsidian#minibridge) for Helm charts).


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Markus Pfundstein <markus@life-electronic.nl> ](https://github.com/MarkusPfundstein/mcp-obsidian) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-obsidian ](https://github.com/MarkusPfundstein/mcp-obsidian)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-obsidian ](https://github.com/MarkusPfundstein/mcp-obsidian)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/charts/mcp-server-obsidian)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-obsidian/docker/Dockerfile)

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
  - `OBSIDIAN_API_KEY` secret to be set as secrets.OBSIDIAN_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `OBSIDIAN_HOST` environment variable to be set by env.OBSIDIAN_HOST

# How to install


Install will helm

```console
helm install mcp-server-obsidian oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-obsidian oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-obsidian
```

From there your MCP server mcp-server-obsidian will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-obsidian` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-obsidian
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-obsidian` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-obsidian oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-obsidian oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-obsidian oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-obsidian oci://docker.io/acuvity/mcp-server-obsidian --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (12)
<details>
<summary>obsidian_list_files_in_dir</summary>

**Description**:

```
Lists all files and directories that exist in a specific Obsidian directory.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dirpath | string | Path to list files from (relative to your vault root). Note that empty directories will not be returned. | Yes
</details>
<details>
<summary>obsidian_list_files_in_vault</summary>

**Description**:

```
Lists all files and directories in the root directory of your Obsidian vault.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>obsidian_get_file_contents</summary>

**Description**:

```
Return the content of a single file in your vault.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filepath | string | Path to the relevant file (relative to your vault root). | Yes
</details>
<details>
<summary>obsidian_simple_search</summary>

**Description**:

```
Simple search for documents matching a specified text query across all files in the vault. 
            Use this tool when you want to do a simple text search
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| context_length | integer | How much context to return around the matching string (default: 100) | No
| query | string | Text to a simple search for in the vault. | Yes
</details>
<details>
<summary>obsidian_patch_content</summary>

**Description**:

```
Insert content into an existing note relative to a heading, block reference, or frontmatter field.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | Content to insert | Yes
| filepath | string | Path to the file (relative to vault root) | Yes
| operation | string | Operation to perform (append, prepend, or replace) | Yes
| target | string | Target identifier (heading path, block reference, or frontmatter field) | Yes
| target_type | string | Type of target to patch | Yes
</details>
<details>
<summary>obsidian_append_content</summary>

**Description**:

```
Append content to a new or existing file in the vault.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | Content to append to the file | Yes
| filepath | string | Path to the file (relative to vault root) | Yes
</details>
<details>
<summary>obsidian_delete_file</summary>

**Description**:

```
Delete a file or directory from the vault.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| confirm | boolean | Confirmation to delete the file (must be true) | Yes
| filepath | string | Path to the file or directory to delete (relative to vault root) | Yes
</details>
<details>
<summary>obsidian_complex_search</summary>

**Description**:

```
Complex search for documents using a JsonLogic query. 
           Supports standard JsonLogic operators plus 'glob' and 'regexp' for pattern matching. Results must be non-falsy.

           Use this tool when you want to do a complex search, e.g. for all documents with certain tags etc.
           
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | object | JsonLogic query object. Example: {"glob": ["*.md", {"var": "path"}]} matches all markdown files | Yes
</details>
<details>
<summary>obsidian_batch_get_file_contents</summary>

**Description**:

```
Return the contents of multiple files in your vault, concatenated with headers.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filepaths | array | List of file paths to read | Yes
</details>
<details>
<summary>obsidian_get_periodic_note</summary>

**Description**:

```
Get current periodic note for the specified period.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| period | string | The period type (daily, weekly, monthly, quarterly, yearly) | Yes
</details>
<details>
<summary>obsidian_get_recent_periodic_notes</summary>

**Description**:

```
Get most recent periodic notes for the specified period type.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| include_content | boolean | Whether to include note content (default: false) | No
| limit | integer | Maximum number of notes to return (default: 5) | No
| period | string | The period type (daily, weekly, monthly, quarterly, yearly) | Yes
</details>
<details>
<summary>obsidian_get_recent_changes</summary>

**Description**:

```
Get recently modified files in the vault.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| days | integer | Only include files modified within this many days (default: 90) | No
| limit | integer | Maximum number of files to return (default: 10) | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | obsidian_append_content | description | 441d8ce7c4744dee9e60afe5ea684d37806eab144459bdb2bbbcf25b05d9eea4 |
| tools | obsidian_append_content | content | af86a002896bd047f188864f96723c19eee92e4e6ec840207eaf9d211e96afb9 |
| tools | obsidian_append_content | filepath | c1e0a87dd03f5dfed770c2d77af79adfbe854333ab1daa7b808c4b04ea4ad3aa |
| tools | obsidian_batch_get_file_contents | description | 3eb385a80708f6f4f5f960e39d4649f568fd4f42f16d4fd34a0e6db922acd605 |
| tools | obsidian_batch_get_file_contents | filepaths | 59959338323ab4d07e7a46254128f48ee77bc8969ba3330ee0c1e0d25fbcbbad |
| tools | obsidian_complex_search | description | b110ffe9d299a9282c25b3b794834fdec938cf7b5256ef49a70f98f7c80c5f84 |
| tools | obsidian_complex_search | query | 343cebc224c0eb9ac883be06d61d7017760ee357221fab4c1f9cc121515b8adc |
| tools | obsidian_delete_file | description | f6dae4e281c0991a9c9a0e632f228c3763a5e2797c8ac567042b29f55deeff61 |
| tools | obsidian_delete_file | confirm | 31bc0e9840bde0ba53b84dfc91d579c62384fddb8bc88396ca869a06e6755de3 |
| tools | obsidian_delete_file | filepath | 4367cc3207ba601d9408d0830c3589fdd8bb5ddd2ea7f3c22105bc1fa499a595 |
| tools | obsidian_get_file_contents | description | b144b5305df6d2fb4001e9c20ae1b5df81ab73d58577e29c4ef70f43d40f9b38 |
| tools | obsidian_get_file_contents | filepath | d6444fd2311e466e0d8e8049819cf18f6dc87078605978c622aca72c75ad00e7 |
| tools | obsidian_get_periodic_note | description | 18cc93fe5728d7a1f04bd06f33dcdc574865ee7ccbe37cda02a6e23b2c629905 |
| tools | obsidian_get_periodic_note | period | 2c78b403d8de3bd859a9a308d8a049d5dc9a76253aee6dbe34c9a37e98ef3c0f |
| tools | obsidian_get_recent_changes | description | 67031ea0334572668909ede8c3d4471b3e251f428061c8a84b6d460abf850983 |
| tools | obsidian_get_recent_changes | days | 096a5e3c567dc2cfdab81fcf395976852b19674ba2b558fe2243d26e1ff57053 |
| tools | obsidian_get_recent_changes | limit | 5c3905fb6770f150a79cce00805499615a09b45eec8d771e81c1f5112d362291 |
| tools | obsidian_get_recent_periodic_notes | description | b1da54b315ff6390fa4fc858befc3fb560f62c25e8eac1a08bc4bd1a1431ac70 |
| tools | obsidian_get_recent_periodic_notes | include_content | fcc2646d21b5a5477107a5fa2c9bcfb02eb0fca95f8496273d2fe0ebbd1e7a43 |
| tools | obsidian_get_recent_periodic_notes | limit | 15f9da0c969f9ba5f9529bad9355e38e3b124075d9ffb787bea317375e851784 |
| tools | obsidian_get_recent_periodic_notes | period | 2c78b403d8de3bd859a9a308d8a049d5dc9a76253aee6dbe34c9a37e98ef3c0f |
| tools | obsidian_list_files_in_dir | description | e4e1172e332ba65647a70aef60d3ad6abedc6d446565cbf9a011016801ab88f7 |
| tools | obsidian_list_files_in_dir | dirpath | 4dff8e9d5f94d6cba23cc7ea1c2eb949695ddc582e9d3d6b5fdd1173d64acaf3 |
| tools | obsidian_list_files_in_vault | description | 909e66b2454aed00ef4fb0a41b18fd0b57c72195e769e11a22d3ce13dc6d8e56 |
| tools | obsidian_patch_content | description | f4b396c531ce3e93495cff36b93e90564aac2e6233a6959e4b33d72c2da6c49d |
| tools | obsidian_patch_content | content | 5b25459a4c9ce938dcde5717cc5eb1bfe2db08703128a51adb09211c12a68c5b |
| tools | obsidian_patch_content | filepath | c1e0a87dd03f5dfed770c2d77af79adfbe854333ab1daa7b808c4b04ea4ad3aa |
| tools | obsidian_patch_content | operation | 9cb954994dc09a6ed42188ac3177679a1e21831141b92e615173982230862a2a |
| tools | obsidian_patch_content | target | 0bec861ab8b37473c204a66e188f5fac95eeba8c84e533de115c80d111e76178 |
| tools | obsidian_patch_content | target_type | 3e807fb37e8635c81f50e15294156e523e0c2dd2394bcc208b987e0edeae1375 |
| tools | obsidian_simple_search | description | 6dfa62c7e5361a04b450fbc672793a703963b9110c99d5108a713aa6bdb8af3f |
| tools | obsidian_simple_search | context_length | 1c0d9d772bf38d8d7bfd45f59c5209b8718ed02396157c2e0303f58ad7b61bfa |
| tools | obsidian_simple_search | query | 7c0544d793c4cab69699cb84eded66c1cce85b060cf030f513d4f3b7dc7e1424 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
