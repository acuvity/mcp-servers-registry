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


# What is mcp-server-gitlab?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-gitlab/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-gitlab/2025.4.25?logo=docker&logoColor=fff&label=2025.4.25)](https://hub.docker.com/r/acuvity/mcp-server-gitlab)
[![PyPI](https://img.shields.io/badge/2025.4.25-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-gitlab)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-gitlab&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GITLAB_PERSONAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-gitlab%3A2025.4.25%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for using the GitLab API

Packaged by Acuvity from @modelcontextprotocol/server-gitlab original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-gitlab/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/charts/mcp-server-gitlab/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-gitlab run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/charts/mcp-server-gitlab#minibridge) for Helm charts).


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ GitLab, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @modelcontextprotocol/server-gitlab ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-gitlab ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/charts/mcp-server-gitlab)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-gitlab/docker/Dockerfile)

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
  - `GITLAB_PERSONAL_ACCESS_TOKEN` secret to be set as secrets.GITLAB_PERSONAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `GITLAB_API_URL=""` environment variable can be changed with `env.GITLAB_API_URL=""`

# How to install


Install will helm

```console
helm install mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-gitlab
```

From there your MCP server mcp-server-gitlab will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-gitlab` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-gitlab
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-gitlab` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-gitlab oci://docker.io/acuvity/mcp-server-gitlab --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>create_or_update_file</summary>

**Description**:

```
Create or update a single file in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to create/update the file in | Yes
| commit_message | string | Commit message | Yes
| content | string | Content of the file | Yes
| file_path | string | Path where to create/update the file | Yes
| previous_path | string | Path of the file to move/rename | No
| project_id | string | Project ID or URL-encoded path | Yes
</details>
<details>
<summary>search_repositories</summary>

**Description**:

```
Search for GitLab projects
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for pagination (default: 1) | No
| per_page | number | Number of results per page (default: 20) | No
| search | string | Search query | Yes
</details>
<details>
<summary>create_repository</summary>

**Description**:

```
Create a new GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | Repository description | No
| initialize_with_readme | boolean | Initialize with README.md | No
| name | string | Repository name | Yes
| visibility | string | Repository visibility level | No
</details>
<details>
<summary>get_file_contents</summary>

**Description**:

```
Get the contents of a file or directory from a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | Path to the file or directory | Yes
| project_id | string | Project ID or URL-encoded path | Yes
| ref | string | Branch/tag/commit to get contents from | No
</details>
<details>
<summary>push_files</summary>

**Description**:

```
Push multiple files to a GitLab project in a single commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to push to | Yes
| commit_message | string | Commit message | Yes
| files | array | Array of files to push | Yes
| project_id | string | Project ID or URL-encoded path | Yes
</details>
<details>
<summary>create_issue</summary>

**Description**:

```
Create a new issue in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignee_ids | array | Array of user IDs to assign | No
| description | string | Issue description | No
| labels | array | Array of label names | No
| milestone_id | number | Milestone ID to assign | No
| project_id | string | Project ID or URL-encoded path | Yes
| title | string | Issue title | Yes
</details>
<details>
<summary>create_merge_request</summary>

**Description**:

```
Create a new merge request in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allow_collaboration | boolean | Allow commits from upstream members | No
| description | string | Merge request description | No
| draft | boolean | Create as draft merge request | No
| project_id | string | Project ID or URL-encoded path | Yes
| source_branch | string | Branch containing changes | Yes
| target_branch | string | Branch to merge into | Yes
| title | string | Merge request title | Yes
</details>
<details>
<summary>fork_repository</summary>

**Description**:

```
Fork a GitLab project to your account or specified namespace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| namespace | string | Namespace to fork to (full path) | No
| project_id | string | Project ID or URL-encoded path | Yes
</details>
<details>
<summary>create_branch</summary>

**Description**:

```
Create a new branch in a GitLab project
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Name for the new branch | Yes
| project_id | string | Project ID or URL-encoded path | Yes
| ref | string | Source branch/commit for new branch | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_branch | description | 370c8fdea4b4ed2c01e13aa6c698e1e547b27bc86998317a904dfe007c640d3b |
| tools | create_branch | branch | 4c318264c967c58971b8a1e0f74375753c460aafb016099268c365625e14b475 |
| tools | create_branch | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_branch | ref | 5fe6a4648ba2c040d592f76e6a1e3b06e058613def274087239e5477e963a651 |
| tools | create_issue | description | 67bd8b1d40a0d879f02ae6df3e7a032e9f67d8185ff96a946b6407a8da74676d |
| tools | create_issue | assignee_ids | b1e95a9a21177c02ec9b67f5619cdf261c9226a4b06fc7ccc1baaaa0ff179af3 |
| tools | create_issue | description | 6fdf4c7fb5a19e122d009b8deed663a56034d8170be9300906c4368c423da250 |
| tools | create_issue | labels | 73e3d3cb50073e91dd598b8c1c00a632d01907f339ed5228197a3d82bd0e1bfd |
| tools | create_issue | milestone_id | 0d1caf40d22dd8764da4abbb92bc5c803236c1b08b4844722a165ce185ea75ea |
| tools | create_issue | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_issue | title | baebb0f722db7150e454ecfb2d432205f6331d57837328637d25ac8413f84644 |
| tools | create_merge_request | description | 2c412a96dcbe413da1ec4527c917ada4201af860c44f3db3a3f0fdf7d5b6846a |
| tools | create_merge_request | allow_collaboration | 79eebf7e7bdf597f123e7d7ce6f7638205f5e21c1d0b62dadbe27b9c4ed68beb |
| tools | create_merge_request | description | 6ee8d87260dcfc89cd9f7aefb2c9309137a659c7bcff8f6f101326b0061218aa |
| tools | create_merge_request | draft | b5890bf1f6c20cd8a358d093142e2d69c59507b4bbdad8c01917649070c5daf6 |
| tools | create_merge_request | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_merge_request | source_branch | f30a2f6fcdb7af894b1cd42fd17f7651a3e9de4c432a615fe383235d8822d669 |
| tools | create_merge_request | target_branch | 68d3d352a8e9b1b21daef0144ddbd5ebbfdfafa1c150afd9184f2889aeba0f54 |
| tools | create_merge_request | title | 009fb5b5349f3ea12220e3d5a8d86edd8c975c1be01feba848bb14d4823ac9e4 |
| tools | create_or_update_file | description | 5a9d17ef2e130c8ce70a42df7f712b4ae8858b25754dd52c2a5f7a26c14cb9c3 |
| tools | create_or_update_file | branch | d6a5e87fe732d76cc378c1d1f1210e9b2deb75c9a0dc93b4e453bd5681e9ebe9 |
| tools | create_or_update_file | commit_message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | create_or_update_file | content | 651936dc46e2fa051b60ccb3cbfe9f87f0f58f41773e79b4839a814525a7d688 |
| tools | create_or_update_file | file_path | c57e5f48646295c4493f5d052c3ce4d46f88f8c963d162f44c187ff5defa6791 |
| tools | create_or_update_file | previous_path | cf397a18416cb0b87c38f5dfff95b3ba924af348310612cb5cce0bd3a472bfc4 |
| tools | create_or_update_file | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | create_repository | description | 1d98765246028af2aabc6e3d9257883b4b744bb9b352cd8396c5466306c468f9 |
| tools | create_repository | description | 2b96b72a003b28027236e3a9d7b66958233d752e92381122915202c3c00f6058 |
| tools | create_repository | initialize_with_readme | 7e2901b2f7514bf8332f7e21b39c372da2839884a4f6f497fc38ba9783044538 |
| tools | create_repository | name | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_repository | visibility | c184fe837e436f41e9f8c51f845c35976bc65dcb9ee55c21dccbda312d38410b |
| tools | fork_repository | description | a12e1d457b0dddd2646db05db4abc33f10d2d9e7d85108510a70effce2175e63 |
| tools | fork_repository | namespace | 1745a33a34c4b0df0dff3502345eb24b9df73588ec9c93253a72a38e29264f88 |
| tools | fork_repository | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | get_file_contents | description | ff1b95763ce6d2fc775ed4fe3f8e654b9d2f12d80fa2ccad22f5ae9186ba2310 |
| tools | get_file_contents | file_path | 52efab3f41db809584fb319e63956f45cdcc3a67736a23ea06daaa495c975658 |
| tools | get_file_contents | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | get_file_contents | ref | d437b023475af49fe4753ed5eeb9f0f4331f914caa7cb9e61224c77758da1541 |
| tools | push_files | description | bd07cf006dbb6be775064074a39533c7494f70a2e56eea1b4f530e4feee038ba |
| tools | push_files | branch | 903fd236be715d2d2dabe8871e567bebdb55a876b1f9b4db0c49400e3b944e01 |
| tools | push_files | commit_message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | push_files | files | a9c47d470281bded4c57e1c0278bbc153c1d133c163a1cf7d5da6b9920ccbe3f |
| tools | push_files | project_id | cde85e86297f3b2d27daff2ebffa97697e7eab0b519fcb150aba3dafa86ae058 |
| tools | search_repositories | description | 7fab15409bf7d2f9911d7cde2a71fdbba5449c8e39f032f37d86feb8b2f33755 |
| tools | search_repositories | page | 72a453385ec021aacde1c9dedd043203bf0244b3414156f8e9455eca78907d8b |
| tools | search_repositories | per_page | 7ab4ede2b5836fe3c170dedd1d2cc91073be26a72af9f1590c05b35f0447ed18 |
| tools | search_repositories | search | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
