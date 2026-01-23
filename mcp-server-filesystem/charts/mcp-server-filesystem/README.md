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


# What is mcp-server-filesystem?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-filesystem/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-filesystem/2026.1.14?logo=docker&logoColor=fff&label=2026.1.14)](https://hub.docker.com/r/acuvity/mcp-server-filesystem)
[![PyPI](https://img.shields.io/badge/2026.1.14-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-filesystem)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-filesystem/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-filesystem&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22path%3A%2Fdata%22%2C%22docker.io%2Facuvity%2Fmcp-server-filesystem%3A2026.1.14%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server for filesystem access

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @modelcontextprotocol/server-filesystem original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-filesystem/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-filesystem/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-filesystem/charts/mcp-server-filesystem/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-filesystem run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-filesystem/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-filesystem#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Anthropic, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @modelcontextprotocol/server-filesystem ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-filesystem ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-filesystem/charts/mcp-server-filesystem)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-filesystem/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-2026.1.14`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-filesystem:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-filesystem:1.0.0-2026.1.14`

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
helm install mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-filesystem
```

From there your MCP server mcp-server-filesystem will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-filesystem` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-filesystem
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-filesystem` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-filesystem oci://docker.io/acuvity/mcp-server-filesystem --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>read_file</summary>

**Description**:

```
Read the complete contents of a file as text. DEPRECATED: Use read_text_file instead.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| head | number | If provided, returns only the first N lines of the file | No
| path | string | not set | Yes
| tail | number | If provided, returns only the last N lines of the file | No
</details>
<details>
<summary>read_text_file</summary>

**Description**:

```
Read the complete contents of a file from the file system as text. Handles various text encodings and provides detailed error messages if the file cannot be read. Use this tool when you need to examine the contents of a single file. Use the 'head' parameter to read only the first N lines of a file, or the 'tail' parameter to read only the last N lines of a file. Operates on the file as text regardless of extension. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| head | number | If provided, returns only the first N lines of the file | No
| path | string | not set | Yes
| tail | number | If provided, returns only the last N lines of the file | No
</details>
<details>
<summary>read_media_file</summary>

**Description**:

```
Read an image or audio file. Returns the base64 encoded data and MIME type. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>read_multiple_files</summary>

**Description**:

```
Read the contents of multiple files simultaneously. This is more efficient than reading files one by one when you need to analyze or compare multiple files. Each file's content is returned with its path as a reference. Failed reads for individual files won't stop the entire operation. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| paths | array | Array of file paths to read. Each path must be a string pointing to a valid file within allowed directories. | Yes
</details>
<details>
<summary>write_file</summary>

**Description**:

```
Create a new file or completely overwrite an existing file with new content. Use with caution as it will overwrite existing files without warning. Handles text content with proper encoding. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>edit_file</summary>

**Description**:

```
Make line-based edits to a text file. Each edit replaces exact line sequences with new content. Returns a git-style diff showing the changes made. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dryRun | boolean | Preview changes using git-style diff format | No
| edits | array | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>create_directory</summary>

**Description**:

```
Create a new directory or ensure a directory exists. Can create multiple nested directories in one operation. If the directory already exists, this operation will succeed silently. Perfect for setting up directory structures for projects or ensuring required paths exist. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>list_directory</summary>

**Description**:

```
Get a detailed listing of all files and directories in a specified path. Results clearly distinguish between files and directories with [FILE] and [DIR] prefixes. This tool is essential for understanding directory structure and finding specific files within a directory. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>list_directory_with_sizes</summary>

**Description**:

```
Get a detailed listing of all files and directories in a specified path, including sizes. Results clearly distinguish between files and directories with [FILE] and [DIR] prefixes. This tool is useful for understanding directory structure and finding specific files within a directory. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
| sortBy | string | Sort entries by name or size | No
</details>
<details>
<summary>directory_tree</summary>

**Description**:

```
Get a recursive tree view of files and directories as a JSON structure. Each entry includes 'name', 'type' (file/directory), and 'children' for directories. Files have no children array, while directories always have a children array (which may be empty). The output is formatted with 2-space indentation for readability. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| excludePatterns | array | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>move_file</summary>

**Description**:

```
Move or rename files and directories. Can move files between directories and rename them in a single operation. If the destination exists, the operation will fail. Works across different directories and can be used for simple renaming within the same directory. Both source and destination must be within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | not set | Yes
| source | string | not set | Yes
</details>
<details>
<summary>search_files</summary>

**Description**:

```
Recursively search for files and directories matching a pattern. The patterns should be glob-style patterns that match paths relative to the working directory. Use pattern like '*.ext' to match files in current directory, and '**/*.ext' to match files in all subdirectories. Returns full paths to all matching items. Great for finding files when you don't know their exact location. Only searches within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| excludePatterns | array | not set | No
| path | string | not set | Yes
| pattern | string | not set | Yes
</details>
<details>
<summary>get_file_info</summary>

**Description**:

```
Retrieve detailed metadata about a file or directory. Returns comprehensive information including size, creation time, last modified time, permissions, and type. This tool is perfect for understanding file characteristics without reading the actual content. Only works within allowed directories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>list_allowed_directories</summary>

**Description**:

```
Returns the list of directories that this server is allowed to access. Subdirectories within these allowed directories are also accessible. Use this to understand which directories and their nested paths are available before trying to access files.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_directory | description | 7e243b9bddbea4a901f0807ae14535972587b896eecde076b03dd4fbd3a9b5bd |
| tools | directory_tree | description | a51dfb91799e4e8ff62aad67e4b3665360cc62a328efe43a541e66e0fb78ff01 |
| tools | edit_file | description | 1349a91ad62c6a43363a6af7995e3f29f44bf5e9c5310dadd8c278aec75e3969 |
| tools | edit_file | dryRun | 3dd869be68e1ef354dda1870b0ed00f8ae2c79ba1604a672b42b054fca958bfc |
| tools | get_file_info | description | e4cae83266b5e75a423ffb34bd21b66c22d0b9d6b673fb4cc45ea02e7298f7f3 |
| tools | list_allowed_directories | description | aa4aecbfa97e7b0b2f37e02248d576743e3ba69c5a3a33ef0334ed652e445474 |
| tools | list_directory | description | 2a89821007a4702b0f7e7cd13107b335d1c49baba8ffc4d38fe8d1cfbe3ac789 |
| tools | list_directory_with_sizes | description | 5f974132fd515ca908bb2dd84e3a7d95426b4b7905e785c6726f2399218a6d6b |
| tools | list_directory_with_sizes | sortBy | 5e32ce70fcf53900d55250eb051af648d170d30b90c58bb858a94b7f8f807da2 |
| tools | move_file | description | 0a86f8ce8d46144ec865434db66cd5c5f90f16123206b3334d7196477526b2a1 |
| tools | read_file | description | 7abf56a4c306cf50c1ad1b4568b4d5f28086f068b4052f81aff20e72c0b92d47 |
| tools | read_file | head | 715e4ce8d72883b7d5318a3869c210d4efb3e5ac4adc1938d331733dbe0db9df |
| tools | read_file | tail | deddd85a025f04978ca0517b89854a51acf2161a49dd63e47f11a06c6d162aba |
| tools | read_media_file | description | 206ef33602ac22560c67dbe0b926b6a096fbc0a29063c33882a7c54310b3715f |
| tools | read_multiple_files | description | d5a30eac51a3257ccd4b0acf3b70788f2b180fe1b9807c02644fa3389ebcbcb0 |
| tools | read_multiple_files | paths | 3dfc4b4246dec264d1f51f24dfccd4b913c856e0629dac4578177331b26133b0 |
| tools | read_text_file | description | 43033fa70cb5bafe3ded0443fe51f1edd90b4e9d45efac6118e4395d2524011f |
| tools | read_text_file | head | 715e4ce8d72883b7d5318a3869c210d4efb3e5ac4adc1938d331733dbe0db9df |
| tools | read_text_file | tail | deddd85a025f04978ca0517b89854a51acf2161a49dd63e47f11a06c6d162aba |
| tools | search_files | description | 7b4e41beb87051cba82183e4a36cbdce4ee542cc6decaa534a3fccf8b38c0a0e |
| tools | write_file | description | 182c8895da7eacc6f301ba5895d779aca5c0a29cf622fa14f34f728657f79688 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
