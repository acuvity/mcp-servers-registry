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


# What is mcp-server-desktop-commander?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-desktop-commander/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=@wonderwhy-er/desktop-commander)](https://github.com/wonderwhy-er/DesktopCommanderMCP)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-desktop-commander/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-desktop-commander&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-desktop-commander%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** A swiss-army-knife that can manage/execute programs and read/write/search/edit code and text files.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @wonderwhy-er/desktop-commander original [sources](https://github.com/wonderwhy-er/DesktopCommanderMCP).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-desktop-commander/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/charts/mcp-server-desktop-commander/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @wonderwhy-er/desktop-commander run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Eduards Ruzga ](https://github.com/wonderwhy-er/DesktopCommanderMCP) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @wonderwhy-er/desktop-commander ](https://github.com/wonderwhy-er/DesktopCommanderMCP)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @wonderwhy-er/desktop-commander ](https://github.com/wonderwhy-er/DesktopCommanderMCP)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/charts/mcp-server-desktop-commander)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-desktop-commander/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-desktop-commander:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-desktop-commander:1.0.0-0.2.0`

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

**Optional Environment variables**:
  - `HOME="/tmp"` environment variable can be changed with `env.HOME="/tmp"`

# How to install


Install will helm

```console
helm install mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-desktop-commander
```

From there your MCP server mcp-server-desktop-commander will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-desktop-commander` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-desktop-commander
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-desktop-commander` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-desktop-commander oci://docker.io/acuvity/mcp-server-desktop-commander --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (18)
<details>
<summary>get_config</summary>

**Description**:

```
Get the complete server configuration as JSON. Config includes fields for: blockedCommands (array of blocked shell commands), defaultShell (shell to use for commands), allowedDirectories (paths the server can access), fileReadLineLimit (max lines for read_file, default 1000), fileWriteLineLimit (max lines per write_file call, default 50), telemetryEnabled (boolean for telemetry opt-in/out). This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>set_config_value</summary>

**Description**:

```
Set a specific configuration value by key. WARNING: Should be used in a separate chat from file operations and command execution to prevent security issues. Config keys include: blockedCommands (array), defaultShell (string), allowedDirectories (array of paths), fileReadLineLimit (number, max lines for read_file), fileWriteLineLimit (number, max lines per write_file call), telemetryEnabled (boolean). IMPORTANT: Setting allowedDirectories to an empty array ([]) allows full access to the entire file system, regardless of the operating system. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| key | string | not set | Yes
| value | any | not set | No
</details>
<details>
<summary>read_file</summary>

**Description**:

```
Read the contents of a file from the file system or a URL with optional offset and length parameters. Prefer this over 'execute_command' with cat/type for viewing files. Supports partial file reading with 'offset' (start line, default: 0) and 'length' (max lines to read, default: configurable via 'fileReadLineLimit' setting, initially 1000). When reading from the file system, only works within allowed directories. Can fetch content from URLs when isUrl parameter is set to true (URLs are always read in full regardless of offset/length). Handles text files normally and image files are returned as viewable images. Recognized image types: PNG, JPEG, GIF, WebP. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| isUrl | boolean | not set | No
| length | number | not set | No
| offset | number | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>read_multiple_files</summary>

**Description**:

```
Read the contents of multiple files simultaneously. Each file's content is returned with its path as a reference. Handles text files normally and renders images as viewable content. Recognized image types: PNG, JPEG, GIF, WebP. Failed reads for individual files won't stop the entire operation. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| paths | array | not set | Yes
</details>
<details>
<summary>write_file</summary>

**Description**:

```
Write or append to file contents with a configurable line limit per call (default: 50 lines). THIS IS A STRICT REQUIREMENT. ANY file with more than the configured limit MUST BE written in chunks or IT WILL FAIL.

                        NEVER attempt to write more than the configured line limit at once.

                        REQUIRED PROCESS FOR LARGE FILES:
                        1. FIRST → write_file(filePath, firstChunk, {mode: 'rewrite'})
                        2. THEN → write_file(filePath, secondChunk, {mode: 'append'})
                        3. THEN → write_file(filePath, thirdChunk, {mode: 'append'})
                        ... and so on for each chunk
                        
                        If asked to continue writing do not restart from beginning, read end of file to see where you stopped and continue from there

                        Files over the line limit (configurable via 'fileWriteLineLimit' setting) WILL BE REJECTED if not broken into chunks as described above.
                        Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| mode | string | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>create_directory</summary>

**Description**:

```
Create a new directory or ensure a directory exists. Can create multiple nested directories in one operation. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
Get a detailed listing of all files and directories in a specified path. Use this instead of 'execute_command' with ls/dir commands. Results distinguish between files and directories with [FILE] and [DIR] prefixes. Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>move_file</summary>

**Description**:

```
Move or rename files and directories. 
                        Can move files between directories and rename them in a single operation. 
                        Both source and destination must be within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
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
Finds files by name using a case-insensitive substring matching. 
                        Use this instead of 'execute_command' with find/dir/ls for locating files.
                        Searches through all subdirectories from the starting path. 
                        Has a default timeout of 30 seconds which can be customized using the timeoutMs parameter. 
                        Only searches within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
| pattern | string | not set | Yes
| timeoutMs | number | not set | No
</details>
<details>
<summary>search_code</summary>

**Description**:

```
Search for text/code patterns within file contents using ripgrep. 
                        Use this instead of 'execute_command' with grep/find for searching code content.
                        Fast and powerful search similar to VS Code search functionality. 
                        Supports regular expressions, file pattern filtering, and context lines. 
                        Has a default timeout of 30 seconds which can be customized. 
                        Only searches within allowed directories. 
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contextLines | number | not set | No
| filePattern | string | not set | No
| ignoreCase | boolean | not set | No
| includeHidden | boolean | not set | No
| maxResults | number | not set | No
| path | string | not set | Yes
| pattern | string | not set | Yes
| timeoutMs | number | not set | No
</details>
<details>
<summary>get_file_info</summary>

**Description**:

```
Retrieve detailed metadata about a file or directory including size, creation time, last modified time, 
                        permissions, and type. 
                        Only works within allowed directories. IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path | string | not set | Yes
</details>
<details>
<summary>edit_block</summary>

**Description**:

```
Apply surgical text replacements to files. 
                        BEST PRACTICE: Make multiple small, focused edits rather than one large edit. 
                        Each edit_block call should change only what needs to be changed - include just enough context to uniquely identify the text being modified. 
                        Takes file_path, old_string (text to replace), new_string (replacement text), and optional expected_replacements parameter. 
                        By default, replaces only ONE occurrence of the search text. 
                        To replace multiple occurrences, provide the expected_replacements parameter with the exact number of matches expected. 
                        UNIQUENESS REQUIREMENT: When expected_replacements=1 (default), include the minimal amount of context necessary (typically 1-3 lines) before and after the change point, with exact whitespace and indentation. 
                        When editing multiple sections, make separate edit_block calls for each distinct change rather than one large replacement. 
                        When a close but non-exact match is found, a character-level diff is shown in the format: common_prefix{-removed-}{+added+}common_suffix to help you identify what's different.
                        Similar to write_file, there is a configurable line limit (fileWriteLineLimit) that warns if the edited file exceeds this limit. If this happens, consider breaking your edits into smaller, more focused changes.
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expected_replacements | number | not set | No
| file_path | string | not set | Yes
| new_string | string | not set | Yes
| old_string | string | not set | Yes
</details>
<details>
<summary>execute_command</summary>

**Description**:

```
Execute a terminal command with timeout. 
                        Command will continue running in background if it doesn't complete within timeout. 
                        NOTE: For file operations, prefer specialized tools like read_file, search_code, list_directory instead of cat, grep, or ls commands.
                        IMPORTANT: Always use absolute paths (starting with '/' or drive letter like 'C:\') for reliability. Relative paths may fail as they depend on the current working directory. Tilde paths (~/...) might not work in all contexts. Unless the user explicitly asks for relative paths, use absolute paths. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | not set | Yes
| shell | string | not set | No
| timeout_ms | number | not set | No
</details>
<details>
<summary>read_output</summary>

**Description**:

```
Read new output from a running terminal session. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
</details>
<details>
<summary>force_terminate</summary>

**Description**:

```
Force terminate a running terminal session. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
</details>
<details>
<summary>list_sessions</summary>

**Description**:

```
List all active terminal sessions. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_processes</summary>

**Description**:

```
List all running processes. Returns process information including PID, command name, CPU usage, and memory usage. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>kill_process</summary>

**Description**:

```
Terminate a running process by PID. Use with caution as this will forcefully terminate the specified process. This command can be referenced as "DC: ..." or "use Desktop Commander to ..." in your instructions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pid | number | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_directory | description | 5b5a70f4ee3d31bb9d3436ed52f344b43654820f57a6a67fc0c99761517a4d81 |
| tools | edit_block | description | e603db2f4c770533b9c0832c4640158bb56596bdb8132d7f67ee3e73ba948ba3 |
| tools | execute_command | description | fa01b0601c17006c15b3a09a14f33ff903dabf294d30b9fdb1d807d9910b8715 |
| tools | force_terminate | description | 2029aca6b7261164d9793bafb7bfb09d19bdf89cf1df99ecea62a2e21d73358e |
| tools | get_config | description | 837be3ebc66a024ada02ec2ee40ee1bdcb29d75273a8ee6295684af4325522f5 |
| tools | get_file_info | description | ff3298ecab0f3e3cc0b721cf63aa81ba6c3dee3c96ecae08826daf3e94bc6622 |
| tools | kill_process | description | 73742047a9517fb4af4b431db0b14805eb760bcf84396cec0e818594f7328cd6 |
| tools | list_directory | description | 2c635e3489e61a026e44245aa2a9b40f975567e3613eb243c2dd9e8d89aad741 |
| tools | list_processes | description | 4393993b155546018e42d72cd399332c734432192702699bcca998347383c32c |
| tools | list_sessions | description | 654fd40cfc9503eec338edcaa3f494ed57a9cec00d5cb5e082e1d7d4d7490337 |
| tools | move_file | description | 7e04f27bca2a50d0a2131c6aedab9e9ef4a6c19ace1788e900154adf1d8377f6 |
| tools | read_file | description | 99cc815304c3f3c5eadc8f681bccec0f015471ceac7c44c0bd217e88341e3782 |
| tools | read_multiple_files | description | 324854dbeccbcccb0dd993a323e67f8b077f8d5bda5045284c84686b6dfc764a |
| tools | read_output | description | 37fb0804d8fa450183a5c07318d0266626664a36c8a0b00d115328aa363420a9 |
| tools | search_code | description | dca0fb3c246fc9677e46538f522cda87e832c09ec657d68d5901ef626bd933b4 |
| tools | search_files | description | f88fab9b0a5d27e1ad95b5799217bfab9738c764fd29d90b461751d5576b2516 |
| tools | set_config_value | description | af29ae6115372ac6c1a748991cd18365c4aa971af2c2d3a82cb8ca883da38f60 |
| tools | write_file | description | 203b58a416592ad675510b702725da1d89c66fba9d724db3ebfb0913bf71fd42 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
