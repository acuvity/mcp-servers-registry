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


# What is mcp-server-harness?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-harness/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-harness/1.0.0-beta?logo=docker&logoColor=fff&label=1.0.0-beta)](https://hub.docker.com/r/acuvity/mcp-server-harness)
[![GitHUB](https://img.shields.io/badge/1.0.0-beta-3775A9?logo=github&logoColor=fff&label=harness/mcp-server)](https://github.com/harness/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-harness/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-harness&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HARNESS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-harness%3A1.0.0-beta%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides seamless integration with Harness APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from harness/mcp-server original [sources](https://github.com/harness/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-harness/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/charts/mcp-server-harness/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure harness/mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Harness ](https://github.com/harness/mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ harness/mcp-server ](https://github.com/harness/mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ harness/mcp-server ](https://github.com/harness/mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/charts/mcp-server-harness)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-harness/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.0-beta`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-harness:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-harness:1.0.0-1.0.0-beta`

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
  - `HARNESS_API_KEY` secret to be set as secrets.HARNESS_API_KEY either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `HARNESS_DEFAULT_ORG_ID=""` environment variable can be changed with `env.HARNESS_DEFAULT_ORG_ID=""`
  - `HARNESS_DEFAULT_PROJECT_ID=""` environment variable can be changed with `env.HARNESS_DEFAULT_PROJECT_ID=""`
  - `HARNESS_BASE_URL=""` environment variable can be changed with `env.HARNESS_BASE_URL=""`
  - `HARNESS_TOOLSETS=""` environment variable can be changed with `env.HARNESS_TOOLSETS=""`
  - `HARNESS_READ_ONLY=""` environment variable can be changed with `env.HARNESS_READ_ONLY=""`

# How to install


Install will helm

```console
helm install mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-harness
```

From there your MCP server mcp-server-harness will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-harness` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-harness
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-harness` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-harness oci://docker.io/acuvity/mcp-server-harness --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (17)
<details>
<summary>create_pull_request</summary>

**Description**:

```
Create a new pull request in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | The description of the pull request | No
| is_draft | boolean | Whether the pull request should be created as a draft | No
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| repo_identifier | string | The identifier of the repository | Yes
| source_branch | string | The source branch for the pull request | Yes
| target_branch | string | The target branch for the pull request | No
| title | string | The title of the pull request | Yes
</details>
<details>
<summary>download_execution_logs</summary>

**Description**:

```
Downloads logs for an execution inside Harness
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| logs_directory | string | The absolute path to the directory where the logs should get downloaded | Yes
| org_id | string | Required ID of the organization. | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>fetch_execution_url</summary>

**Description**:

```
Fetch the execution URL for a pipeline execution in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pipeline_id | string | The ID of the pipeline | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>get_execution</summary>

**Description**:

```
Get details of a specific pipeline execution in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| plan_execution_id | string | The ID of the plan execution | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>get_pipeline</summary>

**Description**:

```
Get details of a specific pipeline in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pipeline_id | string | The ID of the pipeline | Yes
| project_id | string | Required ID of the project. | Yes
</details>
<details>
<summary>get_pull_request</summary>

**Description**:

```
Get details of a specific pull request in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| pr_number | number | The number of the pull request | Yes
| project_id | string | Required ID of the project. | Yes
| repo_id | string | The ID of the repository | Yes
</details>
<details>
<summary>get_pull_request_checks</summary>

**Description**:

```
Get status checks for a specific pull request in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| pr_number | number | The number of the pull request | Yes
| project_id | string | Optional ID of the project. | No
| repo_identifier | string | The identifier of the repository | Yes
</details>
<details>
<summary>get_registry</summary>

**Description**:

```
Get details of a specific registry in Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
</details>
<details>
<summary>get_repository</summary>

**Description**:

```
Get details of a specific repository in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| project_id | string | Optional ID of the project. | No
| repo_identifier | string | The identifier of the repository | Yes
</details>
<details>
<summary>list_artifact_files</summary>

**Description**:

```
List files for a specific artifact version in a Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| artifact | string | The name of the artifact | Yes
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
| size | number | Number of items per page | No
| sort_field | string | Optional field to sort by | No
| sort_order | string | Optional sort order | No
| version | string | The version of the artifact | Yes
</details>
<details>
<summary>list_artifact_versions</summary>

**Description**:

```
List artifact versions in a Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| artifact | string | The name of the artifact | Yes
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
| search | string | Optional search term to filter versions | No
| size | number | Number of items per page | No
</details>
<details>
<summary>list_artifacts</summary>

**Description**:

```
List artifacts in a Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| registry | string | The name of the registry | Yes
| search | string | Optional search term to filter artifacts | No
| size | number | Number of items per page | No
</details>
<details>
<summary>list_executions</summary>

**Description**:

```
List pipeline executions in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Optional branch to filter executions | No
| my_deployments | boolean | Optional flag to show only my deployments | No
| org_id | string | Required ID of the organization. | Yes
| page | number | Page number for pagination - page 0 is the first page | No
| pipeline_identifier | string | Optional pipeline identifier to filter executions | No
| project_id | string | Required ID of the project. | Yes
| search_term | string | Optional search term to filter executions | No
| size | number | Number of items per page | No
| status | string | Optional status to filter executions (e.g., Running, Success, Failed) | No
</details>
<details>
<summary>list_pipelines</summary>

**Description**:

```
List pipelines in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Required ID of the organization. | Yes
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Required ID of the project. | Yes
| search_term | string | Optional search term to filter pipelines | No
| size | number | Number of items per page | No
</details>
<details>
<summary>list_pull_requests</summary>

**Description**:

```
List pull requests in a Harness repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| include_checks | boolean | Optional flag to include CI check information for builds ran in the PR | No
| limit | number | Number of items per page | No
| org_id | string | Required ID of the organization. | Yes
| page | number | Page number for pagination | No
| project_id | string | Required ID of the project. | Yes
| query | string | Optional search query to filter pull requests | No
| repo_id | string | The ID of the repository | Yes
| source_branch | string | Optional source branch to filter pull requests | No
| state | string | Optional comma-separated states to filter pull requests (possible values: open,closed,merged) | No
| target_branch | string | Optional target branch to filter pull requests | No
</details>
<details>
<summary>list_registries</summary>

**Description**:

```
List registries in Harness artifact registry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org_id | string | Optional ID of the organization. | No
| package_type | string | Optional type to filter registries by package type | No
| page | number | Page number for pagination - page 0 is the first page | No
| project_id | string | Optional ID of the project. | No
| size | number | Number of items per page | No
| type | string | Optional type to filter registries | No
</details>
<details>
<summary>list_repositories</summary>

**Description**:

```
List repositories in Harness.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Number of items per page | No
| order | string | Optional sort order (asc or desc) | No
| org_id | string | Optional ID of the organization. | No
| page | number | Page number for pagination | No
| project_id | string | Optional ID of the project. | No
| query | string | Optional search term to filter repositories | No
| sort | string | Optional field to sort by (e.g., identifier) | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_pull_request | description | 7edd77c297ba3cef9ffaad0a5c43335df6ebcea5f48c5c88b254ed0ce048b9e8 |
| tools | create_pull_request | description | b655abbc7f9845299b4aa415d21ab2d859af8766d6683334ed7a9ac7a3af069a |
| tools | create_pull_request | is_draft | fc1ebd4bb02f777c1a5fb6665e78069749476d7ae61d824e85f1abb3d36a9322 |
| tools | create_pull_request | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | create_pull_request | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | create_pull_request | repo_identifier | 3a7fbfb08dc51e4b3769b31385f507136836ba242aa14e09e1ab4729a70db9b7 |
| tools | create_pull_request | source_branch | 5eb4276fce36367ead9a18f42701b20e6499dfd6eaf1deb1189ff5d9ab9fe2ff |
| tools | create_pull_request | target_branch | 70c28f4c35c40e3fa7dbb4c7b96f6aff66fbdde5b1554f659a6b32d7f14d76eb |
| tools | create_pull_request | title | c04c47bf2f47f484df617492655df04711f8dc4320b2c1fb9dfcbd6defdb18bc |
| tools | download_execution_logs | description | 3c0c5d0e2f9005e0691f4a52a41115ad5b3bb9451dcdc5db856d572654083dbd |
| tools | download_execution_logs | logs_directory | 929ab48d698ad36cceb3157b8afbcddb507be1753e81effe67d9c52adadb6d38 |
| tools | download_execution_logs | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | download_execution_logs | plan_execution_id | a300ba3e01c7428f5992ae07c929da21111bd7670e0b40888978c0901e84101d |
| tools | download_execution_logs | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | fetch_execution_url | description | 1469e23ea5f5d25213828d61fff7594b96376297d7c66b48beec3ec08c00c0c5 |
| tools | fetch_execution_url | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | fetch_execution_url | pipeline_id | 50fc23224221dbf67c12e6ee33931b2c183b8e2cabd7a56da6c32e56ae238e0b |
| tools | fetch_execution_url | plan_execution_id | a300ba3e01c7428f5992ae07c929da21111bd7670e0b40888978c0901e84101d |
| tools | fetch_execution_url | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | get_execution | description | 3b3bbc6e056cfc8da6d02c6bd74e8bdf8365653e48c6cca6a52519adb75b9872 |
| tools | get_execution | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | get_execution | plan_execution_id | a300ba3e01c7428f5992ae07c929da21111bd7670e0b40888978c0901e84101d |
| tools | get_execution | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | get_pipeline | description | 973cc89538c9f101377b19ce824e04681a2dd4026ef0493e696639037d5793ab |
| tools | get_pipeline | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | get_pipeline | pipeline_id | 50fc23224221dbf67c12e6ee33931b2c183b8e2cabd7a56da6c32e56ae238e0b |
| tools | get_pipeline | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | get_pull_request | description | 14ddf56099675cc324a0546a09867b8fbb348b9ca6e4eb5527bce22f90fd93be |
| tools | get_pull_request | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | get_pull_request | pr_number | afa56702a1c419b13f54977d41d9296b46b1698c12af60c65ed76dc692fc65ae |
| tools | get_pull_request | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | get_pull_request | repo_id | a49689fd768ef5515ef70b9c7ab84c2eae5840db7b106cb00b6cc38e7e83fe9d |
| tools | get_pull_request_checks | description | 8a4ff87a1073f7613e43d7c07a14618f757accda93ee5e8448680bf8ee0e2216 |
| tools | get_pull_request_checks | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | get_pull_request_checks | pr_number | afa56702a1c419b13f54977d41d9296b46b1698c12af60c65ed76dc692fc65ae |
| tools | get_pull_request_checks | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | get_pull_request_checks | repo_identifier | 3a7fbfb08dc51e4b3769b31385f507136836ba242aa14e09e1ab4729a70db9b7 |
| tools | get_registry | description | 90984c8de3ac34454827df01bdc60c24d71dd83739be448e9038acd40f597aa4 |
| tools | get_registry | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | get_registry | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | get_registry | registry | 8346d081634edfa2688672cadd4cdc138a07ba1ae708d0c0224c29861e7f54f4 |
| tools | get_repository | description | 9210de28da524060d8c696a395cc9ce97a0c6be32792106e2d4e964b9e04dd6c |
| tools | get_repository | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | get_repository | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | get_repository | repo_identifier | 3a7fbfb08dc51e4b3769b31385f507136836ba242aa14e09e1ab4729a70db9b7 |
| tools | list_artifact_files | description | 0adf1393c1df70970f04617b65dad5c177b3fa3a31a1507c3ac54f6a560bbba1 |
| tools | list_artifact_files | artifact | 4d20c4a04e42b30ad55ed87588154ac693a91b3a8992f40b607788c12cf08a69 |
| tools | list_artifact_files | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_artifact_files | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_artifact_files | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_artifact_files | registry | 8346d081634edfa2688672cadd4cdc138a07ba1ae708d0c0224c29861e7f54f4 |
| tools | list_artifact_files | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_artifact_files | sort_field | 547312f5735d083f8694cf94330fa7d618cce03bea696d4d1de5b995f5920aef |
| tools | list_artifact_files | sort_order | 1e83377cd19072af2f77dc60344ebd411cf495e38ebf999ccf6f45c0beabfed3 |
| tools | list_artifact_files | version | 6e38343ae8623cc9de2021a2cb37b5380d020523c1ebea77437118244f96f157 |
| tools | list_artifact_versions | description | 9d273dcf20205975f121617b3227573a30139787b322e048ee5a5e98065f82b4 |
| tools | list_artifact_versions | artifact | 4d20c4a04e42b30ad55ed87588154ac693a91b3a8992f40b607788c12cf08a69 |
| tools | list_artifact_versions | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_artifact_versions | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_artifact_versions | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_artifact_versions | registry | 8346d081634edfa2688672cadd4cdc138a07ba1ae708d0c0224c29861e7f54f4 |
| tools | list_artifact_versions | search | c73938f86d09950128f09331f74783b4ec6f49c8eeafc869cb5389676e4ea3c7 |
| tools | list_artifact_versions | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_artifacts | description | 640b32c26371c343d0435824cfcd2e4b71b831060837cbfd613a9d475fa2e9b8 |
| tools | list_artifacts | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_artifacts | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_artifacts | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_artifacts | registry | 8346d081634edfa2688672cadd4cdc138a07ba1ae708d0c0224c29861e7f54f4 |
| tools | list_artifacts | search | 7518e2469f04df479741de289b08d66300eddb87534d9660f31540ca83021643 |
| tools | list_artifacts | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_executions | description | 639d87a9fc8c56b9da15de96fe1d69f2e6ddfd83f213f72498005f7dc931d025 |
| tools | list_executions | branch | 33b16f813d79b5b0a0e5c5cb8c36260f23491303a4dc312b40585e68210ac5a1 |
| tools | list_executions | my_deployments | f6e15331fb4a9d878510fdcb6e0e71e0fe9536766dcb9bf93286f2e80d0443ee |
| tools | list_executions | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | list_executions | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_executions | pipeline_identifier | ea32bdb79e8c29d407c287993c9e078ad539e607ba8271648d3fb69dcd645054 |
| tools | list_executions | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | list_executions | search_term | a31863dbe6950a21ba780b23fadc50767cf84f1df1b74894ce32fb479d35c36d |
| tools | list_executions | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_executions | status | cd4cfdb5b7e3bd9b0dac5b737705047da58c5c1d338879715e357995b7c531df |
| tools | list_pipelines | description | b4106dda0c4f300945d433b87ffaaaed53a36422ff2c8a23ad6d2f557bdf4ab4 |
| tools | list_pipelines | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | list_pipelines | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_pipelines | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | list_pipelines | search_term | cd148af67bed8f4944b2971b11e88a1b87c244c7efd418adf5379a116e86afaa |
| tools | list_pipelines | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_pull_requests | description | c717524c06e1cfcc41a414283c9d2a27423f305453e64c2a5e0fcd6b72268d93 |
| tools | list_pull_requests | include_checks | fa4fbae6cb0dee508bb2755b68d88b12dc06a8f2ab29fc5f45e9c2d274d707e2 |
| tools | list_pull_requests | limit | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_pull_requests | org_id | 319a0322acf57f3d1885f6bf36706596433a9097f11a943825999a3e7e258a04 |
| tools | list_pull_requests | page | f6889ee3bdc7faaf34e7880f8839b337fe2eebe475334f7f9704ecf9f1a518e0 |
| tools | list_pull_requests | project_id | 5d1f5b068b7410f0be65011b3777b74de87f210ff517482f6b95e72a2256e4e3 |
| tools | list_pull_requests | query | a7e30da1be6129faac89047ce1d7d2050437a2a5b413a39c55061107b0176c0c |
| tools | list_pull_requests | repo_id | a49689fd768ef5515ef70b9c7ab84c2eae5840db7b106cb00b6cc38e7e83fe9d |
| tools | list_pull_requests | source_branch | 37552e81825adef96276491647671036bdfb7d2d51849b8143d5bf28940ab420 |
| tools | list_pull_requests | state | 9cfb8fd0ad7ac5b23a43af6a26148758080d16a539913dafda08b4d96b713b1e |
| tools | list_pull_requests | target_branch | f268ff10654c688d0c61e884316377ac26a66e98733f025763c3b3ba10becd20 |
| tools | list_registries | description | dd6a0053abaee16b2d2902b2032af12895dfccccf36668b49bb6e23627f2c9f8 |
| tools | list_registries | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_registries | package_type | 4354b22815378ebf78185549e227d35ce376eb3780f692caf563e7ef051d1435 |
| tools | list_registries | page | 0f84a52795332fb9fca966705296e85388355771590489c2692620c6babff80b |
| tools | list_registries | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_registries | size | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_registries | type | 7387e3c9a44b684f5791153d68fd976fc5c43ceeca9bcfe552b3b28e1218011e |
| tools | list_repositories | description | 7cb2d6f193177bfd4947077571b5b77db2f154298fe6c08e5ec78ca941609018 |
| tools | list_repositories | limit | f2e65f0a130e2d69335772c1c1dda0767a3ef9415251fdfa0cd4178a574259ca |
| tools | list_repositories | order | c3460ef644a4a48c9bc3d687af93da39c4abeb5c270eeae46be73972a8f5d289 |
| tools | list_repositories | org_id | c15d7bdf41af98ffd70856ef4ed869a683e4112a1cfcaa60f8c4689da0504689 |
| tools | list_repositories | page | f6889ee3bdc7faaf34e7880f8839b337fe2eebe475334f7f9704ecf9f1a518e0 |
| tools | list_repositories | project_id | fa81aafa8ba6089f19b9cda92185b2cfc5adbfb5a51918749af91cf2a9a24367 |
| tools | list_repositories | query | bbe0c2646ed6908854c4d83b0fea6669682f80e87201e469d7c5f17cab4220ae |
| tools | list_repositories | sort | 9369d3b63bef98a4d2b1b3d93fb87fc0b322a0fc2389c176df4e7edbed04d51e |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
