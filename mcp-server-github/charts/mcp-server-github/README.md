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


# What is mcp-server-github?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-github/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-github/v0.5.0?logo=docker&logoColor=fff&label=v0.5.0)](https://hub.docker.com/r/acuvity/mcp-server-github)
[![GitHUB](https://img.shields.io/badge/v0.5.0-3775A9?logo=github&logoColor=fff&label=github/github-mcp-server)](https://github.com/github/github-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-github/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-github&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GITHUB_PERSONAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-github%3Av0.5.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** GitHub's official MCP Server

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from github/github-mcp-server original [sources](https://github.com/github/github-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-github/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/charts/mcp-server-github/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure github/github-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ github ](https://github.com/github/github-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ github/github-mcp-server ](https://github.com/github/github-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ github/github-mcp-server ](https://github.com/github/github-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/charts/mcp-server-github)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-github/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-v0.5.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-github:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-github:1.0.0-v0.5.0`

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
  - `GITHUB_PERSONAL_ACCESS_TOKEN` secret to be set as secrets.GITHUB_PERSONAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `GITHUB_HOST=""` environment variable can be changed with `env.GITHUB_HOST=""`

# How to install


Install will helm

```console
helm install mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-github --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-github --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-github
```

From there your MCP server mcp-server-github will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-github` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-github
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-github` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-github oci://docker.io/acuvity/mcp-server-github --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (51)
<details>
<summary>add_issue_comment</summary>

**Description**:

```
Add a comment to a specific issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | Comment content | Yes
| issue_number | number | Issue number to comment on | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>add_pull_request_review_comment_to_pending_review</summary>

**Description**:

```
Add a comment to the requester's latest pending pull request review, a pending review needs to already exist to call this (check with the user if not sure).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | The text of the review comment | Yes
| line | number | The line of the blob in the pull request diff that the comment applies to. For multi-line comments, the last line of the range | No
| owner | string | Repository owner | Yes
| path | string | The relative path to the file that necessitates a comment | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
| side | string | The side of the diff to comment on. LEFT indicates the previous state, RIGHT indicates the new state | No
| startLine | number | For multi-line comments, the first line of the range that the comment applies to | No
| startSide | string | For multi-line comments, the starting side of the diff that the comment applies to. LEFT indicates the previous state, RIGHT indicates the new state | No
| subjectType | string | The level at which the comment is targeted | Yes
</details>
<details>
<summary>assign_copilot_to_issue</summary>

**Description**:

```
Assign Copilot to a specific issue in a GitHub repository.

This tool can help with the following outcomes:
- a Pull Request created with source code changes to resolve the issue


More information can be found at:
- https://docs.github.com/en/copilot/using-github-copilot/using-copilot-coding-agent-to-work-on-tasks/about-assigning-tasks-to-copilot

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issueNumber | number | Issue number | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_and_submit_pull_request_review</summary>

**Description**:

```
Create and submit a review for a pull request without review comments.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | Review comment text | Yes
| commitID | string | SHA of commit to review | No
| event | string | Review action to perform | Yes
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_branch</summary>

**Description**:

```
Create a new branch in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Name for new branch | Yes
| from_branch | string | Source branch (defaults to repo default) | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_issue</summary>

**Description**:

```
Create a new issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignees | array | Usernames to assign to this issue | No
| body | string | Issue body content | No
| labels | array | Labels to apply to this issue | No
| milestone | number | Milestone number | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| title | string | Issue title | Yes
</details>
<details>
<summary>create_or_update_file</summary>

**Description**:

```
Create or update a single file in a GitHub repository. If updating, you must provide the SHA of the file you want to update.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to create/update the file in | Yes
| content | string | Content of the file | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path where to create/update the file | Yes
| repo | string | Repository name | Yes
| sha | string | SHA of file being replaced (for updates) | No
</details>
<details>
<summary>create_pending_pull_request_review</summary>

**Description**:

```
Create a pending review for a pull request. Call this first before attempting to add comments to a pending review, and ultimately submitting it. A pending pull request review means a pull request review, it is pending because you create it first and submit it later, and the PR author will not see it until it is submitted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| commitID | string | SHA of commit to review | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>create_pull_request</summary>

**Description**:

```
Create a new pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | Branch to merge into | Yes
| body | string | PR description | No
| draft | boolean | Create as draft PR | No
| head | string | Branch containing changes | Yes
| maintainer_can_modify | boolean | Allow maintainer edits | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| title | string | PR title | Yes
</details>
<details>
<summary>create_repository</summary>

**Description**:

```
Create a new GitHub repository in your account
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| autoInit | boolean | Initialize with README | No
| description | string | Repository description | No
| name | string | Repository name | Yes
| private | boolean | Whether repo should be private | No
</details>
<details>
<summary>delete_file</summary>

**Description**:

```
Delete a file from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to delete the file from | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path to the file to delete | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>delete_pending_pull_request_review</summary>

**Description**:

```
Delete the requester's latest pending pull request review. Use this after the user decides not to submit a pending review, if you don't know if they already created one then check first.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>dismiss_notification</summary>

**Description**:

```
Dismiss a notification by marking it as read or done
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| state | string | The new state of the notification (read/done) | No
| threadID | string | The ID of the notification thread | Yes
</details>
<details>
<summary>fork_repository</summary>

**Description**:

```
Fork a GitHub repository to your account or specified organization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| organization | string | Organization to fork to | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_code_scanning_alert</summary>

**Description**:

```
Get details of a specific code scanning alert in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| alertNumber | number | The number of the alert. | Yes
| owner | string | The owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
</details>
<details>
<summary>get_commit</summary>

**Description**:

```
Get details for a commit from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sha | string | Commit SHA, branch name, or tag name | Yes
</details>
<details>
<summary>get_file_contents</summary>

**Description**:

```
Get the contents of a file or directory from a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to get contents from | No
| owner | string | Repository owner (username or organization) | Yes
| path | string | Path to file/directory (directories must end with a slash '/') | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_issue</summary>

**Description**:

```
Get details of a specific issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_number | number | The number of the issue | Yes
| owner | string | The owner of the repository | Yes
| repo | string | The name of the repository | Yes
</details>
<details>
<summary>get_issue_comments</summary>

**Description**:

```
Get comments for a specific issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| issue_number | number | Issue number | Yes
| owner | string | Repository owner | Yes
| page | number | Page number | No
| per_page | number | Number of records per page | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_me</summary>

**Description**:

```
Get details of the authenticated GitHub user. Use this when a request includes "me", "my". The output will not change unless the user changes their profile, so only call this once.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| reason | string | Optional: the reason for requesting the user information | No
</details>
<details>
<summary>get_notification_details</summary>

**Description**:

```
Get detailed information for a specific GitHub notification, always call this tool when the user asks for details about a specific notification, if you don't know the ID list notifications first.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| notificationID | string | The ID of the notification | Yes
</details>
<details>
<summary>get_pull_request</summary>

**Description**:

```
Get details of a specific pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_comments</summary>

**Description**:

```
Get comments for a specific pull request.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_diff</summary>

**Description**:

```
Get the diff of a pull request.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_files</summary>

**Description**:

```
Get the files changed in a specific pull request.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_reviews</summary>

**Description**:

```
Get reviews for a specific pull request.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_pull_request_status</summary>

**Description**:

```
Get the status of a specific pull request.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>get_secret_scanning_alert</summary>

**Description**:

```
Get details of a specific secret scanning alert in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| alertNumber | number | The number of the alert. | Yes
| owner | string | The owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
</details>
<details>
<summary>get_tag</summary>

**Description**:

```
Get details about a specific git tag in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| tag | string | Tag name | Yes
</details>
<details>
<summary>list_branches</summary>

**Description**:

```
List branches in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>list_code_scanning_alerts</summary>

**Description**:

```
List code scanning alerts in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | The owner of the repository. | Yes
| ref | string | The Git reference for the results you want to list. | No
| repo | string | The name of the repository. | Yes
| severity | string | Filter code scanning alerts by severity | No
| state | string | Filter code scanning alerts by state. Defaults to open | No
| tool_name | string | The name of the tool used for code scanning. | No
</details>
<details>
<summary>list_commits</summary>

**Description**:

```
Get list of commits of a branch in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sha | string | SHA or Branch name | No
</details>
<details>
<summary>list_issues</summary>

**Description**:

```
List issues in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| direction | string | Sort direction | No
| labels | array | Filter by labels | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| since | string | Filter by date (ISO 8601 timestamp) | No
| sort | string | Sort order | No
| state | string | Filter by state | No
</details>
<details>
<summary>list_notifications</summary>

**Description**:

```
Lists all GitHub notifications for the authenticated user, including unread notifications, mentions, review requests, assignments, and updates on issues or pull requests. Use this tool whenever the user asks what to work on next, requests a summary of their GitHub activity, wants to see pending reviews, or needs to check for new updates or tasks. This tool is the primary way to discover actionable items, reminders, and outstanding work on GitHub. Always call this tool when asked what to work on next, what is pending, or what needs attention in GitHub.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| before | string | Only show notifications updated before the given time (ISO 8601 format) | No
| filter | string | Filter notifications to, use default unless specified. Read notifications are ones that have already been acknowledged by the user. Participating notifications are those that the user is directly involved in, such as issues or pull requests they have commented on or created. | No
| owner | string | Optional repository owner. If provided with repo, only notifications for this repository are listed. | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Optional repository name. If provided with owner, only notifications for this repository are listed. | No
| since | string | Only show notifications updated after the given time (ISO 8601 format) | No
</details>
<details>
<summary>list_pull_requests</summary>

**Description**:

```
List pull requests in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | Filter by base branch | No
| direction | string | Sort direction | No
| head | string | Filter by head user/org and branch | No
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
| sort | string | Sort by | No
| state | string | Filter by state | No
</details>
<details>
<summary>list_secret_scanning_alerts</summary>

**Description**:

```
List secret scanning alerts in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | The owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
| resolution | string | Filter by resolution | No
| secret_type | string | A comma-separated list of secret types to return. All default secret patterns are returned. To return generic patterns, pass the token name(s) in the parameter. | No
| state | string | Filter by state | No
</details>
<details>
<summary>list_tags</summary>

**Description**:

```
List git tags in a GitHub repository
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| repo | string | Repository name | Yes
</details>
<details>
<summary>manage_notification_subscription</summary>

**Description**:

```
Manage a notification subscription: ignore, watch, or delete a notification thread subscription.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | Action to perform: ignore, watch, or delete the notification subscription. | Yes
| notificationID | string | The ID of the notification thread. | Yes
</details>
<details>
<summary>manage_repository_notification_subscription</summary>

**Description**:

```
Manage a repository notification subscription: ignore, watch, or delete repository notifications subscription for the provided repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| action | string | Action to perform: ignore, watch, or delete the repository notification subscription. | Yes
| owner | string | The account owner of the repository. | Yes
| repo | string | The name of the repository. | Yes
</details>
<details>
<summary>mark_all_notifications_read</summary>

**Description**:

```
Mark all notifications as read
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| lastReadAt | string | Describes the last point that notifications were checked (optional). Default: Now | No
| owner | string | Optional repository owner. If provided with repo, only notifications for this repository are marked as read. | No
| repo | string | Optional repository name. If provided with owner, only notifications for this repository are marked as read. | No
</details>
<details>
<summary>merge_pull_request</summary>

**Description**:

```
Merge a pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| commit_message | string | Extra detail for merge commit | No
| commit_title | string | Title for merge commit | No
| merge_method | string | Merge method | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>push_files</summary>

**Description**:

```
Push multiple files to a GitHub repository in a single commit
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Branch to push to | Yes
| files | array | Array of file objects to push, each object with path (string) and content (string) | Yes
| message | string | Commit message | Yes
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>request_copilot_review</summary>

**Description**:

```
Request a GitHub Copilot code review for a pull request. Use this for automated feedback on pull requests, usually before requesting a human reviewer.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>search_code</summary>

**Description**:

```
Search for code across GitHub repositories
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| q | string | Search query using GitHub code search syntax | Yes
| sort | string | Sort field ('indexed' only) | No
</details>
<details>
<summary>search_issues</summary>

**Description**:

```
Search for issues in GitHub repositories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| q | string | Search query using GitHub issues search syntax | Yes
| sort | string | Sort field by number of matches of categories, defaults to best match | No
</details>
<details>
<summary>search_repositories</summary>

**Description**:

```
Search for GitHub repositories
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| query | string | Search query | Yes
</details>
<details>
<summary>search_users</summary>

**Description**:

```
Search for GitHub users
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order | string | Sort order | No
| page | number | Page number for pagination (min 1) | No
| perPage | number | Results per page for pagination (min 1, max 100) | No
| q | string | Search query using GitHub users search syntax | Yes
| sort | string | Sort field by category | No
</details>
<details>
<summary>submit_pending_pull_request_review</summary>

**Description**:

```
Submit the requester's latest pending pull request review, normally this is a final step after creating a pending review, adding comments first, unless you know that the user already did the first two steps, you should check before calling this.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | The text of the review comment | No
| event | string | The event to perform | Yes
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>
<details>
<summary>update_issue</summary>

**Description**:

```
Update an existing issue in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assignees | array | New assignees | No
| body | string | New description | No
| issue_number | number | Issue number to update | Yes
| labels | array | New labels | No
| milestone | number | New milestone number | No
| owner | string | Repository owner | Yes
| repo | string | Repository name | Yes
| state | string | New state | No
| title | string | New title | No
</details>
<details>
<summary>update_pull_request</summary>

**Description**:

```
Update an existing pull request in a GitHub repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base | string | New base branch name | No
| body | string | New description | No
| maintainer_can_modify | boolean | Allow maintainer edits | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number to update | Yes
| repo | string | Repository name | Yes
| state | string | New state | No
| title | string | New title | No
</details>
<details>
<summary>update_pull_request_branch</summary>

**Description**:

```
Update the branch of a pull request with the latest changes from the base branch.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expectedHeadSha | string | The expected SHA of the pull request's HEAD ref | No
| owner | string | Repository owner | Yes
| pullNumber | number | Pull request number | Yes
| repo | string | Repository name | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_issue_comment | description | a3210a0db80b6830285c353a98c4e7ae99af2fdce86c8bb0fc17a47dae866043 |
| tools | add_issue_comment | body | 76196e088940dc7627854dccef8d659636b54a66ba71c85512d65beb0131a5a8 |
| tools | add_issue_comment | issue_number | 55508553706f381501225c1367bc7f12548ab08da5ce677d10875fb316ee3ce4 |
| tools | add_issue_comment | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | add_issue_comment | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | add_pull_request_review_comment_to_pending_review | description | 539c30ff7a06d5bca9d3fb808257ce3619326f2b0c58c96aff0095430a7d5883 |
| tools | add_pull_request_review_comment_to_pending_review | body | 150bf72e1256c35c56d58cce6912ae25bb0a02e2a048a422297a7eead2024635 |
| tools | add_pull_request_review_comment_to_pending_review | line | 819e79a56ebb1ecd61715def06ef3dda6306d32677da2d9c797a17ea0c2fe4bc |
| tools | add_pull_request_review_comment_to_pending_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | add_pull_request_review_comment_to_pending_review | path | ad65a27b6cdd3e833939b5c162ff0e5e105a2a0d8120a83907c1c286c6ce1c6b |
| tools | add_pull_request_review_comment_to_pending_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | add_pull_request_review_comment_to_pending_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | add_pull_request_review_comment_to_pending_review | side | a8c682b21f75d5200a487c37af5d312ed2fe67abca69116aa93eb2a7ae228b5c |
| tools | add_pull_request_review_comment_to_pending_review | startLine | 19184c9e73d4d7fbb9661702c5af2054059047e4b6cfc56b0e66f31fe3c2ba16 |
| tools | add_pull_request_review_comment_to_pending_review | startSide | 6a4676ef00a54ce3692d9292bdd8dea138dceffd9d3a2bd7af22f2b776395448 |
| tools | add_pull_request_review_comment_to_pending_review | subjectType | 12fc508ce13c1c2a9607f35cb7add1b0335cddf96c243530df7db80cab254182 |
| tools | assign_copilot_to_issue | description | d9f189d6cd4dc4e14f648c16825a32209ecb55bc1528e8d7a5c5d47a936312f3 |
| tools | assign_copilot_to_issue | issueNumber | b90458b6339c0e14f5cea20207035c8a316ca33c0fda5d372ab8c4fc51fdb075 |
| tools | assign_copilot_to_issue | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | assign_copilot_to_issue | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_and_submit_pull_request_review | description | b65276bcbe2570c4078cdcdd9f341cd364e5d420264d94d7c95df01c6feb0040 |
| tools | create_and_submit_pull_request_review | body | 305435be37ca49348dd59f76ed78d1d3db653263c87268f19e38edd8e9903f8a |
| tools | create_and_submit_pull_request_review | commitID | 8edaee0cc39481736353ab6b261838e08ea25f5a48ff2235247349671fd2d092 |
| tools | create_and_submit_pull_request_review | event | 91cce26ef9317542f329d7df06c21c3f7640f53bac235489e5537867c87b579e |
| tools | create_and_submit_pull_request_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_and_submit_pull_request_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | create_and_submit_pull_request_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_branch | description | 178c4aa2cad9c4dec2d6883eb0913ba5385f367e681e9d97cb751a2eb0983645 |
| tools | create_branch | branch | 23431660a4982622d8107024b732941aab6327a832c6715c57299e716e175d88 |
| tools | create_branch | from_branch | 5fa655e2e4b9da16f3de9e22d4d842abb6226464a2e91758242eacc4fec42dc9 |
| tools | create_branch | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_branch | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_issue | description | b66991fa483e01e4bf1f289c9c542b7c3002e27cc3e80970504a896ae5615160 |
| tools | create_issue | assignees | 4b3bd4c85313c2684d6dcf769e368485947d08818835207a231a61700dc3552b |
| tools | create_issue | body | 16e4f6813850b28daf1d698946455b18a587988665d95175da2e415938a906f7 |
| tools | create_issue | labels | 14ab87d13af5cc4d90c937d8c30258158c0afe9d6cedfb89b4a10d0d057d0397 |
| tools | create_issue | milestone | 87dbe6860309e747c0fc0fc44621cdc1b20e79faaccdd485a4b74c5daa8e333d |
| tools | create_issue | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_issue | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_issue | title | baebb0f722db7150e454ecfb2d432205f6331d57837328637d25ac8413f84644 |
| tools | create_or_update_file | description | 3cd2f9da0ba7a1abf23ebfb28dae1694615fa79bd4b6daadf3cf1774b5fc41f9 |
| tools | create_or_update_file | branch | d6a5e87fe732d76cc378c1d1f1210e9b2deb75c9a0dc93b4e453bd5681e9ebe9 |
| tools | create_or_update_file | content | 651936dc46e2fa051b60ccb3cbfe9f87f0f58f41773e79b4839a814525a7d688 |
| tools | create_or_update_file | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | create_or_update_file | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | create_or_update_file | path | c57e5f48646295c4493f5d052c3ce4d46f88f8c963d162f44c187ff5defa6791 |
| tools | create_or_update_file | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_or_update_file | sha | aedc7ce1b7de89c1f0197052ccff35b4ed4f7836d9d93f2fc154b02d7ed67c75 |
| tools | create_pending_pull_request_review | description | 81133c7429aaf6de4a3c1b39812a0e540bea242f847c4e635915b0fb372a0422 |
| tools | create_pending_pull_request_review | commitID | 8edaee0cc39481736353ab6b261838e08ea25f5a48ff2235247349671fd2d092 |
| tools | create_pending_pull_request_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_pending_pull_request_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | create_pending_pull_request_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_pull_request | description | b3ce1a8e1c8396e567b2df7957109ec2298ca873d8084f9a9c033f39657f3572 |
| tools | create_pull_request | base | 68d3d352a8e9b1b21daef0144ddbd5ebbfdfafa1c150afd9184f2889aeba0f54 |
| tools | create_pull_request | body | 6b20fc28a2739e184ca6e00b2e894ed90a2213780fe67c05664a6917b26e1010 |
| tools | create_pull_request | draft | 13570f145a780449c8841dec203e2f3b37b7ced1b53e0a675553880b30b743db |
| tools | create_pull_request | head | f30a2f6fcdb7af894b1cd42fd17f7651a3e9de4c432a615fe383235d8822d669 |
| tools | create_pull_request | maintainer_can_modify | 4c61cb2daa11e76d1bd1483894ba1f0c8d8430cf9011793815d3cbd017f341ad |
| tools | create_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | create_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_pull_request | title | 878bfb1640ec1cecdf8cab8f3c62f5413e6b4084e0e1a4494df8f65a5a5eebf7 |
| tools | create_repository | description | f44928d7808fe825e9451518452be54abfa32929ece5256d2c96a8c91f7df5d1 |
| tools | create_repository | autoInit | fb659aaef50b97ff2f1d0518139663caef0d38424fc1107a8bf1a0cd7d7a637b |
| tools | create_repository | description | 2b96b72a003b28027236e3a9d7b66958233d752e92381122915202c3c00f6058 |
| tools | create_repository | name | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | create_repository | private | d2180d4e67c48806764e44a9533344b63b6c05db56d6974818cb393c38e666e1 |
| tools | delete_file | description | a6706184f6656f1e0a1d8b6322d2c1c18bb3672a97cd2ac5bf71b0daf99e8900 |
| tools | delete_file | branch | eed2c3cf92bd302596d7dd8c0d052f667e6d9d3e5debc46913ff50de8c370a59 |
| tools | delete_file | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | delete_file | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | delete_file | path | d4e57b1045d6bdf511b312f8574c99772b8c03cc0528da2604ebc5f7d6daa335 |
| tools | delete_file | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | delete_pending_pull_request_review | description | a98af500cdc7ac540520f6a1927d0b9aec9d47abc7d7fca32cbcfc0d4c8e3968 |
| tools | delete_pending_pull_request_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | delete_pending_pull_request_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | delete_pending_pull_request_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | dismiss_notification | description | 72806460489c61ba45e9f10a43ff5b5f5cf5d43155b64b4d192cffe3979c0305 |
| tools | dismiss_notification | state | 80c2b70a2d60321a56fcd4a56d6f2118f18ff42da296406b28f49283ae40d5e5 |
| tools | dismiss_notification | threadID | 962f9d0f9e05ca7be087c4469fa646fa0736953d173654910e94a0d5f817a1c2 |
| tools | fork_repository | description | b9c81712c56e48175df559052b73f7e28646208f961b6b61c3ac3f3545eef86f |
| tools | fork_repository | organization | 715d8a3a0d64573efa8d492a5ac06ccf88e4ecb1db7a7b6cb0d30ee9369e6ccb |
| tools | fork_repository | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | fork_repository | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_code_scanning_alert | description | c9355e6046bba99a24d2d56a7b7ae04bd213029c8921890e6a080b11cf924a17 |
| tools | get_code_scanning_alert | alertNumber | 1cf32d483c0692dad2135b6c2188b130c24fe94e4b770e95250652466e365605 |
| tools | get_code_scanning_alert | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | get_code_scanning_alert | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | get_commit | description | a27095bf05dc570a18bf4f6db26662c8dd39f2997f914127c59e8ecf906bf30f |
| tools | get_commit | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_commit | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | get_commit | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | get_commit | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_commit | sha | dcf39de8e2207559c31e5f4576561e8e569c991a889b697d8db7a3460924b445 |
| tools | get_file_contents | description | 54de6216aa12cd8da08e335b6955e2261b4241359f184959829407d0e40dcdc0 |
| tools | get_file_contents | branch | 845c6e38397f1251842f78808bd433f2656d160a31e29109bae6088fba5037b4 |
| tools | get_file_contents | owner | 637f8af6d00297f7764a512ae2421160b429cfc1592dcf476db18f1f2d9521b6 |
| tools | get_file_contents | path | 7feb0806ae965d2a00bf345a3f17897e9547100bfbb88544cce35312e9b9f27e |
| tools | get_file_contents | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_issue | description | e0739745fb9853ee88c1f23196a40765b25dd4c425d93132efddc0975e66e049 |
| tools | get_issue | issue_number | 792880d24307a7c2e3ccb34d164888a960335024892f6faa8729fe06657409fe |
| tools | get_issue | owner | ee38b59dccfd5b3c8d391330a1f61654141c77f7a3bfcd3da617d6f32f3fba55 |
| tools | get_issue | repo | 707cdfc2a1225dbd1d0ab3c3e9c69aa50df8556f176cfcb822744bef5cee4481 |
| tools | get_issue_comments | description | 53fa0ebd975991416f2920ec6a43587eefe7f81d8c78a331d86ccf3142a3cce8 |
| tools | get_issue_comments | issue_number | b90458b6339c0e14f5cea20207035c8a316ca33c0fda5d372ab8c4fc51fdb075 |
| tools | get_issue_comments | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_issue_comments | page | 05fa2e3b0a10226acb6eb73c76977fe622ae5d2e1c11d1e00ea5e83da9321069 |
| tools | get_issue_comments | per_page | 1da3c6e59c56c4f9ee1b4b0efd181852a0424750dc1dcce569d8a7fab419b678 |
| tools | get_issue_comments | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_me | description | 9f897aa25f945c469a123122a5063c852f2660916835d4f3a310f809b4900c11 |
| tools | get_me | reason | 67773473a042cb954c921a6bb447ad1fe2f4702a37cbebe7e00e88b3c35748b2 |
| tools | get_notification_details | description | ec76845152fc49b3d76ac0087fe8752555ea3631b04d04d6a8d0f153cb0e1176 |
| tools | get_notification_details | notificationID | 2a05833ca06d7a872d98001b3ac22be64ef6cfffa973772867b821b4ed5e421f |
| tools | get_pull_request | description | ee092d1809d130e6bca75b71d2147a78e1d0a20bb08535182b5e7f037eafccb7 |
| tools | get_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_comments | description | 3f4e80a03fad0cc5140e207224f2f5fda157d50a9b0e531016132b1613705dcd |
| tools | get_pull_request_comments | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_comments | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_comments | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_diff | description | 3e6c9aeb744fcfd564c176afe15c2df8ce5dbfa7e034db9cd27704ce49dc4d7f |
| tools | get_pull_request_diff | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_diff | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_diff | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_files | description | b1b26ff4305b4953a717913d7eec40389a6a2505544520107611a86a5a48f29f |
| tools | get_pull_request_files | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_files | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_files | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_reviews | description | 74424c9f5b5f967c46da1d93507e77c35ae6af0f2a5bfdf3cc5258354424d072 |
| tools | get_pull_request_reviews | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_reviews | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_reviews | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_pull_request_status | description | c2fa8b4cf2f1cf0f5fa2464041726dfed49ec56fe494fcba8c7b77e94366afe8 |
| tools | get_pull_request_status | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_pull_request_status | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | get_pull_request_status | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_secret_scanning_alert | description | 0cc5a272aafe264f496df0317c38e5b24c554afbc136cfe98919d2447663e5c3 |
| tools | get_secret_scanning_alert | alertNumber | 1cf32d483c0692dad2135b6c2188b130c24fe94e4b770e95250652466e365605 |
| tools | get_secret_scanning_alert | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | get_secret_scanning_alert | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | get_tag | description | e6d557e07eb01ac88760ac5a62bc68d3b795b61d4d7fa4be36758c0f7ce61eae |
| tools | get_tag | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | get_tag | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | get_tag | tag | 1ace926bc7cdee5323e297d439d2d268286749252b1c7f5e332d5003681d092d |
| tools | list_branches | description | 8ce903bf8c1572fd527fd93f38d7d2ccb9b8d463ffe947100aeb1b8187363840 |
| tools | list_branches | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_branches | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_branches | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_branches | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_code_scanning_alerts | description | 2157c013472c46218c4a0315e1b0ba5e6eb9315cf7065b1f572d0a4c25fd7db7 |
| tools | list_code_scanning_alerts | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | list_code_scanning_alerts | ref | 2b4293ec0232d33ef23f0d89a5a150e1e4e234c5a3dc9a6b4273cd37d25393bc |
| tools | list_code_scanning_alerts | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | list_code_scanning_alerts | severity | 9e8b684d29e88335cb2d708ce5ceca799ddb6094c60e0cb74c691f5f3b5cf2d9 |
| tools | list_code_scanning_alerts | state | 9ddc484fe54a5a6c6c4633c8e012a31307a78cc9a8c11377ea40a724a5b741ed |
| tools | list_code_scanning_alerts | tool_name | 8b7eaf66d0062b14f656ad3c31c6a95a723f743d0094208b0776ead3cbdf5402 |
| tools | list_commits | description | 1c0d03ab4c651faf18fe16b157121151639027341f9e0e708ab106150cb23461 |
| tools | list_commits | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_commits | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_commits | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_commits | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_commits | sha | 1cb4096e4bfb01ccc794b77a3f36efdbd471ec34b3dea0516efaf93c0201f642 |
| tools | list_issues | description | 64d775fc37887031520551399de4ef46513ad48a6624e52910b5f322c904f5c1 |
| tools | list_issues | direction | 29c8371d927b118d8d71544c8c8d336f340b0fe893a48faa5a746880f578f373 |
| tools | list_issues | labels | cd8837d9c837a6e1991502a822f57a44fc95a741eeece870f890f82c275c16a3 |
| tools | list_issues | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_issues | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_issues | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_issues | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_issues | since | ea0dd87c74f5845692af7bc86972f1f210d984342fb26602fe35c0c04a3a49cd |
| tools | list_issues | sort | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | list_issues | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | list_notifications | description | d10e656b1bf56afd6198d99dfbacab9b89240e71050cb766e6fc4e1952e4cc1c |
| tools | list_notifications | before | 8f3368c0cc20a07762d9ec5aedc6d3372c203d23d6a2e02c83941d4635cdf22d |
| tools | list_notifications | filter | 6cff8ccd8331867367670666112d79969f23f7f39a92b0c292e4e24b1ec745ef |
| tools | list_notifications | owner | 8e2cb4e3bf5d60a3aaac76a355e6de92a51d40a991243707ff5f7d8bae965ec0 |
| tools | list_notifications | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_notifications | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_notifications | repo | dca9d8fa52d40f94ac6413179eca8f64af79142cc78de65050c1e7c6931a5a65 |
| tools | list_notifications | since | 2ec0b5bca09cc7fd1a3925f6fc0d35407e6bc1e95afcefeb3ed6f2eb0e5cf9c9 |
| tools | list_pull_requests | description | f26161311922a22f509a5758def0b5736e9d57dab5a64de85cd6943ac3323cf9 |
| tools | list_pull_requests | base | 3915eefd074b833c42fa1a78466ff3667210bb7cd9e867bce531f6d69b6b25f1 |
| tools | list_pull_requests | direction | 29c8371d927b118d8d71544c8c8d336f340b0fe893a48faa5a746880f578f373 |
| tools | list_pull_requests | head | dc15fecf43097ca55e53fff94ae252ac6f7a0325fa37efb0ba854276c2eea920 |
| tools | list_pull_requests | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_pull_requests | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_pull_requests | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_pull_requests | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | list_pull_requests | sort | c9129025bd3ff6522a7eeebc1abf1481f36e4ac9d74524a473ac1c3be1c6fc2f |
| tools | list_pull_requests | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | list_secret_scanning_alerts | description | 3894671d369d1afd5626bc7a85fd304dc23c40e42ac99eab42ef7472f50cf231 |
| tools | list_secret_scanning_alerts | owner | 59efffac3bd8dd345c342df96df6e2a727f7c1d2483903c6bfb261acf946d96e |
| tools | list_secret_scanning_alerts | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | list_secret_scanning_alerts | resolution | 43f25b84021219ca1dc81d938db1e65ba764b7c84b208724d8f426c9ab2f1004 |
| tools | list_secret_scanning_alerts | secret_type | d92ec333a3e61d232bf74066b54f328522d20f590d20ef126cffdcc1af676e21 |
| tools | list_secret_scanning_alerts | state | 2b25d08228e3152d0b529fbf269381f1f000c2adf30f1186b7e9ac7eb2cba425 |
| tools | list_tags | description | b45b57651e9a56b5d03befc9edb790d1c1d92742cc6e1cd9d56f6b41fc3dca92 |
| tools | list_tags | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | list_tags | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | list_tags | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | list_tags | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | manage_notification_subscription | description | be32b04a7ce2d90c4cf1ba0bfe8674b5eeed86fdac39522df6afe856d12b0a06 |
| tools | manage_notification_subscription | action | 87165d54f132e25027bff709b19d191159dd029cf91fa180622a068a711468fd |
| tools | manage_notification_subscription | notificationID | 621468ca2aa0eb1aa72bca26d3013ae8c4d200a6e66c5acf1f19e14ea5cd6452 |
| tools | manage_repository_notification_subscription | description | 97e8f7279d5f6b8b031b73e5ecc55d093571b3eb9d4e244a65bc9acd31e907a1 |
| tools | manage_repository_notification_subscription | action | ef0feed55d6ab9d2fc3a525a0fd662f1171691fcb8117f898df7290d1262a84f |
| tools | manage_repository_notification_subscription | owner | dbf176c46bfb0ed84c9b81bea412da323f5912c25c9f54639916cd97e696f291 |
| tools | manage_repository_notification_subscription | repo | 077296c2d63a8df1f5032955887382a08bef79c0c8c9d5d5470ecb09dc10bb45 |
| tools | mark_all_notifications_read | description | 87e6c2a922e258ce8d6383d847f1cb480037d95d9baa6d366cf10fbca63a4c0b |
| tools | mark_all_notifications_read | lastReadAt | 5d6a1f0fd2976b4afa70352c96bbca354414a3e178d571da71a713fabbcd33ff |
| tools | mark_all_notifications_read | owner | c9850214816046dfdfca79df5569362340c4017116b2277684c90884b342c894 |
| tools | mark_all_notifications_read | repo | 91e6d20fc5b1f0b5e86911e5662348e757761b7e3e0f9ea3739cb1a37ba09304 |
| tools | merge_pull_request | description | 124cd641ce348386107609b1831084962d2198fa82fe58f7a040dd7e1cebb6b4 |
| tools | merge_pull_request | commit_message | 8b3fd7f52419bc6922db1546614fcd15e214033be38066ff4cd1cbb841ba27ce |
| tools | merge_pull_request | commit_title | df303c95cc0cb2a4ceb92b29c47c9b965ec484d53b5fee6add5c9189e2f96342 |
| tools | merge_pull_request | merge_method | 889b19c3b7a37b0d3249fd662f04c6cdc914c42bfc45d642c5d74946ca8837db |
| tools | merge_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | merge_pull_request | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | merge_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | push_files | description | 0ea99ad23e44e739ed503658bdaab5ee2dc239246cb00e715d8fff3d80fe544f |
| tools | push_files | branch | 903fd236be715d2d2dabe8871e567bebdb55a876b1f9b4db0c49400e3b944e01 |
| tools | push_files | files | 1c55ce034da38092a4c35795368bf7da13897eb6ab576f0539b22e02cda877a0 |
| tools | push_files | message | 26306d203c4a6f1a77f32cd065d7d11593ba0c7a9b5c52c188b98f22b620941f |
| tools | push_files | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | push_files | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | request_copilot_review | description | 0a31c498daefdb4310ae1335e16496ed8d238d01ebf12c04d45a1b215e4c7de3 |
| tools | request_copilot_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | request_copilot_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | request_copilot_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | search_code | description | c47330f5060c9cac8a1867a95cd93c42ab1e6e3b5e6aa7e7dd8b1dec1a8d1e79 |
| tools | search_code | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_code | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_code | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_code | q | f28bd330504534bb418432cb9ed5d2710fd6ab8ce3ad1a15eef949522f7be10e |
| tools | search_code | sort | 5a8b728c15aab0284ebfeb9dfb94debf67e55d178d8bf7c3b660fe36ef92855f |
| tools | search_issues | description | 6c9613cebddafe9b57cfdbaf8cc66801954610fad9e51918ff4b014f1721bfe3 |
| tools | search_issues | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_issues | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_issues | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_issues | q | ba2ce5263245f1c7beda19f750b937dee26e69df9b0773c5ee3902142e81e3ee |
| tools | search_issues | sort | 45f652334776f448a204bdd17cb144e1d6a7b0bf6e6746e677874ad01432470d |
| tools | search_repositories | description | adf4a039f4409fab912a621c93aea801631f04db16e035808e7bab8e0f67aa82 |
| tools | search_repositories | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_repositories | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_repositories | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | search_users | description | 89d1a69aba0bca0b320f01ef132c9a72005ebefc054b69a0d01e035ed188a61e |
| tools | search_users | order | 3c9b30285f90cf05528b2502044ec5c2b125b6c1885be9af8aeff0ba722fffbb |
| tools | search_users | page | b7c5240244916494e69b93a6fc0ad57b364a457e44ef68ed22739cb55ffb1359 |
| tools | search_users | perPage | 059dde8a01aac1a755c9e5efbbfaccb57fa34c3988494a154c873dfa7779a1d7 |
| tools | search_users | q | 411fdded1833c9660c80d3528c9fe3117d7fc0efd34b8f6756fd7dd82b6b16fd |
| tools | search_users | sort | 7b4f03e0b12896994cd874649134fe440d505ae1eafaa19f7f330a8b2fa4b055 |
| tools | submit_pending_pull_request_review | description | 61929abd9c3ecaf274c5ecabcf310474f023dc63a93f029ffb624704bf789061 |
| tools | submit_pending_pull_request_review | body | 150bf72e1256c35c56d58cce6912ae25bb0a02e2a048a422297a7eead2024635 |
| tools | submit_pending_pull_request_review | event | 9cebe2efbb82f53c7afe8547fddd42a8324b996564d9b38efc390d1d028e07cf |
| tools | submit_pending_pull_request_review | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | submit_pending_pull_request_review | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | submit_pending_pull_request_review | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | update_issue | description | 84a37c5e28746e6ff6c9ec1063d35d03b623e2124107697514916fcd04dd54ea |
| tools | update_issue | assignees | 09ed592a172e1fab692d52395b578ddb80014f1348ab79b3685483856aecfbef |
| tools | update_issue | body | 23b7ce65508de7bbfb013fd25a384491f896e839f62116c96813ec6f53945e98 |
| tools | update_issue | issue_number | 45f54a035e52ddd24bd931710aed635cc2d5a202ba687d0708c618fe76095437 |
| tools | update_issue | labels | d5304eef496f551a4ae71c2345ef665475ae22c93b4c8b3fc7043385e0011194 |
| tools | update_issue | milestone | e503beb4738eefdedd535449eb967367e51888787a8c6d246206e94de8fdc60d |
| tools | update_issue | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_issue | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | update_issue | state | 73d2abfb99c5146711a52488e33aa097ebd94cc1f1d14a0e21e9a6ed88709818 |
| tools | update_issue | title | 522156b9b0af7eb99063569c92036931a3c9f027728ac6de8a70bcd0a1d3721c |
| tools | update_pull_request | description | bed4d74cfd86d23ab02749d6b4fffa5ba43c3290bfa7c9810514cf821e0563eb |
| tools | update_pull_request | base | 33cd739abf299499afc569d0b3bf88e53d9833841bb0af1c9e7c3a61c827991a |
| tools | update_pull_request | body | 23b7ce65508de7bbfb013fd25a384491f896e839f62116c96813ec6f53945e98 |
| tools | update_pull_request | maintainer_can_modify | 4c61cb2daa11e76d1bd1483894ba1f0c8d8430cf9011793815d3cbd017f341ad |
| tools | update_pull_request | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_pull_request | pullNumber | 4f4b068a5c13d2a2547b7a13655111963fd97b583156f8cea0fd62c4a16f7375 |
| tools | update_pull_request | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |
| tools | update_pull_request | state | 73d2abfb99c5146711a52488e33aa097ebd94cc1f1d14a0e21e9a6ed88709818 |
| tools | update_pull_request | title | 522156b9b0af7eb99063569c92036931a3c9f027728ac6de8a70bcd0a1d3721c |
| tools | update_pull_request_branch | description | bb1dacdad1b56b12c6b26f7833d5b189a7827f66ea3d04917632eed63277d80d |
| tools | update_pull_request_branch | expectedHeadSha | 86e4137627e7ef4e6244395428104ab03f903b5c98f1a4be25279deb54f96c00 |
| tools | update_pull_request_branch | owner | f0d16bda4d13e782383008c51526b15a1d34e639b794b48ce0e4aaa9929b2a4a |
| tools | update_pull_request_branch | pullNumber | c45ef7560e9361e486ad92db8751f01655bdaad2e8375566effb91d07090b338 |
| tools | update_pull_request_branch | repo | a2b1b3f24a4b0370e287023edc5ccf8c9b4d8af69e97a2f698cf3aa6dae8c558 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
