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


# What is mcp-server-circleci?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-circleci/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-circleci/0.9.0?logo=docker&logoColor=fff&label=0.9.0)](https://hub.docker.com/r/acuvity/mcp-server-circleci)
[![PyPI](https://img.shields.io/badge/0.9.0-3775A9?logo=pypi&logoColor=fff&label=@circleci/mcp-server-circleci)](https://github.com/CircleCI-Public/mcp-server-circleci)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-circleci/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-circleci&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-circleci%3A0.9.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Enable AI Agents to fix build failures from CircleCI.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @circleci/mcp-server-circleci original [sources](https://github.com/CircleCI-Public/mcp-server-circleci).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-circleci/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/charts/mcp-server-circleci/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @circleci/mcp-server-circleci run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/CircleCI-Public/mcp-server-circleci) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @circleci/mcp-server-circleci ](https://github.com/CircleCI-Public/mcp-server-circleci)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @circleci/mcp-server-circleci ](https://github.com/CircleCI-Public/mcp-server-circleci)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/charts/mcp-server-circleci)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-circleci/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.9.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-circleci:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-circleci:1.0.0-0.9.0`

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
  - `CIRCLECI_TOKEN=""` environment variable can be changed with `env.CIRCLECI_TOKEN=""`
  - `CIRCLECI_BASE_URL="https://circleci.com"` environment variable can be changed with `env.CIRCLECI_BASE_URL="https://circleci.com"`

# How to install


Install will helm

```console
helm install mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-circleci
```

From there your MCP server mcp-server-circleci will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-circleci` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-circleci
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-circleci` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-circleci oci://docker.io/acuvity/mcp-server-circleci --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (11)
<details>
<summary>get_build_failure_logs</summary>

**Description**:

```

    This tool helps debug CircleCI build failures by retrieving failure logs.

    CRITICAL REQUIREMENTS:
    1. Truncation Handling (HIGHEST PRIORITY):
       - ALWAYS check for <MCPTruncationWarning> in the output
       - When present, you MUST start your response with:
         "WARNING: The logs have been truncated. Only showing the most recent entries. Earlier build failures may not be visible."
       - Only proceed with log analysis after acknowledging the truncation

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL: https://app.circleci.com/pipelines/gh/organization/project
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Legacy Job URL: https://circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch
    
    Recommended Workflow:
    1. Use listFollowedProjects tool to get a list of projects
    2. Extract the projectSlug from the chosen project (format: "gh/organization/project")
    3. Use that projectSlug with a branch name for this tool

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>find_flaky_tests</summary>

**Description**:

```

    This tool retrieves information about flaky tests in a CircleCI project. 
    
    The agent receiving this output MUST analyze the flaky test data and implement appropriate fixes based on the specific issues identified.

    CRITICAL REQUIREMENTS:
    1. Truncation Handling (HIGHEST PRIORITY):
       - ALWAYS check for <MCPTruncationWarning> in the output
       - When present, you MUST start your response with:
         "WARNING: The logs have been truncated. Only showing the most recent entries. Earlier build failures may not be visible."
       - Only proceed with log analysis after acknowledging the truncation

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug:
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL: https://app.circleci.com/pipelines/gh/organization/project
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, BOTH parameters (workspaceRoot, gitRemoteURL) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>get_latest_pipeline_status</summary>

**Description**:

```

    This tool retrieves the status of the latest pipeline for a CircleCI project. It can be used to check pipeline status, get latest build status, or view current pipeline state.

    Common use cases:
    - Check latest pipeline status
    - Get current build status
    - View pipeline state
    - Check build progress
    - Get pipeline information

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL: https://app.circleci.com/pipelines/gh/organization/project
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz
      * Legacy Job URL: https://circleci.com/gh/organization/project/123

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch
    
    Recommended Workflow:
    1. Use listFollowedProjects tool to get a list of projects
    2. Extract the projectSlug from the chosen project (format: "gh/organization/project")
    3. Use that projectSlug with a branch name for this tool

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>get_job_test_results</summary>

**Description**:

```

    This tool retrieves test metadata for a CircleCI job.

    PRIORITY USE CASE:
    - When asked "are tests passing in CI?" or similar questions about test status
    - When asked to "fix failed tests in CI" or help with CI test failures
    - Use this tool to check if tests are passing in CircleCI and identify failed tests
    
    Common use cases:
    - Get test metadata for a specific job
    - Get test metadata for all jobs in a project
    - Get test metadata for a specific branch
    - Get test metadata for a specific pipeline
    - Get test metadata for a specific workflow
    - Get test metadata for a specific job

    CRITICAL REQUIREMENTS:
    1. Truncation Handling (HIGHEST PRIORITY):
       - ALWAYS check for <MCPTruncationWarning> in the output
       - When present, you MUST start your response with:
         "WARNING: The test results have been truncated. Only showing the most recent entries. Some test data may not be visible."
       - Only proceed with test result analysis after acknowledging the truncation

    2. Test Result Filtering:
       - Use filterByTestsResult parameter to filter test results:
         * filterByTestsResult: 'failure' - Show only failed tests
         * filterByTestsResult: 'success' - Show only successful tests
       - When looking for failed tests, ALWAYS set filterByTestsResult to 'failure'
       - When checking if tests are passing, set filterByTestsResult to 'success'

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI job in any of these formats:
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/789
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch
    
    For simple test status checks (e.g., "are tests passing in CI?") or fixing failed tests, prefer Option 1 with a recent pipeline URL if available.

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects and include the branch parameter
    - If using Option 2, the URL MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>config_helper</summary>

**Description**:

```

  This tool helps analyze and validate and fix CircleCI configuration files.

  Parameters:
  - params: An object containing:
    - configFile: string - The full contents of the CircleCI config file as a string. This should be the raw YAML content, not a file path.

  Example usage:
  {
    "params": {
      "configFile": "version: 2.1
orbs:
  node: circleci/node@7
..."
    }
  }

  Note: The configFile content should be provided as a properly escaped string with newlines represented as 
.

  Tool output instructions:
    - If the config is invalid, the tool will return the errors and the original config. Use the errors to fix the config.
    - If the config is valid, do nothing.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>create_prompt_template</summary>

**Description**:

```

  ABOUT THIS TOOL:
  - This tool is part of a toolchain that generates and provides test cases for a prompt template.
  - This tool helps an AI assistant to generate a prompt template based on one of the following:
    1. feature requirements defined by a user - in which case the tool will generate a new prompt template based on the feature requirements.
    2. a pre-existing prompt or prompt template that a user wants to test, evaluate, or modify - in which case the tool will convert it into a more structured and testable prompt template while leaving the original prompt language relatively unchanged.
  - This tool will return a structured prompt template (e.g. `template`) along with a context schema (e.g. ``contextSchema``) that defines the expected input parameters for the prompt template.
  - In some cases, a user will want to add test coverage for ALL of the prompts in a given application. In these cases, the AI agent should use this tool to generate a prompt template for each prompt in the application, and should check the entire application for AI prompts that are not already covered by a prompt template in the `./prompts` directory.

  WHEN SHOULD THIS TOOL BE TRIGGERED?
  - This tool should be triggered whenever the user provides requirements for a new AI-enabled application or a new AI-enabled feature of an existing  application (i.e. one that requires a prompt request to an LLM or any AI model).
  - This tool should also be triggered if the user provides a pre-existing prompt or prompt template from their codebase that they want to test, evaluate, or modify.
  - This tool should be triggered even if there are pre-existing files in the `./prompts` directory with the `<relevant-name>.prompt.yml` convention (e.g. `bedtime-story-generator.prompt.yml`, `plant-care-assistant.prompt.yml`, `customer-support-chatbot.prompt.yml`, etc.). Similar files should NEVER be generated directly by the AI agent. Instead, the AI agent should use this tool to first generate a new prompt template.

  PARAMETERS:
  - params: object
    - prompt: string (the feature requirements or pre-existing prompt/prompt template that will be used to generate a prompt template. Can be a multi-line string.)
    - promptOrigin: "codebase" | "requirements" (indicates whether the prompt comes from an existing codebase or from new requirements)
    - model: string (the model that the prompt template will be tested against. Explicitly specify the model if it can be inferred from the codebase. Otherwise, defaults to `gpt-4o-mini`.)

  EXAMPLE USAGE (from new requirements):
  {
    "params": {
      "prompt": "Create an app that takes any topic and an age (in years), then renders a 1-minute bedtime story for a person of that age.",
      "promptOrigin": "requirements"
      "model": "gpt-4o-mini"
    }
  }

  EXAMPLE USAGE (from pre-existing prompt/prompt template in codebase):
  {
    "params": {
      "prompt": "The user wants a bedtime story about {{topic}} for a person of age {{age}} years old. Please craft a captivating tale that captivates their imagination and provides a delightful bedtime experience.",
      "promptOrigin": "codebase"
      "model": "claude-3-5-sonnet-latest"
    }
  }

  TOOL OUTPUT INSTRUCTIONS:
  - The tool will return...
    - a `template` that reformulates the user's prompt into a more structured format.
    - a ``contextSchema`` that defines the expected input parameters for the template.
    - a `promptOrigin` that indicates whether the prompt comes from an existing prompt or prompt template in the user's codebase or from new requirements.
  - The tool output -- the `template`, ``contextSchema``, and `promptOrigin` -- will also be used as input to the `recommend_prompt_template_tests` tool to generate a list of recommended tests that can be used to test the prompt template.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>recommend_prompt_template_tests</summary>

**Description**:

```

  About this tool:
  - This tool is part of a toolchain that generates and provides test cases for a prompt template.
  - This tool generates an array of recommended tests for a given prompt template.

  Parameters:
  - params: object
    - promptTemplate: string (the prompt template to be tested)
    - contextSchema: object (the context schema that defines the expected input parameters for the prompt template)
    - promptOrigin: "codebase" | "requirements" (indicates whether the prompt comes from an existing codebase or from new requirements)
    - model: string (the model that the prompt template will be tested against)
    
  Example usage:
  {
    "params": {
      "promptTemplate": "The user wants a bedtime story about {{topic}} for a person of age {{age}} years old. Please craft a captivating tale that captivates their imagination and provides a delightful bedtime experience.",
      "contextSchema": {
        "topic": "string",
        "age": "number"
      },
      "promptOrigin": "codebase"
    }
  }

  The tool will return a structured array of test cases that can be used to test the prompt template.

  Tool output instructions:
    - The tool will return a `recommendedTests` array that can be used to test the prompt template.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>run_pipeline</summary>

**Description**:

```

    This tool triggers a new CircleCI pipeline and returns the URL to monitor its progress.

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL with branch: https://app.circleci.com/pipelines/gh/organization/project?branch=feature-branch
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch

    Configuration:
    - an optional configContent parameter can be provided to override the default pipeline configuration

    Pipeline Selection:
    - If the project has multiple pipeline definitions, the tool will return a list of available pipelines
    - You must then make another call with the chosen pipeline name using the pipelineChoiceName parameter
    - The pipelineChoiceName must exactly match one of the pipeline names returned by the tool
    - If the project has only one pipeline definition, pipelineChoiceName is not needed

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call

    Returns:
    - A URL to the newly triggered pipeline that can be used to monitor its progress
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>list_followed_projects</summary>

**Description**:

```

    This tool lists all projects that the user is following on CircleCI.
    
    Common use cases:
    - Identify which CircleCI projects are available to the user
    - Select a project for subsequent operations
    - Obtain the projectSlug needed for other CircleCI tools
    
    Returns:
    - A list of projects that the user is following on CircleCI
    - Each entry includes the project name and its projectSlug
    
    Workflow:
    1. Run this tool to see available projects
    2. User selects a project from the list
    3. The LLM should extract and use the projectSlug (not the project name) from the selected project for subsequent tool calls
    4. The projectSlug is required for many other CircleCI tools, and will be used for those tool calls after a project is selected
    
    Note: If pagination limits are reached, the tool will indicate that not all projects could be displayed.
    
    IMPORTANT: Do not automatically run any additional tools after this tool is called. Wait for explicit user instruction before executing further tool calls. The LLM MUST NOT invoke any other CircleCI tools until receiving a clear instruction from the user about what to do next, even if the user selects a project. It is acceptable to list out tool call options for the user to choose from, but do not execute them until instructed.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>run_evaluation_tests</summary>

**Description**:

```

    This tool allows the users to run evaluation tests on a circleci pipeline.
    They can be referred to as "Prompt Tests" or "Evaluation Tests".

    This tool triggers a new CircleCI pipeline and returns the URL to monitor its progress.
    The tool will generate an appropriate circleci configuration file and trigger a pipeline using this temporary configuration.
    The tool will return the project slug.

    Input options (EXACTLY ONE of these THREE options must be used):

    Option 1 - Project Slug and branch (BOTH required):
    - projectSlug: The project slug obtained from listFollowedProjects tool (e.g., "gh/organization/project")
    - branch: The name of the branch (required when using projectSlug)

    Option 2 - Direct URL (provide ONE of these):
    - projectURL: The URL of the CircleCI project in any of these formats:
      * Project URL with branch: https://app.circleci.com/pipelines/gh/organization/project?branch=feature-branch
      * Pipeline URL: https://app.circleci.com/pipelines/gh/organization/project/123
      * Workflow URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def
      * Job URL: https://app.circleci.com/pipelines/gh/organization/project/123/workflows/abc-def/jobs/xyz

    Option 3 - Project Detection (ALL of these must be provided together):
    - workspaceRoot: The absolute path to the workspace root
    - gitRemoteURL: The URL of the git remote repository
    - branch: The name of the current branch

    Test Files:
    - promptFiles: Array of prompt template file objects from the ./prompts directory, each containing:
      * fileName: The name of the prompt template file
      * fileContent: The contents of the prompt template file

    Pipeline Selection:
    - If the project has multiple pipeline definitions, the tool will return a list of available pipelines
    - You must then make another call with the chosen pipeline name using the pipelineChoiceName parameter
    - The pipelineChoiceName must exactly match one of the pipeline names returned by the tool
    - If the project has only one pipeline definition, pipelineChoiceName is not needed

    Additional Requirements:
    - Never call this tool with incomplete parameters
    - If using Option 1, make sure to extract the projectSlug exactly as provided by listFollowedProjects
    - If using Option 2, the URLs MUST be provided by the user - do not attempt to construct or guess URLs
    - If using Option 3, ALL THREE parameters (workspaceRoot, gitRemoteURL, branch) must be provided
    - If none of the options can be fully satisfied, ask the user for the missing information before making the tool call

    Returns:
    - A URL to the newly triggered pipeline that can be used to monitor its progress
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>
<details>
<summary>rerun_workflow</summary>

**Description**:

```

  This tool is used to rerun a workflow from start or from the failed job.

  Common use cases:
  - Rerun a workflow from a failed job
  - Rerun a workflow from start

Input options (EXACTLY ONE of these TWO options must be used):

Option 1 - Workflow ID:
- workflowId: The ID of the workflow to rerun
- fromFailed: true to rerun from failed, false to rerun from start. If omitted, behavior is based on workflow status. (optional)

Option 2 - Workflow URL:
- workflowURL: The URL of the workflow to rerun
  * Workflow URL: https://app.circleci.com/pipelines/:vcsType/:orgName/:projectName/:pipelineNumber/workflows/:workflowId
  * Workflow Job URL: https://app.circleci.com/pipelines/:vcsType/:orgName/:projectName/:pipelineNumber/workflows/:workflowId/jobs/:buildNumber
- fromFailed: true to rerun from failed, false to rerun from start. If omitted, behavior is based on workflow status. (optional)
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| params | object | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | config_helper | description | f02dd33f38a3495a590d901debe94a7d61f55b1c13aa49695ea04495280a6a81 |
| tools | create_prompt_template | description | 1a0d5f49ed5ef89ab02439a0fc88d97c2623bd19082b8b8f307f513ba759313f |
| tools | find_flaky_tests | description | d7791ab55054527245f4201e3f3e852a2260aabb35703b49b88f617f585ce931 |
| tools | get_build_failure_logs | description | 0a53cd10b05b19c22e09353276900b0eac42fae325a0a17f0404a38eb917a3da |
| tools | get_job_test_results | description | f193e7ccd1d8695d7c7b830f6ad58ec602a544b679c1309bc6d19a7ec9d61b72 |
| tools | get_latest_pipeline_status | description | 63b01e12f1d869921e612fd53bc8f010312aeec0af67a2a9fad71a73114bdb49 |
| tools | list_followed_projects | description | 505f69b885e2acbd4c3210dd5d405128bef0b85673ecbe797674ecb358410533 |
| tools | recommend_prompt_template_tests | description | 7481bf74eda856271b8b6ae88d71d8aa8a64f031ee83b407c3362332386b1b39 |
| tools | rerun_workflow | description | 37895cf96d7fd2ed226e0aa1e0c5c30652436fae285136016d3a30205bb29ee8 |
| tools | run_evaluation_tests | description | f9b65c47dc2ab687a5d6e567fc28177ae5f5ca552f74a3cf1c30e68a761e0082 |
| tools | run_pipeline | description | 27592345c42aec34546ce5d145ceab8ee313d902276bfea3d357ebd3c88126ae |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
