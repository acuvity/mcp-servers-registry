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


# What is mcp-server-bitrise?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-bitrise/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-bitrise/v1.1.0?logo=docker&logoColor=fff&label=v1.1.0)](https://hub.docker.com/r/acuvity/mcp-server-bitrise)
[![GitHUB](https://img.shields.io/badge/v1.1.0-3775A9?logo=github&logoColor=fff&label=bitrise-io/bitrise-mcp)](https://github.com/bitrise-io/bitrise-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-bitrise/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bitrise&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BITRISE_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-bitrise%3Av1.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Chat with your builds, CI, and more via the Bitrise API.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from bitrise-io/bitrise-mcp original [sources](https://github.com/bitrise-io/bitrise-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-bitrise/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrise/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrise/charts/mcp-server-bitrise/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure bitrise-io/bitrise-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrise/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ bitrise-io ](https://github.com/bitrise-io/bitrise-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ bitrise-io/bitrise-mcp ](https://github.com/bitrise-io/bitrise-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ bitrise-io/bitrise-mcp ](https://github.com/bitrise-io/bitrise-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrise/charts/mcp-server-bitrise)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bitrise/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-v1.1.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-bitrise:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-bitrise:1.0.0-v1.1.0`

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
  - `BITRISE_TOKEN` secret to be set as secrets.BITRISE_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-bitrise oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-bitrise oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-bitrise
```

From there your MCP server mcp-server-bitrise will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-bitrise` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-bitrise
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-bitrise` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-bitrise oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-bitrise oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-bitrise oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-bitrise oci://docker.io/acuvity/mcp-server-bitrise --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (56)
<details>
<summary>list_apps</summary>

**Description**:

```
List all the apps available for the authenticated account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Max number of elements per page (default: 50) | No
| next | string | Slug of the first app in the response | No
| sort_by | string | Order of the apps: last_build_at (default) or created_at. If set, you should accept the response as sorted. | No
</details>
<details>
<summary>register_app</summary>

**Description**:

```
Add a new app to Bitrise. After this app should be finished on order to be registered completely on Bitrise (via the finish_bitrise_app tool). Before doing this step, try understanding the repository details from the repository URL. This is a two-step process. First, you register the app with the Bitrise API, and then you finish the setup. The first step creates a new app in Bitrise, and the second step configures it with the necessary settings. If the user has multiple workspaces, always prompt the user to choose which one you should use. Don't prompt the user for finishing the app, just do it automatically.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| is_public | boolean | Whether the app's builds visibility is "public" | Yes
| organization_slug | string | The organization (aka workspace) the app to add to | Yes
| project_type | string | Type of project (ios, android, etc.) | No
| provider | string | Repository provider | No
| repo_url | string | Repository URL | Yes
</details>
<details>
<summary>finish_bitrise_app</summary>

**Description**:

```
Finish the setup of a Bitrise app. If this is successful, a build can be triggered via trigger_bitrise_build. If you have access to the repository, decide the project type, the stack ID, and the config to use, based on https://stacks.bitrise.io/, and the config should be also based on the projec type.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | The slug of the Bitrise app to finish setup for. | Yes
| config | string | The configuration to use for the app (default is "default-android-config", other valid values are "other-config", "default-ios-config", "default-macos-config", etc). | No
| mode | string | The mode of setup. | No
| project_type | string | The type of project (e.g., android, ios, flutter, etc.). | No
| stack_id | string | The stack ID to use for the app. | No
</details>
<details>
<summary>get_app</summary>

**Description**:

```
Get the details of a specific app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>delete_app</summary>

**Description**:

```
Delete an app from Bitrise. When deleting apps belonging to multiple workspaces always confirm that which workspaces' apps the user wants to delete.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>update_app</summary>

**Description**:

```
Update an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| is_public | boolean | Whether the app's builds visibility is "public" | Yes
| project_type | string | Type of project | Yes
| provider | string | Repository provider | Yes
| repo_url | string | Repository URL | Yes
</details>
<details>
<summary>get_bitrise_yml</summary>

**Description**:

```
Get the current Bitrise YML config file of a specified Bitrise app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app (e.g., "d8db74e2675d54c4" or "8eb495d0-f653-4eed-910b-8d6b56cc0ec7") | Yes
</details>
<details>
<summary>update_bitrise_yml</summary>

**Description**:

```
Update the Bitrise YML config file of a specified Bitrise app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app (e.g., "d8db74e2675d54c4" or "8eb495d0-f653-4eed-910b-8d6b56cc0ec7") | Yes
| bitrise_yml_as_json | string | The new Bitrise YML config file content to be updated. It must be a string. | Yes
</details>
<details>
<summary>list_branches</summary>

**Description**:

```
List the branches with existing builds of an app's repository.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>register_ssh_key</summary>

**Description**:

```
Add an SSH-key to a specific app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| auth_ssh_private_key | string | Private SSH key | Yes
| auth_ssh_public_key | string | Public SSH key | Yes
| is_register_key_into_provider_service | boolean | Register the key in the provider service | Yes
</details>
<details>
<summary>register_webhook</summary>

**Description**:

```
Register an incoming webhook for a specific application.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>list_builds</summary>

**Description**:

```
List all the builds of a specified Bitrise app or all accessible builds.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | No
| branch | string | Filter builds by branch | No
| limit | integer | Max number of elements per page (default: 50) | No
| next | string | Slug of the first build in the response | No
| sort_by | string | Order of builds: created_at (default), running_first | No
| status | integer | Filter builds by status (0: not finished, 1: successful, 2: failed, 3: aborted, 4: in-progress) | No
| workflow | string | Filter builds by workflow | No
</details>
<details>
<summary>trigger_bitrise_build</summary>

**Description**:

```
Trigger a new build/pipeline for a specified Bitrise app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app (e.g., "d8db74e2675d54c4" or "8eb495d0-f653-4eed-910b-8d6b56cc0ec7") | Yes
| branch | string | The branch to build | No
| commit_hash | string | The commit hash for the build | No
| commit_message | string | The commit message for the build | No
| workflow_id | string | The workflow to build | No
</details>
<details>
<summary>get_build</summary>

**Description**:

```
Get a specific build of a given app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| build_slug | string | Identifier of the build | Yes
</details>
<details>
<summary>abort_build</summary>

**Description**:

```
Abort a specific build.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| build_slug | string | Identifier of the build | Yes
| reason | string | Reason for aborting the build | No
</details>
<details>
<summary>get_build_log</summary>

**Description**:

```
Get the build log of a specified build of a Bitrise app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app (e.g., "d8db74e2675d54c4" or "8eb495d0-f653-4eed-910b-8d6b56cc0ec7") | Yes
| build_slug | string | Identifier of the Bitrise build | Yes
</details>
<details>
<summary>get_build_bitrise_yml</summary>

**Description**:

```
Get the bitrise.yml of a build.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| build_slug | string | Identifier of the build | Yes
</details>
<details>
<summary>list_build_workflows</summary>

**Description**:

```
List the workflows of an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>list_artifacts</summary>

**Description**:

```
Get a list of all build artifacts.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| build_slug | string | Identifier of the build | Yes
| limit | integer | Max number of elements per page (default: 50) | No
| next | string | Slug of the first artifact in the response | No
</details>
<details>
<summary>get_artifact</summary>

**Description**:

```
Get a specific build artifact.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| artifact_slug | string | Identifier of the artifact | Yes
| build_slug | string | Identifier of the build | Yes
</details>
<details>
<summary>list_outgoing_webhooks</summary>

**Description**:

```
List the outgoing webhooks of an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>list_cache_items</summary>

**Description**:

```
List the key-value cache items belonging to an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>delete_all_cache_items</summary>

**Description**:

```
Delete all key-value cache items belonging to an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>delete_cache_item</summary>

**Description**:

```
Delete a key-value cache item.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| cache_item_id | string | Key of the cache item | Yes
</details>
<details>
<summary>get_cache_item_download_url</summary>

**Description**:

```
Not set, but really should be.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| cache_item_id | string | Key of the cache item | Yes
</details>
<details>
<summary>list_pipelines</summary>

**Description**:

```
List all pipelines and standalone builds of an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
</details>
<details>
<summary>get_pipeline</summary>

**Description**:

```
Get a pipeline of a given app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| pipeline_id | string | Identifier of the pipeline | Yes
</details>
<details>
<summary>abort_pipeline</summary>

**Description**:

```
Abort a pipeline.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| pipeline_id | string | Identifier of the pipeline | Yes
| reason | string | Reason for aborting the pipeline | No
</details>
<details>
<summary>rebuild_pipeline</summary>

**Description**:

```
Rebuild a pipeline.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| pipeline_id | string | Identifier of the pipeline | Yes
</details>
<details>
<summary>list_group_roles</summary>

**Description**:

```
List group roles for an app
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| role_name | string | Name of the role | Yes
</details>
<details>
<summary>replace_group_roles</summary>

**Description**:

```
Replace group roles for an app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_slug | string | Identifier of the Bitrise app | Yes
| group_slugs | array | List of group slugs | Yes
| role_name | string | Name of the role | Yes
</details>
<details>
<summary>list_workspaces</summary>

**Description**:

```
List the workspaces the user has access to
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_workspace</summary>

**Description**:

```
Get details for one workspace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| workspace_slug | string | Slug of the Bitrise workspace | Yes
</details>
<details>
<summary>get_workspace_groups</summary>

**Description**:

```
Get the groups in a workspace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| workspace_slug | string | Slug of the Bitrise workspace | Yes
</details>
<details>
<summary>create_workspace_group</summary>

**Description**:

```
Create a new group in a workspace.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| group_name | string | Name of the group | Yes
| workspace_slug | string | Slug of the Bitrise workspace | Yes
</details>
<details>
<summary>get_workspace_members</summary>

**Description**:

```
Get the members of a workspace
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| workspace_slug | string | Slug of the Bitrise workspace | Yes
</details>
<details>
<summary>invite_member_to_workspace</summary>

**Description**:

```
Invite new Bitrise users to a workspace.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| email | string | Email address of the user | Yes
| workspace_slug | string | Slug of the Bitrise workspace | Yes
</details>
<details>
<summary>add_member_to_group</summary>

**Description**:

```
Add a member to a group.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| group_slug | string | Slug of the group | Yes
| user_slug | string | Slug of the user | Yes
</details>
<details>
<summary>me</summary>

**Description**:

```
Get user info for the currently authenticated user account
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_connected_app</summary>

**Description**:

```
Add a new Release Management connected app to Bitrise.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | An uuidV4 identifier for your new connected app. If it is not given, one will be generated. It is useful for making the request idempotent or if the id is triggered outside of Bitrise and needs to be stored separately as well. | No
| manual_connection | boolean | If set to true it indicates a manual connection (bypassing using store api keys) and requires giving 'store_app_name' as well. This can be especially useful for enterprise apps. | No
| platform | string | The mobile platform for the connected app. Available values are 'ios' and 'android'. | Yes
| project_id | string | Specifies which Bitrise Project you want to get the connected app to be associated with. If this field is not given a new project will be created alongside with the connected app. | No
| store_app_id | string | The app store identifier for the connected app. In case of 'ios' platform it is the bundle id from App Store Connect. For additional context you can check the property description: https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifierIn case of Android platform it is the package name. Check the documentation: https://developer.android.com/build/configure-app-module#set_the_application_id | Yes
| store_app_name | string | If you have no active app store API keys added on Bitrise, you can decide to add your app manually by giving the app's name as well while indicating manual connection with the similarly named boolean flag. | No
| store_credential_id | string | If you have credentials added on Bitrise, you can decide to select one for your app. In case of ios platform it will be an Apple API credential id. In case of android platform it will be a Google Service credential id. | No
| workspace_slug | string | Identifier of the Bitrise workspace for the Release Management connected app. This field is mandatory. | Yes
</details>
<details>
<summary>list_connected_apps</summary>

**Description**:

```
List Release Management connected apps available for the authenticated account within a workspace.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| items_per_page | integer | Specifies the maximum number of connected apps returned per page. Default value is 10. | No
| page | integer | Specifies which page should be returned from the whole result set in a paginated scenario. Default value is 1. | No
| platform | string | Filters for a specific mobile platform for the list of connected apps. Available values are: 'ios' and 'android'. | No
| project_id | string | Specifies which Bitrise Project you want to get associated connected apps for | No
| search | string | Search by bundle ID (for ios), package name (for android), or app title (for both platforms). The filter is case-sensitive. | No
| workspace_slug | string | Identifier of the Bitrise workspace for the Release Management connected apps. This field is mandatory. | Yes
</details>
<details>
<summary>get_connected_app</summary>

**Description**:

```
Gives back a Release Management connected app for the authenticated account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Identifier of the Release Management connected app | Yes
</details>
<details>
<summary>update_connected_app</summary>

**Description**:

```
Updates a connected app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connect_to_store | boolean | If true, will check connected app validity against the Apple App Store or Google Play Store (dependent on the platform of your connected app). This means, that the already set or just given store_app_id will be validated against the Store, using the already set or just given store credential id. | No
| connected_app_id | string | The uuidV4 identifier for your connected app. | Yes
| store_app_id | string | The store identifier for your app. You can change the previously set store_app_id to match the one in the App Store or Google Play depending on the app platform. This is especially useful if you want to connect your app with the store as the system will validate the given store_app_id against the Store. In case of iOS platform it is the bundle id. In case of Android platform it is the package name. | Yes
| store_credential_id | string | If you have credentials added on Bitrise, you can decide to select one for your app. In case of ios platform it will be an Apple API credential id. In case of android platform it will be a Google Service credential id. | No
</details>
<details>
<summary>list_installable_artifacts</summary>

**Description**:

```
List Release Management installable artifacts of a connected app available for the authenticated account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after_date | string | A date in ISO 8601 string format specifying the start of the interval when the installable artifact to be returned was created or uploaded. This value will be defaulted to 1 month ago if distribution_ready filter is not set or set to false. | No
| artifact_type | string | Filters for a specific artifact type or file extension for the list of installable artifacts. Available values are: 'aab' and 'apk' for android artifacts and 'ipa' for ios artifacts. | No
| before_date | string | A date in ISO 8601 string format specifying the end of the interval when the installable artifact to be returned was created or uploaded. This value will be defaulted to the current time if distribution_ready filter is not set or set to false. | No
| branch | string | Filters for the Bitrise CI branch of the installable artifact on which it has been generated on. | No
| connected_app_id | string | Identifier of the Release Management connected app for the installable artifacts. This field is mandatory. | Yes
| distribution_ready | boolean | Filters for distribution ready installable artifacts. This means .apk and .ipa (with distribution type ad-hoc, development, or enterprise) installable artifacts. | No
| items_per_page | integer | Specifies the maximum number of installable artifacts to be returned per page. Default value is 10. | No
| page | integer | Specifies which page should be returned from the whole result set in a paginated scenario. Default value is 1. | No
| platform | string | Filters for a specific mobile platform for the list of installable artifacts. Available values are: 'ios' and 'android'. | No
| search | string | Search by version, filename or build number (Bitrise CI). The filter is case-sensitive. | No
| source | string | Filters for the source of installable artifacts to be returned. Available values are 'api' and 'ci'. | No
| store_signed | boolean | Filters for store ready installable artifacts. This means signed .aab and .ipa (with distribution type app-store) installable artifacts. | No
| version | string | Filters for the version this installable artifact was created for. This field is required if the distribution_ready filter is set to true. | No
| workflow | string | Filters for the Bitrise CI workflow of the installable artifact it has been generated by. | No
</details>
<details>
<summary>generate_installable_artifact_upload_url</summary>

**Description**:

```
Generates a signed upload url valid for 1 hour for an installable artifact to be uploaded to Bitrise Release Management. The response will contain an url that can be used to upload an artifact to Bitrise Release Management using a simple curl request with the file data that should be uploaded. The necessary headers and http method will also be in the response. This artifact will need to be processed after upload to be usable. The status of processing can be checked by making another requestto a different url giving back the processed status of an installable artifact.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branch | string | Optionally you can add the name of the CI branch the installable artifact has been generated on. | No
| connected_app_id | string | Identifier of the Release Management connected app for the installable artifact. This field is mandatory. | Yes
| file_name | string | The name of the installable artifact file (with extension) to be uploaded to Bitrise. This field is mandatory. | Yes
| file_size_bytes | string | The byte size of the installable artifact file to be uploaded. | Yes
| installable_artifact_id | string | An uuidv4 identifier generated on the client side for the installable artifact. This field is mandatory. | Yes
| with_public_page | boolean | Optionally, you can enable public install page for your artifact. This can only be enabled by Bitrise Project Admins, Bitrise Project Owners and Bitrise Workspace Admins. Changing this value without proper permissions will result in an error. The default value is false. | No
| workflow | string | Optionally you can add the name of the CI workflow this installable artifact has been generated by. | No
</details>
<details>
<summary>get_installable_artifact_upload_and_processing_status</summary>

**Description**:

```
Gets the processing and upload status of an installable artifact. An artifact will need to be processed after upload to be usable. This endpoint helps understanding when an uploaded installable artifacts becomes usable for later purposes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | Identifier of the Release Management connected app for the installable artifact. This field is mandatory. | Yes
| installable_artifact_id | string | The uuidv4 identifier for the installable artifact. This field is mandatory. | Yes
</details>
<details>
<summary>set_installable_artifact_public_install_page</summary>

**Description**:

```
Changes whether public install page should be available for the installable artifact or not.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | Identifier of the Release Management connected app for the installable artifact. This field is mandatory. | Yes
| installable_artifact_id | string | The uuidv4 identifier for the installable artifact. This field is mandatory. | Yes
| with_public_page | boolean | Boolean flag for enabling/disabling public install page for the installable artifact. This field is mandatory. | Yes
</details>
<details>
<summary>list_build_distribution_versions</summary>

**Description**:

```
Lists Build Distribution versions. Release Management offers a convenient, secure solution to distribute the builds of your mobile apps to testers without having to engage with either TestFlight or Google Play. Once you have installable artifacts, Bitrise can generate both private and public install links that testers or other stakeholders can use to install the app on real devices via over-the-air installation. Build distribution allows you to define tester groups that can receive notifications about installable artifacts. The email takes the notified testers to the test build page, from where they can install the app on their own device. Build distribution versions are the  app versions available for testers.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the app the build distribution is connected to. This field is mandatory. | Yes
| items_per_page | integer | Specifies the maximum number of build distribution versions returned per page. Default value is 10. | No
| page | integer | Specifies which page should be returned from the whole result set in a paginated scenario. Default value is 1. | No
</details>
<details>
<summary>list_build_distribution_version_test_builds</summary>

**Description**:

```
Gives back a list of test builds for the given build distribution version.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the app the build distribution is connected to. This field is mandatory. | Yes
| items_per_page | integer | Specifies the maximum number of test builds to return for a build distribution version per page. Default value is 10. | No
| page | integer | Specifies which page should be returned from the whole result set in a paginated scenario. Default value is 1. | No
| version | string | The version of the build distribution. This field is mandatory. | Yes
</details>
<details>
<summary>create_tester_group</summary>

**Description**:

```
Creates a tester group for a Release Management connected app. Tester groups can be used to distribute installable artifacts to testers automatically. When a new installable artifact is available, the tester groups can either automatically or manually be notified via email. The notification email will contain a link to the installable artifact page for the artifact within Bitrise Release Management. A Release Management connected app can have multiple tester groups. Project team members of the connected app can be selected to be testers and added to the tester group. This endpoint has an elevated access level requirement. Only the owner of the related Bitrise Workspace, a workspace manager or the related project's admin can manage tester groups.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_notify | boolean | If set to true it indicates that the tester group will receive notifications automatically. | No
| connected_app_id | string | The uuidV4 identifier of the related Release Management connected app. | Yes
| name | string | The name for the new tester group. Must be unique in the scope of the connected app. | Yes
</details>
<details>
<summary>notify_tester_group</summary>

**Description**:

```
Notifies a tester group about a new test build.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the related Release Management connected app. | Yes
| id | string | The uuidV4 identifier of the tester group whose members will be notified about the test build. | Yes
| test_build_id | string | The unique identifier of the test build what will be sent in the notification of the tester group. | Yes
</details>
<details>
<summary>add_testers_to_tester_group</summary>

**Description**:

```
Adds testers to a tester group of a connected app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the related Release Management connected app. | Yes
| id | string | The uuidV4 identifier of the tester group to which testers will be added. | Yes
| user_slugs | array | The list of users identified by slugs that will be added to the tester group. | Yes
</details>
<details>
<summary>update_tester_group</summary>

**Description**:

```
Updates the given tester group. The name and the auto notification setting can be updated optionally.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_notify | boolean | If set to true it indicates the tester group will receive email notifications automatically from now on about new installable builds. | No
| connected_app_id | string | The uuidV4 identifier of the related Release Management connected app. | Yes
| id | string | The uuidV4 identifier of the tester group to which testers will be added. | Yes
| name | string | The new name for the tester group. Must be unique in the scope of the related connected app. | No
</details>
<details>
<summary>list_tester_groups</summary>

**Description**:

```
Gives back a list of tester groups related to a specific Release Management connected app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the app the tester group is connected to. This field is mandatory. | Yes
| items_per_page | integer | Specifies the maximum number of tester groups to return related to a specific connected app. Default value is 10. | No
| page | integer | Specifies which page should be returned from the whole result set in a paginated scenario. Default value is 1. | No
</details>
<details>
<summary>get_tester_group</summary>

**Description**:

```
Gives back the details of the selected tester group.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the app the tester group is connected to. This field is mandatory. | Yes
| id | string | The uuidV4 identifier of the tester group. This field is mandatory. | Yes
</details>
<details>
<summary>get_potential_testers</summary>

**Description**:

```
Gets a list of potential testers whom can be added as testers to a specific tester group. The list consists of Bitrise users having access to the related Release Management connected app.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connected_app_id | string | The uuidV4 identifier of the app the tester group is connected to. This field is mandatory. | Yes
| id | string | The uuidV4 identifier of the tester group. This field is mandatory. | Yes
| items_per_page | integer | Specifies the maximum number of potential testers to return having access to a specific connected app. Default value is 10. | No
| page | integer | Specifies which page should be returned from the whole result set in a paginated scenario. Default value is 1. | No
| search | string | Searches for potential testers based on email or username using a case-insensitive approach. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | abort_build | description | ef8c97cf42232ddba498237ea7d7c20bf9129d65f1835cce65fdd60f5a3eddff |
| tools | abort_build | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | abort_build | build_slug | d61d679c4b78dbacd64f7f911bfcaa797cbe27cad4e871ac91dd66db6333e9da |
| tools | abort_build | reason | 46d09ed4bf44cfcfc4c869fa143485fb251a1eabe454467578730231fc34f2bd |
| tools | abort_pipeline | description | cdbec36a3b871913fc74aaf20ccad0f64315f2e57dc320a6031f522c3ef3926a |
| tools | abort_pipeline | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | abort_pipeline | pipeline_id | 6e9966c5eff5c2582e4934292fcb402fc179b2064dbfee939e830522b70e1dd1 |
| tools | abort_pipeline | reason | b458c1c086531c1cfb74af57513a255c8cf08fa863917c854b213d06c080905d |
| tools | add_member_to_group | description | a94962f1d2e31ae8c81cdd75533acbe61b1030c3a8804f286ef858a6e1f5e834 |
| tools | add_member_to_group | group_slug | ff3f97f429d5e3a103244b1b8bff84e9c0a020b86a3a191017711a3285f38575 |
| tools | add_member_to_group | user_slug | 679cfa9d3f635ce83c31f593d18f7c3bc87236352f98afe5d91927c8b583e0f6 |
| tools | add_testers_to_tester_group | description | 72ce73d34f3ba1f7a14a7c3a4cef578f59cb866162e1d52215be91e4dbf549e6 |
| tools | add_testers_to_tester_group | connected_app_id | a1f402921d99db58a195fdf902a5871945ae5d361f1a31ba76c9c5d3e8fd3287 |
| tools | add_testers_to_tester_group | id | f22ddea39b815ed0916e6ba11db5679e1d337d3f35a599efcaedb0c89597f909 |
| tools | add_testers_to_tester_group | user_slugs | c7c045de4d32079a595d72210c4e38266d47762564d9632a903b2351ce0dd891 |
| tools | create_connected_app | description | fbc3209f0bc8f36f981c2b27620f99c735d37e1d7c4e013b78b2a22bdcc97b35 |
| tools | create_connected_app | id | ceed25d355c0955dc202ac2360febbe85716f605eb721fa9f9ecf03a6ae57ced |
| tools | create_connected_app | manual_connection | 1dd3cb0d4d3285fd8c835191e2810a7080aff2f15646433269e2b3476b15b149 |
| tools | create_connected_app | platform | bf4c3f0f25f3486392eb30780419c2dbd0896c927b3a1e64b0e65a6a4995ebb7 |
| tools | create_connected_app | project_id | 8ed63733440d6a36a862c24fd905e8d8ef5710e47146348ba9df83d19b2fd762 |
| tools | create_connected_app | store_app_id | a00c83ebdc1f534996055ec1a5ae39e6449a55b024652a64ca18e02c54b4f6d1 |
| tools | create_connected_app | store_app_name | cdd7b608789d56a8615eeb4a97cef02e95c5992853d8f267c467a9e4b48d80ed |
| tools | create_connected_app | store_credential_id | a08d919e2f347e1e491c30ac0636b96a6350a954593541a642f7b3bf6cc66e1f |
| tools | create_connected_app | workspace_slug | c36e325940ea066bbd63c076be5a8dba665df83efc7c1e59b6784b2f92087ed4 |
| tools | create_tester_group | description | fa0c9c32233965f9ffc662e7d3b4c60a49d686b5b513e282cae8b4a1b76c5419 |
| tools | create_tester_group | auto_notify | 412c8f20771bfaa3547b52249191d0f685ddd65357131d38ab7b8d4c67acffa4 |
| tools | create_tester_group | connected_app_id | a1f402921d99db58a195fdf902a5871945ae5d361f1a31ba76c9c5d3e8fd3287 |
| tools | create_tester_group | name | fc30ac118d7af428d7ae9a59365880da541f0a6a0314f76ac2f00521150f47c2 |
| tools | create_workspace_group | description | 7edd9e74cf00e789c352cf34a30c2fb549eb05432fb5ee900da687948a42d7e2 |
| tools | create_workspace_group | group_name | d692cebacdf6154863eb66a5cce4b9859bf4f0696a1115f2ccbf7d546bc035e2 |
| tools | create_workspace_group | workspace_slug | ab86e8b6f4878c78da2f22e0f57cdf0f3283dc2a56dbcb3d7a303e5d94da7871 |
| tools | delete_all_cache_items | description | d4c375c21af665ee3941a0614251661a88d3fc7b4727e220701e76f22f9a3570 |
| tools | delete_all_cache_items | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | delete_app | description | 801fa3e14e78a3845458d6f45bb9c5197b8d5166d95e0802f62e0a70f711d9fc |
| tools | delete_app | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | delete_cache_item | description | 930513883bf175b79554a92e1abc3349f49d6193cd486f1da2ecf149466f6034 |
| tools | delete_cache_item | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | delete_cache_item | cache_item_id | cc3fb654aef43b59c4dfafbaf75d75aa1437b2e05d52f769333d55e21bfd50bf |
| tools | finish_bitrise_app | description | 2f8127dff5f78d6895dac8a1b93957bf3d80fa930c554fa6445bea1192fa4325 |
| tools | finish_bitrise_app | app_slug | 2ea685ede4257ca4697977495f9c4019cef8015c4c28c1f7c8a4089268049eba |
| tools | finish_bitrise_app | config | a95c3e3b104900722462b0787deb35fa28f7c7da2c3ea99120185dacff3fd6b8 |
| tools | finish_bitrise_app | mode | cbdbd44073d0ab9dd7e9c8be07a16894489e95e5dde188ccf587b7a3689c365d |
| tools | finish_bitrise_app | project_type | 017447274a841f3c5ef40ceeaa572b8b39d3a2075b2115fe2c0aabab60bce2fa |
| tools | finish_bitrise_app | stack_id | 933aefe6ac5b42e0032bea642895f8bbd7796e15938b8b468e4a9555303f347c |
| tools | generate_installable_artifact_upload_url | description | 9423c9fe1f416f7fb030de3974fd4b19738d9ac6bd236c175f6a51410ecf820b |
| tools | generate_installable_artifact_upload_url | branch | d27cc736ca5638a2f2dabfda60096bde10e8092ad7264f3a05a08297d5890fab |
| tools | generate_installable_artifact_upload_url | connected_app_id | 78ecdd33cd32c970bd08e719ed640d58defc691573e1bb15b879ac9a743ebbee |
| tools | generate_installable_artifact_upload_url | file_name | 443a313a3548630c1297742a1d0fcac61ebcdcfe6396c292e5b167beeb0d4048 |
| tools | generate_installable_artifact_upload_url | file_size_bytes | 03fac2a185d87b7b6290d5b544a171b7f2c64cd30f0adc65ddfabca7d18909cd |
| tools | generate_installable_artifact_upload_url | installable_artifact_id | 6187e899372406cab9d373aca4bb53b6caf0f2ed87d6d064c14e95dfbcc748b5 |
| tools | generate_installable_artifact_upload_url | with_public_page | 00f61b9dea6344747632560bdd06d6365ad7f0bc4be2bf13d20bb79e55495f6b |
| tools | generate_installable_artifact_upload_url | workflow | 9ebdf7e983f45103ce0ba7f758f452fcfefeefad23f8948365e492d0e8b948fc |
| tools | get_app | description | f058d2ff51f6bdf33a760f0ba2fb7a661c33a73f9ee89813aa1bbfdb4266833e |
| tools | get_app | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | get_artifact | description | 51a62414d396f81f9e534a010b3772424de64cf79a09656f5a0b8b5fe618b65e |
| tools | get_artifact | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | get_artifact | artifact_slug | 4db785a401917603e99305e0ea8c6de87918bcc237c3d3164853746e280b0c8d |
| tools | get_artifact | build_slug | d61d679c4b78dbacd64f7f911bfcaa797cbe27cad4e871ac91dd66db6333e9da |
| tools | get_bitrise_yml | description | 60616deb2a0f2b3ab92be86af813274d7d8c672ffc8ced4a00ac79a962039720 |
| tools | get_bitrise_yml | app_slug | c6b078f854286e9f9c5d61e8ce99f8d4a807c85cf2fb94be3f42899830eaf9e7 |
| tools | get_build | description | d1fc04f8bef3e65fa55901f30df898a31732c1ef3a1fe20e45c461bdbc5d6ed7 |
| tools | get_build | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | get_build | build_slug | d61d679c4b78dbacd64f7f911bfcaa797cbe27cad4e871ac91dd66db6333e9da |
| tools | get_build_bitrise_yml | description | 9fce8c4eb62d699e55cacb0b99e40b8178ef06b0156e959d1748a204cd51c356 |
| tools | get_build_bitrise_yml | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | get_build_bitrise_yml | build_slug | d61d679c4b78dbacd64f7f911bfcaa797cbe27cad4e871ac91dd66db6333e9da |
| tools | get_build_log | description | 5132b7f49b13e80eb0abeb1ea618c93cbf61eca5a2493d9d4bdb57b96ec11498 |
| tools | get_build_log | app_slug | c6b078f854286e9f9c5d61e8ce99f8d4a807c85cf2fb94be3f42899830eaf9e7 |
| tools | get_build_log | build_slug | ecbac931a310f8ac941f1e56f3506ac289083863043a1e91eb374170b642eab3 |
| tools | get_cache_item_download_url | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | get_cache_item_download_url | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | get_cache_item_download_url | cache_item_id | cc3fb654aef43b59c4dfafbaf75d75aa1437b2e05d52f769333d55e21bfd50bf |
| tools | get_connected_app | description | 0a3457f220d6b498a29105feda9fedfad4c5cc9324fdff257ff6a0f7b549d879 |
| tools | get_connected_app | id | b1a45dfd256af6cb904458cedce27377dd9002252b0c0d6e4ce29fcb0bc5271b |
| tools | get_installable_artifact_upload_and_processing_status | description | ca6ba25a9f2e2b8d75a06ed3f139f56c0b7d6be2dde2a816374a6d7ae4bf8a1b |
| tools | get_installable_artifact_upload_and_processing_status | connected_app_id | 78ecdd33cd32c970bd08e719ed640d58defc691573e1bb15b879ac9a743ebbee |
| tools | get_installable_artifact_upload_and_processing_status | installable_artifact_id | 9a9a81c2c59b022fb6fdcbfafa7fe832f201755c9f5b6251396aaef6658e8476 |
| tools | get_pipeline | description | df7044cac25d58bdce432df9ec9c44eece9ad88ffad52a77a52a499b749bfeb4 |
| tools | get_pipeline | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | get_pipeline | pipeline_id | 6e9966c5eff5c2582e4934292fcb402fc179b2064dbfee939e830522b70e1dd1 |
| tools | get_potential_testers | description | 1c5497fad2af8452acf54e8d60cf2b42d43c15c1b7f58908fc8db4ac1e9af3b9 |
| tools | get_potential_testers | connected_app_id | a14a6a4d9c9ba703a8b03ae7e746df1a3ad46d4511bcdb6c1d0f42a2f7abcc1a |
| tools | get_potential_testers | id | 6e4544adb313c4aae1679fda6f79d12887dfc63b13a8d525ce25a6620e938554 |
| tools | get_potential_testers | items_per_page | 9d5418828eb77491532ba9e5bfaa649f53143b679b948ca1ce1e04caa0690fc0 |
| tools | get_potential_testers | page | e27f5234c9a9ba7e3e1e2a227f02bab4f75acae8283217201676e22244c10851 |
| tools | get_potential_testers | search | 7d425ef70d1cd49c5aef30b103418299431490dd6ed64196c5d74f3df4f1e7db |
| tools | get_tester_group | description | 647d2624a820716e8c1b001d4115056492a5e4fbea7e402cef46b79ed9b7cbf8 |
| tools | get_tester_group | connected_app_id | a14a6a4d9c9ba703a8b03ae7e746df1a3ad46d4511bcdb6c1d0f42a2f7abcc1a |
| tools | get_tester_group | id | 6e4544adb313c4aae1679fda6f79d12887dfc63b13a8d525ce25a6620e938554 |
| tools | get_workspace | description | 3a3b6dd2997de3c4c4089997498fe45a76617238965ca43af025de356499b5d2 |
| tools | get_workspace | workspace_slug | ab86e8b6f4878c78da2f22e0f57cdf0f3283dc2a56dbcb3d7a303e5d94da7871 |
| tools | get_workspace_groups | description | 19373156d26162a045c058ed903c0ea5feeea80a8d9718f3c8ea02cb4b2f300d |
| tools | get_workspace_groups | workspace_slug | ab86e8b6f4878c78da2f22e0f57cdf0f3283dc2a56dbcb3d7a303e5d94da7871 |
| tools | get_workspace_members | description | 54bf86afeaeb8486a94826045aa03abb178bcdca797c203149ba6bdc07785d71 |
| tools | get_workspace_members | workspace_slug | ab86e8b6f4878c78da2f22e0f57cdf0f3283dc2a56dbcb3d7a303e5d94da7871 |
| tools | invite_member_to_workspace | description | 82bd3da1d0a32e49f97b4076e6ac2000c7aa387d616e8a51838814a41017206f |
| tools | invite_member_to_workspace | email | 08583424bb1414c9e0d4077c4d4c155fb770ab10865b5d823ba660bdface0539 |
| tools | invite_member_to_workspace | workspace_slug | ab86e8b6f4878c78da2f22e0f57cdf0f3283dc2a56dbcb3d7a303e5d94da7871 |
| tools | list_apps | description | 20f50354c16add3381427f8063fcdbc1bd08f454cba0a0bd821e86b63b89149e |
| tools | list_apps | limit | cdfd5419dc04c045cd4713666e7efc8047b295d894e3516fa3b18dcfb0378b9a |
| tools | list_apps | next | 3d01a9e934cdc3d09d38453cc7dee96d3ae5ca3f6fac12349af384209bed1e5a |
| tools | list_apps | sort_by | 5669788e1b849af161732aa5b50520a484b2b26918311869d7b9b865b6425cdc |
| tools | list_artifacts | description | b5f1bd4798fde0d3fb943c5201e1c9d15b92a9148acbaed316f443a6e8d5457e |
| tools | list_artifacts | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_artifacts | build_slug | d61d679c4b78dbacd64f7f911bfcaa797cbe27cad4e871ac91dd66db6333e9da |
| tools | list_artifacts | limit | cdfd5419dc04c045cd4713666e7efc8047b295d894e3516fa3b18dcfb0378b9a |
| tools | list_artifacts | next | aa2db3c4cb1d526268670daecbc04308c21f809682a5324913f4f9ef12af4b5c |
| tools | list_branches | description | d7f40b58992b81ae90d5bc8e6d36b58c3d4ffe3df56f636e17c2aece8ea600e9 |
| tools | list_branches | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_build_distribution_version_test_builds | description | b06b2028b128bd7ccf2a6d1cbc1d3fe00222f9386f1da6004599c5d10e92661b |
| tools | list_build_distribution_version_test_builds | connected_app_id | ca11223cf06d1214bc2b16bbf5fd6519026b038f2317b556a47bc0181f850d49 |
| tools | list_build_distribution_version_test_builds | items_per_page | a87a40bb4a9ea96a03ec2dc7e55046f05e8f6a4bf11f93b9e16d3a422f645596 |
| tools | list_build_distribution_version_test_builds | page | e27f5234c9a9ba7e3e1e2a227f02bab4f75acae8283217201676e22244c10851 |
| tools | list_build_distribution_version_test_builds | version | 5e511acf87855d16c871ccca3bbcc8782cf8054c39704a370747a512b015b5bc |
| tools | list_build_distribution_versions | description | 7d9702e933a2c1e1d1b3a5fadbfefafdfb737c78dc962e19930b89b8804541b7 |
| tools | list_build_distribution_versions | connected_app_id | ca11223cf06d1214bc2b16bbf5fd6519026b038f2317b556a47bc0181f850d49 |
| tools | list_build_distribution_versions | items_per_page | 5030c50a4551c7630abaf3f5052603b0316f24d5f9183896b7cc6fbc284d2ef9 |
| tools | list_build_distribution_versions | page | e27f5234c9a9ba7e3e1e2a227f02bab4f75acae8283217201676e22244c10851 |
| tools | list_build_workflows | description | 001100e53ce56c7eb788bf91c4162933643d930f37d09ad930a526d389dff72a |
| tools | list_build_workflows | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_builds | description | b91b3908ced7288161e6dade0627d7f9f7d77e034a18b58ab09c5da79493e11a |
| tools | list_builds | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_builds | branch | b4b89eb1b2971099da00c8685a9259900e0b0da9068149b2e954abff1ee662ec |
| tools | list_builds | limit | cdfd5419dc04c045cd4713666e7efc8047b295d894e3516fa3b18dcfb0378b9a |
| tools | list_builds | next | 7aa37d82a2dc8a1e85609b83ad984b8eb43750d202b28633a2d7b95b94329cf7 |
| tools | list_builds | sort_by | f708558fec4a255366497537e12be6250e3fa2934ff3d5ffaeccb15bcdf1b3d7 |
| tools | list_builds | status | dfbe76da5c8ca30254849f8b37ee582f0421950635abef58cb809047e51716b3 |
| tools | list_builds | workflow | 18e32947143046baade94c4a0cc915b31a26001d302bae7eca5dc2dfc567616a |
| tools | list_cache_items | description | f082508f0074f0ef8e2507110ad5410540fbb2e61377184db37570965e75e15e |
| tools | list_cache_items | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_connected_apps | description | b40ffb97eddac9a6c6cd27885acb9929306e1cacc2a22a992e9f8ca5cabb826b |
| tools | list_connected_apps | items_per_page | b6792b0b411022973469673763d3ee2e877d98b24ca6bf9abc96fa0b03e29d3c |
| tools | list_connected_apps | page | e27f5234c9a9ba7e3e1e2a227f02bab4f75acae8283217201676e22244c10851 |
| tools | list_connected_apps | platform | f8d638765f8688846479c08451b6ad2ca7ec81847689f8f96e345abb68fa96d7 |
| tools | list_connected_apps | project_id | 13c9ea3ac2a89de65b09a51a7bb594158e17aa7c3a430c346d2d7dd135e5ca9e |
| tools | list_connected_apps | search | ab2994d34177f4462ab60bfcad999df35978a9d09edbd1d85ba00fb53975eb61 |
| tools | list_connected_apps | workspace_slug | 981c6fec94d9d0b8c6e44b63e512d932999f704f5536b36cbe7fb1223287c33f |
| tools | list_group_roles | description | da9e774f04fad098427d1f2b034ec9b47bedd9e3298ee9ef1074f83bc4483949 |
| tools | list_group_roles | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_group_roles | role_name | dfc578882381da691f1f35fcbf69f6472aecfec9e5c88a1d29d98dc3de6e8211 |
| tools | list_installable_artifacts | description | 3cbf3b1371dd89bd0ebff121a876225056984715d5e172809d12d34420d2abb0 |
| tools | list_installable_artifacts | after_date | 2af3f2712446f1218ce05a779751c16b907be7af4293393e65e5e34ff87f4893 |
| tools | list_installable_artifacts | artifact_type | c3ad973145e8f5b18a702fa6cc0b2f89c60822c77e55c4a42536899b95652661 |
| tools | list_installable_artifacts | before_date | 93b9c96d13545184196c4c1d57026b270709097909d71356c60ca14e0c6f7ca2 |
| tools | list_installable_artifacts | branch | 9387278c2749f75ae8a6d36bf1c152306d3d8ec837d499ad81c6be22dcf23fda |
| tools | list_installable_artifacts | connected_app_id | 8c60def5fcd7ecf65f27ba92e6fdc2be7bf0774905293bb7d9d015e13eca14fa |
| tools | list_installable_artifacts | distribution_ready | 42d44685fbf2cd9fad484fe8fcb09ea788234622b7758ff9a268774dd53e6c4d |
| tools | list_installable_artifacts | items_per_page | 97fbf5a4b62a9981df1e14cfba7e7db4f8acf3e4d50901af6d3144ce48e6fc72 |
| tools | list_installable_artifacts | page | e27f5234c9a9ba7e3e1e2a227f02bab4f75acae8283217201676e22244c10851 |
| tools | list_installable_artifacts | platform | 7d9f3a96494bd9e44150b41466060f6f3e1dc3e12d7f1c4bb8ce5e4286dd6fc8 |
| tools | list_installable_artifacts | search | 2211e4b2c3c67cd779576a75046406d7d39fe61011a835c3a3139ebb543fd5cd |
| tools | list_installable_artifacts | source | febb71b50c4c79d99237fd6be766070878df05e33199b666d9d33642bd8ba1cc |
| tools | list_installable_artifacts | store_signed | 098c1053d94a30942a9d782c309abefd31ad556de8d6818bad6ba29d34474aee |
| tools | list_installable_artifacts | version | 22d99b8a17a4e221dcd4cba6eb225c5ef3016d22ba85feeac39093ac291c9d72 |
| tools | list_installable_artifacts | workflow | cdc6791c7ba54da5888286c317d9e905cfd7de45a22f7cc34daa337f2add27ac |
| tools | list_outgoing_webhooks | description | 52acbacbad91e74c0bbe8bf97c6f5c331a648ec253751319529f971d21328336 |
| tools | list_outgoing_webhooks | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_pipelines | description | f224915e6522186d2d517ffce2a0ec581e96bab9618d438917bee1b9af2d4e8d |
| tools | list_pipelines | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | list_tester_groups | description | 7c3c2648f280218ff612063904efa57ac9e9d0f12699a7a8e2bdcfa648e4a256 |
| tools | list_tester_groups | connected_app_id | a14a6a4d9c9ba703a8b03ae7e746df1a3ad46d4511bcdb6c1d0f42a2f7abcc1a |
| tools | list_tester_groups | items_per_page | 056bf9acce917ade2d03d573cc1988b62fc37b9fa28fd06f71df05246ecc4087 |
| tools | list_tester_groups | page | e27f5234c9a9ba7e3e1e2a227f02bab4f75acae8283217201676e22244c10851 |
| tools | list_workspaces | description | 94efddc0886a4abedd193127c6ce4e1a551a936e0558b2f1856da11830e5477d |
| tools | me | description | 9d8f6062d380932d47ecd31f08244048bd7636ad6a3a4a155c225b6e2c4795b6 |
| tools | notify_tester_group | description | 353b8391e6fd8ee110f1aec9a3850d8a4f47fda20c4c293b4b76d4f9e6d58216 |
| tools | notify_tester_group | connected_app_id | a1f402921d99db58a195fdf902a5871945ae5d361f1a31ba76c9c5d3e8fd3287 |
| tools | notify_tester_group | id | 233e498214acac872f431cad472b0c83d33fa38e859f68ba510954daf5b31653 |
| tools | notify_tester_group | test_build_id | fc28f248324615dfa1186604e2feb03e43122442af931490acba6e90770e6545 |
| tools | rebuild_pipeline | description | f05c86b5f0a37346780db81b0a51c29156b98a1b96d0e638f7e8d26e65b8e7fc |
| tools | rebuild_pipeline | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | rebuild_pipeline | pipeline_id | 6e9966c5eff5c2582e4934292fcb402fc179b2064dbfee939e830522b70e1dd1 |
| tools | register_app | description | 116266340b73b027a63808b4dd9abafce8123a1e6ad852b9ad09490e1520af96 |
| tools | register_app | is_public | 0d54c4181f84ec111fe68287a56281ddf401b8cf555430bb07eeb2ea33a667ef |
| tools | register_app | organization_slug | f5e6e917ff9ef5492347e5d5653fb169327a660cd67e2e6dfbbde9c887221f18 |
| tools | register_app | project_type | b83960b24daaebadd169fa9c2d0acd3ea14cd08749a11bb4b92cba1fcfa85677 |
| tools | register_app | provider | d873f20a889f4ca480473f528dd00344315a5758dc61feafd94bc5703d0382e0 |
| tools | register_app | repo_url | c83db0133850dfccdc6743bb4391c7765e59c5f12e22e9b6ed250e850e0f8c36 |
| tools | register_ssh_key | description | 500d7099103a00aca1e1174a6e2e50319f03325d24cb61add1ab23ff4d28ed1d |
| tools | register_ssh_key | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | register_ssh_key | auth_ssh_private_key | 8acdf4459ec846fecbb28995491b72c758cc88b7b9b5aab2bca07c6e66096dd8 |
| tools | register_ssh_key | auth_ssh_public_key | 6c2dd5537ac1be6bed7eb92f0b4ff42bb2aa35ef28e487fbf98db548b79d5051 |
| tools | register_ssh_key | is_register_key_into_provider_service | 86a933db370e7688ced1be370e273b8b4d9d4b31e4303ac8ad0a8fa41d89c225 |
| tools | register_webhook | description | e8ec954020caaad04ec4d0eaaa281418ebf219e71a99dfaf41da70bf1aeef60a |
| tools | register_webhook | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | replace_group_roles | description | e722f651f109e2026f2a2a72abc6b414bd5da8fc57d26aa8c22e045036650f6d |
| tools | replace_group_roles | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | replace_group_roles | group_slugs | 83698b6392c3c72dfa142a8880f09d40ab8032dce7dc1f6f2ae15b22d78be66b |
| tools | replace_group_roles | role_name | dfc578882381da691f1f35fcbf69f6472aecfec9e5c88a1d29d98dc3de6e8211 |
| tools | set_installable_artifact_public_install_page | description | b115d334b5e4b1f4a0e1ba2f7faec17dee8ca0a0a7c126be2899fa7ecb677a06 |
| tools | set_installable_artifact_public_install_page | connected_app_id | 78ecdd33cd32c970bd08e719ed640d58defc691573e1bb15b879ac9a743ebbee |
| tools | set_installable_artifact_public_install_page | installable_artifact_id | 9a9a81c2c59b022fb6fdcbfafa7fe832f201755c9f5b6251396aaef6658e8476 |
| tools | set_installable_artifact_public_install_page | with_public_page | e30173967dd6aadda6877b928e7628eb78eb523bd746cf6014a20ded4054f315 |
| tools | trigger_bitrise_build | description | 6e99241be7dc47be3df1d2597a7a0467208b477fab9288a2af689c48df0281b2 |
| tools | trigger_bitrise_build | app_slug | c6b078f854286e9f9c5d61e8ce99f8d4a807c85cf2fb94be3f42899830eaf9e7 |
| tools | trigger_bitrise_build | branch | 84d8c05dc547465867baea43baca4d7dcab615cb11855f3f17fbe26310685cc1 |
| tools | trigger_bitrise_build | commit_hash | eb5b88dea305d119c5067ecd79b3df891909b9a28909ae39092ba2e8f312c4a4 |
| tools | trigger_bitrise_build | commit_message | 9f36e2a81a20636e1963d873eed9a8f6818d9ae3bf5cfdca56e49294a6a23bba |
| tools | trigger_bitrise_build | workflow_id | 1953f5300d3a174f8f81f439f41d879be911a2a4ad239b3ae01fc2d8f0369d46 |
| tools | update_app | description | 68b8e5f2e8479a74ad77de38335d82c2796f155feab14f9ca57eb338721bcb02 |
| tools | update_app | app_slug | 65749d80855f14dab4a238b607d70f74b702ea7c7eb178865d44fcdf99be9b66 |
| tools | update_app | is_public | 0d54c4181f84ec111fe68287a56281ddf401b8cf555430bb07eeb2ea33a667ef |
| tools | update_app | project_type | 209869bd23a5d664808a01c83d559041e0f0e379f160b449f1e49fadf6ba1b04 |
| tools | update_app | provider | d873f20a889f4ca480473f528dd00344315a5758dc61feafd94bc5703d0382e0 |
| tools | update_app | repo_url | c83db0133850dfccdc6743bb4391c7765e59c5f12e22e9b6ed250e850e0f8c36 |
| tools | update_bitrise_yml | description | d2a59d9603f2597c4e7fa9abd9bc839f7d61aa7ee0baf848bb860fd275e5ab34 |
| tools | update_bitrise_yml | app_slug | c6b078f854286e9f9c5d61e8ce99f8d4a807c85cf2fb94be3f42899830eaf9e7 |
| tools | update_bitrise_yml | bitrise_yml_as_json | 0fa88738e585be3a2847977360c29a0432dd92227d9fa501fa6df2852edc6f3b |
| tools | update_connected_app | description | 38f24ddf4269beb52f819c800231fe581e16ffddf0e7e435dd90f32bb37f0e9a |
| tools | update_connected_app | connect_to_store | c9b06edbc4836aecb072bbc90304af2ceea2b6c53ff08c18c42ea41666235681 |
| tools | update_connected_app | connected_app_id | b28be0349de58bb3f1e53398314a99c494b973e8e9c2b7d3e2f9d426507e412b |
| tools | update_connected_app | store_app_id | f5d4cbca496ba0d8ca6227ff01987332b443cd504863c5e8a609a0eb49cbce3b |
| tools | update_connected_app | store_credential_id | a08d919e2f347e1e491c30ac0636b96a6350a954593541a642f7b3bf6cc66e1f |
| tools | update_tester_group | description | 25e5eec2e38032db568df618efc5f6026de667a110b9e33c929485eb08b9db47 |
| tools | update_tester_group | auto_notify | f2bec9a4f9870718bb598345ac3a0c2c2aca038a0c0fdd27a9da628a834baf7d |
| tools | update_tester_group | connected_app_id | a1f402921d99db58a195fdf902a5871945ae5d361f1a31ba76c9c5d3e8fd3287 |
| tools | update_tester_group | id | f22ddea39b815ed0916e6ba11db5679e1d337d3f35a599efcaedb0c89597f909 |
| tools | update_tester_group | name | ba6f9ce62378378d1c6d5f39a48725a0ee474d759e1993cbde0cab0fc2fe83ab |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
