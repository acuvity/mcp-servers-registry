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


# What is mcp-server-heroku?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-heroku/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-heroku/1.0.5?logo=docker&logoColor=fff&label=1.0.5)](https://hub.docker.com/r/acuvity/mcp-server-heroku)
[![PyPI](https://img.shields.io/badge/1.0.5-3775A9?logo=pypi&logoColor=fff&label=@heroku/mcp-server)](https://github.com/heroku/heroku-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-heroku/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-heroku&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22HEROKU_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-heroku%3A1.0.5%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Facilitate LLMs interaction with Heroku Platform resources.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @heroku/mcp-server original [sources](https://github.com/heroku/heroku-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-heroku/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-heroku/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-heroku/charts/mcp-server-heroku/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @heroku/mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-heroku/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Heroku ](https://github.com/heroku/heroku-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @heroku/mcp-server ](https://github.com/heroku/heroku-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @heroku/mcp-server ](https://github.com/heroku/heroku-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-heroku/charts/mcp-server-heroku)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-heroku/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.5`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-heroku:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-heroku:1.0.0-1.0.5`

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
  - `HEROKU_API_KEY` secret to be set as secrets.HEROKU_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-heroku oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-heroku oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-heroku
```

From there your MCP server mcp-server-heroku will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-heroku` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-heroku
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-heroku` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-heroku oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-heroku oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-heroku oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-heroku oci://docker.io/acuvity/mcp-server-heroku --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (37)
<details>
<summary>list_apps</summary>

**Description**:

```
List Heroku apps: owned, collaborator access, team/space filtering
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| all | boolean | Show owned apps and collaborator access. Default: owned only | No
| personal | boolean | List personal account apps only, ignoring default team | No
| space | string | Filter by private space name. Excludes team param | No
| team | string | Filter by team name. Excludes space param | No
</details>
<details>
<summary>get_app_info</summary>

**Description**:

```
Get app details: config, dynos, addons, access, domains
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name. Requires access permissions | Yes
| json | boolean | JSON output with full metadata. Default: text format | No
</details>
<details>
<summary>create_app</summary>

**Description**:

```
Create app: custom name, region (US/EU), team, private space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App name. Auto-generated if omitted | No
| region | string | Region: us/eu. Default: us. Excludes space param | No
| space | string | Private space name. Inherits region. Excludes region param | No
| team | string | Team name for ownership | No
</details>
<details>
<summary>rename_app</summary>

**Description**:

```
Rename app: validate and update app name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Current app name. Requires access | Yes
| newName | string | New unique app name | Yes
</details>
<details>
<summary>transfer_app</summary>

**Description**:

```
Transfer app ownership to user/team
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App to transfer. Requires owner/admin access | Yes
| recipient | string | Target user email or team name | Yes
</details>
<details>
<summary>maintenance_on</summary>

**Description**:

```
Enable maintenance mode and redirect traffic for a Heroku app
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target Heroku app name | Yes
</details>
<details>
<summary>maintenance_off</summary>

**Description**:

```
Disable maintenance mode and restore normal app operations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target Heroku app name | Yes
</details>
<details>
<summary>get_app_logs</summary>

**Description**:

```
App logs: monitor/debug/filter by dyno/process/source
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Heroku app name. Requires: permissions, Cedar-gen | Yes
| dynoName | string | Format: web.1/worker.2. Excludes processType | No
| processType | string | web|worker. All instances. Excludes dynoName | No
| source | string | app=application, heroku=platform. Default: all | No
</details>
<details>
<summary>list_private_spaces</summary>

**Description**:

```
Lists Heroku Private Spaces with CIDR blocks, regions, compliance and capacity details. JSON output supported.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| json | boolean | JSON output for detailed space metadata, text output if false/omitted | No
</details>
<details>
<summary>list_teams</summary>

**Description**:

```
Lists accessible Heroku Teams. Use for: viewing teams, checking membership, getting team metadata, and verifying access. JSON output available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| json | boolean | Output format control - true for detailed JSON with team metadata, false/omitted for simplified text | No
</details>
<details>
<summary>list_addons</summary>

**Description**:

```
List add-ons: all apps or specific app, detailed metadata
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| all | boolean | List all add-ons across accessible apps. Overrides app param, shows full status | No
| app | string | Filter by app name. Shows add-ons and attachments. Uses Git remote default if omitted | No
</details>
<details>
<summary>get_addon_info</summary>

**Description**:

```
Get add-on details: plan, state, billing
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addon | string | Add-on identifier: UUID, name (postgresql-curved-12345), or attachment name (DATABASE) | Yes
| app | string | App context for add-on lookup. Required for attachment names. Uses Git remote default | No
</details>
<details>
<summary>create_addon</summary>

**Description**:

```
Create add-on: specify service, plan, custom names
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app for add-on. Must have write access. Region/space affects availability | Yes
| as | string | Custom attachment name. Used for config vars prefix. Must be unique in app | No
| name | string | Global add-on identifier. Must be unique across all Heroku add-ons | No
| serviceAndPlan | string | Format: service_slug:plan_slug (e.g., heroku-postgresql:essential-0) | Yes
</details>
<details>
<summary>list_addon_services</summary>

**Description**:

```
List available add-on services and features
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| json | boolean | JSON output with sharing options and app generation support. Default: basic text | No
</details>
<details>
<summary>list_addon_plans</summary>

**Description**:

```
List service plans: features, pricing, availability
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| json | boolean | JSON output with pricing, features, space compatibility. Default: text format | No
| service | string | Service slug (e.g., heroku-postgresql). Get from list_addon_services | Yes
</details>
<details>
<summary>pg_psql</summary>

**Description**:

```
Execute SQL queries: analyze, debug, modify schema, manage data
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | app to run command against | Yes
| command | string | SQL command. Single line. Ignored if file provided | No
| credential | string | credential to use | No
| database | string | Database identifier: config var, name, ID, alias. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
| file | string | SQL file path. Ignored if command provided | No
</details>
<details>
<summary>pg_info</summary>

**Description**:

```
View database status: config, metrics, resources, health
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: all databases | No
</details>
<details>
<summary>pg_ps</summary>

**Description**:

```
Monitor active queries: progress, resources, performance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
| verbose | boolean | Show query plan and memory usage | No
</details>
<details>
<summary>pg_locks</summary>

**Description**:

```
Analyze locks: blocked queries, deadlocks, concurrency
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
| truncate | boolean | Truncate queries to 40 chars | No
</details>
<details>
<summary>pg_outliers</summary>

**Description**:

```
Find resource-heavy queries: performance, patterns, optimization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
| num | number | Number of queries to show. Default: 10 | No
| reset | boolean | Reset pg_stat_statements stats | No
| truncate | boolean | Truncate queries to 40 chars | No
</details>
<details>
<summary>pg_credentials</summary>

**Description**:

```
Manage access: credentials, permissions, security, monitoring
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
</details>
<details>
<summary>pg_kill</summary>

**Description**:

```
Stop processes: stuck queries, blocking transactions, runaway operations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
| force | boolean | Force immediate termination | No
| pid | number | Process ID to terminate | Yes
</details>
<details>
<summary>pg_maintenance</summary>

**Description**:

```
Track maintenance: windows, schedules, progress, planning
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
</details>
<details>
<summary>pg_backups</summary>

**Description**:

```
Manage backups: schedules, status, verification, recovery
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
</details>
<details>
<summary>pg_upgrade</summary>

**Description**:

```
Upgrade PostgreSQL: version migration, compatibility, safety
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name | Yes
| confirm | string | Confirmation for destructive operation | No
| database | string | Database identifier. Format: APP_NAME::DB for other apps. Default: DATABASE_URL | No
| version | string | PostgreSQL version target | No
</details>
<details>
<summary>ps_list</summary>

**Description**:

```
List and monitor Heroku app dynos. View running dynos, check status/health, monitor process states, verify configurations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App name to list processes for | Yes
| json | boolean | Output process info in JSON format | No
</details>
<details>
<summary>ps_scale</summary>

**Description**:

```
Scale Heroku app dynos. Adjust quantities, change sizes, view formation details, manage resources.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App name to scale | Yes
| dyno | string | Dyno type and quantity (e.g., web=3:Standard-2X, worker+1). Omit to show current formation | No
</details>
<details>
<summary>ps_restart</summary>

**Description**:

```
Restart Heroku app processes. Restart specific dynos, process types, or all dynos. Reset dyno states selectively.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App name to restart processes for | Yes
| dyno-name | string | Specific dyno to restart (e.g., web.1). Omit both options to restart all | No
| process-type | string | Dyno type to restart (e.g., web). Omit both options to restart all | No
</details>
<details>
<summary>pipelines_create</summary>

**Description**:

```
Creates new Heroku deployment pipeline with configurable stages, apps, and team settings
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App to add to pipeline | No
| name | string | Pipeline name | Yes
| stage | string | Initial pipeline stage | Yes
| team | string | Team owning the pipeline | No
</details>
<details>
<summary>pipelines_promote</summary>

**Description**:

```
Promotes apps between pipeline stages with configurable target applications
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Source app for promotion | Yes
| to | string | Target apps for promotion (comma-separated) | No
</details>
<details>
<summary>pipelines_list</summary>

**Description**:

```
Lists accessible Heroku pipelines with ownership and configuration details
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| json | boolean | Enable JSON output | No
</details>
<details>
<summary>pipelines_info</summary>

**Description**:

```
Displays detailed pipeline configuration, stages, and connected applications
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| json | boolean | Enable JSON output | No
| pipeline | string | Target pipeline name | Yes
</details>
<details>
<summary>deploy_to_heroku</summary>

**Description**:

```
Use for all deployments. Deploys new/existing apps, with or without teams/spaces, and env vars to Heroku. Ask for app name if missing. Requires valid app.json via appJson param.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appJson | string | App.json config for deployment. Must follow schema: {"default":{"$schema":"http://json-schema.org/draft-07/schema#","title":"Heroku app.json Schema","description":"app.json is a manifest format for describing web apps. It declares environment variables, add-ons, and other information required to run an app on Heroku. Used for dynamic configurations or converted projects","type":"object","properties":{"name":{"type":"string","pattern":"^[a-zA-Z-_\\.]+","maxLength":300},"description":{"type":"string"},"keywords":{"type":"array","items":{"type":"string"}},"website":{"$ref":"#/definitions/uriString"},"repository":{"$ref":"#/definitions/uriString"},"logo":{"$ref":"#/definitions/uriString"},"success_url":{"type":"string"},"scripts":{"$ref":"#/definitions/scripts"},"env":{"$ref":"#/definitions/env"},"formation":{"$ref":"#/definitions/formation"},"addons":{"$ref":"#/definitions/addons"},"buildpacks":{"$ref":"#/definitions/buildpacks"},"environments":{"$ref":"#/definitions/environments"},"stack":{"$ref":"#/definitions/stack"},"image":{"type":"string"}},"additionalProperties":false,"definitions":{"uriString":{"type":"string","format":"uri"},"scripts":{"type":"object","properties":{"postdeploy":{"type":"string"},"pr-predestroy":{"type":"string"}},"additionalProperties":false},"env":{"type":"object","patternProperties":{"^[A-Z][A-Z0-9_]*$":{"type":"object","properties":{"description":{"type":"string"},"value":{"type":"string"},"required":{"type":"boolean"},"generator":{"type":"string","enum":["secret"]}},"additionalProperties":false}}},"dynoSize":{"type":"string","enum":["free","eco","hobby","basic","standard-1x","standard-2x","performance-m","performance-l","private-s","private-m","private-l","shield-s","shield-m","shield-l"]},"formation":{"type":"object","patternProperties":{"^[a-zA-Z0-9_-]+$":{"type":"object","properties":{"quantity":{"type":"integer","minimum":0},"size":{"$ref":"#/definitions/dynoSize"}},"required":["quantity"],"additionalProperties":false}}},"addons":{"type":"array","items":{"oneOf":[{"type":"string"},{"type":"object","properties":{"plan":{"type":"string"},"as":{"type":"string"},"options":{"type":"object"}},"required":["plan"],"additionalProperties":false}]}},"buildpacks":{"type":"array","items":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false}},"environmentConfig":{"type":"object","properties":{"env":{"type":"object"},"formation":{"type":"object"},"addons":{"type":"array"},"buildpacks":{"type":"array"}}},"environments":{"type":"object","properties":{"test":{"allOf":[{"$ref":"#/definitions/environmentConfig"},{"type":"object","properties":{"scripts":{"type":"object","properties":{"test":{"type":"string"}},"additionalProperties":false}}}]},"review":{"$ref":"#/definitions/environmentConfig"},"production":{"$ref":"#/definitions/environmentConfig"}},"additionalProperties":false},"stack":{"type":"string","enum":["heroku-18","heroku-20","heroku-22","heroku-24"]}}}} | Yes
| env | object | Environment variables overriding app.json values | No
| internalRouting | boolean | Enable internal routing in private spaces. | No
| name | string | App name for deployment. Creates new app if not exists. | Yes
| rootUri | string | Workspace root directory path. | Yes
| spaceId | string | Private space ID for space deployments. | No
| tarballUri | string | URL of deployment tarball. Creates from rootUri if not provided. | No
| teamId | string | Team ID for team deployments. | No
</details>
<details>
<summary>deploy_one_off_dyno</summary>

**Description**:

```

Run code/commands in Heroku one-off dyno with network and filesystem access.

Requirements:
- Show command output
- Use app_info for buildpack detection
- Support shell setup commands
- Use stdout/stderr

Features:
- Network/filesystem access
- Environment variables
- File operations
- Temp directory handling

Usage:
1. Use Heroku runtime
2. Proper syntax/imports
3. Organized code structure
4. Package management:
   - Define dependencies
   - Minimize external deps
   - Prefer native modules

Example package.json:
```json
{
  "type": "module",
  "dependencies": {
    "axios": "^1.6.0"
  }
}
```

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| command | string | Command to run in dyno. | Yes
| env | object | Dyno environment variables. | No
| name | string | Target Heroku app name. | Yes
| size | string | Dyno size. | No
| sources | array | Source files to include in dyno. | No
| timeToLive | number | Dyno lifetime in seconds. | No
</details>
<details>
<summary>list_ai_available_models</summary>

**Description**:

```
List available AI inference models
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>provision_ai_model</summary>

**Description**:

```
Provision AI model access for app
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | Target app name for AI model access provisioning | Yes
| as | string | Alias for the model resource when attaching to the app. Randomly generated if not provided. | No
| modelName | string | Name of the AI model to provision access for. Valid model names can be found with tool "list_ai_available_models" | Yes
</details>
<details>
<summary>make_ai_inference</summary>

**Description**:

```
Make inference request to Heroku AI API
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app | string | App name/ID (required for alias) | Yes
| json | boolean | Output as JSON | No
| modelResource | string | Model resource ID/alias (requires --app for alias) | No
| opts | string | JSON string with model, messages, and optional params (temp, tools, etc) | Yes
| output | string | Output file path | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_addon | description | 7b87bbc7690b85ae072007b48e79f033810dd1d3b90aee7f4331542eaaa88c1f |
| tools | create_addon | app | 24ab2aa712c622fe0f0e3c0cda83e75e84e8f39530419f6fb57abda8acf033de |
| tools | create_addon | as | a6cd2c67f6b1c90c078d94ce7e40b630a91d2faa0e0423625c1740d5bcd1b24f |
| tools | create_addon | name | d75fa5b46df0c32202be457c7c58d9cc29667d2df8187d32bc0ce7c57e91bf45 |
| tools | create_addon | serviceAndPlan | b1722f48a2744ecb4c6a12710777b2e3f247e9e9d138538afaf292706472ff36 |
| tools | create_app | description | 3fae4b8e392b5680b940cf9e3dedc97ec2394e193d8d43b794bbcb0fd39623c9 |
| tools | create_app | app | 4cce5a7968e2d016a9ea327983bc38e4cae0fdea9cc20d30f59a247db6c423a5 |
| tools | create_app | region | 8f0f7a6457ffaa94306953f8b7b90f6429b4d37864a258d78679fcb86fd4c229 |
| tools | create_app | space | 9aecdb587e47971c4a785cb113249401443f7e014e89e533f61396c3f781d238 |
| tools | create_app | team | 70e6a51aaef73736dadc4409e348a809c3e9de0b4e4751a7250f2c51cde27fc1 |
| tools | deploy_one_off_dyno | description | 1be6965781bdfe3930e1f9cfc67d01f8e995f08cc4824058aba6bba706662403 |
| tools | deploy_one_off_dyno | command | 46a778d1af4712d2a1c264c27beff6a7376d9ed9da36efce7974b80812e3c635 |
| tools | deploy_one_off_dyno | env | cecd3ade56bfbc918c75cde5ad7a16a9538a8e1d42ca43ed7c556728450fe89a |
| tools | deploy_one_off_dyno | name | e4a96be60b771d63ff344ae4ca2db83b1bbeb03eefabd3306d6e87a636020558 |
| tools | deploy_one_off_dyno | size | b1e9aee7a23ffdb83bb00193bc21cbbc9ff1ba74077e3756a2a873560293a32b |
| tools | deploy_one_off_dyno | sources | c3ff3b40f596093aeaf695e63b1f95d24320b8eac11feb4347ff382ecad1ad2d |
| tools | deploy_one_off_dyno | timeToLive | 46aa75f5a8bd0523fd4992247e6c00a30f4076dee787d4b5b3008eaaeb6eea0f |
| tools | deploy_to_heroku | description | 6ab4f355c660c50cac1656b6ce9f33f96473c0dcae2079aa77c554978577c4d4 |
| tools | deploy_to_heroku | appJson | d942f444e796220db55a80990f45a625b57af4bf8c1a7c6c903790e617100b6d |
| tools | deploy_to_heroku | env | 1e9579120b58f4b40abffa049dda733202df80e3be3e250c27da8355cb64cf4f |
| tools | deploy_to_heroku | internalRouting | 296668d50d90157d700553aac612c931459fb8557a6cb611087cca744b4e4c58 |
| tools | deploy_to_heroku | name | 40b042000e648dcc9ce736ddcae730215458326c3a9475e58f579ba430bce5aa |
| tools | deploy_to_heroku | rootUri | ddbcf25b0c39e7e337cd54d8fd847219393105f48086a7de3bd5cf12c9a445ef |
| tools | deploy_to_heroku | spaceId | e85ba734c0d04b0150e9083ad0525442adfc59739534cd5001621e20a963c4b6 |
| tools | deploy_to_heroku | tarballUri | b5e4120369fc614c2e9c819093a6e9bfd049be6b63aec922cbbecbe8e2d345a1 |
| tools | deploy_to_heroku | teamId | 202e7dae8a06e6935fbdf7dc53a26278d00a6a779fec2e70087e40b346a77e81 |
| tools | get_addon_info | description | 92793dab36d1ff0ade81ac59b9e6de2c083ed0e9a86986d1ae7979484032b116 |
| tools | get_addon_info | addon | ad8b341b18b834cdef6a41c1987995a8cda8fd302799795bf7aaef46a7d9f3b0 |
| tools | get_addon_info | app | 45d232c87ab54000c6b23de289a24bdfd0eb994880fbb879ea52b2a8fc8541a9 |
| tools | get_app_info | description | 7a3ca8307e8b4cbd1127f5d7166c50637f06d83a0abd9b720d679defdbfcdf02 |
| tools | get_app_info | app | 367ee7d2c4d9ef87b5eef319b42b02c0cb284529916fc245d79d2aeabfb565e0 |
| tools | get_app_info | json | cde41e990c09a6a290a65a863f62ce5765362567cb98372a5bb966ac611cc5e7 |
| tools | get_app_logs | description | e8f03812ff859e6ba6596f19712fa0891015f8c29d0e00b1a0e8e555964c4fc4 |
| tools | get_app_logs | app | 210ee895eb455afeaeb59b55c965d59a8587c06ea1ae9f9ada4d8f5f88552340 |
| tools | get_app_logs | dynoName | e6987a1f60f316e3a25c442562aaec4ea95e9b9c62cf768e475f57c2462570a5 |
| tools | get_app_logs | processType | c842967cbfe3262e9d87300fc503c712c99c8f335975de01919da14e777e3195 |
| tools | get_app_logs | source | d13d9ef50562fbc91b9f46200ecc66ad52b697707e514fd168b8f97948ec8f31 |
| tools | list_addon_plans | description | 3b6b4bd9e950f45add8c841afa225af338f5880250e78a163878bcfaff3ea6af |
| tools | list_addon_plans | json | 9c9126f643a90923d0676632d2f4204d86e2ce152384a8d179ec75b0115d0961 |
| tools | list_addon_plans | service | 8b594e172353dbb2c5d8f2d427faee637f9a12b3935ce7b2bf5e322f5a5c1c72 |
| tools | list_addon_services | description | f5f0e8ca03282b26a6f2c71fbe5dd2f79aca249c4cb738ca0e463e56dc9c55a2 |
| tools | list_addon_services | json | 480322b714b8bebc837029d2f3c1740fd43e99f665b8bf3e30931ea1b064d47f |
| tools | list_addons | description | 2c170ca104a962b6eba6daae6dd9894145d37c2ee9e78f295c7c1ff55fdf9d8d |
| tools | list_addons | all | e55a0a219ebfc6ec3d5b8de0e79ead644e3a0a591ccf325893263c3a45417f78 |
| tools | list_addons | app | cccdaa08fda82ffdbbb5297a7d159dca1ebde91ad27c8e38fc7b969637957ba4 |
| tools | list_ai_available_models | description | 7452aaf0f4f03bfdb64d5cdddcd91c053a21d611f34c083e653870b6770c8a8c |
| tools | list_apps | description | dec4d3ca08ca82d7dd75b6a070515bc23542b37e244e454766eac75217a2ea37 |
| tools | list_apps | all | d33519328e93f43bbe579f126f927109d22a63f214edcc2d37fb5662f170cfa2 |
| tools | list_apps | personal | 66c22b9d2e6dcc8c7a8651ca8d8cf728b8eb20bb0e8e5a2da6fa0007541bc0f3 |
| tools | list_apps | space | 28cfad56dbbff4d373a9e4f4c15d71e8b0b0adc70cc02203e550060523944d5a |
| tools | list_apps | team | 85ff082cda8203187f824271e56bdefc69de4371101c999bdd0a5bf26235ce17 |
| tools | list_private_spaces | description | 58f3891893fc752fe57851f5ed1a5ce15276418864337ce9f5dcb6811be68a2b |
| tools | list_private_spaces | json | 841af1777884e5e0c80f224fb7187aacc868c4fb5a0c4edba2f55a5613a39d5f |
| tools | list_teams | description | 1167503086027785f83255c842e509a8d64d54a7e438fc73987864f42d33b069 |
| tools | list_teams | json | 9fe639b11ce788012e52d5242b8463418a2666f73e689d966c29aa0896c486f9 |
| tools | maintenance_off | description | 04945c49158101a656f25a9003c154d0feb178306f3392f91a611eea2cd751f8 |
| tools | maintenance_off | app | d577197287449a19c7587d0155ffbf4f2647aa0f3daa402e8e6585ec6c6b935e |
| tools | maintenance_on | description | 11f087707bd2ade4cdc552209b35885bf1d64665abe5c1e338f4aa70de73a9c4 |
| tools | maintenance_on | app | d577197287449a19c7587d0155ffbf4f2647aa0f3daa402e8e6585ec6c6b935e |
| tools | make_ai_inference | description | 731d0caec0a9d519eaa6f3066557fb5e7d3843ecb4dc1081049612e5656d03fa |
| tools | make_ai_inference | app | e37cba2ed0141c23a2cd9fa1862143becef6ae3a5ce1170e114d0f404c047243 |
| tools | make_ai_inference | json | e4b707ac734031dc0cec48982cda6b24aefce497d27b886df06510f94755e9c4 |
| tools | make_ai_inference | modelResource | 8b2a4be07befbdf438ab99b34506de33fa41ceb67ab2e4473f2baf6564d6974e |
| tools | make_ai_inference | opts | 18a0f50ad3ad400236790c3ded6965878b3765ed22b47587c56955d97a97d20c |
| tools | make_ai_inference | output | 712cc0b9f5153cdb089d8e613e5e01ba205daafa646bd3425ffbf44b35723694 |
| tools | pg_backups | description | 6a23071e3332bc34966aae79529da0c8b1fa0d3837aa92e31b65142b3c8e3acc |
| tools | pg_backups | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_credentials | description | 87db349c6b058ebc0ebe5cc2b04a8adf0d5c343af399374364faf362de776bba |
| tools | pg_credentials | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_credentials | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_info | description | 6dfa3721b6a17766953e970509a58eedb4d41cfabc69b605f224a1d130432dfe |
| tools | pg_info | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_info | database | bc2ed728508bd1f62e41c1cb732bf579b1d459e3d5ce2e12935a56c7a0b1e4a0 |
| tools | pg_kill | description | df6f14a186fac44fdf07aa12f06e257ca522ac8c2cc0d98370720939226b2057 |
| tools | pg_kill | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_kill | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_kill | force | 50fbd9f6c5a768d6bd464926fba650cb6e8de49f4d2943260e5444026fb8a0a3 |
| tools | pg_kill | pid | a357b0f30bc6f8c44ecbe7a39d3ce17516ea90ee1927396d7b7a0797cf6df77e |
| tools | pg_locks | description | 32de05ceafdd032177052588c80de6dca5ec717615686a9e347fa764cfe3686a |
| tools | pg_locks | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_locks | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_locks | truncate | 0091a777675547cc91a21cdb4ec9857e50eaa27d8de40634b6dcce5323833021 |
| tools | pg_maintenance | description | 62bb5dfe9716b418cd06328ebae10982acb1758386b4182691e2eca2870e7db0 |
| tools | pg_maintenance | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_maintenance | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_outliers | description | fe10bba92aa28dd5561618a07f8fb8cf4532d641ea4be243eb742551a3886e13 |
| tools | pg_outliers | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_outliers | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_outliers | num | 5f9938ecac337bec1ce97d62ebb93898b545a44760829e3f18a237cd3e04955b |
| tools | pg_outliers | reset | a788612e52e6d70e33161059ae675405af9f07cd623dad3698dafa081a6a2d84 |
| tools | pg_outliers | truncate | 0091a777675547cc91a21cdb4ec9857e50eaa27d8de40634b6dcce5323833021 |
| tools | pg_ps | description | 047bf9b3c372a87312e0dc90bf27d55baf9ee0510db6ee1c53e299b034546bec |
| tools | pg_ps | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_ps | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_ps | verbose | 0b71653409333c0e804b067e458486fe6155ade5d078c1e5679980dc37a99130 |
| tools | pg_psql | description | 155a2edbfa58adfa49ab5d739b659db002db1a9e641a71f016ea88ebc8042730 |
| tools | pg_psql | app | a8ecdfc2a93f14513fd64c7793ce3db3ec0ee0a21b5b2d0790c4b91432c7c40d |
| tools | pg_psql | command | 19a44494aa612dcd7e5a1745daa0a8e1ccbff0826a5d52ca13a756934dfd7355 |
| tools | pg_psql | credential | b6ed427f3cb384fc846342c858f8e6df70a2a28665a9d0d131f15f4f80c63f28 |
| tools | pg_psql | database | f436f5b3ccb5891341aab59755337ecc86be41569744838072b474f7bdbf459e |
| tools | pg_psql | file | c0e6356730a5c4e0d3006223cffc10680ee3c765b22f49f8ca817aa018838624 |
| tools | pg_upgrade | description | a9c746b085940cd604e4b92659bc3da54f002b7d271a00735d8f5b5e33c28120 |
| tools | pg_upgrade | app | 9fdf0b1003c3eb81df3617f7a2cea05e141680c27d4bd2caf88df5134606fc5a |
| tools | pg_upgrade | confirm | 1300f8dcb8d80b6f0063302ed89e74e30dfa16084e5b2dfe0961466c233aa1d4 |
| tools | pg_upgrade | database | 0c19c3f718bcc82acfc3aa876fc45a7a2c1657f909a12e6fd5210cca334c2422 |
| tools | pg_upgrade | version | 6b851bee388f75b5aa495c514e61bcc6277bd4f4c4fbdbb354d24ad51d953579 |
| tools | pipelines_create | description | 7a1810ed031742d43902707bc9ff93a818012a233f3585d896057a1f694ce035 |
| tools | pipelines_create | app | 96c1f1ec07a2a52c1a088eb723a1918df278ba8f35893a2ed4f4967d468af20b |
| tools | pipelines_create | name | 5ba239395eea1fb6eb46d2daa331cea55664f85758a828ece6561a87058ef35d |
| tools | pipelines_create | stage | ffa7564b5e92da376522b63e029584f4525f6f3cb95c30c7305652087fd1bbf8 |
| tools | pipelines_create | team | 08be084bb223fe0b1c5540bab48dde2ae3522e0822255436fa35a807d824b902 |
| tools | pipelines_info | description | ee729dc60aafe61a1ec46c8a5ee6def95fa938d51747039bd3c379b1087a2602 |
| tools | pipelines_info | json | cfcd0b98b2e02457cbe08f2670d8a14dfedcd8309bf6d953755c34428bbc06f2 |
| tools | pipelines_info | pipeline | d2fbadab142ebb10b987edb5063297a50d5b047badf6ffc98ce078add8e85e51 |
| tools | pipelines_list | description | 998a16c3a2ce5dbdffae6b6091661541c5622c8ae6b5abf85fac8fd4a1990fa3 |
| tools | pipelines_list | json | cfcd0b98b2e02457cbe08f2670d8a14dfedcd8309bf6d953755c34428bbc06f2 |
| tools | pipelines_promote | description | a0b1721fb875b894e94d2c9c6a12cc79bca4589322521aa963046c9d3d3ad49f |
| tools | pipelines_promote | app | a2e32fe7d01a8c9728de73b7d2d869305f6498132dea4c91c658a050e456cd23 |
| tools | pipelines_promote | to | 5ece66f55d54764e751f5180a85c48f711e4b748500572d0600912eab4fc1d21 |
| tools | provision_ai_model | description | 39e7fc80538a840309a36d3394ab99bb81afd07055f8c67d0a665cdfb1c95c84 |
| tools | provision_ai_model | app | 2e4742a39dfd957a17a2b79382f9a8a6b76ddc2305ae926766d1bce34b69e82f |
| tools | provision_ai_model | as | 10270c018bf2c1352b073c8cc01cc7ea3b59584ef6455267b5faa4f5cd7a52f2 |
| tools | provision_ai_model | modelName | b99629853a49a7862d6e63fe7a30a06b8664653ad42a8f7b825e871374750500 |
| tools | ps_list | description | 57d27a234c46f1ac7bcb2950c6aebeef6158c982ef18ce1350119c5663f0daad |
| tools | ps_list | app | 1344ab3c7d098d6d85d86fa8e212fab098e3ecd21f26bd3bde43fded7495cd9c |
| tools | ps_list | json | 6ab308f9b27116d50c9c0133af59b35b3a14756b7862e3b76e0e7f031ceb4e04 |
| tools | ps_restart | description | ecc40f5be345c401bdb7324ec303d58c2fa3cdf1f230c5975a4911c0c4cb9fc7 |
| tools | ps_restart | app | dc628277268c964f52400b73a092cadc8c819f14c12e23b08cc2765a8b8f5d9a |
| tools | ps_restart | dyno-name | f2f4b8e9ee2c3553bf3a74cb08ff82be27966bd895676f2f8a4ea69931d7b3ee |
| tools | ps_restart | process-type | 27247ace1c9dec148a561a8d4da4bc841b23973e7e2cb6d8511214bea31ec985 |
| tools | ps_scale | description | b3924dcc10ab996afe8a9b5756cf2cd740096038ffd9350b211b5f87470d9b8b |
| tools | ps_scale | app | 219a0b7fcd434d06725243970396b4b9be2fe718f185380379bb9b85a8338b30 |
| tools | ps_scale | dyno | a0fe7f76f000386a34fb40cc5a4c27e147d8f797b62b6e31948239162ce5619d |
| tools | rename_app | description | 9fff835236675ea9ce57a2277eb872d7eb69f5b35f40973701be1e271006d7c1 |
| tools | rename_app | app | d092daac8ed307460d9efb4c9c4ab6259635bbd741df8f3a53cb404062cc5825 |
| tools | rename_app | newName | d1458146455eb236b30602f55211b969201fbec119fb383eb2ffad009d31c1e6 |
| tools | transfer_app | description | 66b48d6191482551e5252398d78d18320043a73f5fe74565adbf4cfd04b961c9 |
| tools | transfer_app | app | d82fef382119028ddbf6b6a9df9463a93b4b6a4d32703bf362df2283a6ec2b72 |
| tools | transfer_app | recipient | 9bf8cad069d199dc0f3bee1cfdfba07d44318b0dc6cc2347eea9b42ae36dadf3 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
