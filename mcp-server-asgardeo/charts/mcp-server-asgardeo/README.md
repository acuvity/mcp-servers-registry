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


# What is mcp-server-asgardeo?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-asgardeo/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-asgardeo/v0.1.0?logo=docker&logoColor=fff&label=v0.1.0)](https://hub.docker.com/r/acuvity/mcp-server-asgardeo)
[![GitHUB](https://img.shields.io/badge/v0.1.0-3775A9?logo=github&logoColor=fff&label=asgardeo/asgardeo-mcp-server)](https://github.com/asgardeo/asgardeo-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-asgardeo/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-asgardeo&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ASGARDEO_BASE_URL%22%2C%22-e%22%2C%22ASGARDEO_CLIENT_ID%22%2C%22-e%22%2C%22ASGARDEO_CLIENT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-asgardeo%3Av0.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server to interact with your Asgardeo organization through LLM tools.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from asgardeo/asgardeo-mcp-server original [sources](https://github.com/asgardeo/asgardeo-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-asgardeo/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/charts/mcp-server-asgardeo/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure asgardeo/asgardeo-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ asgardeo ](https://github.com/asgardeo/asgardeo-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ asgardeo/asgardeo-mcp-server ](https://github.com/asgardeo/asgardeo-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ asgardeo/asgardeo-mcp-server ](https://github.com/asgardeo/asgardeo-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/charts/mcp-server-asgardeo)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-v0.1.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-asgardeo:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-asgardeo:1.0.0-v0.1.0`

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
  - `ASGARDEO_CLIENT_ID` secret to be set as secrets.ASGARDEO_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `ASGARDEO_CLIENT_SECRET` secret to be set as secrets.ASGARDEO_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `ASGARDEO_BASE_URL` environment variable to be set by env.ASGARDEO_BASE_URL

# How to install


Install will helm

```console
helm install mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-asgardeo
```

From there your MCP server mcp-server-asgardeo will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-asgardeo` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-asgardeo
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-asgardeo` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>authorize_api</summary>

**Description**:

```
Authorize Asgardeo API
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appId | string | This is the id of the application. | Yes
| id | string | This is the id of the API resource to be authorized. | Yes
| policyIdentifier | string | This indicates the authorization policy of the API authorization. | Yes
| scopes | array | This is the list of scope names for the API resource. | Yes
</details>
<details>
<summary>create_api_resource</summary>

**Description**:

```
Create an API Resource in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | This is the identifier for the API resource. | Yes
| name | string | This is the name of the API resource. | Yes
| requiresAuthorization | boolean | This indicates whether the API resource requires authorization. | Yes
| scopes | array | This is the list of scopes for the API resource. Eg: [{"name": "scope1", "displayName": "Scope 1", "description": "Description for scope 1"}, {"name": "scope2", "displayName": "Scope 2", "description": "Description for scope 2"}] | Yes
</details>
<details>
<summary>create_m2m_app</summary>

**Description**:

```
Create a new M2M Application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
</details>
<details>
<summary>create_mobile_app</summary>

**Description**:

```
Create a new Mobile Application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
| redirect_url | string | Redirect URL of the application | Yes
</details>
<details>
<summary>create_single_page_app</summary>

**Description**:

```
Create a new Single Page Application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
| redirect_url | string | Redirect URL of the application | Yes
</details>
<details>
<summary>create_user</summary>

**Description**:

```
Create a user in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| email | string | This is the email of the user. | Yes
| first_name | string | This is the first name of the user. | Yes
| last_name | string | This is the last name of the user. | Yes
| password | string | This is the password of the user. Eg; atGHL1234# | Yes
| username | string | This is the username of the user. This should be an email address. | Yes
| userstore_domain | string | This is the userstore domain of the user. | No
</details>
<details>
<summary>create_webapp_with_ssr</summary>

**Description**:

```
Create a new regular web application that implements server side rendring in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
| redirect_url | string | Redirect URL of the application | Yes
</details>
<details>
<summary>get_api_resource_by_identifier</summary>

**Description**:

```
Get API Resource registered in Asgardeo by identifier
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | This is the identifier of the API resource. | Yes
</details>
<details>
<summary>get_application_by_client_id</summary>

**Description**:

```
Get details of an application by client ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| client_id | string | Client ID of the application | Yes
</details>
<details>
<summary>get_application_by_name</summary>

**Description**:

```
Get details of an application by name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
</details>
<details>
<summary>list_api_resources</summary>

**Description**:

```
List API Resources registered in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | Base64 encoded cursor value for forward pagination. | No
| before | string | Base64 encoded cursor value for backward pagination. | No
| filter | string | Filter expression to apply, e.g., name eq Payments API, identifier eq payments_api. Supports 'sw', 'co', 'ew' and 'eq' operations. | No
| limit | number | The maximum number of results to return. It is recommended to set this value to 100 or less. | No
</details>
<details>
<summary>list_applications</summary>

**Description**:

```
List all applications in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_authorized_api</summary>

**Description**:

```
List authorized API resources of an application
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_id | string | This is the id of the application. | Yes
</details>
<details>
<summary>list_claims</summary>

**Description**:

```
List all claims in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>search_api_resources_by_name</summary>

**Description**:

```
Search API Resources registered in Asgardeo by name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | This is the name of the API resource. | Yes
</details>
<details>
<summary>update_application_basic_info</summary>

**Description**:

```
Update basic information of an application
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| access_url | string | Access URL of the application | No
| description | string | Description of the application | No
| id | string | ID of the application | Yes
| image_url | string | URL of the application image icon | No
| logout_return_url | string | A URL of the application to return upon logout | No
| name | string | Name of the application | No
</details>
<details>
<summary>update_application_claim_config</summary>

**Description**:

```
Update claim configurations of an application.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| claims | array | List of claims to be added as requested claims in the application. Eg: list of URIs like http://wso2.org/claims/username, http://wso2.org/claims/emailaddress | Yes
| id | string | ID of the application | Yes
</details>
<details>
<summary>update_application_oauth_config</summary>

**Description**:

```
Update OAuth/OIDC configurations of an application
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| access_token_attributes | array | Access token attributes | No
| allowed_origins | array | Allowed origins for CORS | No
| application_access_token_expiry_time | number | Expiry time of the access token issued on behalf of the application | No
| id | string | ID of the application | Yes
| redirect_urls | array | Redirect URLs of the application | No
| refresh_token_expiry_time | number | Expiry time of the refresh token | No
| revoke_tokens_when_idp_session_terminated | boolean | Revoke tokens when IDP session is terminated | No
| user_access_token_expiry_time | number | Expiry time of the access token issued on behalf of the user | No
</details>
<details>
<summary>update_login_flow</summary>

**Description**:

```
Update login flow in an application for given user prompt.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_id | string | This is the id of the application for which the login flow is updated. | Yes
| user_prompt | string | This is the user prompt for the login flow. Eg: "Username and password as first factor and Email OTP as second factor" | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
