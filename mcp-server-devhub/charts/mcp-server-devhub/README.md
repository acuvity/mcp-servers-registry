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


# What is mcp-server-devhub?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-devhub/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-devhub/0.3.0?logo=docker&logoColor=fff&label=0.3.0)](https://hub.docker.com/r/acuvity/mcp-server-devhub)
[![PyPI](https://img.shields.io/badge/0.3.0-3775A9?logo=pypi&logoColor=fff&label=devhub-cms-mcp)](https://github.com/devhub/devhub-cms-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-devhub&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22DEVHUB_API_KEY%22%2C%22-e%22%2C%22DEVHUB_API_SECRET%22%2C%22-e%22%2C%22DEVHUB_BASE_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-devhub%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Manage content and operations in DevHub CMS using MCP.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from devhub-cms-mcp original [sources](https://github.com/devhub/devhub-cms-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-devhub/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/charts/mcp-server-devhub/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure devhub-cms-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/charts/mcp-server-devhub#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Author ](https://github.com/devhub/devhub-cms-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ devhub-cms-mcp ](https://github.com/devhub/devhub-cms-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ devhub-cms-mcp ](https://github.com/devhub/devhub-cms-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/charts/mcp-server-devhub)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-devhub/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.3.0`

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
  - `DEVHUB_API_KEY` secret to be set as secrets.DEVHUB_API_KEY either by `.value` or from existing with `.valueFrom`
  - `DEVHUB_API_SECRET` secret to be set as secrets.DEVHUB_API_SECRET either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `DEVHUB_BASE_URL` environment variable to be set by env.DEVHUB_BASE_URL

# How to install


Install will helm

```console
helm install mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-devhub
```

From there your MCP server mcp-server-devhub will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-devhub` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-devhub
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-devhub` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-devhub oci://docker.io/acuvity/mcp-server-devhub --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>get_hours_of_operation</summary>

**Description**:

```
Get the hours of operation for a DevHub location

    Returns a list of items representing days of the week

    Except for the special case formatting, this object is a list of 7 items which represent each day.

    Each day can can have one-four time ranges. For example, two time ranges denotes a "lunch-break". No time ranges denotes closed.

    Examples:
    9am-5pm [["09:00:00", "17:00:00"]]
    9am-12pm and 1pm-5pm [["09:00:00", "12:00:00"], ["13:00:00", "17:00:00"]]
    Closed - an empty list []

    Args:
        location_id: DevHub Location ID
        hours_type: Defaults to 'primary' unless the user specifies a different type
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hours_type | string | not set | No
| location_id | integer | not set | Yes
</details>
<details>
<summary>get_businesses</summary>

**Description**:

```
Get all businesses within the DevHub account

    Returns a list of businesses with the following fields:
    - id: Business ID that can be used in the other tools
    - business_name: Business name

    If only one business exists in the account, you can assume that the user wants to use that business for any business_id related tools.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_locations</summary>

**Description**:

```
Get all locations for a business

    Returns a list of locations with the following fields:
    - id: Location ID that can be used in the other tools
    - location_name: Location name
    - location_url: Location URL in DevHub
    - street: Street address
    - city: City
    - state: State
    - country: Country
    - postal_code: Postal code
    - lat: Latitude
    - lon: Longitude
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| business_id | integer | not set | Yes
</details>
<details>
<summary>update_hours</summary>

**Description**:

```
Update the hours of operation for a DevHub location

    Send a list of items representing days of the week

    Except for the special case formatting, this object is a list of 7 items which represent each day.

    Each day can can have one-four time ranges. For example, two time ranges denotes a "lunch-break". No time ranges denotes closed.

    Examples:
    9am-5pm [["09:00:00", "17:00:00"]]
    9am-12pm and 1pm-5pm [["09:00:00", "12:00:00"], ["13:00:00", "17:00:00"]]
    Closed - an empty list []

    Args:
        location_id: DevHub Location ID
        new_hours: Structured format of the new hours
        hours_type: Defaults to 'primary' unless the user specifies a different type
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| hours_type | string | not set | No
| location_id | integer | not set | Yes
| new_hours | array | not set | Yes
</details>
<details>
<summary>site_from_url</summary>

**Description**:

```
Get the DevHub site ID from a URL.

    Can prompt the user for the URL instead of passing a site_id.

    Returns details about the Site matches the URL that can be used in the other tools.
    - Site ID: ID of the DevHub site
    - Site URL: URL of the DevHub site
    - Site Location IDs: List of location IDs associated with the site

    Args:
        url: URL of the DevHub site, all lowercase and ends with a slash
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>upload_image</summary>

**Description**:

```
Upload an image to the DevHub media gallery

    Supports webp, jpeg and png images

    Args:
        base64_image_content: Base 64 encoded content of the image file
        filename: Filename including the extension
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base64_image_content | string | not set | Yes
| filename | string | not set | Yes
</details>
<details>
<summary>get_blog_post</summary>

**Description**:

```
Get a single blog post

    Args:
        post_id: Blog post id
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| post_id | integer | not set | Yes
</details>
<details>
<summary>create_blog_post</summary>

**Description**:

```
Create a new blog post

    Args:
        site_id: Website ID where the post will be published. Prompt the user for this ID.
        title: Blog post title
        content: HTML content of blog post. Should not include a <h1> tag, only h2+
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | Yes
| site_id | integer | not set | Yes
| title | string | not set | Yes
</details>
<details>
<summary>update_blog_post</summary>

**Description**:

```
Update a single blog post

    Args:
        post_id: Blog post ID
        title: Blog post title
        content: HTML content of blog post. Should not include a <h1> tag, only h2+
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| content | string | not set | No
| post_id | integer | not set | Yes
| title | string | not set | No
</details>
<details>
<summary>get_nearest_location</summary>

**Description**:

```
Get the nearest DevHub location

    Args:
        business_id: DevHub Business ID associated with the location. Prompt the user for this ID
        latitude: Latitude of the location
        longitude: Longitude of the location
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| business_id | integer | not set | Yes
| latitude | number | not set | Yes
| longitude | number | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_blog_post | description | 9e39fbe4f8a7ac6401cf20a346550d90f1dc92afdb9c443939d4a9067f6a8751 |
| tools | get_blog_post | description | 871f9785dccca0da160cf2f62af387303ce45d7a74fac831819388650d399ec8 |
| tools | get_businesses | description | 86b9d98b2e4c8166181626185561b4987e06d267f6402d0238d06e77f91d952b |
| tools | get_hours_of_operation | description | 23e21cb76d1da66b30d8a5e508c714865ce164ca7ae403c69a9af895558d9f28 |
| tools | get_locations | description | 621b4235ef8d26c795d37799148d6d2210a4694fa3cd392fbe2b072584e9eb69 |
| tools | get_nearest_location | description | 55b3ad22cc6a57aa822c3b4580d309ed113f11b5d49ce09008571b1b601c0f9d |
| tools | site_from_url | description | 6fe1b9682bb8f0862fbc692516a2460656da288943ef82258c249b5e24fc3ad0 |
| tools | update_blog_post | description | f404f48ef275837efeaf11092055b954cb470e62f086379370ef36268a0b8e61 |
| tools | update_hours | description | c3c77feafaa539b2cc464e8cdca1edd396646478c172eaabe38d2781ad25a4bf |
| tools | upload_image | description | d09cf5af3e7579af477b3f7652288da152948d0d02c6e9be0c8d1244924f4c69 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
