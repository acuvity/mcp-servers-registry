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


# What is mcp-server-brightdata?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-brightdata/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-brightdata/1.8.1?logo=docker&logoColor=fff&label=1.8.1)](https://hub.docker.com/r/acuvity/mcp-server-brightdata)
[![PyPI](https://img.shields.io/badge/1.8.1-3775A9?logo=pypi&logoColor=fff&label=@brightdata/mcp)](https://github.com/luminati-io/brightdata-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-brightdata&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22API_TOKEN%22%2C%22-e%22%2C%22BROWSER_AUTH%22%2C%22docker.io%2Facuvity%2Fmcp-server-brightdata%3A1.8.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Discover, extract, and interact with the web - automated access across the public internet.

Packaged by Acuvity from @brightdata/mcp original [sources](https://github.com/luminati-io/brightdata-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-brightdata/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/charts/mcp-server-brightdata/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @brightdata/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/charts/mcp-server-brightdata#minibridge) for Helm charts).


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Bright Data ](https://github.com/luminati-io/brightdata-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @brightdata/mcp ](https://github.com/luminati-io/brightdata-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @brightdata/mcp ](https://github.com/luminati-io/brightdata-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/charts/mcp-server-brightdata)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-brightdata/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.8.1`

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
  - `API_TOKEN` secret to be set as secrets.API_TOKEN either by `.value` or from existing with `.valueFrom`
  - `BROWSER_AUTH` secret to be set as secrets.BROWSER_AUTH either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `WEB_UNLOCKER_ZONE=""` environment variable can be changed with `env.WEB_UNLOCKER_ZONE=""`

# How to install


Install will helm

```console
helm install mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-brightdata
```

From there your MCP server mcp-server-brightdata will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-brightdata` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-brightdata
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-brightdata` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-brightdata oci://docker.io/acuvity/mcp-server-brightdata --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (30)
<details>
<summary>search_engine</summary>

**Description**:

```
Scrape search results from Google, Bing or Yandex. Returns SERP results in markdown (URL, title, description)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| engine | string | not set | No
| query | string | not set | Yes
</details>
<details>
<summary>scrape_as_markdown</summary>

**Description**:

```
Scrape a single webpage URL with advanced options for content extraction and get back the results in MarkDown language. This tool can unlock any webpage even if it uses bot detection or CAPTCHA.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>scrape_as_html</summary>

**Description**:

```
Scrape a single webpage URL with advanced options for content extraction and get back the results in HTML. This tool can unlock any webpage even if it uses bot detection or CAPTCHA.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>session_stats</summary>

**Description**:

```
Tell the user about the tool usage during this session
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>web_data_amazon_product</summary>

**Description**:

```
Quickly read structured amazon product data.
Requires a valid product URL with /dp/ in it.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_amazon_product_reviews</summary>

**Description**:

```
Quickly read structured amazon product review data.
Requires a valid product URL with /dp/ in it.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_person_profile</summary>

**Description**:

```
Quickly read structured linkedin people profile data.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_linkedin_company_profile</summary>

**Description**:

```
Quickly read structured linkedin company profile data
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_zoominfo_company_profile</summary>

**Description**:

```
Quickly read structured ZoomInfo company profile data.
Requires a valid ZoomInfo company URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_profiles</summary>

**Description**:

```
Quickly read structured Instagram profile data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_posts</summary>

**Description**:

```
Quickly read structured Instagram post data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_reels</summary>

**Description**:

```
Quickly read structured Instagram reel data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_instagram_comments</summary>

**Description**:

```
Quickly read structured Instagram comments data.
Requires a valid Instagram URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_posts</summary>

**Description**:

```
Quickly read structured Facebook post data.
Requires a valid Facebook post URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_marketplace_listings</summary>

**Description**:

```
Quickly read structured Facebook marketplace listing data.
Requires a valid Facebook marketplace listing URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_facebook_company_reviews</summary>

**Description**:

```
Quickly read structured Facebook company reviews data.
Requires a valid Facebook company URL and number of reviews.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| num_of_reviews | string | not set | Yes
| url | string | not set | Yes
</details>
<details>
<summary>web_data_x_posts</summary>

**Description**:

```
Quickly read structured X post data.
Requires a valid X post URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_zillow_properties_listing</summary>

**Description**:

```
Quickly read structured zillow properties listing data.
Requires a valid zillow properties listing URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_booking_hotel_listings</summary>

**Description**:

```
Quickly read structured booking hotel listings data.
Requires a valid booking hotel listing URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>web_data_youtube_videos</summary>

**Description**:

```
Quickly read structured YpuTube videos data.
Requires a valid YouTube video URL.
This can be a cache lookup, so it can be more reliable than scraping
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | not set | Yes
</details>
<details>
<summary>scraping_browser_navigate</summary>

**Description**:

```
Navigate a scraping browser session to a new URL
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| url | string | The URL to navigate to | Yes
</details>
<details>
<summary>scraping_browser_go_back</summary>

**Description**:

```
Go back to the previous page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_go_forward</summary>

**Description**:

```
Go forward to the next page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_links</summary>

**Description**:

```
Get all links on the current page, text and selectors
It's strongly recommended that you call the links tool to check that your click target is valid
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_click</summary>

**Description**:

```
Click on an element.
Avoid calling this unless you know the element selector (you can use other tools to find those)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for the element to click | Yes
</details>
<details>
<summary>scraping_browser_type</summary>

**Description**:

```
Type text into an element
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector for the element to type into | Yes
| submit | boolean | Whether to submit the form after typing (press Enter) | No
| text | string | Text to type | Yes
</details>
<details>
<summary>scraping_browser_wait_for</summary>

**Description**:

```
Wait for an element to be visible on the page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| selector | string | CSS selector to wait for | Yes
| timeout | number | Maximum time to wait in milliseconds (default: 30000) | No
</details>
<details>
<summary>scraping_browser_screenshot</summary>

**Description**:

```
Take a screenshot of the current page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| full_page | boolean | Whether to screenshot the full page (default: false)
You should avoid fullscreen if it's not important, since the images can be quite large | No
</details>
<details>
<summary>scraping_browser_get_text</summary>

**Description**:

```
Get the text content of the current page
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>scraping_browser_get_html</summary>

**Description**:

```
Get the HTML content of the current page. Avoid using the full_page option unless it is important to see things like script tags since this can be large
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| full_page | boolean | Whether to get the full page HTML including head and script tags
Avoid this if you only need the extra HTML, since it can be quite large | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | scrape_as_html | description | ccb1fe327d30ca65f76fccdc0ce114d0a96d6769d5c08da818bee2aa0374e4ba |
| tools | scrape_as_markdown | description | 48946c5fc24b9fcf9fbadbd981dd26be62eb3f34f642e1950aa4f01e9db9d9bc |
| tools | scraping_browser_click | description | 9e9459df10de555dc6aedcfcf83c6f24d93f16675d0a62b1150aa15e3c71a1d0 |
| tools | scraping_browser_click | selector | b472eecbbc30b0cf10580e321a828b5b50472aac057c0712023b625869274969 |
| tools | scraping_browser_get_html | description | e9db1ed3982226fa5e634cefeaac3825200257fb26c11720068c9a5c3d28814d |
| tools | scraping_browser_get_html | full_page | 227462f39892944bb89922121fd64f11432bf36046e72adcaaba2df6e402cb73 |
| tools | scraping_browser_get_text | description | da41b92ae44df5399a35b18908cd1ea1c2ccaf5eb058edc749767a9519eaca96 |
| tools | scraping_browser_go_back | description | 1070d603d3951f9282bc8e5111b7a6993fa05215c23ba5099429b567a9bdb467 |
| tools | scraping_browser_go_forward | description | 4f74235e282e3cba526b98047b02c344c6bc32566bb325d5408e897eadfc6a7e |
| tools | scraping_browser_links | description | ad9a62f8931d3317d6627e72de82f4606bab9357cd04d19b7133c81aa4816aa0 |
| tools | scraping_browser_navigate | description | 4dd63c7c00a6ccd7de8df8d4efa78821477c05dd0fe9fee4f9f530a8fbc78ddd |
| tools | scraping_browser_navigate | url | 63d749360d127f3c1d0d108336745c687aaa08760a306f0dadbbef4e9fadf27f |
| tools | scraping_browser_screenshot | description | 769e18b9e5b78a944b15bd8342288959fd92d197631e87a9b6f293a8aa9c7caf |
| tools | scraping_browser_screenshot | full_page | b8634cbc1491ba7afc92714a4c557a81e3ae93ef4cc4ee2568f9c15d1bb4ed22 |
| tools | scraping_browser_type | description | 9cd8fb996ff445688e56e6c500ed27847e27b72c606d5c8174708d92fe8ec726 |
| tools | scraping_browser_type | selector | 8432a6c9577dcae09ef6bd2b0f59c8b350c5e6e0703169193a6639555168f976 |
| tools | scraping_browser_type | submit | 9ad8eef45aadaffc2eceb18d4eded88374b264f66b08c3865109a3d96ba7acac |
| tools | scraping_browser_type | text | 2bf42268dbb30ce1452879e6fdf8c10a259316e899df9c4fb0405b1f0e42fe8c |
| tools | scraping_browser_wait_for | description | dc6f8b68829f63f13684b67baf0e443da64f87e0e4af158f17f798531665b39a |
| tools | scraping_browser_wait_for | selector | 036462863c2f283ab491e0e7b27eaf9d692a530b555b7e805c8841d80ea2e2a3 |
| tools | scraping_browser_wait_for | timeout | 74f20c7f092d948e04cca44c284e61d1fdf8d1a9668dfa5a689ce55bcb15fb32 |
| tools | search_engine | description | 596a407954d04c093fd9ff3adec1ddab4bcdfe214b6c82189a2607c514f9ade5 |
| tools | session_stats | description | a361dcc45d17f9cad5e4b1872ef7ff26d4b355774d5be01159573e9616ac7c76 |
| tools | web_data_amazon_product | description | 65fba1ff50443ee093a32d8301d918bf2b785e736dbb5cb0aadbc76cb889f599 |
| tools | web_data_amazon_product_reviews | description | 8891e947fd3a6e9d47b6ef925dc5976566a78e8e1ede12b2f1e350fea32bbaac |
| tools | web_data_booking_hotel_listings | description | 45efafdd1a85f8985481e45e09c96dd3ae729e5cf7fa467f2288d0ca0f068fde |
| tools | web_data_facebook_company_reviews | description | 47afecccab5540c3e5f1505d4a3d66e5dfbd0c231b796be1d9c28db62b6968c6 |
| tools | web_data_facebook_marketplace_listings | description | 887d03156bd3d324c2cec6bcba737c0d6ee5dd6305cfc86e1821c14cbceaacb4 |
| tools | web_data_facebook_posts | description | 111981d475ce7965823736c78972c7d1d0b07a5bc057af4b1a4e2393719c96b0 |
| tools | web_data_instagram_comments | description | a52e0e54c786ba9c11485ab321afe7e5105a734c7f4bfec3ebd1f708de3d43e5 |
| tools | web_data_instagram_posts | description | 9b186d6fba3efb94bff3bbd0d03580f86c160b15c49aa4da5ee714ee4f675cad |
| tools | web_data_instagram_profiles | description | 6e61b41570fd385d752770d973317ac34f25c655ea490e20ac2f64b0750e97af |
| tools | web_data_instagram_reels | description | a8435edf89782be578fcc1cdecd65f754634f092e3d24bbf86290c265319d791 |
| tools | web_data_linkedin_company_profile | description | ccffa642e9b1120c15f275650d1b685bb127c4a6ea8f6048ddc9061698c59f95 |
| tools | web_data_linkedin_person_profile | description | 652f6bc070db40560b87b14c185a85ead84a45a05840122b0ec5c4e6775ea283 |
| tools | web_data_x_posts | description | 29aae5cb1605b99c1fc5d29e6e8d1d00bccb99963ca7f3522fde9d8786174192 |
| tools | web_data_youtube_videos | description | b55fbbdd0cc2f0dd25a91869e20cd94197422d56f23e41eef1fb968c5e3169e4 |
| tools | web_data_zillow_properties_listing | description | 8e799a15b56be6999cc0634f6276f7c84079cf92e6aa09d62f9ec955e160e25f |
| tools | web_data_zoominfo_company_profile | description | ee4d09fab58d64165808f582046d95685895bb920a2e86954ba0db0918963891 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
