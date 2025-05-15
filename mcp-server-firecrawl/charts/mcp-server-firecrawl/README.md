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


# What is mcp-server-firecrawl?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-firecrawl/1.10.0?logo=docker&logoColor=fff&label=1.10.0)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl)
[![PyPI](https://img.shields.io/badge/1.10.0-3775A9?logo=pypi&logoColor=fff&label=firecrawl-mcp)](https://github.com/mendableai/firecrawl-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-firecrawl&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIRECRAWL_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-firecrawl%3A1.10.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates Firecrawl for web scraping and data extraction.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from firecrawl-mcp original [sources](https://github.com/mendableai/firecrawl-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-firecrawl/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/charts/mcp-server-firecrawl/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure firecrawl-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/charts/mcp-server-firecrawl#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ vrknetha ](https://github.com/mendableai/firecrawl-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ firecrawl-mcp ](https://github.com/mendableai/firecrawl-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ firecrawl-mcp ](https://github.com/mendableai/firecrawl-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/charts/mcp-server-firecrawl)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.10.0`

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
  - `FIRECRAWL_API_KEY` secret to be set as secrets.FIRECRAWL_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-firecrawl
```

From there your MCP server mcp-server-firecrawl will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-firecrawl` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-firecrawl
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-firecrawl` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-firecrawl oci://docker.io/acuvity/mcp-server-firecrawl --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>firecrawl_scrape</summary>

**Description**:

```
Scrape a single webpage with advanced options for content extraction. Supports various formats including markdown, HTML, and screenshots. Can execute custom actions like clicking or scrolling before scraping.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| actions | array | List of actions to perform before scraping | No
| excludeTags | array | HTML tags to exclude from extraction | No
| extract | object | Configuration for structured data extraction | No
| formats | array | Content formats to extract (default: ['markdown']) | No
| includeTags | array | HTML tags to specifically include in extraction | No
| location | object | Location settings for scraping | No
| mobile | boolean | Use mobile viewport | No
| onlyMainContent | boolean | Extract only the main content, filtering out navigation, footers, etc. | No
| removeBase64Images | boolean | Remove base64 encoded images from output | No
| skipTlsVerification | boolean | Skip TLS certificate verification | No
| timeout | number | Maximum time in milliseconds to wait for the page to load | No
| url | string | The URL to scrape | Yes
| waitFor | number | Time in milliseconds to wait for dynamic content to load | No
</details>
<details>
<summary>firecrawl_map</summary>

**Description**:

```
Discover URLs from a starting point. Can use both sitemap.xml and HTML link discovery.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreSitemap | boolean | Skip sitemap.xml discovery and only use HTML links | No
| includeSubdomains | boolean | Include URLs from subdomains in results | No
| limit | number | Maximum number of URLs to return | No
| search | string | Optional search term to filter URLs | No
| sitemapOnly | boolean | Only use sitemap.xml for discovery, ignore HTML links | No
| url | string | Starting URL for URL discovery | Yes
</details>
<details>
<summary>firecrawl_crawl</summary>

**Description**:

```
Start an asynchronous crawl of multiple pages from a starting URL. Supports depth control, path filtering, and webhook notifications.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowBackwardLinks | boolean | Allow crawling links that point to parent directories | No
| allowExternalLinks | boolean | Allow crawling links to external domains | No
| deduplicateSimilarURLs | boolean | Remove similar URLs during crawl | No
| excludePaths | array | URL paths to exclude from crawling | No
| ignoreQueryParameters | boolean | Ignore query parameters when comparing URLs | No
| ignoreSitemap | boolean | Skip sitemap.xml discovery | No
| includePaths | array | Only crawl these URL paths | No
| limit | number | Maximum number of pages to crawl | No
| maxDepth | number | Maximum link depth to crawl | No
| scrapeOptions | object | Options for scraping each page | No
| url | string | Starting URL for the crawl | Yes
| webhook | any | not set | No
</details>
<details>
<summary>firecrawl_check_crawl_status</summary>

**Description**:

```
Check the status of a crawl job.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Crawl job ID to check | Yes
</details>
<details>
<summary>firecrawl_search</summary>

**Description**:

```
Search and retrieve content from web pages with optional scraping. Returns SERP results by default (url, title, description) or full page content when scrapeOptions are provided.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| country | string | Country code for search results (default: us) | No
| filter | string | Search filter | No
| lang | string | Language code for search results (default: en) | No
| limit | number | Maximum number of results to return (default: 5) | No
| location | object | Location settings for search | No
| query | string | Search query string | Yes
| scrapeOptions | object | Options for scraping search results | No
| tbs | string | Time-based search filter | No
</details>
<details>
<summary>firecrawl_extract</summary>

**Description**:

```
Extract structured information from web pages using LLM. Supports both cloud AI and self-hosted LLM extraction.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowExternalLinks | boolean | Allow extraction from external links | No
| enableWebSearch | boolean | Enable web search for additional context | No
| includeSubdomains | boolean | Include subdomains in extraction | No
| prompt | string | Prompt for the LLM extraction | No
| schema | object | JSON schema for structured data extraction | No
| systemPrompt | string | System prompt for LLM extraction | No
| urls | array | List of URLs to extract information from | Yes
</details>
<details>
<summary>firecrawl_deep_research</summary>

**Description**:

```
Conduct deep research on a query using web crawling, search, and AI analysis.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxDepth | number | Maximum depth of research iterations (1-10) | No
| maxUrls | number | Maximum number of URLs to analyze (1-1000) | No
| query | string | The query to research | Yes
| timeLimit | number | Time limit in seconds (30-300) | No
</details>
<details>
<summary>firecrawl_generate_llmstxt</summary>

**Description**:

```
Generate standardized LLMs.txt file for a given URL, which provides context about how LLMs should interact with the website.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxUrls | number | Maximum number of URLs to process (1-100, default: 10) | No
| showFullText | boolean | Whether to show the full LLMs-full.txt in the response | No
| url | string | The URL to generate LLMs.txt from | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | firecrawl_check_crawl_status | description | fd958592fa7c0b7c879345ff20a17e5625fc3f63ff67b11043ba57e4da73f2c6 |
| tools | firecrawl_check_crawl_status | id | 0c614ab04ca020c84254edf880b7833a0d62bff8bf9415ca47e49a42f777d9e9 |
| tools | firecrawl_crawl | description | f0d4336cf6abcddb3a85c5f0444a029709de263898d694f07b65032040a8962f |
| tools | firecrawl_crawl | allowBackwardLinks | e89208c8514c445777f6f590b8028f79141b0e0f3f3b5760775a0b4bf24aa920 |
| tools | firecrawl_crawl | allowExternalLinks | 9121d3a4f83244b94a2e6f6cefb0482f1f2114ece5a36534ff80dc946649d18d |
| tools | firecrawl_crawl | deduplicateSimilarURLs | ade4fa12f79645e177a873522346a5a305a12009ee7087742b7ff0e6d9ae209a |
| tools | firecrawl_crawl | excludePaths | c463218e8a777fb19b5577ab6601667d8106944100bf36b7d303ef468fe83de9 |
| tools | firecrawl_crawl | ignoreQueryParameters | 1054aec6744e6004fe271a995078b368cd3532afb3d19c22b972a717628e3ba8 |
| tools | firecrawl_crawl | ignoreSitemap | cbd443f5ef1c5188e36bfb02a1c0bb72eec39568e644bcd5de4eec5cee921cb6 |
| tools | firecrawl_crawl | includePaths | 8fb12f86d8a110106d8426774860061f765ef8a3fc712d98cc1eac30bc954b77 |
| tools | firecrawl_crawl | limit | aa1a6788da008bc02d96360fd183aaf430a8b2bb57a219290bc8e4eedf63db27 |
| tools | firecrawl_crawl | maxDepth | 0a201647d57160b971527bbc0f0fde20fc39d78c9165a0c4bc2dff14ffb1926e |
| tools | firecrawl_crawl | scrapeOptions | 38715999ad3ca8d678c0eae1d590c6ade0695cb88d98c51990a1b80c43aa6ce4 |
| tools | firecrawl_crawl | url | e954315e5eaf72e34a80734a62b3b8274a01dcd01c68f3b57a1e7aea43785d18 |
| tools | firecrawl_deep_research | description | bf4dffc377bc1e2323c83ad3386f463773537bee8d39250722ee439d1443c3ff |
| tools | firecrawl_deep_research | maxDepth | eb98da0e742e5e82c6d99da220a8753c6d8e402102893b8173b3383cc6debf18 |
| tools | firecrawl_deep_research | maxUrls | 7fecb4a145806af223a4bd609f5be8644fdbe6ae9a902e4cf14a436e08c2bcbb |
| tools | firecrawl_deep_research | query | 52aac1d933892ff9859ca8a3e87375c67fb60049e3842dd9cca0f7a0dd516454 |
| tools | firecrawl_deep_research | timeLimit | c704cf97a8cd413b1b6b7c1ed10220e8dc5eaa5805446f30b10e4f3e6df8a601 |
| tools | firecrawl_extract | description | af02ca4844f3fca5c8ad142685bfb767bbf1c42502047cf71f8e52096db7367f |
| tools | firecrawl_extract | allowExternalLinks | b69d79cf31c44e83b2358c09c5040266e0453e11758832a8c5c7fc5c9836343b |
| tools | firecrawl_extract | enableWebSearch | 19a678682b34d674fad1a87808578fadd5be524a0de91201a13f9ee761b5a81e |
| tools | firecrawl_extract | includeSubdomains | 369755ca36e6dec58e4c61040409951d8e3d2cfc16b961f8397ab9e70c9bd063 |
| tools | firecrawl_extract | prompt | 2d919124fcdd222f16ae9e360b418908ee0ec6c0277d05dd848a5401e46117d2 |
| tools | firecrawl_extract | schema | 2aee66dfa297cbe1272bee515825d7e903694a2dbb63935abbd259db0b117534 |
| tools | firecrawl_extract | systemPrompt | 7830b76b75e88d2a7423a67248ba1dce76831d44c94d22a4e730fc8526f3d3a1 |
| tools | firecrawl_extract | urls | 67f02a9592eb80b2cc81ef7ec464c3dfb0a1ad864f873e653b04abaa61f94e52 |
| tools | firecrawl_generate_llmstxt | description | 56cfb20c853b6e8d572e5956f09df65c74f018231d272db6716e64ae5c1c1d3a |
| tools | firecrawl_generate_llmstxt | maxUrls | 78a560eb7b4a212e8306330ec5044cd7a788851c96dcdcc49b2b8cce3068da43 |
| tools | firecrawl_generate_llmstxt | showFullText | 304bfd7fa89649f2b0f2f1aef5f4a585c45af670dc2064ad93c262f4cbef5bf9 |
| tools | firecrawl_generate_llmstxt | url | b203738b7bf7f16621dccdc62803e29b482260f87faf724876f504efe8b507ac |
| tools | firecrawl_map | description | 1ed29cfb896ee1ddac62b07f7657feebc6e30b8fc24873d2aec98e25d0ba6ee3 |
| tools | firecrawl_map | ignoreSitemap | b5e4d4b0b5648ea5ad5257a2bbc45a0a3fa77087dce3fff059c909a5c42774ce |
| tools | firecrawl_map | includeSubdomains | 04d8854c1155877b00d6cee63f59305e63cf6bedbcc63c0f00ad370d8787c05b |
| tools | firecrawl_map | limit | c26ef1fd854506c4ef24c973b30b67250582d20bb64ce6fd01ae4a67584391e8 |
| tools | firecrawl_map | search | 677570e0fd01ab38e9032dced8f373104dfc504191def1da7e1690fe03e8161c |
| tools | firecrawl_map | sitemapOnly | eb60fc4a14f435377b4ccd594de65f8844ffe92a237625ce9c6c357ff89f3e98 |
| tools | firecrawl_map | url | 80c10d0a28cd868a79e65511b1bf5118737130e3220d3057546b3c6b5bc32c76 |
| tools | firecrawl_scrape | description | 9aab016594f2eca81fb99ed9d25a2a5e3e874dae627c1b3e12189f4a138b6bbd |
| tools | firecrawl_scrape | actions | 921bd53fca4eaef05096a1dfd6aee6f9cfb1824a4f56f4e6aca057a1935cf869 |
| tools | firecrawl_scrape | excludeTags | bc4a10bce1fb2824dd57128af3760d2f375ccb559746491e7c4c186db80799cf |
| tools | firecrawl_scrape | extract | 8eaadf6cdda39b59ae307cd19bc64516732388bb4975cd8049e615c64409671b |
| tools | firecrawl_scrape | formats | d7dc5348bb424a9fcaa52f6e8128d3d42c863d2cd5e2e98bd8e4de8012bf67d6 |
| tools | firecrawl_scrape | includeTags | ec278ffa32508336e94cf9e8982c15209578dcb7789394260467591e2b1b16d9 |
| tools | firecrawl_scrape | location | 5dbc304ef00d86b6ae5638406dc60bdc2678771221b68c72bc064b870ba94ce6 |
| tools | firecrawl_scrape | mobile | 653500e2aa55eb8784f594ebbc9809d34d6cd76dc8cde38b0b09d16d1ccf8a47 |
| tools | firecrawl_scrape | onlyMainContent | 009120be8ac47ec00db7225366084af765798d75926e19e4deb89929e0f8022a |
| tools | firecrawl_scrape | removeBase64Images | 7c6ab3ef581b1baed25a99329da83370665ea25b73745d58b3d475a9f2dbd6c7 |
| tools | firecrawl_scrape | skipTlsVerification | c03ab9d1f3715be2d5f011b0b988ca756f241a2549173c4206203cccb53d569d |
| tools | firecrawl_scrape | timeout | 9d44708ce68333fb1ef65746115d76e74d8a51b5286012c466850ba5e3d7919e |
| tools | firecrawl_scrape | url | 411017ed7507e7e9879b327be68b92dd9bd90e63a4ce7f399e5cc2d792d90db3 |
| tools | firecrawl_scrape | waitFor | 7593fc914b1db5fbb9967c65b14e5ab548dbe5efa58f4022f1c20ee675c1fbb9 |
| tools | firecrawl_search | description | b0f634f112a7c6b27b86526196a4191dceb6da1f85695d71af2c0a9a857328b9 |
| tools | firecrawl_search | country | b45d0cf9d2cf66f30494405b46d2e5d58a507466b6e59397e9f7a06ac0c52083 |
| tools | firecrawl_search | filter | a4018947ed66c967d492cec22784f1cac91a0613e8a63c2b4b3d16f151b3833b |
| tools | firecrawl_search | lang | cda9615ab0341ba35603a4116740d672e235ef4a2407d5389b60b77c11af52d8 |
| tools | firecrawl_search | limit | 67e0339f693dfed4c5829cff9c9bcbac919348c530d4ac6551ef09831c29f6b9 |
| tools | firecrawl_search | location | 38ed24ed60f2228927fd75310d36c807a8590bb5a5cf47503aa9216107178b54 |
| tools | firecrawl_search | query | 8e9ae34f3ab997644b536290b765a6cff69a69cfb1cf9e46595b7a8f9f41d93a |
| tools | firecrawl_search | scrapeOptions | a5957f45245d69d16d807a83ee89aa7f3627c87e6c4649202351dace4f1bf237 |
| tools | firecrawl_search | tbs | 639c9e8fef7415edd99c1090bfc30eaaf6801e1cede480f65be44f2ef58f592d |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
