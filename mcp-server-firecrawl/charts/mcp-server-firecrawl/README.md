<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://acuvity.ai/wp-content/uploads/2025/09/1.-Acuvity-Logo-Black-scaled-e1758135197226.png" height="90" alt="Acuvity logo"/>
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
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-firecrawl/3.7.4?logo=docker&logoColor=fff&label=3.7.4)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl)
[![PyPI](https://img.shields.io/badge/3.7.4-3775A9?logo=pypi&logoColor=fff&label=firecrawl-mcp)](https://github.com/mendableai/firecrawl-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-firecrawl/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-firecrawl&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIRECRAWL_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-firecrawl%3A3.7.4%22%5D%2C%22command%22%3A%22docker%22%7D)

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

### 📦 Isolated Immutable Sandbox

| Feature                   | Description                                                                                                            |
|---------------------------|------------------------------------------------------------------------------------------------------------------------|
| Isolated Execution        | All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.         |
| Non-root by Default       | Enforces least-privilege principles, minimizing the impact of potential security breaches.                              |
| Read-only Filesystem      | Ensures runtime immutability, preventing unauthorized modification.                                                     |
| Version Pinning           | Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.                  |
| CVE Scanning              | Continuously scans images for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation. |
| SBOM & Provenance         | Delivers full supply chain transparency by embedding metadata and traceable build information.                          |
| Container Signing (Cosign) | Implements image signing using [Cosign](https://github.com/sigstore/cosign) to ensure integrity and authenticity of container images.                             |

### 🛡️ Runtime Security and Guardrails

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-firecrawl#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


| Guardrail                        | Summary                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `resource integrity`             | Embeds a hash of all exposed resources to ensure their authenticity and prevent unauthorized modifications, guarding against supply chain attacks and dynamic alterations of tool metadata. |
| `covert-instruction-detection`   | Detects hidden or obfuscated directives in requests.                    |
| `sensitive-pattern-detection`    | Flags patterns suggesting sensitive data or filesystem exposure.        |
| `shadowing-pattern-detection`    | Identifies tool descriptions that override or influence others.         |
| `schema-misuse-prevention`       | Enforces strict schema compliance on input data.                        |
| `cross-origin-tool-access`       | Controls calls to external services or APIs.                            |
| `secrets-redaction`              | Prevents exposure of credentials or sensitive values.                   |
| `basic authentication`           | Enables the configuration of a shared secret to restrict unauthorized access to the MCP server and ensure only approved clients can connect. |

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

> [!NOTE]
> By default, all guardrails except `resource integrity` are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ firecrawl ](https://github.com/mendableai/firecrawl-mcp-server) for application

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
  - container: `1.0.0-3.7.4`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-firecrawl:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-firecrawl:1.0.0-3.7.4`

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

Scrape content from a single URL with advanced options. 
This is the most powerful, fastest and most reliable scraper tool, if available you should always default to using this tool for any web scraping needs.

**Best for:** Single page content extraction, when you know exactly which page contains the information.
**Not recommended for:** Multiple pages (use batch_scrape), unknown page (use search), structured data (use extract).
**Common mistakes:** Using scrape for a list of URLs (use batch_scrape instead). If batch scrape doesnt work, just use scrape and call it multiple times.
**Other Features:** Use 'branding' format to extract brand identity (colors, fonts, typography, spacing, UI components) for design analysis or style replication.
**Prompt Example:** "Get the content of the page at https://example.com."
**Usage Example:**
```json
{
  "name": "firecrawl_scrape",
  "arguments": {
    "url": "https://example.com",
    "formats": ["markdown"],
    "maxAge": 172800000
  }
}
```
**Performance:** Add maxAge parameter for 500% faster scrapes using cached data.
**Returns:** Markdown, HTML, or other formats as specified.


```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| actions | array | not set | No
| excludeTags | array | not set | No
| formats | array | not set | No
| includeTags | array | not set | No
| location | object | not set | No
| maxAge | number | not set | No
| mobile | boolean | not set | No
| onlyMainContent | boolean | not set | No
| parsers | array | not set | No
| proxy | string | not set | No
| removeBase64Images | boolean | not set | No
| skipTlsVerification | boolean | not set | No
| storeInCache | boolean | not set | No
| url | string | not set | Yes
| waitFor | number | not set | No
| zeroDataRetention | boolean | not set | No
</details>
<details>
<summary>firecrawl_map</summary>

**Description**:

```

Map a website to discover all indexed URLs on the site.

**Best for:** Discovering URLs on a website before deciding what to scrape; finding specific sections of a website.
**Not recommended for:** When you already know which specific URL you need (use scrape or batch_scrape); when you need the content of the pages (use scrape after mapping).
**Common mistakes:** Using crawl to discover URLs instead of map.
**Prompt Example:** "List all URLs on example.com."
**Usage Example:**
```json
{
  "name": "firecrawl_map",
  "arguments": {
    "url": "https://example.com"
  }
}
```
**Returns:** Array of URLs found on the site.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ignoreQueryParameters | boolean | not set | No
| includeSubdomains | boolean | not set | No
| limit | number | not set | No
| search | string | not set | No
| sitemap | string | not set | No
| url | string | not set | Yes
</details>
<details>
<summary>firecrawl_search</summary>

**Description**:

```

Search the web and optionally extract content from search results. This is the most powerful web search tool available, and if available you should always default to using this tool for any web search needs.

The query also supports search operators, that you can use if needed to refine the search:
| Operator | Functionality | Examples |
---|-|-|
| `""` | Non-fuzzy matches a string of text | `"Firecrawl"`
| `-` | Excludes certain keywords or negates other operators | `-bad`, `-site:firecrawl.dev`
| `site:` | Only returns results from a specified website | `site:firecrawl.dev`
| `inurl:` | Only returns results that include a word in the URL | `inurl:firecrawl`
| `allinurl:` | Only returns results that include multiple words in the URL | `allinurl:git firecrawl`
| `intitle:` | Only returns results that include a word in the title of the page | `intitle:Firecrawl`
| `allintitle:` | Only returns results that include multiple words in the title of the page | `allintitle:firecrawl playground`
| `related:` | Only returns results that are related to a specific domain | `related:firecrawl.dev`
| `imagesize:` | Only returns images with exact dimensions | `imagesize:1920x1080`
| `larger:` | Only returns images larger than specified dimensions | `larger:1920x1080`

**Best for:** Finding specific information across multiple websites, when you don't know which website has the information; when you need the most relevant content for a query.
**Not recommended for:** When you need to search the filesystem. When you already know which website to scrape (use scrape); when you need comprehensive coverage of a single website (use map or crawl.
**Common mistakes:** Using crawl or map for open-ended questions (use search instead).
**Prompt Example:** "Find the latest research papers on AI published in 2023."
**Sources:** web, images, news, default to web unless needed images or news.
**Scrape Options:** Only use scrapeOptions when you think it is absolutely necessary. When you do so default to a lower limit to avoid timeouts, 5 or lower.
**Optimal Workflow:** Search first using firecrawl_search without formats, then after fetching the results, use the scrape tool to get the content of the relevantpage(s) that you want to scrape

**Usage Example without formats (Preferred):**
```json
{
  "name": "firecrawl_search",
  "arguments": {
    "query": "top AI companies",
    "limit": 5,
    "sources": [
      "web"
    ]
  }
}
```
**Usage Example with formats:**
```json
{
  "name": "firecrawl_search",
  "arguments": {
    "query": "latest AI research papers 2023",
    "limit": 5,
    "lang": "en",
    "country": "us",
    "sources": [
      "web",
      "images",
      "news"
    ],
    "scrapeOptions": {
      "formats": ["markdown"],
      "onlyMainContent": true
    }
  }
}
```
**Returns:** Array of search results (with optional scraped content).

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| enterprise | array | not set | No
| filter | string | not set | No
| limit | number | not set | No
| location | string | not set | No
| query | string | not set | Yes
| scrapeOptions | object | not set | No
| sources | array | not set | No
| tbs | string | not set | No
</details>
<details>
<summary>firecrawl_crawl</summary>

**Description**:

```

 Starts a crawl job on a website and extracts content from all pages.
 
 **Best for:** Extracting content from multiple related pages, when you need comprehensive coverage.
 **Not recommended for:** Extracting content from a single page (use scrape); when token limits are a concern (use map + batch_scrape); when you need fast results (crawling can be slow).
 **Warning:** Crawl responses can be very large and may exceed token limits. Limit the crawl depth and number of pages, or use map + batch_scrape for better control.
 **Common mistakes:** Setting limit or maxDiscoveryDepth too high (causes token overflow) or too low (causes missing pages); using crawl for a single page (use scrape instead). Using a /* wildcard is not recommended.
 **Prompt Example:** "Get all blog posts from the first two levels of example.com/blog."
 **Usage Example:**
 ```json
 {
   "name": "firecrawl_crawl",
   "arguments": {
     "url": "https://example.com/blog/*",
     "maxDiscoveryDepth": 5,
     "limit": 20,
     "allowExternalLinks": false,
     "deduplicateSimilarURLs": true,
     "sitemap": "include"
   }
 }
 ```
 **Returns:** Operation ID for status checking; use firecrawl_check_crawl_status to check progress.
 
 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowExternalLinks | boolean | not set | No
| allowSubdomains | boolean | not set | No
| crawlEntireDomain | boolean | not set | No
| deduplicateSimilarURLs | boolean | not set | No
| delay | number | not set | No
| excludePaths | array | not set | No
| ignoreQueryParameters | boolean | not set | No
| includePaths | array | not set | No
| limit | number | not set | No
| maxConcurrency | number | not set | No
| maxDiscoveryDepth | number | not set | No
| prompt | string | not set | No
| scrapeOptions | object | not set | No
| sitemap | string | not set | No
| url | string | not set | Yes
| webhook | any | not set | No
</details>
<details>
<summary>firecrawl_check_crawl_status</summary>

**Description**:

```

Check the status of a crawl job.

**Usage Example:**
```json
{
  "name": "firecrawl_check_crawl_status",
  "arguments": {
    "id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```
**Returns:** Status and progress of the crawl job, including results if available.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>
<details>
<summary>firecrawl_extract</summary>

**Description**:

```

Extract structured information from web pages using LLM capabilities. Supports both cloud AI and self-hosted LLM extraction.

**Best for:** Extracting specific structured data like prices, names, details from web pages.
**Not recommended for:** When you need the full content of a page (use scrape); when you're not looking for specific structured data.
**Arguments:**
- urls: Array of URLs to extract information from
- prompt: Custom prompt for the LLM extraction
- schema: JSON schema for structured data extraction
- allowExternalLinks: Allow extraction from external links
- enableWebSearch: Enable web search for additional context
- includeSubdomains: Include subdomains in extraction
**Prompt Example:** "Extract the product name, price, and description from these product pages."
**Usage Example:**
```json
{
  "name": "firecrawl_extract",
  "arguments": {
    "urls": ["https://example.com/page1", "https://example.com/page2"],
    "prompt": "Extract product information including name, price, and description",
    "schema": {
      "type": "object",
      "properties": {
        "name": { "type": "string" },
        "price": { "type": "number" },
        "description": { "type": "string" }
      },
      "required": ["name", "price"]
    },
    "allowExternalLinks": false,
    "enableWebSearch": false,
    "includeSubdomains": false
  }
}
```
**Returns:** Extracted structured data as defined by your schema.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowExternalLinks | boolean | not set | No
| enableWebSearch | boolean | not set | No
| includeSubdomains | boolean | not set | No
| prompt | string | not set | No
| schema | object | not set | No
| urls | array | not set | Yes
</details>
<details>
<summary>firecrawl_agent</summary>

**Description**:

```

Autonomous web data gathering agent. Describe what data you want, and the agent searches, navigates, and extracts it from anywhere on the web.

**Best for:** Complex data gathering tasks where you don't know the exact URLs; research tasks requiring multiple sources; finding data in hard-to-reach places.
**Not recommended for:** Simple single-page scraping (use scrape); when you already know the exact URL (use scrape or extract).
**Key advantages over extract:**
- No URLs required - just describe what you need
- Autonomously searches and navigates the web
- Faster and more cost-effective for complex tasks
- Higher reliability for varied queries

**Arguments:**
- prompt: Natural language description of the data you want (required, max 10,000 characters)
- urls: Optional array of URLs to focus the agent on specific pages
- schema: Optional JSON schema for structured output

**Prompt Example:** "Find the founders of Firecrawl and their backgrounds"
**Usage Example (no URLs):**
```json
{
  "name": "firecrawl_agent",
  "arguments": {
    "prompt": "Find the top 5 AI startups founded in 2024 and their funding amounts",
    "schema": {
      "type": "object",
      "properties": {
        "startups": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "funding": { "type": "string" },
              "founded": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```
**Usage Example (with URLs):**
```json
{
  "name": "firecrawl_agent",
  "arguments": {
    "urls": ["https://docs.firecrawl.dev", "https://firecrawl.dev/pricing"],
    "prompt": "Compare the features and pricing information from these pages"
  }
}
```
**Returns:** Extracted data matching your prompt/schema, plus credits used.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt | string | not set | Yes
| schema | object | not set | No
| urls | array | not set | No
</details>
<details>
<summary>firecrawl_agent_status</summary>

**Description**:

```

Check the status of an agent job.

**Usage Example:**
```json
{
  "name": "firecrawl_agent_status",
  "arguments": {
    "id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```
**Possible statuses:**
- processing: Agent is still working
- completed: Extraction finished successfully
- failed: An error occurred

**Returns:** Status, progress, and results (if completed) of the agent job.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | firecrawl_agent | description | b02374bb87d60f67a3b73d30a8934279dde6bdc56f4318b0bae77bf8ddc1ea1c |
| tools | firecrawl_agent_status | description | b7ccb553a02a7a5fc6f2966aea638ee736f829b60989737a5022a8eaa4ccf3ea |
| tools | firecrawl_check_crawl_status | description | b203ead94aae907fe82506e9a27415571fcdcfc37443f3e9139e675032de1ca7 |
| tools | firecrawl_crawl | description | dd06ade8893a0fdfb59db62309f483714fd4ef9075660e50830435d531df7cb7 |
| tools | firecrawl_extract | description | 4d1e1af8ded9e112fa750ae6538321861de40150a5de14774d30920ef61cfe4a |
| tools | firecrawl_map | description | f1889673ef441a4485805204021eebd8d373c2ac49871d2ade46a7cd70c422ba |
| tools | firecrawl_scrape | description | ee58f6ff53532d74731be3215d8922c8cec1f0875f994667bd8b5b8450bda948 |
| tools | firecrawl_search | description | dd960026a92d9b910741ea123119ef6783776ce19c28c8d67620adcc05b1ab0f |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
