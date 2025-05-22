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


# What is mcp-server-oxylabs?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-oxylabs/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-oxylabs/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-oxylabs)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=oxylabs-mcp)](https://github.com/oxylabs/oxylabs-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-oxylabs/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-oxylabs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22OXYLABS_PASSWORD%22%2C%22-e%22%2C%22OXYLABS_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-oxylabs%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Scrapes web data for AI applications using the Model Context Protocol.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from oxylabs-mcp original [sources](https://github.com/oxylabs/oxylabs-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-oxylabs/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/charts/mcp-server-oxylabs/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure oxylabs-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Augis Braziunas <augis.braziunas@oxylabs.io>, Rostyslav Borovyk <rostyslav.borovyk@oxylabs.io> ](https://github.com/oxylabs/oxylabs-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ oxylabs-mcp ](https://github.com/oxylabs/oxylabs-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ oxylabs-mcp ](https://github.com/oxylabs/oxylabs-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/charts/mcp-server-oxylabs)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-oxylabs/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-oxylabs:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-oxylabs:1.0.0-0.2.0`

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
  - `OXYLABS_PASSWORD` secret to be set as secrets.OXYLABS_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `OXYLABS_USERNAME` environment variable to be set by env.OXYLABS_USERNAME

# How to install


Install will helm

```console
helm install mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-oxylabs
```

From there your MCP server mcp-server-oxylabs will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-oxylabs` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-oxylabs
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-oxylabs` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-oxylabs oci://docker.io/acuvity/mcp-server-oxylabs --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (4)
<details>
<summary>universal_scraper</summary>

**Description**:

```
Get a content of any webpage.

    Supports browser rendering, parsing of certain webpages
    and different output formats.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| url | string | Website url to scrape. | Yes
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>
<details>
<summary>google_search_scraper</summary>

**Description**:

```
Scrape Google Search results.

    Supports content parsing, different user agent types, pagination,
    domain, geolocation, locale parameters and different output formats.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ad_mode | boolean | If true will use the Google Ads source optimized for the paid ads. | No
| domain | string | 
        Domain localization for Google.
        Use country top level domains.
        For example:
            - 'co.uk' for United Kingdom
            - 'us' for United States
            - 'fr' for France
         | No
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| limit | integer | Number of results to retrieve in each page. | No
| locale | string | 
        Set 'Accept-Language' header value which changes your Google search page web interface language.
        Examples:
            - 'en-US' for English, United States
            - 'de-AT' for German, Austria
            - 'fr-FR' for French, France
         | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| pages | integer | Number of pages to retrieve. | No
| parse | boolean | Should result be parsed. If the result is not parsed, the output_format parameter is applied. | No
| query | string | URL-encoded keyword to search for. | Yes
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| start_page | integer | Starting page number. | No
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>
<details>
<summary>amazon_search_scraper</summary>

**Description**:

```
Scrape Amazon search results.

    Supports content parsing, different user agent types, pagination,
    domain, geolocation, locale parameters and different output formats.
    Supports Amazon specific parameters such as category id, merchant id, currency.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category_id | string | Search for items in a particular browse node (product category). | No
| currency | string | Currency that will be used to display the prices. | No
| domain | string | 
        Domain localization for Google.
        Use country top level domains.
        For example:
            - 'co.uk' for United Kingdom
            - 'us' for United States
            - 'fr' for France
         | No
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| locale | string | 
        Set 'Accept-Language' header value which changes your Google search page web interface language.
        Examples:
            - 'en-US' for English, United States
            - 'de-AT' for German, Austria
            - 'fr-FR' for French, France
         | No
| merchant_id | string | Search for items sold by a particular seller. | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| pages | integer | Number of pages to retrieve. | No
| parse | boolean | Should result be parsed. If the result is not parsed, the output_format parameter is applied. | No
| query | string | Keyword to search for. | Yes
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| start_page | integer | Starting page number. | No
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>
<details>
<summary>amazon_product_scraper</summary>

**Description**:

```
Scrape Amazon products.

    Supports content parsing, different user agent types, domain,
    geolocation, locale parameters and different output formats.
    Supports Amazon specific parameters such as currency and getting
    more accurate pricing data with auto select variant.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| autoselect_variant | boolean | To get accurate pricing/buybox data, set this parameter to true. | No
| currency | string | Currency that will be used to display the prices. | No
| domain | string | 
        Domain localization for Google.
        Use country top level domains.
        For example:
            - 'co.uk' for United Kingdom
            - 'us' for United States
            - 'fr' for France
         | No
| geo_location | string | 
        The geographical location that the result should be adapted for.
        Use ISO-3166 country codes.
        Examples:
            - 'California, United States'
            - 'Mexico'
            - 'US' for United States
            - 'DE' for Germany
            - 'FR' for France
         | No
| locale | string | 
        Set 'Accept-Language' header value which changes your Google search page web interface language.
        Examples:
            - 'en-US' for English, United States
            - 'de-AT' for German, Austria
            - 'fr-FR' for French, France
         | No
| output_format | string | 
        The format of the output. Works only when parse parameter is false.
            - links - Most efficient when the goal is navigation or finding specific URLs. Use this first when you need to locate a specific page within a website.
            - md - Best for extracting and reading visible content once you've found the right page. Use this to get structured content that's easy to read and process.
            - html - Should be used sparingly only when you need the raw HTML structure, JavaScript code, or styling information.
         | No
| parse | boolean | Should result be parsed. If the result is not parsed, the output_format parameter is applied. | No
| query | string | Keyword to search for. | Yes
| render | string | 
        Whether a headless browser should be used to render the page.
        For example:
            - 'html' when browser is required to render the page.
         | No
| user_agent_type | string | Device type and browser that will be used to determine User-Agent header value. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | amazon_product_scraper | description | 556ffee33f9b5f0f3da719d7b1b7c37fa398d92b63ad77bfbc024922468e2594 |
| tools | amazon_product_scraper | autoselect_variant | 3578e27b85b918f331e2cb209a684c24839013acd3eaf037f6ba46680214118c |
| tools | amazon_product_scraper | currency | aa5edb7592bad79e700e4134bdfeb65bf2b6c96c81ac459cc1b8d9197101f1e4 |
| tools | amazon_product_scraper | domain | dbd1f8b171d5449998fb7d55dbc8f3baf6867aec480ff864799d805a4563d142 |
| tools | amazon_product_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | amazon_product_scraper | locale | cdbb6d79df927f48d9866b4ac1d085c581cf4f1286fa9b2332be8650326d8079 |
| tools | amazon_product_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | amazon_product_scraper | parse | c27cc9870b8d21da98e8a4a1efc1aeed03266a9adec16794037c90a0c4b25e97 |
| tools | amazon_product_scraper | query | 2b7bab00754c254fbe9efbf66ea830cb4573faeea75fdbd269801084ef67b584 |
| tools | amazon_product_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | amazon_product_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |
| tools | amazon_search_scraper | description | b026096a4c93afe5c9ab78ec43196cc26c0325f5c7d36e637e4f09a1651e3dbf |
| tools | amazon_search_scraper | category_id | 384916ff38c65e7481cc6da4e72d0bb534aafd6b5d10246966301238ae8eb1ba |
| tools | amazon_search_scraper | currency | aa5edb7592bad79e700e4134bdfeb65bf2b6c96c81ac459cc1b8d9197101f1e4 |
| tools | amazon_search_scraper | domain | dbd1f8b171d5449998fb7d55dbc8f3baf6867aec480ff864799d805a4563d142 |
| tools | amazon_search_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | amazon_search_scraper | locale | cdbb6d79df927f48d9866b4ac1d085c581cf4f1286fa9b2332be8650326d8079 |
| tools | amazon_search_scraper | merchant_id | 29666bfc6be92abb60838bfef609ea8f0a2841ad2121b9ae8033a1cc6544ff8a |
| tools | amazon_search_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | amazon_search_scraper | pages | 6db2005db03ae818a014763c6edf9ca97bc018de88b4b7d0941dc0fb8b672946 |
| tools | amazon_search_scraper | parse | c27cc9870b8d21da98e8a4a1efc1aeed03266a9adec16794037c90a0c4b25e97 |
| tools | amazon_search_scraper | query | 2b7bab00754c254fbe9efbf66ea830cb4573faeea75fdbd269801084ef67b584 |
| tools | amazon_search_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | amazon_search_scraper | start_page | 8d3ebdba8acecea8bc50bd6d0b07311cef7fe1ce5f009a0f1be75817c6d8eaef |
| tools | amazon_search_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |
| tools | google_search_scraper | description | 29fbda527f73d022b8ce16fa2cefa7154cdef35b6facfb5d0ec8e274e72a8d82 |
| tools | google_search_scraper | ad_mode | b461196e920ee39fec41727d81c88bb9a88f0fd6457c506a7b77affe3908f294 |
| tools | google_search_scraper | domain | dbd1f8b171d5449998fb7d55dbc8f3baf6867aec480ff864799d805a4563d142 |
| tools | google_search_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | google_search_scraper | limit | 753cb86d3a3ce07de849c5bda9b324700c07e63071cd056a178c575496e0e268 |
| tools | google_search_scraper | locale | cdbb6d79df927f48d9866b4ac1d085c581cf4f1286fa9b2332be8650326d8079 |
| tools | google_search_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | google_search_scraper | pages | 6db2005db03ae818a014763c6edf9ca97bc018de88b4b7d0941dc0fb8b672946 |
| tools | google_search_scraper | parse | c27cc9870b8d21da98e8a4a1efc1aeed03266a9adec16794037c90a0c4b25e97 |
| tools | google_search_scraper | query | 86f841b07fc2d38c87a89cd644f2e5a3a1a640855ad46e2a1c57c2d4df7cb1d8 |
| tools | google_search_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | google_search_scraper | start_page | 8d3ebdba8acecea8bc50bd6d0b07311cef7fe1ce5f009a0f1be75817c6d8eaef |
| tools | google_search_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |
| tools | universal_scraper | description | f17aff38c8d58bd300f276435edd6230f7a92afb25aa1fcf5e5ba10dd0cb237b |
| tools | universal_scraper | geo_location | 19ebddb494a31c7282c038ff01533fb047842dc9f79528cbd6f4b29907123687 |
| tools | universal_scraper | output_format | 086107d164d549c1f6789d183fdf4a947b863e12bada384cf1819fb4c91fd2f8 |
| tools | universal_scraper | render | 4a4de0e6cff4a37c08074c1904434178ed30ff04f47040761b5d9e7922ea63a8 |
| tools | universal_scraper | url | d0959362daefa321a0e2cac5ca3653682f65d5e25d22b5c30e9fd965f8b3d7e4 |
| tools | universal_scraper | user_agent_type | b57f53f88bf2e36ea9538f3b7f97b49222a1bcae88afe7a6f08562115edf9ce1 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
