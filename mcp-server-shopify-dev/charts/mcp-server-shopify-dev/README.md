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


# What is mcp-server-shopify-dev?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-shopify-dev/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-shopify-dev/1.6.0?logo=docker&logoColor=fff&label=1.6.0)](https://hub.docker.com/r/acuvity/mcp-server-shopify-dev)
[![PyPI](https://img.shields.io/badge/1.6.0-3775A9?logo=pypi&logoColor=fff&label=@shopify/dev-mcp)](https://github.com/Shopify/dev-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-shopify-dev/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-shopify-dev&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-shopify-dev%3A1.6.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Model Context Protocol (MCP) server that interacts with Shopify Dev.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @shopify/dev-mcp original [sources](https://github.com/Shopify/dev-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-shopify-dev/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-shopify-dev/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-shopify-dev/charts/mcp-server-shopify-dev/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @shopify/dev-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-shopify-dev/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-shopify-dev#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Author ](https://github.com/Shopify/dev-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @shopify/dev-mcp ](https://github.com/Shopify/dev-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @shopify/dev-mcp ](https://github.com/Shopify/dev-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-shopify-dev/charts/mcp-server-shopify-dev)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-shopify-dev/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.6.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-shopify-dev:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-shopify-dev:1.0.0-1.6.0`

---

# Table of Contents
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

# How to install


Install will helm

```console
helm install mcp-server-shopify-dev oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-shopify-dev oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-shopify-dev
```

From there your MCP server mcp-server-shopify-dev will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-shopify-dev` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-shopify-dev
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
  mcp-server-scope: standalone
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-shopify-dev` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-shopify-dev oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-shopify-dev oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-shopify-dev oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-shopify-dev oci://docker.io/acuvity/mcp-server-shopify-dev --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (8)
<details>
<summary>introspect_graphql_schema</summary>

**Description**:

```
This tool introspects and returns the portion of the Shopify GraphQL schema relevant to the user prompt, including scope information for queries, mutations, and objects. Use this for any Shopify GraphQL API including Admin API, Storefront API, Partner API, Customer API, Payments Apps API, and Function APIs (for validating Function input GraphQL queries).

    🚨 CRITICAL: This is your primary tool when working with GraphQL APIs, especially when exploring schema fields or when search_docs_chunks returns an error (HTTP 500/503 or "fetch failed").

    ⚠️ API CONTEXT WARNING:
    - If you've already called learn_shopify_api with a specific API (e.g., "admin")

    - You MUST continue using that same API for ALL subsequent tool calls
    - DO NOT switch to "admin" or any other API unless explicitly requested by the user
    - The 'api' parameter should match what you used in learn_shopify_api

    USAGE TIPS:
    - Search for operations by their action: "create", "update", "delete", "list", "capture", "refund"
    - Search for specific objects: "product", "order", "customer", "discount"
    - Search for specific fields: "version", "publicApiVersions", "shop"
    - Try multiple variations if first search returns nothing

        - For camelCase names, search for individual words: "captureSession" → try "capture" or "session"

    FALLBACK STRATEGY:
    1. Start with the most specific term from the user's request
    2. If no results, try broader terms or related words
    3. For "list" operations, try "all", "list", or the plural object name
    4. For mutations, try the action verb: "create", "update", "delete", etc.

    The schema HAS THE ANSWERS - if the first introspection call doesn't yield expected results, try searching for shorter words that are part of your initial query!
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api | string | The GraphQL API to use. Valid options are:
- 'admin': The Admin GraphQL API lets you build apps and integrations that extend and enhance the Shopify admin.
- 'storefront-graphql': Use for custom storefronts requiring direct GraphQL queries/mutations for data fetching and cart operations. Choose this when you need full control over data fetching and rendering your own UI. NOT for Web Components - if the prompt mentions HTML tags like <shopify-store>, <shopify-cart>, use storefront-web-components instead.
- 'partner': The Partner API lets you programmatically access data about your Partner Dashboard, including your apps, themes, and affiliate referrals.
- 'customer': The Customer Account API allows customers to access their own data including orders, payment methods, and addresses.
- 'payments-apps': The Payments Apps API enables payment providers to integrate their payment solutions with Shopify's checkout.
- 'functions_cart_checkout_validation': GraphQL schema for Cart and Checkout Validation Function input queries
- 'functions_cart_transform': GraphQL schema for Cart Transform Function input queries
- 'functions_delivery_customization': GraphQL schema for Delivery Customization Function input queries
- 'functions_discount': GraphQL schema for Discount Function input queries
- 'functions_discounts_allocator': GraphQL schema for Discounts Allocator Function input queries
- 'functions_fulfillment_constraints': GraphQL schema for Fulfillment Constraints Function input queries
- 'functions_local_pickup_delivery_option_generator': GraphQL schema for Local Pickup Delivery Option Generator Function input queries
- 'functions_order_discounts': GraphQL schema for Order Discounts Function input queries
- 'functions_order_routing_location_rule': GraphQL schema for Order Routing Location Rule Function input queries
- 'functions_payment_customization': GraphQL schema for Payment Customization Function input queries
- 'functions_pickup_point_delivery_option_generator': GraphQL schema for Pickup Point Delivery Option Generator Function input queries
- 'functions_product_discounts': GraphQL schema for Product Discounts Function input queries
- 'functions_shipping_discounts': GraphQL schema for Shipping Discounts Function input queries
Default is 'admin'. | No
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
| filter | array | Filter results to show specific sections. Valid values are 'types', 'queries', 'mutations', or 'all' (default) | No
| query | string | Search term to filter schema elements by name. Only pass simple terms like 'product', 'discountProduct', etc. | Yes
</details>
<details>
<summary>learn_extension_target_types</summary>

**Description**:

```

      This tool returns the type declarations of different components and APIs usable within a specific extension target.
      You MUST call this tool ONLY AFTER calling learn_shopify_api for the API names listed below.
          - Polaris Admin Extensions: Add custom actions and blocks from your app at contextually relevant spots throughout the Shopify Admin. Admin UI Extensions also supports scaffolding new adminextensions using Shopify CLI commands.
    - Polaris Checkout Extensions: Build custom functionality that merchants can install at defined points in the checkout flow, including product information, shipping, payment, order summary, and Shop Pay. Checkout UI Extensions also supports scaffolding new checkout extensions using Shopify CLI commands.
    - Polaris Customer Account Extensions: Build custom functionality that merchants can install at defined points on the Order index, Order status, and Profile pages in customer accounts. Customer Account UI Extensions also supports scaffolding new customer account extensions using Shopify CLI commands.
    - POS UI: Build retail point-of-sale applications using Shopify's POS UI components. These components provide a consistent and familiar interface for POS applications. POS UI Extensions also supports scaffolding new POS extensions using Shopify CLI commands. Keywords: POS, Retail, smart grid
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api | string | The Shopify API you are building for | Yes
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
| extension_target | string | extension_target represents where your UI extension will appear. extension_target decides the available apis and components for the given api | Yes
</details>
<details>
<summary>learn_shopify_api</summary>

**Description**:

```

    🚨 MANDATORY FIRST STEP: This tool MUST be called before any other Shopify tools.

    ⚠️  ALL OTHER SHOPIFY TOOLS WILL FAIL without a conversationId from this tool.
    This tool generates a conversationId that is REQUIRED for all subsequent tool calls. After calling this tool, you MUST extract the conversationId from the response and pass it to every other Shopify tool call.

    🔄 MULTIPLE API SUPPORT: You MUST call this tool multiple times in the same conversation when you need to learn about different Shopify APIs. THIS IS NOT OPTIONAL. Just pass the existing conversationId to maintain conversation continuity while loading the new API context.

    For example, a user might ask a question about the Admin API, then switch to the Functions API, then ask a question about polaris UI components. In this case I would expect you to call learn_shopify_api three times with the following arguments:

    - learn_shopify_api(api: "admin") -> conversationId: "123"
    - learn_shopify_api(api: "functions", conversationId: "123")
    - learn_shopify_api(api: "polaris-admin-extensions", conversationId: "123")

    This is because the conversationId is used to maintain conversation continuity while loading the new API context.

    🚨 Valid arguments for `api` are:
        - Admin API: The Admin GraphQL API lets you build apps and integrations that extend and enhance the Shopify admin.
    - Storefront GraphQL API: Use for custom storefronts requiring direct GraphQL queries/mutations for data fetching and cart operations. Choose this when you need full control over data fetching and rendering your own UI. NOT for Web Components - if the prompt mentions HTML tags like <shopify-store>, <shopify-cart>, use storefront-web-components instead.
    - Partner API: The Partner API lets you programmatically access data about your Partner Dashboard, including your apps, themes, and affiliate referrals.
    - Customer Account API: The Customer Account API allows customers to access their own data including orders, payment methods, and addresses.
    - Payments Apps API: The Payments Apps API enables payment providers to integrate their payment solutions with Shopify's checkout.
    - Shopify Functions: Shopify Functions allow developers to customize the backend logic that powers parts of Shopify. Available APIs: Discount, Cart and Checkout Validation, Cart Transform, Pickup Point Delivery Option Generator, Delivery Customization, Fulfillment Constraints, Local Pickup Delivery Option Generator, Order Routing Location Rule, Payment Customization
    - Polaris App Home: Build your app's primary user interface embedded in the Shopify admin. If the prompt just mentions `Polaris` and you can't tell based off of the context what API they meant, assume they meant this API.
    - Hydrogen: Hydrogen storefront implementation cookbooks. Some of the available recipes are: B2B Commerce, Bundles, Combined Listings, Custom Cart Method, Dynamic Content with Metaobjects, Express Server, Google Tag Manager Integration, Infinite Scroll, Legacy Customer Account Flow, Markets, Partytown + Google Tag Manager, Subscriptions, Third-party API Queries and Caching. MANDATORY: Use this API for ANY Hydrogen storefront question - do NOT use Storefront GraphQL when 'Hydrogen' is mentioned.
    - Liquid: Liquid is an open-source templating language created by Shopify. It is the backbone of Shopify themes and is used to load dynamic content on storefronts. Keywords: liquid, theme, shopify-theme, liquid-component, liquid-block, liquid-section, liquid-snippet, liquid-schemas, shopify-theme-schemas
    - Custom Data: MUST be used first when prompts mention Metafields or Metaobjects. Use Metafields and Metaobjects to model and store custom data for your app. Metafields extend built-in Shopify data types like products or customers, Metaobjects are custom data types that can be used to store bespoke data structures. Metafield and Metaobject definitions provide a schema and configuration for values to follow.

    For APIs     - Polaris Admin Extensions: Add custom actions and blocks from your app at contextually relevant spots throughout the Shopify Admin. Admin UI Extensions also supports scaffolding new adminextensions using Shopify CLI commands.
    - Polaris Checkout Extensions: Build custom functionality that merchants can install at defined points in the checkout flow, including product information, shipping, payment, order summary, and Shop Pay. Checkout UI Extensions also supports scaffolding new checkout extensions using Shopify CLI commands.
    - Polaris Customer Account Extensions: Build custom functionality that merchants can install at defined points on the Order index, Order status, and Profile pages in customer accounts. Customer Account UI Extensions also supports scaffolding new customer account extensions using Shopify CLI commands.
    - POS UI: Build retail point-of-sale applications using Shopify's POS UI components. These components provide a consistent and familiar interface for POS applications. POS UI Extensions also supports scaffolding new POS extensions using Shopify CLI commands. Keywords: POS, Retail, smart grid, call learn_shopify_api to get the conversationId and then YOU MUST call learn_extension_target_types.

    🔄 WORKFLOW:
    1. Call learn_shopify_api first with the initial API
    2. Extract the conversationId from the response
    3. Pass that same conversationId to ALL other Shopify tools
    4. If you need to know more about a different API at any point in the conversation, call learn_shopify_api again with the new API and the same conversationId

    When tool outputs are saved to a file always read the entire file first.
    DON'T SEARCH THE WEB WHEN REFERENCING INFORMATION FROM THIS DOCUMENTATION. IT WILL NOT BE ACCURATE.
    PREFER THE USE OF THE fetch_full_docs TOOL TO RETRIEVE INFORMATION FROM THE DEVELOPER DOCUMENTATION SITE.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api | string | The Shopify API you are building for | Yes
| conversationId | string | Optional existing conversation UUID. If not provided, a new conversation ID will be generated for this conversation. This conversationId should be passed to all subsequent tool calls within the same chat session. | No
</details>
<details>
<summary>validate_theme</summary>

**Description**:

```
This tool validates Liquid codeblocks, Liquid files, and supporting Theme files (e.g. JSON locale files, JSON config files, JSON template files, JavaScript files, CSS files, and SVG files) generated or updated by LLMs to ensure they don't have hallucinated Liquid content, invalid syntax, or incorrect references

    It returns a comprehensive validation result with details for each code block explaining why it was valid or invalid.
    This detail is provided so LLMs know how to modify code snippets to remove errors.
    It also returns an artifact ID and revision number for each code block. This is used to track the code block and its validation results. When validating an iteration of the same code block, use the same artifact ID and increment the revision number. Do not pass your own artifact ID to this tool, the tool will generate one for you.. Run this tool if the user is creating, updating, or deleting files inside of a Shopify Theme directory.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| absoluteThemePath | string | The absolute path to the theme directory | Yes
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
| filesCreatedOrUpdated | array | Array of files with path and optional artifact metadata | Yes
</details>
<details>
<summary>search_docs_chunks</summary>

**Description**:

```
This tool will take in the user prompt, search shopify.dev, and return relevant documentation and code examples that will help answer the user's question.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
| max_num_results | number | Maximum number of results to return from the search. Do not pass this when calling the tool for the first time, only use this when you want to limit the number of results deal with small context window issues. | No
| prompt | string | The search query for Shopify documentation | Yes
</details>
<details>
<summary>fetch_full_docs</summary>

**Description**:

```
Use this tool to retrieve a list of full documentation pages from shopify.dev.
    When you find relevant document chunks using the search_docs_chunks tool, YOU MUST USE THIS TOOL TO RETRIEVE THE FULL DOCUMENTATION PAGES. THIS IS IMPORTANT. You can use the `url` attribute of the chunks.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
| paths | array | The paths to the full documentation pages to read, i.e. ["/docs/api/app-home", "/docs/api/functions"]. Paths should be relative to the root of the developer documentation site. | Yes
</details>
<details>
<summary>validate_component_codeblocks</summary>

**Description**:

```
🚨 MANDATORY VALIDATION TOOL - MUST BE CALLED WHEN COMPONENTS FROM SHOPIFY PACKAGES ARE USED. DONT ASK THE USER TO DO THIS. DON'T CONTEXT SWITCH.

    This tool MUST be used to validate ALL code blocks containing Shopify components, regardless of size or complexity.

    ⚠️  CRITICAL REQUIREMENTS:
    - Call this tool IMMEDIATELY after generating ANY Shopify component code
    - NEVER skip validation, even for simple examples or snippets
    - ALWAYS use this tool when generating JSX, TSX, or web component code
    - This validation prevents hallucinated components, props, and prop values
    - Your major tasks while structuring the input is to ensure that:
    1. If the code contains JS/TS code, it should be wrapped inside a function. 
    2. All Javascript code is outside return statement of the function.
    3. All the polaris web components are in return statement of the function.

    INPUT STRUCTURE:
    Do not pass in tiny snippets of code. Follow the example given below as the input to validate_component_codeblocks tool.
    {
      "api": "The API name (e.g., 'polaris-app-home', 'pos-ui')",
      "code": [
        {
          "content": "
const Extension = () => {
  const [isConnected, setIsConnected] = useState(
    shopify.connectivity.current.value.internetConnected === 'Connected'
  );

  useEffect(() => {
    const unsubscribe = shopify.connectivity.current.subscribe((newConnectivity) => {
      setIsConnected(newConnectivity.internetConnected === 'Connected');
    });
    return unsubscribe;
  }, []);

  return (
    <s-tile
      heading="My App"
      disabled={!isConnected}
    />
  );
};
"
        }
      ]
    }

    📤 OUTPUTS:
    - Comprehensive validation results with specific error details
    - Clear guidance on how to fix any validation failures
    - Component-by-component validation status

    🔄 WORKFLOW: Generate Code → Validate → Fix Errors and replace code → Re-validate if needed


    It returns a comprehensive validation result with details for each code block explaining why it was valid or invalid.
    This detail is provided so LLMs know how to modify code snippets to remove errors.
    It also returns an artifact ID and revision number for each code block. This is used to track the code block and its validation results. When validating an iteration of the same code block, use the same artifact ID and increment the revision number. Do not pass your own artifact ID to this tool, the tool will generate one for you.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api | string | API name to validate against (e.g., 'pos-ui', 'polaris-app-home'). | Yes
| code | array | Array of code blocks with content and optional artifact metadata. Supported code blocks are JS/TS React, vanilla JS/TS, Preact, and HTML with Polaris web components. | Yes
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
| extensionTarget | string | Required for extension surface APIs (polaris-admin-extensions, polaris-checkout-extensions, polaris-customer-account-extensions, pos-ui). The extension target determines which components and APIs are available. Get available targets using learn_extension_target_types tool. | No
</details>
<details>
<summary>validate_graphql_codeblocks</summary>

**Description**:

```
This tool validates GraphQL code blocks against the Shopify GraphQL schema to ensure they don't contain hallucinated fields or operations. If a user asks for an LLM to generate a GraphQL operation, this tool should always be used to ensure valid code was generated.

    Supports all Shopify GraphQL APIs including Admin, Storefront, Partner, Customer, Payments Apps, and Function APIs. For Shopify Functions, use this to validate the input GraphQL queries (run.graphql).


    It returns a comprehensive validation result with details for each code block explaining why it was valid or invalid.
    This detail is provided so LLMs know how to modify code snippets to remove errors.
    It also returns an artifact ID and revision number for each code block. This is used to track the code block and its validation results. When validating an iteration of the same code block, use the same artifact ID and increment the revision number. Do not pass your own artifact ID to this tool, the tool will generate one for you.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api | string | The GraphQL API to use. Valid options are:
- 'admin': The Admin GraphQL API lets you build apps and integrations that extend and enhance the Shopify admin.
- 'storefront-graphql': Use for custom storefronts requiring direct GraphQL queries/mutations for data fetching and cart operations. Choose this when you need full control over data fetching and rendering your own UI. NOT for Web Components - if the prompt mentions HTML tags like <shopify-store>, <shopify-cart>, use storefront-web-components instead.
- 'partner': The Partner API lets you programmatically access data about your Partner Dashboard, including your apps, themes, and affiliate referrals.
- 'customer': The Customer Account API allows customers to access their own data including orders, payment methods, and addresses.
- 'payments-apps': The Payments Apps API enables payment providers to integrate their payment solutions with Shopify's checkout.
- 'functions_cart_checkout_validation': GraphQL schema for Cart and Checkout Validation Function input queries
- 'functions_cart_transform': GraphQL schema for Cart Transform Function input queries
- 'functions_delivery_customization': GraphQL schema for Delivery Customization Function input queries
- 'functions_discount': GraphQL schema for Discount Function input queries
- 'functions_discounts_allocator': GraphQL schema for Discounts Allocator Function input queries
- 'functions_fulfillment_constraints': GraphQL schema for Fulfillment Constraints Function input queries
- 'functions_local_pickup_delivery_option_generator': GraphQL schema for Local Pickup Delivery Option Generator Function input queries
- 'functions_order_discounts': GraphQL schema for Order Discounts Function input queries
- 'functions_order_routing_location_rule': GraphQL schema for Order Routing Location Rule Function input queries
- 'functions_payment_customization': GraphQL schema for Payment Customization Function input queries
- 'functions_pickup_point_delivery_option_generator': GraphQL schema for Pickup Point Delivery Option Generator Function input queries
- 'functions_product_discounts': GraphQL schema for Product Discounts Function input queries
- 'functions_shipping_discounts': GraphQL schema for Shipping Discounts Function input queries
Default is 'admin'. | No
| codeblocks | array | Array of GraphQL code blocks with content and optional artifact metadata | Yes
| conversationId | string | 🔗 REQUIRED: conversationId from learn_shopify_api tool. Call learn_shopify_api first if you don't have this. | Yes
</details>

## 📝 Prompts (1)
<details>
<summary>shopify_admin_graphql</summary>

**Description**:

```
<no value>
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| query | The specific Shopify Admin API question or request |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | shopify_admin_graphql | description | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| prompts | shopify_admin_graphql | query | 98093c057eeae040401bc67ad3071116be498b22221a4151563759d2f43f2ced |
| tools | fetch_full_docs | description | 2aa3561e5f053085c9629ced63262015c02ca463411420666b28c770579c14a4 |
| tools | fetch_full_docs | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | fetch_full_docs | paths | 755860698146c208554fd5b5e694a809420cfb95cc12d15445076799c6eca222 |
| tools | introspect_graphql_schema | description | 3889345e0e05311cf1f9621336c3ba873c0d35e6064e488363f57e41204ee4f9 |
| tools | introspect_graphql_schema | api | f37a0336d2361b9614488a1cef99acbcd19b70856ebf161ac101360233a880fc |
| tools | introspect_graphql_schema | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | introspect_graphql_schema | filter | 00bf1feddd40ca7dac8f5bcc1ea7ca723dcd1e58343c6bf5f3f09cea0cdbbf00 |
| tools | introspect_graphql_schema | query | df71bf519a32b0b8e76710c33d12a47d11c093bcc2bfecd1e7a04bb345c38f1d |
| tools | learn_extension_target_types | description | d3b5c3293af706e74c9660301acb2e711530c97a7209ce3f40d4139453d2dbe0 |
| tools | learn_extension_target_types | api | 020bba209b3e40636585ee28353121ec237df37f856c33d2f0da686466ad12b9 |
| tools | learn_extension_target_types | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | learn_extension_target_types | extension_target | 002ceb792dd961c740697cf1f548e02cc3a8e3c0cda87b4c2bcd61faa319b3b5 |
| tools | learn_shopify_api | description | 88a845cf9e2216a698b3c9a6331b0d99dfd599ca8b847de597132fafff855d84 |
| tools | learn_shopify_api | api | 020bba209b3e40636585ee28353121ec237df37f856c33d2f0da686466ad12b9 |
| tools | learn_shopify_api | conversationId | 88075add27481ae31f608d1e7f4c39455522dd99f2d25dac00e2f1a714e6f324 |
| tools | search_docs_chunks | description | 71b635f91481bb590101c163904f8c3b548425df09ff329e5a203a37023d366b |
| tools | search_docs_chunks | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | search_docs_chunks | max_num_results | 52c464378da791f2bd8b5852648cb8b55d3b3a21213fbf5422dcceae1a92307c |
| tools | search_docs_chunks | prompt | eb7cfc554f21b5a2cb77a094dd923a7ce2b5a4d9428f607506615f7a252c9871 |
| tools | validate_component_codeblocks | description | 069ca4888909daff17f6e6195b4935f2afcd987a9bdb90ee59f404f31cdccdae |
| tools | validate_component_codeblocks | api | 12ed4db1c15dd054b771a72292c3672dbc209d2bc85404b185df74520786f3b2 |
| tools | validate_component_codeblocks | code | 65e344ba843f0537595e331a4002c3d99d4984f84e3b4bcb5196597421e71cf5 |
| tools | validate_component_codeblocks | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | validate_component_codeblocks | extensionTarget | 1cf6682ec8af15afbc3a2a3ce557fbd86aebbd0c821457d30499ea2d577e2a93 |
| tools | validate_graphql_codeblocks | description | 9f416005cfa1815c6f4c5b4ca418d03dbf0139024a10d63c0cc1f37b7e25627d |
| tools | validate_graphql_codeblocks | api | f37a0336d2361b9614488a1cef99acbcd19b70856ebf161ac101360233a880fc |
| tools | validate_graphql_codeblocks | codeblocks | 8a2dfbb017f6aa5dd4d15f16b2e39bf0436402fc33cde1052cc9bbee84d2431e |
| tools | validate_graphql_codeblocks | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | validate_theme | description | a9bc7db19b94f9a1acbe028bfc1ee7c2cf6ec7522f046172cc514929152949ee |
| tools | validate_theme | absoluteThemePath | 44d62c86a7d837e7adfec4d5d75ec3183e805ceeac1d39b48a0c1dc3aea13365 |
| tools | validate_theme | conversationId | 15fe39c4a6a174baef0154b3ca3852df599e5dc3ca53b11a408ce57a7a27e3ae |
| tools | validate_theme | filesCreatedOrUpdated | 8980f3aa6f6a1508ac1c0ace0e84e33674195e4e39540b7927ebecdaa3e29643 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
