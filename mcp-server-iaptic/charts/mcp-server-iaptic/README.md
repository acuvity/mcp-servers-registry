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


# What is mcp-server-iaptic?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-iaptic/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-iaptic/1.0.1?logo=docker&logoColor=fff&label=1.0.1)](https://hub.docker.com/r/acuvity/mcp-server-iaptic)
[![PyPI](https://img.shields.io/badge/1.0.1-3775A9?logo=pypi&logoColor=fff&label=mcp-server-iaptic)](https://github.com/iaptic/mcp-server-iaptic)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-iaptic&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22IAPTIC_API_KEY%22%2C%22-e%22%2C%22IAPTIC_APP_NAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-iaptic%3A1.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connect AIs to Iaptic data for customer and transaction insights.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-server-iaptic original [sources](https://github.com/iaptic/mcp-server-iaptic).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-iaptic/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/charts/mcp-server-iaptic/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-server-iaptic run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/charts/mcp-server-iaptic#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Jean-Christophe Hoelt ](https://github.com/iaptic/mcp-server-iaptic) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-server-iaptic ](https://github.com/iaptic/mcp-server-iaptic)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-server-iaptic ](https://github.com/iaptic/mcp-server-iaptic)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/charts/mcp-server-iaptic)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-iaptic/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.1`

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
  - `IAPTIC_API_KEY` secret to be set as secrets.IAPTIC_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `IAPTIC_APP_NAME` environment variable to be set by env.IAPTIC_APP_NAME

# How to install


Install will helm

```console
helm install mcp-server-iaptic oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-iaptic oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-iaptic
```

From there your MCP server mcp-server-iaptic will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-iaptic` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-iaptic
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-iaptic` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-iaptic oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-iaptic oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-iaptic oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-iaptic oci://docker.io/acuvity/mcp-server-iaptic --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (16)
<details>
<summary>customer_list</summary>

**Description**:

```
List customers from your Iaptic account.
- Returns a paginated list of customers with their purchase status
- Each customer includes:
  - Application username
  - Last purchase information
  - Subscription status (active/lapsed)
  - Renewal intent
  - Trial/introductory period status
- Use limit and offset for pagination (default: 100 customers per page)
- Results are ordered by creation date (newest first)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of customers to return (default: 100) | No
| offset | number | Number of customers to skip for pagination | No
</details>
<details>
<summary>customer_get</summary>

**Description**:

```
Get detailed information about a specific customer.
- Returns complete customer profile including:
  - Application username
  - Purchase history
  - Active and expired subscriptions
  - Last purchase details
  - Subscription renewal status
  - Trial and introductory period information
- Required: customerId parameter
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customerId | string | Unique identifier of the customer | Yes
</details>
<details>
<summary>customer_add_purchase</summary>

**Description**:

```
Manually associate a customer with a purchase.
- Links a purchase to a specific customer
- Takes priority over receipt validation links
- Useful for manual purchase management
- Purchase format should be "platform:purchaseId", for example apple:123109519983
- Required: customerId and purchaseId
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customerId | string | Application username of the customer | Yes
| purchaseId | string | ID of the purchase to associate | Yes
</details>
<details>
<summary>customer_subscription</summary>

**Description**:

```
Get customer's subscription status.
- Returns active subscription details if any
- Includes:
  - Subscription status and expiry
  - Payment and renewal information
  - Trial/introductory period status
- Simpler alternative to customer_get for subscription-only apps
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customerId | string | Application username of the customer | Yes
</details>
<details>
<summary>customer_transactions</summary>

**Description**:

```
Get customer's transaction history.
- Returns list of all transactions
- Includes:
  - Payment details
  - Transaction status
  - Associated purchases
  - Timestamps
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customerId | string | Application username of the customer | Yes
</details>
<details>
<summary>purchase_list</summary>

**Description**:

```
List purchases from your Iaptic account.
- Returns a paginated list of purchases
- Use limit and offset for pagination (default: 100 per page)
- Filter by date range using startdate and enddate (ISO format)
- Filter by customerId to see purchases from a specific customer
- Results include purchase status, product info, and transaction details
- Results are ordered by purchase date (newest first)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customerId | string | Filter purchases by customer ID | No
| enddate | string | Filter purchases before this date (ISO format, e.g. 2024-12-31) | No
| limit | number | Maximum number of purchases to return (default: 100, max: 1000) | No
| offset | number | Number of purchases to skip for pagination | No
| startdate | string | Filter purchases after this date (ISO format, e.g. 2024-01-01) | No
</details>
<details>
<summary>purchase_get</summary>

**Description**:

```
Get detailed information about a specific purchase.
- Returns complete purchase details including:
  - Product information
  - Purchase status
  - Associated transactions
  - Customer information
  - Subscription details (if applicable)
- Required: purchaseId parameter
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| purchaseId | string | Unique identifier of the purchase | Yes
</details>
<details>
<summary>transaction_list</summary>

**Description**:

```
List financial transactions from your Iaptic account.
- Returns a paginated list of transactions
- Use limit and offset for pagination (default: 100 per page)
- Filter by date range using startdate and enddate (ISO format)
- Filter by purchaseId to see transactions for a specific purchase
- Results include transaction status, amount, currency, and payment details
- Results are ordered by transaction date (newest first)
- Important: Use date filtering to avoid retrieving too many records
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| enddate | string | Filter transactions before this date (ISO format, e.g. 2024-12-31) | No
| limit | number | Maximum number of transactions to return (default: 100, max: 1000) | No
| offset | number | Number of transactions to skip for pagination | No
| purchaseId | string | Filter transactions by purchase ID | No
| startdate | string | Filter transactions after this date (ISO format, e.g. 2024-01-01) | No
</details>
<details>
<summary>transaction_get</summary>

**Description**:

```
Get detailed information about a specific transaction.
- Returns complete transaction details including:
  - Transaction status
  - Amount and currency
  - Payment method details
  - Associated purchase information
  - Customer information
  - Timestamps and audit data
- Required: transactionId parameter
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| transactionId | string | Unique identifier of the transaction | Yes
</details>
<details>
<summary>stats_get</summary>

**Description**:

```
Get general transactions, revenue and usage statistics from your Iaptic account.
- Returns aggregated metrics including:
  - Total revenue
  - Number of active subscriptions
  - Customer growth metrics
  - Transaction success rates
  - Revenue by product type
- Data is aggregated across all your applications
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>stats_app</summary>

**Description**:

```
Get statistics specific to your application.
- Returns app-specific metrics including:
  - App revenue and growth
  - Active subscriptions for this app
  - Customer metrics for this app
  - Product performance statistics
  - Transaction metrics
- Uses the app name provided during server initialization
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>stripe_prices</summary>

**Description**:

```
Get available Stripe products and prices.
- Returns list of products with their associated prices
- Each product includes:
  - Product ID and display name
  - Description and metadata
  - Available pricing offers
  - Subscription terms if applicable
- Results are cached for 5 minutes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>event_list</summary>

**Description**:

```
List recent events from your Iaptic account.
- Returns a paginated list of system events
- Events include:
  - Receipt validations
  - Platform notifications (Apple/Google/etc)
  - Webhook deliveries
  - Purchase status changes
  - Subscription renewals
- Use limit and offset for pagination
- Results ordered by date (newest first)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| enddate | string | Filter events before this date (ISO format, e.g. 2024-12-31) | No
| limit | number | Maximum number of events to return (default: 100) | No
| offset | number | Number of events to skip for pagination | No
| startdate | string | Filter events after this date (ISO format, e.g. 2024-01-01) | No
</details>
<details>
<summary>iaptic_switch_app</summary>

**Description**:

```
Switch to a different Iaptic app.
- Allows temporarily using a different app's credentials
- All subsequent API calls will use the new app name and API key
- If using a master key, only the app name needs to be changed
- Useful for managing multiple apps in the same session
- Required: appName parameter (apiKey required only if not using master key)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| apiKey | string | API key for the app (not required if using master key) | No
| appName | string | Name of the app to switch to | Yes
</details>
<details>
<summary>iaptic_reset_app</summary>

**Description**:

```
Reset to the default Iaptic app.
- Reverts to the original app credentials provided during server initialization
- All subsequent API calls will use the default app name and API key
- Use this after using iaptic_switch_app to return to the default app
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>iaptic_current_app</summary>

**Description**:

```
Get information about the currently active Iaptic app.
- Returns the current app name
- Indicates whether using default or custom credentials
- Shows if using a master key for authentication
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | customer_add_purchase | description | f01df77ebf1fb3562d7326e8a9ab9ccdbb78cc8a47da7fcdf44bff8f1b62e936 |
| tools | customer_add_purchase | customerId | 7ccd7cb0783c5d697468fb22f0a17a3a47afafe5f1d5418a2b7a67c62cf72adf |
| tools | customer_add_purchase | purchaseId | 16164dc6057158f07e1afc722bda4f9ea34d532fec03e1d3c6483332c4c6c992 |
| tools | customer_get | description | a36f1fa858f52947787aae2ffab6669dbfd7dd7992c5d46e8430dd77e5ea2299 |
| tools | customer_get | customerId | e00ded4e8ef763573ab231f6829d634374c65a51ef32b00ee3e56e20d6921fb4 |
| tools | customer_list | description | 6c78853de46303eeb589496a8ad734f6262d0d13bb0b74e2a7ad6c6a27f6d6f0 |
| tools | customer_list | limit | d548adf4bae21778c9ae3ad6ddcb98604602d64d2a0890110f927da7e4059bb4 |
| tools | customer_list | offset | a0c37c1ae0fb670e2da9a922adc47fda28a631599c371e4b91d1dc78712dea87 |
| tools | customer_subscription | description | 5e09514c986683c2bf7d77f8d26dfc0dbba2879e8f0cb617e87ca17a83b4b881 |
| tools | customer_subscription | customerId | 7ccd7cb0783c5d697468fb22f0a17a3a47afafe5f1d5418a2b7a67c62cf72adf |
| tools | customer_transactions | description | 44d6bb1f960d3d4b714a0a6241327cc98edbf68ff7a99376db899213eb8a1cc4 |
| tools | customer_transactions | customerId | 7ccd7cb0783c5d697468fb22f0a17a3a47afafe5f1d5418a2b7a67c62cf72adf |
| tools | event_list | description | 1b0f0ed17e656c53317c07c06acb3dce6a37a35c9fe027f94f2fc931f3958076 |
| tools | event_list | enddate | ae5547a8c217fa66c16503805f12927f481d594bbbf252a373006dcd434c4f49 |
| tools | event_list | limit | f6ab788255412b8faee8bc361ec05a06a5ed90708779d89d3e3d2a367442181d |
| tools | event_list | offset | 720edc02115b8710ffce1028d2f01f169e21361dd33c7be6d16860214a09bf28 |
| tools | event_list | startdate | 21ee5b1371bbcd5f92c00b275f14dc7ee12d09afbb16d1645c42d92e3e72adc8 |
| tools | iaptic_current_app | description | 327d1d940252298414397b4c203b405828d045f2103c0dc709bdb08bbddea030 |
| tools | iaptic_reset_app | description | 0809be869700bf292e53601f43d26fcc4c59ffebae50d7d84c641e1541ed2ee7 |
| tools | iaptic_switch_app | description | f1f283221d9726eab50287cf595ba956867d47862880aa8b4ed5333f3a1d1f77 |
| tools | iaptic_switch_app | apiKey | f6c6c910bd40e0d620648f0eef25aa1843a41e12ff0c806ec50eac80cb27afc4 |
| tools | iaptic_switch_app | appName | dd6450f3211e55064a228dcf3847b563588ecb28e63ed6082dc7dc92a79d4496 |
| tools | purchase_get | description | 004f4769d124af57336c52c34817597269e664d786492be91f9686b59d200120 |
| tools | purchase_get | purchaseId | 9f1d79a1bafe63f77629971db9e5ed4deeaf007b7f9e1167039485b72c1a19ad |
| tools | purchase_list | description | 193ecbbf1342905454ab9bf20ac33787e1acb3021d696485f37cde6feb6e3381 |
| tools | purchase_list | customerId | 1df5a96d2e7a5f2513207850ce4a6065f76b5484163890018eb7a58e92902883 |
| tools | purchase_list | enddate | 03afabe664ac35cee9083044a97663bf119edc2faba15d0bb180c00195ee8e9f |
| tools | purchase_list | limit | a7d3e1fc7524714fd78564026a4c14c70e8615ea9db106a39764b5acf4667184 |
| tools | purchase_list | offset | 58bf8a0677b4ff543642d3926bba32faa23a817b8dd753664ce870ee7201ac82 |
| tools | purchase_list | startdate | ec319c52791aa618d34a7fc4620bf996759677e7649c6a1033e9248c3933d87d |
| tools | stats_app | description | 49b4f3ac74deb1d85e8bd8bffdc8d05fcd39a16a99472e41ba0d673ab798534e |
| tools | stats_get | description | 76d2e6c309a4f0402b76f2009b34806aae0c4e8bc0254a6fe06b46a3af9cf965 |
| tools | stripe_prices | description | 33107b481b1662f209ead75e63e7938a3bb7383257521a9d62ebde0a7f6c13c8 |
| tools | transaction_get | description | 57deb56932831e6275ea5eb2d4d475bf0c16f36bbd3e5f5a11b7e248aa2f1fe5 |
| tools | transaction_get | transactionId | 4d93fbfb030372be546eb52533feb6e46328f66542fd375f3d4ac8116e06971b |
| tools | transaction_list | description | bcdfe529318b1bc7960e73791e76fe704eb44534041a2ae67ef4bb003a2d1fd5 |
| tools | transaction_list | enddate | 1c3ebcc7edf56a24e339c067959856a0aed34bc9d24e78dfb797651952f2ab90 |
| tools | transaction_list | limit | 433b4a6c3a74b603bee0d1a763f55de9321f113c6f05a94f70883c98b8288e60 |
| tools | transaction_list | offset | ea864a453d182e3bee5799e748f3ca29182bb6283d3a3bbe9cf0a97b0c718794 |
| tools | transaction_list | purchaseId | 16d35d594e4083a6b418ac275790775ae5c0cde0511de3da78bf87cc908c129a |
| tools | transaction_list | startdate | e891d7059a1c66ed582e0aa37aef2b42bc31afe85f8d85121cc7caadf1a3160a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
