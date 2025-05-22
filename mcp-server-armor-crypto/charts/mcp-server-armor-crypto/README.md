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


# What is mcp-server-armor-crypto?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-armor-crypto/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-armor-crypto/0.2.1?logo=docker&logoColor=fff&label=0.2.1)](https://hub.docker.com/r/acuvity/mcp-server-armor-crypto)
[![PyPI](https://img.shields.io/badge/0.2.1-3775A9?logo=pypi&logoColor=fff&label=armor-crypto-mcp)](https://github.com/armorwallet/armor-crypto-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-armor-crypto/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-armor-crypto&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-armor-crypto%3A0.2.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Blockchain integration, staking, DeFi, swap, bridging, wallet, DCA, Orders, Coin Lookup, Tracking.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from armor-crypto-mcp original [sources](https://github.com/armorwallet/armor-crypto-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-armor-crypto/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-armor-crypto/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-armor-crypto/charts/mcp-server-armor-crypto/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure armor-crypto-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-armor-crypto/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Armor Wallet <info@armorwallet.ai> ](https://github.com/armorwallet/armor-crypto-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ armor-crypto-mcp ](https://github.com/armorwallet/armor-crypto-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ armor-crypto-mcp ](https://github.com/armorwallet/armor-crypto-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-armor-crypto/charts/mcp-server-armor-crypto)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-armor-crypto/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-armor-crypto:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-armor-crypto:1.0.0-0.2.1`

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
helm install mcp-server-armor-crypto oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-armor-crypto oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-armor-crypto
```

From there your MCP server mcp-server-armor-crypto will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-armor-crypto` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-armor-crypto
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-armor-crypto` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-armor-crypto oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-armor-crypto oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-armor-crypto oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-armor-crypto oci://docker.io/acuvity/mcp-server-armor-crypto --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (37)
<details>
<summary>get_armor_mcp_version</summary>

**Description**:

```
Get the current Armor Wallet version
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>wait_a_moment</summary>

**Description**:

```
Wait for some short amount of time, no more than 10 seconds
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| seconds | number | not set | Yes
</details>
<details>
<summary>get_current_time</summary>

**Description**:

```
Gets the current time and date
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>calculator</summary>

**Description**:

```

    Safely evaluates a mathematical or statistical expression string using Python syntax.

    Supports arithmetic operations (+, -, *, /, **, %, //), list expressions, and a range of math and statistics functions: 
    abs, round, min, max, len, sum, mean, median, stdev, variance, sin, cos, tan, sqrt, log, exp, floor, ceil, etc.

    Custom variables can be passed via the 'variables' dict, including lists for time series data.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expression | string | not set | Yes
| variables | object | not set | Yes
</details>
<details>
<summary>get_wallet_token_balance</summary>

**Description**:

```

    Get the balance for a list of wallet/token pairs.
    
    Expects a WalletTokenPairsContainer, returns a list of WalletTokenBalance.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| wallet_token_pairs | any | not set | Yes
</details>
<details>
<summary>calculate_token_conversion</summary>

**Description**:

```

    Perform token conversion quote between two tokens. Good for quickly calculating market prices.
    
    Expects a ConversionRequestContainer, returns a list of ConversionResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| conversion_requests | any | not set | Yes
</details>
<details>
<summary>swap_quote</summary>

**Description**:

```

    Retrieve a swap quote. Be sure to add slippage!
    
    Expects a SwapQuoteRequestContainer, returns a list of SwapQuoteResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| swap_quote_requests | any | not set | Yes
</details>
<details>
<summary>swap_transaction</summary>

**Description**:

```

    Execute a swap transaction.
    
    Expects a SwapTransactionRequestContainer, returns a list of SwapTransactionResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| swap_transaction_requests | any | not set | Yes
</details>
<details>
<summary>get_all_wallets</summary>

**Description**:

```

    Retrieve all wallets with balances.
    
    Returns a list of Wallets and asssets
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| get_all_wallets_requests | any | not set | Yes
</details>
<details>
<summary>get_all_orders</summary>

**Description**:

```

    Retrieve all limit and stop loss orders.
    
    Returns a list of orders.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| get_all_orders_requests | any | not set | Yes
</details>
<details>
<summary>search_official_token_address</summary>

**Description**:

```

    Get the official token address and symbol for a token symbol or token address.
    Try to use this first to get address and symbol of coin. If not found, use search_token_details to get details.

    Expects a TokenDetailsRequestContainer, returns a TokenDetailsResponseContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| token_details_requests | any | not set | Yes
</details>
<details>
<summary>search_token_details</summary>

**Description**:

```

    Search and retrieve details about single token.
    If only address or symbol is needed, use get_official_token_address first.
    
    Expects a TokenSearchRequest, returns a list of TokenDetailsResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| token_search_requests | any | not set | Yes
</details>
<details>
<summary>list_groups</summary>

**Description**:

```

    List all wallet groups.
    
    Returns a list of GroupInfo.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_single_group</summary>

**Description**:

```

    Retrieve details for a single wallet group.
    
    Expects the group name as a parameter, returns SingleGroupInfo.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| list_single_group_requests | any | not set | Yes
</details>
<details>
<summary>create_wallet</summary>

**Description**:

```

    Create new wallets.
    
    Expects a list of wallet names, returns a list of WalletInfo.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| create_wallet_requests | any | not set | Yes
</details>
<details>
<summary>archive_wallets</summary>

**Description**:

```

    Archive wallets.
    
    Expects a list of wallet names, returns a list of WalletArchiveOrUnarchiveResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| archive_wallet_requests | any | not set | Yes
</details>
<details>
<summary>unarchive_wallets</summary>

**Description**:

```

    Unarchive wallets.
    
    Expects a list of wallet names, returns a list of WalletArchiveOrUnarchiveResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| unarchive_wallet_requests | any | not set | Yes
</details>
<details>
<summary>create_groups</summary>

**Description**:

```

    Create new wallet groups.
    
    Expects a list of group names, returns a list of CreateGroupResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| create_groups_requests | any | not set | Yes
</details>
<details>
<summary>add_wallets_to_group</summary>

**Description**:

```

    Add wallets to a specified group.
    
    Expects the group name and a list of wallet names, returns a list of AddWalletToGroupResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| add_wallet_to_group_requests | any | not set | Yes
</details>
<details>
<summary>archive_wallet_group</summary>

**Description**:

```

    Archive wallet groups.
    
    Expects a list of group names, returns a list of GroupArchiveOrUnarchiveResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| archive_wallet_group_requests | any | not set | Yes
</details>
<details>
<summary>unarchive_wallet_group</summary>

**Description**:

```

    Unarchive wallet groups.
    
    Expects a list of group names, returns a list of GroupArchiveOrUnarchiveResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| unarchive_wallet_group_requests | any | not set | Yes
</details>
<details>
<summary>remove_wallets_from_group</summary>

**Description**:

```

    Remove wallets from a specified group.
    
    Expects the group name and a list of wallet names, returns a list of RemoveWalletFromGroupResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| remove_wallets_from_group_requests | any | not set | Yes
</details>
<details>
<summary>transfer_tokens</summary>

**Description**:

```

    Transfer tokens from one wallet to another.
    
    Expects a TransferTokensRequestContainer, returns a list of TransferTokenResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| transfer_tokens_requests | any | not set | Yes
</details>
<details>
<summary>create_dca_order</summary>

**Description**:

```

    Create a DCA order.
    
    Expects a DCAOrderRequestContainer, returns a list of DCAOrderResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dca_order_requests | any | not set | Yes
</details>
<details>
<summary>list_dca_orders</summary>

**Description**:

```

    List all DCA orders.
    
    Returns a list of DCAOrderResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| list_dca_order_requests | any | not set | Yes
</details>
<details>
<summary>cancel_dca_order</summary>

**Description**:

```

    Create a DCA order.

    Note: Make a single or multiple dca_order_requests 
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cancel_dca_order_requests | any | not set | Yes
</details>
<details>
<summary>create_order</summary>

**Description**:

```

    Create a order. Can be a limit or stop loss order
    
    Expects a CreateOrderRequestContainer, returns a CreateOrderResponseContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| create_order_requests | any | not set | Yes
</details>
<details>
<summary>cancel_order</summary>

**Description**:

```

    Cancel a limit or stop loss order.
    
    Expects a CancelOrderRequestContainer, returns a CancelOrderResponseContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cancel_order_requests | any | not set | Yes
</details>
<details>
<summary>stake_quote</summary>

**Description**:

```

    Retrieve a stake quote.
    
    Expects a StakeQuoteRequestContainer, returns a SwapQuoteRequestContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stake_quote_requests | any | not set | Yes
</details>
<details>
<summary>unstake_quote</summary>

**Description**:

```

    Retrieve an unstake quote.

    Expects a UnstakeQuoteRequestContainer, returns a SwapQuoteRequestContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| unstake_quote_requests | any | not set | Yes
</details>
<details>
<summary>stake_transaction</summary>

**Description**:

```

    Execute a stake transaction.
    
    Expects a StakeTransactionRequestContainer, returns a SwapTransactionRequestContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stake_transaction_requests | any | not set | Yes
</details>
<details>
<summary>unstake_transaction</summary>

**Description**:

```

    Execute an unstake transaction.
    
    Expects a UnstakeTransactionRequestContainer, returns a SwapTransactionRequestContainer.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| unstake_transaction_requests | any | not set | Yes
</details>
<details>
<summary>get_top_trending_tokens</summary>

**Description**:

```

    Get the top trending tokens in a particular time frame. Great for comparing market cap or volume.
    
    Expects a TopTrendingTokensRequest, returns a list of tokens with their details.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| top_trending_tokens_requests | any | not set | Yes
</details>
<details>
<summary>get_stake_balances</summary>

**Description**:

```

    Get the balance of staked SOL (jupSOL).
    
    Returns a StakeBalanceResponse.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>rename_wallets</summary>

**Description**:

```

    Rename wallets.
    
    Expects a RenameWalletRequestContainer, returns a list.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| rename_wallet_requests | any | not set | Yes
</details>
<details>
<summary>get_token_candle_data</summary>

**Description**:

```

    Get candle data about any token for analysis.

    Expects a CandleStickRequest, returns a list of candle sticks.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| candle_stick_requests | any | not set | Yes
</details>
<details>
<summary>send_key_to_telegram</summary>

**Description**:

```

    Send the mnemonic or private key to telegram.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| private_key_request | any | not set | Yes
</details>

## 📝 Prompts (1)
<details>
<summary>login_prompt</summary>

**Description**:

```

    A sample prompt to ask the user for their access token after providing an email.
    
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| email | not set |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | login_prompt | description | 1d2b1c9081a1da30310bdde4bc3bd285b2fdcdc557a63176b926e752d54e51aa |
| prompts | login_prompt | email | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| tools | add_wallets_to_group | description | a92848ff918afddafecc13d2acb22edf5b380893276a10c5e2c65a5e1c753747 |
| tools | archive_wallet_group | description | 834ad1201e6d49fe574311966069cf68060d708f2428d036bd1cf797881878c0 |
| tools | archive_wallets | description | dbfefce51287721c267e3577449d59bbdb4fa3d0716b6cb85dea34021a4c6953 |
| tools | calculate_token_conversion | description | fa276f406ba6f9527323dd020f443ca61f9b1ab9a9c9f49f68a51b2c4ea286b9 |
| tools | calculator | description | c81ae7f6b4be034c50efd9be2d02a13f960cb2ca29cf7766e3199078c85f507a |
| tools | cancel_dca_order | description | d1dce965b293e44ff4b9aef8199289246fab8f9ee8b4e07d07752f25d7564ff7 |
| tools | cancel_order | description | 2c0e81dac0e62c5701af6aee3a0d3b9a5a304127f458f4c4d13b2fb5e567f4eb |
| tools | create_dca_order | description | 3563a16213680f862a3f41490468fd03b142d0456cc7eb52c2bd1092f834b9ed |
| tools | create_groups | description | 065fbf7645047dee0d03e2ad1e95c5261975bfc0d66a384618d286d80d91d73e |
| tools | create_order | description | 1b4031957ce37fdbffec6c0628929aadf73042a188ddfd4cecd536ced03a8f1e |
| tools | create_wallet | description | e348a008c19665493a85cf188b4f83a96ca74a4afa7d29b44c04629a4a954b8c |
| tools | get_all_orders | description | 543c3eeca882e0f7d1b7ca4fc27155c16793647d04c02018ea2a8fcd2c805211 |
| tools | get_all_wallets | description | a78d9e2ca7068f5928084eacb8c21b29e45a51c8bd493f947892aa9dcfe90504 |
| tools | get_armor_mcp_version | description | 7e30f301f4471a7dc9cd43437566b55614a4b51b3acb5b9edfbd2e20b96f0547 |
| tools | get_current_time | description | 36a16feb359f4dca32e78bf78853eef054a0ddad07a08cf603aa0c5a7cbf1b13 |
| tools | get_stake_balances | description | 3dbd458a0274095a97b0471adc18f197c44894e4c5f83f46de81757f58fcc5d5 |
| tools | get_token_candle_data | description | a61a2fb25b8dc2db7fe079a4c07109126892b066c23dadd34f67bd117e9d9ce6 |
| tools | get_top_trending_tokens | description | 583ec6008c17ec8448134b94b26d29ba33ca0335745bd1f0b0a0015e893fcc1f |
| tools | get_wallet_token_balance | description | a8474468f5c948b45bd63fed218bd316c89fa0b7a1ff3f1e24e73f2ba4805f37 |
| tools | list_dca_orders | description | 3816fa6952ee576ce4d7c02f33d418b52c32ce68d03479210d9e7c37f5d137c0 |
| tools | list_groups | description | 66885c0fe5691ee0480c8a6b7d6618ecf87b99b720e1e41e93f8c717976d8fa5 |
| tools | list_single_group | description | a6dc27ac6f49bf6cf46c55868e78fb0296e9a0271ecae7e9f8937fe34d3eed78 |
| tools | remove_wallets_from_group | description | 6940d566ff428326ba534638882317f12b40b27ba88a3dc9914b76fc9b629b86 |
| tools | rename_wallets | description | fcd07f846ea7983164a49dcdd06755e9a658d0a57735076db894991307277688 |
| tools | search_official_token_address | description | 94046a4947c62f52335f048761c321dacc685666b3ee22ad23f0cd05e2f08a44 |
| tools | search_token_details | description | c01d85c0e22789b5b019d5e9d3ea80bb34cca4bfa64256df66f74d3d37a43b80 |
| tools | send_key_to_telegram | description | 47a717f81f02a337ea460290239c26fa250c59c4b0bfcfd78e57e558ec663db6 |
| tools | stake_quote | description | f4f753918cdec22c4e3cbc8f60bb6e1ec58903f8e8cbed48a602e83ff7eed637 |
| tools | stake_transaction | description | 845ba6e75a53a61f956737af0887e5637e2bef5e1041d57750300427d8f05541 |
| tools | swap_quote | description | f020139f785da4b4eac1850ed21af8e6496a654469fa20ca01cd07a4d078c47e |
| tools | swap_transaction | description | fc23531dd62802f22ead258b29be86a26c19c239b1e09b6c664f738698a6c482 |
| tools | transfer_tokens | description | c6eec1f09699dbebb8e81e9502be4c300f13285abf473c27d98d99882d175244 |
| tools | unarchive_wallet_group | description | 626ace1ce93c841e9834cd952f64efc3fb518910412d71171035c466c38e5f07 |
| tools | unarchive_wallets | description | 5969c40c29e1916d3ec2e88fed1908b9ac2faff0ea8ca1da9020af5c514047fe |
| tools | unstake_quote | description | 143bbd69b1aae9f84cd90736bf5fb7b6cee4ae56a566771ea13a9e2c532db6e5 |
| tools | unstake_transaction | description | 5b637d0e10ad62cd0fb54ff91c271fb303fe8ef8a83edae23d6d897f3ad34535 |
| tools | wait_a_moment | description | d8ba2c2eaf7253f2d0c3acdf7c482a56a45e4b759f0ab55f081d72747d8abd6e |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
