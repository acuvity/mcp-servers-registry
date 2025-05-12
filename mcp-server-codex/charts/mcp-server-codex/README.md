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


# What is mcp-server-codex?

[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-codex/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-codex/0.1.3?logo=docker&logoColor=fff&label=0.1.3)](https://hub.docker.com/r/acuvity/mcp-server-codex)
[![PyPI](https://img.shields.io/badge/0.1.3-3775A9?logo=pypi&logoColor=fff&label=@codex-data/codex-mcp)](https://github.com/Codex-Data/codex-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-codex&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CODEX_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-codex%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Codex API integration for real-time enriched blockchain and market data on 60+ networks.

Packaged by Acuvity from @codex-data/codex-mcp original [sources](https://github.com/Codex-Data/codex-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-codex/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/charts/mcp-server-codex/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @codex-data/codex-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/charts/mcp-server-codex#minibridge) for Helm charts).


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Codex ](https://github.com/Codex-Data/codex-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @codex-data/codex-mcp ](https://github.com/Codex-Data/codex-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @codex-data/codex-mcp ](https://github.com/Codex-Data/codex-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/charts/mcp-server-codex)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-codex/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.3`

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
  - `CODEX_API_KEY` secret to be set as secrets.CODEX_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-codex --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-codex --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-codex
```

From there your MCP server mcp-server-codex will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-codex` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-codex
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-codex` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-codex oci://docker.io/acuvity/mcp-server-codex --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (25)
<details>
<summary>get_networks</summary>

**Description**:

```
Get a list of all blockchain networks supported by Codex
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_network_status</summary>

**Description**:

```
Get the status of a specific blockchain network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| networkId | number | The network ID to get status for | Yes
</details>
<details>
<summary>get_network_stats</summary>

**Description**:

```
Get metadata and statistics for a given network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| networkId | number | The network ID to get stats for | Yes
</details>
<details>
<summary>get_token_info</summary>

**Description**:

```
Get detailed information about a specific token
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_tokens</summary>

**Description**:

```
Get detailed information about multiple tokens
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ids | array | not set | Yes
</details>
<details>
<summary>get_token_prices</summary>

**Description**:

```
Get real-time or historical prices for a list of tokens
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| inputs | array | not set | Yes
</details>
<details>
<summary>filter_tokens</summary>

**Description**:

```
Filter tokens by various criteria
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| excludeTokens | array | A list of token IDs to exclude from results (address:networkId) | No
| filters | object | A set of filters to apply | No
| limit | number | Maximum number of items to return | No
| offset | number | Number of items to skip | No
| phrase | string | A phrase to search for. Can match a token contract address or partially match a token's name or symbol | No
| rankings | array | A list of ranking attributes to apply | No
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
| tokens | any | A list of token IDs (address:networkId) or addresses. Can be left blank to discover new tokens | No
</details>
<details>
<summary>get_token_holders</summary>

**Description**:

```
Returns list of wallets that hold a given token, ordered by holdings descending. Also has the unique count of holders for that token. (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| cursor | string | Cursor for pagination | No
| networkId | number | The network ID the token is on | Yes
| sort | object | Sort options for the holders list | No
</details>
<details>
<summary>get_token_balances</summary>

**Description**:

```
Get token balances for a wallet (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | Cursor for pagination | No
| filterToken | string | Optional token to filter balances for | No
| includeNative | boolean | Include native token balances | No
| networkId | number | The network ID the wallet is on | Yes
| walletAddress | string | The wallet address to get balances for | Yes
</details>
<details>
<summary>get_top_10_holders_percent</summary>

**Description**:

```
Get the percentage of tokens held by top 10 holders
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_token_chart_data</summary>

**Description**:

```
Returns bar chart data to track token price changes over time. Can be queried using either a pair address or token address.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair address or token address to get chart data for. If a token address is provided, the token's top pair will be used. | Yes
| countback | number | not set | No
| currencyCode | string | not set | No
| from | number | Unix timestamp | Yes
| networkId | number | The network ID the pair or token is on | Yes
| quoteToken | string | The token of interest (token0 or token1) | No
| removeEmptyBars | boolean | not set | No
| removeLeadingNullValues | any | not set | No
| resolution | string | The time frame for each candle. Available options are 1, 5, 15, 30, 60, 240, 720, 1D, 7D | Yes
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
| symbolType | string | not set | No
| to | any | not set | Yes
</details>
<details>
<summary>get_token_chart_urls</summary>

**Description**:

```
Chart images for token pairs (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| networkId | number | The network ID the pair is on | Yes
| pairAddress | string | The pair contract address | Yes
| quoteToken | string | The token of interest (token0 or token1) | No
</details>
<details>
<summary>get_latest_tokens</summary>

**Description**:

```
Get a list of the latests token contracts deployed (Codex Growth and Enterprise Plans only). Note: This endpoint is only available on Ethereum, Optimum, Base, and Arbitrum networks (network IDs 1, 10, 8453, and 42161).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | Maximum number of items to return | No
| networkFilter | array | not set | Yes
| offset | number | Number of items to skip | No
</details>
<details>
<summary>get_token_sparklines</summary>

**Description**:

```
Get a list of token simple chart data (sparklines) for the given tokens
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | Array of token contract addresses | Yes
| networkId | number | The network ID the tokens are on | Yes
</details>
<details>
<summary>get_token_events</summary>

**Description**:

```
Get transactions for a token pair
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | A cursor for use in pagination | No
| direction | string | The direction to sort the events by | No
| limit | number | The maximum number of events to return | No
| query | object | Query parameters for filtering token events | Yes
</details>
<details>
<summary>get_token_events_for_maker</summary>

**Description**:

```
Get a list of token events for a given wallet address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | A cursor for use in pagination | No
| direction | string | The direction to sort the events by | No
| limit | number | The maximum number of events to return | No
| query | object | Query parameters for filtering token events | Yes
</details>
<details>
<summary>get_detailed_pair_stats</summary>

**Description**:

```
Get bucketed stats for a given token within a pair
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| bucketCount | number | The number of aggregated values to receive. Note: Each duration has predetermined bucket sizes. The first n-1 buckets are historical. The last bucket is a snapshot of current data. | No
| duration | string | The duration for stats | Yes
| networkId | number | The network ID the pair is on | Yes
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
| timestamp | number | not set | No
| tokenOfInterest | string | not set | No
</details>
<details>
<summary>get_detailed_pairs_stats</summary>

**Description**:

```
Get bucketed stats for a given token within a list of pairs
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| bucketCount | number | The number of aggregated values to receive. Note: Each duration has predetermined bucket sizes. The first n-1 buckets are historical. The last bucket is a snapshot of current data. | No
| duration | string | The duration for stats | Yes
| networkId | number | The network ID the pairs are on | Yes
| pairAddresses | array | Array of pair contract addresses | Yes
</details>
<details>
<summary>filter_pairs</summary>

**Description**:

```
Get a list of pairs based on various filters like volume, price, liquidity, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | not set | No
| limit | number | Maximum number of items to return | No
| offset | number | Number of items to skip | No
| pairs | any | not set | No
| phrase | string | not set | No
| rankings | any | not set | No
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
</details>
<details>
<summary>get_pair_metadata</summary>

**Description**:

```
Get metadata for a pair of tokens, including price, volume, and liquidity stats over various timeframes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| networkId | number | The network ID the pair is on | Yes
| quoteToken | string | The token of interest (token0 or token1) | No
| statsType | string | The type of statistics returned. Can be FILTERED or UNFILTERED | No
</details>
<details>
<summary>get_token_pairs</summary>

**Description**:

```
Get a list of pairs for a token
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| limit | number | Maximum number of pairs to return (default: 10) | No
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_token_pairs_with_metadata</summary>

**Description**:

```
Get pairs with metadata for a specific token
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The token contract address | Yes
| limit | number | Maximum number of pairs to return (default: 10) | No
| networkId | number | The network ID the token is on | Yes
</details>
<details>
<summary>get_liquidity_metadata</summary>

**Description**:

```
Get liquidity metadata for a pair, including both unlocked and locked liquidity data
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| networkId | number | The network ID the pair is on | Yes
</details>
<details>
<summary>get_liquidity_locks</summary>

**Description**:

```
Get liquidity locks for a pair, including details about locked amounts, lock duration, and owner information (Codex Growth and Enterprise Plans only)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The pair contract address | Yes
| cursor | string | Cursor for pagination | No
| networkId | number | The network ID the pair is on | Yes
</details>
<details>
<summary>filter_exchanges</summary>

**Description**:

```
Get a list of exchanges based on various filters like volume, transactions, active users, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | object | not set | No
| limit | number | Maximum number of items to return | No
| offset | number | Number of items to skip | No
| phrase | string | A phrase to search for. Can match an exchange address or ID (address:networkId), or partially match an exchange name | No
| rankings | array | A list of ranking attributes to apply | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | filter_exchanges | description | 8630c1b6c5eebcc85ba3291a22119ec0c08d81cfd442d6a98e5984a36a43fa7e |
| tools | filter_exchanges | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | filter_exchanges | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | filter_exchanges | phrase | 53f29b67c8d12d5eba8d98ce93c733c3da39a26b8615c11d42a8d14dbd6ecc64 |
| tools | filter_exchanges | rankings | 7ffc7462315f7dc4a4d4d466ae87caba4c8a82ac3434dd69690de0bd6447aa5c |
| tools | filter_pairs | description | 21860fffc620dc64fb8a8950458c0ca1c2d246f10a43132bb0eff087687afc54 |
| tools | filter_pairs | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | filter_pairs | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | filter_pairs | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | filter_tokens | description | 7f42285dfb6edeb092932d1d5150790d852fa4088d9843b76fb0146e3c7092f1 |
| tools | filter_tokens | excludeTokens | 2a18cae57bbaa74042dac148d0785f623868ca19c323c6b14009aebf5545819b |
| tools | filter_tokens | filters | 5e2d490530e30f2a5c970a251f1982736aac2e3d6245f6146115ce846563d092 |
| tools | filter_tokens | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | filter_tokens | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | filter_tokens | phrase | 3a4cd287a899ea850962f034b94b6d9304978abc39f0e5b12e19295dcec4002a |
| tools | filter_tokens | rankings | 7ffc7462315f7dc4a4d4d466ae87caba4c8a82ac3434dd69690de0bd6447aa5c |
| tools | filter_tokens | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | filter_tokens | tokens | 620a1127deffb97aeddc2ddef7bfb5d4cfd3160011685d6f16602a2a5d09ffd0 |
| tools | get_detailed_pair_stats | description | 9fc39174e9aa193c8ad1c90bb004d9a522d3596cddca3d9de827a1c8a6cc4ee1 |
| tools | get_detailed_pair_stats | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_detailed_pair_stats | bucketCount | a8115d5bc9d7211a3ba644593d51d8abce2209688f49bbd22071802730a50bbf |
| tools | get_detailed_pair_stats | duration | eca43c06d8b35b718ce4c6f1b1fa2edee25e80de7ff735e5f627e73a4d7b8462 |
| tools | get_detailed_pair_stats | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_detailed_pair_stats | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | get_detailed_pairs_stats | description | 470cb8d70ab7a48d4eaae053c2ac0d6e72bdc8093c1b73d6ce69baa47f3a7cbc |
| tools | get_detailed_pairs_stats | bucketCount | a8115d5bc9d7211a3ba644593d51d8abce2209688f49bbd22071802730a50bbf |
| tools | get_detailed_pairs_stats | duration | eca43c06d8b35b718ce4c6f1b1fa2edee25e80de7ff735e5f627e73a4d7b8462 |
| tools | get_detailed_pairs_stats | networkId | 769e842b67f6ecd7e0b62c7ded4ac995cd898d2d4c08490ec62a6d96b0cb67a2 |
| tools | get_detailed_pairs_stats | pairAddresses | bb118d83f2028e02dce29ed7b4f033e1c10535002722036d1d9e9d1884ed0b52 |
| tools | get_latest_tokens | description | 6c1f9cf9296841e1ce565d3e5dafd616c18bddf8a0ff3071c523bb919c97b195 |
| tools | get_latest_tokens | limit | 4fcfd7f301034d3a93e4f4f9f430796d7b41713775c03972f6ca853570df4404 |
| tools | get_latest_tokens | offset | 8abf1d3bcf2b7ca974c3ddfbb224bdd579328225311ab88f42c50f8097f74d85 |
| tools | get_liquidity_locks | description | 46313e0acd7757c54bf60a9c30b5ff96cf35b055e12bc116ef775a424b80a3a0 |
| tools | get_liquidity_locks | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_liquidity_locks | cursor | 81a3aa63db02772fff8daadbfc1304469ac0c2bee674363902041e3474bd5d14 |
| tools | get_liquidity_locks | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_liquidity_metadata | description | 9fffc813b44d940c80c42534a9f958e068700e0988c2be7bd759e6cf66b308b6 |
| tools | get_liquidity_metadata | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_liquidity_metadata | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_network_stats | description | ffcfa8385b76a2fd430b1d9b87e46efe9a5897cc31fa9c7fce6e6ef6086cabbf |
| tools | get_network_stats | networkId | 51f97a45d980cadc59936925b9f4ba1d832f3025192094619863ddf3bace4f13 |
| tools | get_network_status | description | d00d1303c24cf762215e9237abfceffa4495737886ed702fca5b4ecf014eab1e |
| tools | get_network_status | networkId | ec0489f5be47d47fc4000d7ffa78fe9b986e3845433b8187fcbb61917f137ba8 |
| tools | get_networks | description | d3f5cff9649dd3b2dbfbf114fef1de8109c97ffcc942d2d0c39f5fd9adb0b4be |
| tools | get_pair_metadata | description | 9e96de2e28ddcf03d626555cdd2a0f2122b6da251ffae11d1eba0eb006f94dab |
| tools | get_pair_metadata | address | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_pair_metadata | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_pair_metadata | quoteToken | 08bbd99302b6a571a05e72dcaccd7e2be846a5ebd5b6671fc79059888022545b |
| tools | get_pair_metadata | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | get_token_balances | description | 092b99a455a510605e2c11239bd4e660cc9d59590f5a63881f809ea0ae6e4829 |
| tools | get_token_balances | cursor | 81a3aa63db02772fff8daadbfc1304469ac0c2bee674363902041e3474bd5d14 |
| tools | get_token_balances | filterToken | 856147bf47963c5fa3b398000b8254dc8c9183d4fdc0f19f5b0a53ce6b92e1f9 |
| tools | get_token_balances | includeNative | 1fa43d78f4ac0bf01712926d814025c68c12f802f698c513aec50c724d753ce0 |
| tools | get_token_balances | networkId | 842075da3361b80fb82e59882ca0aeca463b0dfae3a88cafc1d93300c6435f94 |
| tools | get_token_balances | walletAddress | 16994c44e621216227e163edaaa50a589cc00005411bbe22ae036e8761e3438c |
| tools | get_token_chart_data | description | a19d5851b5e4388b73126f470c87ff7cd2b53bcbedc615ba3123c54a335e193e |
| tools | get_token_chart_data | address | b5f3cdb268f4472b253f29af47672b6790fb7a33594a31e128772ebf02743426 |
| tools | get_token_chart_data | from | 57c536372fb30c9882041213d54caf3b1c24a0339c1fda6980dd7b07eefa862a |
| tools | get_token_chart_data | networkId | afb0b46b6fb98b529d11e9570a99683ed44f3ead5b731c042a7def871d6cdf9e |
| tools | get_token_chart_data | quoteToken | 08bbd99302b6a571a05e72dcaccd7e2be846a5ebd5b6671fc79059888022545b |
| tools | get_token_chart_data | resolution | 9411ec331a694f15f2a44c23b97541bd2ef8b3283fcdc08128b4e5d075465e70 |
| tools | get_token_chart_data | statsType | 0ddbc9e19f5dd643d1319be910b8afb320993917806f9bd83574f8adcbc028d1 |
| tools | get_token_chart_urls | description | d13d3a29be9f78df3f02f44a7efdaf8989d6859601cbaa88c3ab3d97fe1426db |
| tools | get_token_chart_urls | networkId | 18700deb62cb74d9dfbcee29ff61e94d1ceb4d9c93d9fb8d0c98ba61339459b9 |
| tools | get_token_chart_urls | pairAddress | a38aa3fcfff27ccf28aca359f18943a9ec5cea998c7b5634865d63debd9c1084 |
| tools | get_token_chart_urls | quoteToken | 08bbd99302b6a571a05e72dcaccd7e2be846a5ebd5b6671fc79059888022545b |
| tools | get_token_events | description | 6d57b89054e980fcfd78227c5a2d6e5227b12c522d3456a8e9f139d3036374e0 |
| tools | get_token_events | cursor | bdb32017fa9c6d99d3a448b4b82f877ab67b967dafb13768023bede720ce5e36 |
| tools | get_token_events | direction | ae424249e49728aa72ea501db533ddb30f70cc1a41725e4acefd5ff942d6ca28 |
| tools | get_token_events | limit | 58aeef310c17e3ae9fbad20ae949bfd619e1aa233457b5ec4e319134febc3119 |
| tools | get_token_events | query | ad287d740db02910935323d0212f11fa32701a3197672cf6a56241a0cd885d6f |
| tools | get_token_events_for_maker | description | 30d3fca07600242d64807ed0b273c5eb198511dfc0966604d97e185e5702e039 |
| tools | get_token_events_for_maker | cursor | bdb32017fa9c6d99d3a448b4b82f877ab67b967dafb13768023bede720ce5e36 |
| tools | get_token_events_for_maker | direction | ae424249e49728aa72ea501db533ddb30f70cc1a41725e4acefd5ff942d6ca28 |
| tools | get_token_events_for_maker | limit | 58aeef310c17e3ae9fbad20ae949bfd619e1aa233457b5ec4e319134febc3119 |
| tools | get_token_events_for_maker | query | ad287d740db02910935323d0212f11fa32701a3197672cf6a56241a0cd885d6f |
| tools | get_token_holders | description | fc449faf373608ebe12f069e17fd58357247fb08b0beeff0c287e9bbf03cc196 |
| tools | get_token_holders | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_holders | cursor | 81a3aa63db02772fff8daadbfc1304469ac0c2bee674363902041e3474bd5d14 |
| tools | get_token_holders | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_holders | sort | 4a0bb4740faf12bf6d6e89b2ac9d91a4079ee16aa499ff91e757e0fe175232f8 |
| tools | get_token_info | description | 73948792b8dee5194fa86152b0b138facda5af769ddf019e7521aedcfb8daf46 |
| tools | get_token_info | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_info | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_pairs | description | 4892a5976e03b2131377a544ca747d1430ee2d1a26a49bb49be268daa32faddc |
| tools | get_token_pairs | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_pairs | limit | 41d99529a15a9452e284d987dcd32299180074a66358962c9047d6c8e8c24ebc |
| tools | get_token_pairs | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_pairs_with_metadata | description | 64fe25d2e3dffafedf1e38ad2430f9138a88d669685d55acf62af61a08bff029 |
| tools | get_token_pairs_with_metadata | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_token_pairs_with_metadata | limit | 41d99529a15a9452e284d987dcd32299180074a66358962c9047d6c8e8c24ebc |
| tools | get_token_pairs_with_metadata | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |
| tools | get_token_prices | description | ae01f6a57c459aa1829b25acde1a313b6bafe76d56239d96047762000cee346d |
| tools | get_token_sparklines | description | c8f00c6033b79ff5b4e5a956356df5aea4fcd5bf182c8122cb58285a8f286a26 |
| tools | get_token_sparklines | addresses | e27c4e3ea68338285c4c8a4aa13227ea5d3508adeb94adc4111585c82509e2b8 |
| tools | get_token_sparklines | networkId | ee19b925f1ac5a57dbd766748d5b17eec77f951b90ea9289b93d29939944e1de |
| tools | get_tokens | description | 5d94664ccc45387dcd5cada3ba00d9458c198d715358e4853e08f513112bc478 |
| tools | get_top_10_holders_percent | description | a51fc3400cb76ea941fec38a581728c9c0df1985b8c3d0dc83088e9f8a0f0114 |
| tools | get_top_10_holders_percent | address | 92cf3586d95381037ab1da77d5f68fd3532dd9d94e3398abe8bf6dee4f945c47 |
| tools | get_top_10_holders_percent | networkId | fbed697d623d0cc2b42dce6e350a9ac29ac3e421d770069fe7812cf6df86643a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
