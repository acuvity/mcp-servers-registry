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


# What is mcp-server-evm?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-evm/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-evm/1.1.3?logo=docker&logoColor=fff&label=1.1.3)](https://hub.docker.com/r/acuvity/mcp-server-evm)
[![PyPI](https://img.shields.io/badge/1.1.3-3775A9?logo=pypi&logoColor=fff&label=@mcpdotdirect/evm-mcp-server)](https://github.com/mcpdotdirect/evm-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-evm/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-evm&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-evm%3A1.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Comprehensive blockchain services for 30+ networks, on native tokens, ERC20, NFTs, smart contracts.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @mcpdotdirect/evm-mcp-server original [sources](https://github.com/mcpdotdirect/evm-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-evm/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm/charts/mcp-server-evm/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @mcpdotdirect/evm-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Etheral ](https://github.com/mcpdotdirect/evm-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @mcpdotdirect/evm-mcp-server ](https://github.com/mcpdotdirect/evm-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @mcpdotdirect/evm-mcp-server ](https://github.com/mcpdotdirect/evm-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm/charts/mcp-server-evm)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.1.3`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-evm:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-evm:1.0.0-1.1.3`

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
helm install mcp-server-evm oci://docker.io/acuvity/mcp-server-evm --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-evm --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-evm --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-evm oci://docker.io/acuvity/mcp-server-evm --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-evm
```

From there your MCP server mcp-server-evm will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-evm` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-evm
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-evm` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-evm oci://docker.io/acuvity/mcp-server-evm --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-evm oci://docker.io/acuvity/mcp-server-evm --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-evm oci://docker.io/acuvity/mcp-server-evm --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-evm oci://docker.io/acuvity/mcp-server-evm --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (28)
<details>
<summary>get_chain_info</summary>

**Description**:

```
Get information about an EVM network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>resolve_ens</summary>

**Description**:

```
Resolve an ENS name to an Ethereum address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ensName | string | ENS name to resolve (e.g., 'vitalik.eth') | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. ENS resolution works best on Ethereum mainnet. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_supported_networks</summary>

**Description**:

```
Get a list of supported EVM networks
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_block_by_number</summary>

**Description**:

```
Get a block by its block number
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| blockNumber | number | The block number to fetch | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_latest_block</summary>

**Description**:

```
Get the latest block from the EVM
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_balance</summary>

**Description**:

```
Get the native token balance (ETH, MATIC, etc.) for an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The wallet address or ENS name (e.g., '0x1234...' or 'vitalik.eth') to check the balance for | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_erc20_balance</summary>

**Description**:

```
Get the ERC20 token balance of an Ethereum address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The Ethereum address to check | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| tokenAddress | string | The ERC20 token contract address | Yes
</details>
<details>
<summary>get_token_balance</summary>

**Description**:

```
Get the balance of an ERC20 token for an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
| ownerAddress | string | The wallet address or ENS name to check the balance for (e.g., '0x1234...' or 'vitalik.eth') | Yes
| tokenAddress | string | The contract address or ENS name of the ERC20 token (e.g., '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' for USDC or 'uniswap.eth') | Yes
</details>
<details>
<summary>get_transaction</summary>

**Description**:

```
Get detailed information about a specific transaction by its hash. Includes sender, recipient, value, data, and more.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Defaults to Ethereum mainnet. | No
| txHash | string | The transaction hash to look up (e.g., '0x1234...') | Yes
</details>
<details>
<summary>get_transaction_receipt</summary>

**Description**:

```
Get a transaction receipt by its hash
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| txHash | string | The transaction hash to look up | Yes
</details>
<details>
<summary>estimate_gas</summary>

**Description**:

```
Estimate the gas cost for a transaction
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | string | The transaction data as a hex string | No
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| to | string | The recipient address | Yes
| value | string | The amount of ETH to send in ether (e.g., '0.1') | No
</details>
<details>
<summary>transfer_eth</summary>

**Description**:

```
Transfer native tokens (ETH, MATIC, etc.) to an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | Amount to send in ETH (or the native token of the network), as a string (e.g., '0.1') | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
| privateKey | string | Private key of the sender account in hex format (with or without 0x prefix). SECURITY: This is used only for transaction signing and is not stored. | Yes
| to | string | The recipient address or ENS name (e.g., '0x1234...' or 'vitalik.eth') | Yes
</details>
<details>
<summary>transfer_erc20</summary>

**Description**:

```
Transfer ERC20 tokens to another address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The amount of tokens to send (in token units, e.g., '10' for 10 tokens) | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
| privateKey | string | Private key of the sending account (this is used for signing and is never stored) | Yes
| toAddress | string | The recipient address | Yes
| tokenAddress | string | The address of the ERC20 token contract | Yes
</details>
<details>
<summary>approve_token_spending</summary>

**Description**:

```
Approve another address (like a DeFi protocol or exchange) to spend your ERC20 tokens. This is often required before interacting with DeFi protocols.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The amount of tokens to approve in token units, not wei (e.g., '1000' to approve spending 1000 tokens). Use a very large number for unlimited approval. | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Defaults to Ethereum mainnet. | No
| privateKey | string | Private key of the token owner account in hex format (with or without 0x prefix). SECURITY: This is used only for transaction signing and is not stored. | Yes
| spenderAddress | string | The contract address being approved to spend your tokens (e.g., a DEX or lending protocol) | Yes
| tokenAddress | string | The contract address of the ERC20 token to approve for spending (e.g., '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' for USDC on Ethereum) | Yes
</details>
<details>
<summary>transfer_nft</summary>

**Description**:

```
Transfer an NFT (ERC721 token) from one address to another. Requires the private key of the current owner for signing the transaction.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Most NFTs are on Ethereum mainnet, which is the default. | No
| privateKey | string | Private key of the NFT owner account in hex format (with or without 0x prefix). SECURITY: This is used only for transaction signing and is not stored. | Yes
| toAddress | string | The recipient wallet address that will receive the NFT | Yes
| tokenAddress | string | The contract address of the NFT collection (e.g., '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D' for Bored Ape Yacht Club) | Yes
| tokenId | string | The ID of the specific NFT to transfer (e.g., '1234') | Yes
</details>
<details>
<summary>transfer_erc1155</summary>

**Description**:

```
Transfer ERC1155 tokens to another address. ERC1155 is a multi-token standard that can represent both fungible and non-fungible tokens in a single contract.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | The quantity of tokens to send (e.g., '1' for a single NFT or '10' for 10 fungible tokens) | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. ERC1155 tokens exist across many networks. Defaults to Ethereum mainnet. | No
| privateKey | string | Private key of the token owner account in hex format (with or without 0x prefix). SECURITY: This is used only for transaction signing and is not stored. | Yes
| toAddress | string | The recipient wallet address that will receive the tokens | Yes
| tokenAddress | string | The contract address of the ERC1155 token collection (e.g., '0x76BE3b62873462d2142405439777e971754E8E77') | Yes
| tokenId | string | The ID of the specific token to transfer (e.g., '1234') | Yes
</details>
<details>
<summary>transfer_token</summary>

**Description**:

```
Transfer ERC20 tokens to an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | Amount of tokens to send as a string (e.g., '100' for 100 tokens). This will be adjusted for the token's decimals. | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
| privateKey | string | Private key of the sender account in hex format (with or without 0x prefix). SECURITY: This is used only for transaction signing and is not stored. | Yes
| toAddress | string | The recipient address or ENS name that will receive the tokens (e.g., '0x1234...' or 'vitalik.eth') | Yes
| tokenAddress | string | The contract address or ENS name of the ERC20 token to transfer (e.g., '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' for USDC or 'uniswap.eth') | Yes
</details>
<details>
<summary>read_contract</summary>

**Description**:

```
Read data from a smart contract by calling a view/pure function. This doesn't modify blockchain state and doesn't require gas or signing.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| abi | array | The ABI (Application Binary Interface) of the smart contract function, as a JSON array | Yes
| args | array | The arguments to pass to the function, as an array (e.g., ['0x1234...']) | No
| contractAddress | string | The address of the smart contract to interact with | Yes
| functionName | string | The name of the function to call on the contract (e.g., 'balanceOf') | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>write_contract</summary>

**Description**:

```
Write data to a smart contract by calling a state-changing function. This modifies blockchain state and requires gas payment and transaction signing.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| abi | array | The ABI (Application Binary Interface) of the smart contract function, as a JSON array | Yes
| args | array | The arguments to pass to the function, as an array (e.g., ['0x1234...', '1000000000000000000']) | Yes
| contractAddress | string | The address of the smart contract to interact with | Yes
| functionName | string | The name of the function to call on the contract (e.g., 'transfer') | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Defaults to Ethereum mainnet. | No
| privateKey | string | Private key of the sending account in hex format (with or without 0x prefix). SECURITY: This is used only for transaction signing and is not stored. | Yes
</details>
<details>
<summary>is_contract</summary>

**Description**:

```
Check if an address is a smart contract or an externally owned account (EOA)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The wallet or contract address or ENS name to check (e.g., '0x1234...' or 'uniswap.eth') | Yes
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_token_info</summary>

**Description**:

```
Get comprehensive information about an ERC20 token including name, symbol, decimals, total supply, and other metadata. Use this to analyze any token on EVM chains.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Defaults to Ethereum mainnet. | No
| tokenAddress | string | The contract address of the ERC20 token (e.g., '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' for USDC on Ethereum) | Yes
</details>
<details>
<summary>get_token_balance_erc20</summary>

**Description**:

```
Get ERC20 token balance for an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The address to check balance for | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| tokenAddress | string | The ERC20 token contract address | Yes
</details>
<details>
<summary>get_nft_info</summary>

**Description**:

```
Get detailed information about a specific NFT (ERC721 token), including collection name, symbol, token URI, and current owner if available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Most NFTs are on Ethereum mainnet, which is the default. | No
| tokenAddress | string | The contract address of the NFT collection (e.g., '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D' for Bored Ape Yacht Club) | Yes
| tokenId | string | The ID of the specific NFT token to query (e.g., '1234') | Yes
</details>
<details>
<summary>check_nft_ownership</summary>

**Description**:

```
Check if an address owns a specific NFT
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. | No
| ownerAddress | string | The wallet address or ENS name to check ownership against (e.g., '0x1234...' or 'vitalik.eth') | Yes
| tokenAddress | string | The contract address or ENS name of the NFT collection (e.g., '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D' for BAYC or 'boredapeyachtclub.eth') | Yes
| tokenId | string | The ID of the NFT to check (e.g., '1234') | Yes
</details>
<details>
<summary>get_erc1155_token_uri</summary>

**Description**:

```
Get the metadata URI for an ERC1155 token (multi-token standard used for both fungible and non-fungible tokens). The URI typically points to JSON metadata about the token.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. ERC1155 tokens exist across many networks. Defaults to Ethereum mainnet. | No
| tokenAddress | string | The contract address of the ERC1155 token collection (e.g., '0x76BE3b62873462d2142405439777e971754E8E77') | Yes
| tokenId | string | The ID of the specific token to query metadata for (e.g., '1234') | Yes
</details>
<details>
<summary>get_nft_balance</summary>

**Description**:

```
Get the total number of NFTs owned by an address from a specific collection. This returns the count of NFTs, not individual token IDs.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. Most NFTs are on Ethereum mainnet, which is the default. | No
| ownerAddress | string | The wallet address to check the NFT balance for (e.g., '0x1234...') | Yes
| tokenAddress | string | The contract address of the NFT collection (e.g., '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D' for Bored Ape Yacht Club) | Yes
</details>
<details>
<summary>get_erc1155_balance</summary>

**Description**:

```
Get the balance of a specific ERC1155 token ID owned by an address. ERC1155 allows multiple tokens of the same ID, so the balance can be greater than 1.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', 'polygon') or chain ID. ERC1155 tokens exist across many networks. Defaults to Ethereum mainnet. | No
| ownerAddress | string | The wallet address to check the token balance for (e.g., '0x1234...') | Yes
| tokenAddress | string | The contract address of the ERC1155 token collection (e.g., '0x76BE3b62873462d2142405439777e971754E8E77') | Yes
| tokenId | string | The ID of the specific token to check the balance for (e.g., '1234') | Yes
</details>
<details>
<summary>get_address_from_private_key</summary>

**Description**:

```
Get the EVM address derived from a private key
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| privateKey | string | Private key in hex format (with or without 0x prefix). SECURITY: This is used only for address derivation and is not stored. | Yes
</details>

## 📚 Resources (3)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| ethereum_chain_info | <no value> | evm://chain | - |
| default_latest_block | <no value> | evm://block/latest | - |
| supported_networks | <no value> | evm://networks | - |

</details>

## 📝 Prompts (7)
<details>
<summary>explore_block</summary>

**Description**:

```
Explore information about a specific block
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| blockNumber | Block number to explore. If not provided, latest block will be used. |No |
| network | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. |No |
<details>
<summary>analyze_transaction</summary>

**Description**:

```
Analyze a specific transaction
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| txHash | Transaction hash to analyze |Yes |
| network | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. |No |
<details>
<summary>analyze_address</summary>

**Description**:

```
Analyze an EVM address
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| address | Ethereum address to analyze |Yes |
| network | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. |No |
<details>
<summary>interact_with_contract</summary>

**Description**:

```
Get guidance on interacting with a smart contract
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| contractAddress | The contract address |Yes |
| abiJson | The contract ABI as a JSON string |No |
| network | Network name or chain ID. Defaults to Ethereum mainnet. |No |
<details>
<summary>explain_evm_concept</summary>

**Description**:

```
Get an explanation of an EVM concept
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| concept | The EVM concept to explain (e.g., gas, nonce, etc.) |Yes |
<details>
<summary>compare_networks</summary>

**Description**:

```
Compare different EVM-compatible networks
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| networkList | Comma-separated list of networks to compare (e.g., 'ethereum,optimism,arbitrum') |Yes |
<details>
<summary>analyze_token</summary>

**Description**:

```
Analyze an ERC20 or NFT token
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| tokenAddress | Token contract address to analyze |Yes |
| tokenType | Type of token to analyze (erc20, erc721/nft, or auto-detect). Defaults to auto. |No |
| tokenId | Token ID (required for NFT analysis) |No |
| network | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base', etc.) or chain ID. Supports all EVM-compatible networks. Defaults to Ethereum mainnet. |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | analyze_address | description | a3d10ea9e5c55645dabb4350f7394c0bafe3cdde7bcb5b5bf2a47f0824b4ebee |
| prompts | analyze_address | address | 311dcba201a1ef5be9ac016f1d3c72200e4b6b248ad8d7accffb1466885c408b |
| prompts | analyze_address | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| prompts | analyze_token | description | 2bae06837d084fb58815b823f5a74ef00659b310d027db844ede0254c7a15280 |
| prompts | analyze_token | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| prompts | analyze_token | tokenAddress | 829054ad26e90c638a514270039b80a53cd9915008e5709d2f34d684c42852bf |
| prompts | analyze_token | tokenId | e6a0f353c70ddd30130ef530e7d44203d08becb00d21bca0e2dffec853906e41 |
| prompts | analyze_token | tokenType | 8ad772d8e8192ca4e793a632275e56b3db00d2cf21e160dab2dc803d4e45b4fa |
| prompts | analyze_transaction | description | e242ac0615bc7e7cb83cb552b196012d92e2490d92bc9bd3ce71b116fd58d6b5 |
| prompts | analyze_transaction | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| prompts | analyze_transaction | txHash | 47d32477b3344bde9f0a97f226546000add778da0b56a4fb7b6ca41bc1286606 |
| prompts | compare_networks | description | 4bf22d97c014a4cb4762d0bc637dc41ca66358b9e166d56a1466e3909ccf8337 |
| prompts | compare_networks | networkList | 2a963dd6b9c130767138578ae3999af85ab3549bb3624e8c932c0de8c35734dd |
| prompts | explain_evm_concept | description | 29f0d801f5aefcf2107dde4481f0a9035201a670a69db5f727154b48714f4a0e |
| prompts | explain_evm_concept | concept | 3c0359a16ead2f23910fed460268cf3644c973ca948f79ef15212c755d43ad01 |
| prompts | explore_block | description | 88f4e7860230a1b9acaac42f0b81fadc931268c6ed465e19bacabe2c36e2380b |
| prompts | explore_block | blockNumber | 181c993b2fdc61cb36374e2b61fe18b9195a0d7db2fb32d6bd1c633918dd85d8 |
| prompts | explore_block | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| prompts | interact_with_contract | description | 3a61986f4a7c0d91dbee1e0d7930f183990de18d1b1c3eef45bea5c2708aba81 |
| prompts | interact_with_contract | abiJson | c0a6f79ef3f1c6591424dabdd595e88cbbf73da039e730901246dff920e07a2f |
| prompts | interact_with_contract | contractAddress | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| prompts | interact_with_contract | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | approve_token_spending | description | b00e61e134fe8a072d31d784e6391036c4d04d1a6e0744b272976cb2b588e240 |
| tools | approve_token_spending | amount | 4a39fdaae43b1ecd650ab8962296e4868587228dbefaf8839851561c0d58517b |
| tools | approve_token_spending | network | a523ffb0a7e725e5308cbb9b463f463f52a4e4233bad8b347aa9ea1da8942400 |
| tools | approve_token_spending | privateKey | dc6091bd40b8d3f50d62948a0712aa15033903a3ea15f0de15c437b3f75de4ba |
| tools | approve_token_spending | spenderAddress | 1f67e3544649ef0b4a8dba578bf3bc86c3463e8e437849b6c0a4448c54c270d4 |
| tools | approve_token_spending | tokenAddress | 1c7a04404ec77cc03f124b3242e78264e43701fdc7025796830ca8a98caf415d |
| tools | check_nft_ownership | description | 9c4966befd449575ec0c87a838796fbc712f616330eab6fcc2d8e37955c7dbfb |
| tools | check_nft_ownership | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | check_nft_ownership | ownerAddress | e41e0e3ce1be354b7d917f2bc6c42ec38b51c0ccc8ac3430f313dd6b86e1a0dc |
| tools | check_nft_ownership | tokenAddress | 3e7e6540bfb1fe5f44136880c08aca802320188162b48f8374dc41366bbf0180 |
| tools | check_nft_ownership | tokenId | 02ce590bfb7a7e2124ed98924512d154599c819411161d02ad04f529d99e4fd4 |
| tools | estimate_gas | description | ec1ebf129dbe2678b04f56f5125350d1999176747fbfd0d83a6017e261bc9f94 |
| tools | estimate_gas | data | 5ca5677824e622047e3ab62cc1fbd335ce74bca333ea5b4acbaa53d5d2579bab |
| tools | estimate_gas | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | estimate_gas | to | c8935d359296d18c8a856163e67205421b0c33fa7f066fd2345fec1ffd3c224f |
| tools | estimate_gas | value | b900cfdec95137b1b0c48b5fb6afee4b2124898ced586f62d6f6282a361b6ad5 |
| tools | get_address_from_private_key | description | 091a3f1f43c249ab195f769d09773e80bd72fa7cf926b77016b6ac3ae16eb443 |
| tools | get_address_from_private_key | privateKey | 802f61fc2e3541909ca8d8a7d78a1a9f5fc3618b179e43764eab343e88999574 |
| tools | get_balance | description | a6f92954c2ed11ae9698eff9b547859d53a2c17b1a7f5d6b89635c543b7f2ea6 |
| tools | get_balance | address | 7029f9dcdfc6671a0dfbcfe94f87b947f0385fe595f14aa48bd033f47542b74b |
| tools | get_balance | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | get_block_by_number | description | 05baba4e8181a36f6d01724ca88f84e771629920b62ef9004475afb1814d9a7b |
| tools | get_block_by_number | blockNumber | e3f789b5d3e0a7a76147f63d83a71cc7ca26a03082cf271722af16574c052084 |
| tools | get_block_by_number | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_chain_info | description | c4d52950f10b75be6cf3d275f545219ade10869209ed037b56cf1841a7dc69d7 |
| tools | get_chain_info | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | get_erc1155_balance | description | fa46a03db8bdadc5e2235b8a660861e537e868ee92ba4371b3e03d6c84ac127c |
| tools | get_erc1155_balance | network | 2cb70e2978a2adb163ca5aa93c2888761083145403aa79c740354d6d284bdc59 |
| tools | get_erc1155_balance | ownerAddress | 1c409ddf069d16124a259a1ce4018c8eb3252dca3bcc0ec8117504c16f345c0d |
| tools | get_erc1155_balance | tokenAddress | d99aed71a568492fda6388ee38a07212ba9ebd8441d2af709d4e622186a114dc |
| tools | get_erc1155_balance | tokenId | c1005dfdaf55d2d822718f07755ce96b421d2089da8fe176aa975d5dee39297a |
| tools | get_erc1155_token_uri | description | e155608c67b0c880e33e2046b4fe0e7490e148272a2cd287e8f9aa8b335f7adc |
| tools | get_erc1155_token_uri | network | 2cb70e2978a2adb163ca5aa93c2888761083145403aa79c740354d6d284bdc59 |
| tools | get_erc1155_token_uri | tokenAddress | d99aed71a568492fda6388ee38a07212ba9ebd8441d2af709d4e622186a114dc |
| tools | get_erc1155_token_uri | tokenId | 92802ccc60556a3cac73846f2d7919def0d1349aa99f00aa0de22b10ab0745bf |
| tools | get_erc20_balance | description | 0026b5d9ef1ff8d926832201fffe0617e951770e019b27305e813e62b38a1f20 |
| tools | get_erc20_balance | address | 7285a66f5c5bf5dd9d11249dd56ed8baff520a89b60276b0b5318003f1c91f04 |
| tools | get_erc20_balance | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_erc20_balance | tokenAddress | ccb95c8622b7dd78e99d94b1aea053e6b7cbc26cc690cf808c0869b887a86d98 |
| tools | get_latest_block | description | 6d930e3eba4286f3e8f71b39e29df7652223297f379d509af3b7f56a3fe91816 |
| tools | get_latest_block | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_nft_balance | description | aedc0974dffbfde436ca5912fd2c61da7bb339821a7cb8aee1d7646833b4f941 |
| tools | get_nft_balance | network | d45598e2cf567891fca8c1ca1db2edfcc6c70ebd98b212717f39d4f6f64efff7 |
| tools | get_nft_balance | ownerAddress | ec0d9518b158900f5212dce55511c1ee7d5ad2aab81a9139bf097b8e7b5cadce |
| tools | get_nft_balance | tokenAddress | 132410c56f99ee8938d13355b3f1a9989a067c6d13c155931010b6f7b2280585 |
| tools | get_nft_info | description | e9353e84f2be08920044a5271d4e7baa146e5376ea2d60f7f4b6c5b52f6c3bbc |
| tools | get_nft_info | network | d45598e2cf567891fca8c1ca1db2edfcc6c70ebd98b212717f39d4f6f64efff7 |
| tools | get_nft_info | tokenAddress | 132410c56f99ee8938d13355b3f1a9989a067c6d13c155931010b6f7b2280585 |
| tools | get_nft_info | tokenId | aaa6ded4245eed2b3176fdd7d196f70aba85d40a555a0db6a1907398c6fdc1f2 |
| tools | get_supported_networks | description | dda7f80e68f493352f32702cb140b147c3d23e0b2c9321c03cf4a2d9e3d0e704 |
| tools | get_token_balance | description | 7e9fcfff9af42fcd26bb4248a35c4e4486e10c1f412cdfb715f00c67e3752d08 |
| tools | get_token_balance | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | get_token_balance | ownerAddress | 6fedb93e402a8905756f3a49f8697011dffa799aa58ba0128c2c3478a42e3c13 |
| tools | get_token_balance | tokenAddress | db610e246db48790257afc261f434e0aa1b8cd09cb2b96926d5edd550773670d |
| tools | get_token_balance_erc20 | description | 46eccb5ac0c6c31c1f9cbbcd98169bed8e8bf8c7d43e0077533d400f808e2259 |
| tools | get_token_balance_erc20 | address | eb69f50753dc0602ffcf9a954289544ede534ff2d5245500739f35d54cf46928 |
| tools | get_token_balance_erc20 | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_token_balance_erc20 | tokenAddress | ccb95c8622b7dd78e99d94b1aea053e6b7cbc26cc690cf808c0869b887a86d98 |
| tools | get_token_info | description | 72eb2c3b73041d3297ae27bbbcf6a0e774a8b326977802f07fa040e52529d8ed |
| tools | get_token_info | network | a523ffb0a7e725e5308cbb9b463f463f52a4e4233bad8b347aa9ea1da8942400 |
| tools | get_token_info | tokenAddress | 35597c89b62ff8e1631e8016db40bfe1df6563932d23b25a18aa010b338e03b1 |
| tools | get_transaction | description | 619dd927999d4368096373d6b9ba676ea952a7a433d8e8b2621b7c11cd3fc743 |
| tools | get_transaction | network | a523ffb0a7e725e5308cbb9b463f463f52a4e4233bad8b347aa9ea1da8942400 |
| tools | get_transaction | txHash | 801dc6d65913a2b5035439109b426ffebc22255f4f6e5685fee2284e73a65e69 |
| tools | get_transaction_receipt | description | dbf758ffd33da7c3ed432a56472bdd8045e4515a9af7446f9ff5bff7aed2fd05 |
| tools | get_transaction_receipt | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_transaction_receipt | txHash | 2eaa5e4afa29ec4dea199637c4672755a581a72df105495b90570b072fce7789 |
| tools | is_contract | description | d45ec2f4cd92459354af2b87078961e2583ef753b73eec86795c98979950d972 |
| tools | is_contract | address | 9d5bd5a8aeaa405adc4b3a98de902df07d99f56a26507dbec9803897aded2510 |
| tools | is_contract | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | read_contract | description | ac77259cecd83216bb809db3f8ba0c1b4ffae82f8078d57efc3dbea1581ecc51 |
| tools | read_contract | abi | e80ba4b912f5d6fec1c0d32e1c278a27db8ee482dd6f5531ad07796f02a66c56 |
| tools | read_contract | args | 247710264312d30ec9cfe8376ee6b825dd263735c03b6566b6d4aea37fa47569 |
| tools | read_contract | contractAddress | 6c3b4e8c0ccacc09e7cb6ad98d3e3f90c51c6e668f3055ee61a5d057b177e04e |
| tools | read_contract | functionName | c2d5e70eaf216afc681351f04e10381f3f7074fcb763209a17169b7a104fb6d4 |
| tools | read_contract | network | a523ffb0a7e725e5308cbb9b463f463f52a4e4233bad8b347aa9ea1da8942400 |
| tools | resolve_ens | description | c5c1baae2eef139c72c06bba15bf3b0231475c83948bf724f2eac819e0f98805 |
| tools | resolve_ens | ensName | 63d3085dd50ca20453836ca17da2eb3f1eda5655cbb2b551f9b9b19220c838b2 |
| tools | resolve_ens | network | 85fe23d05acba8230ce8593fff37e02d8f713df7906519c357f232e8bd9440a4 |
| tools | transfer_erc1155 | description | 6b9cb27d688fef365b4cb77e655282ff9380229a872633fdc905077f06abe39d |
| tools | transfer_erc1155 | amount | 1289c3df0c9d7b67a747c12e2d8278944e329a04f5ff47dd361ce0b2fccb844f |
| tools | transfer_erc1155 | network | 2cb70e2978a2adb163ca5aa93c2888761083145403aa79c740354d6d284bdc59 |
| tools | transfer_erc1155 | privateKey | dc6091bd40b8d3f50d62948a0712aa15033903a3ea15f0de15c437b3f75de4ba |
| tools | transfer_erc1155 | toAddress | 7f21ec4fa7cbe100e9e8cdbcfc4a628a75fddcd84f63c478b123fbf20e82a728 |
| tools | transfer_erc1155 | tokenAddress | d99aed71a568492fda6388ee38a07212ba9ebd8441d2af709d4e622186a114dc |
| tools | transfer_erc1155 | tokenId | 7eec3b141725b00df47c82ecc5631ca69b55bb7d3dc7af1c708df0f427769a58 |
| tools | transfer_erc20 | description | ea2dae47a6f93360e50db4c8cb63d3043ae809be3e1cac5d5e4cc0f4ce4bcf47 |
| tools | transfer_erc20 | amount | be4e8ca46efa7e72557546dc87160886778d1d062314c1de40f3f862656cc843 |
| tools | transfer_erc20 | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | transfer_erc20 | privateKey | 85964339a28f20d6ee9f3730ae3853288b362cf429dedc50e218e21709bab674 |
| tools | transfer_erc20 | toAddress | c8935d359296d18c8a856163e67205421b0c33fa7f066fd2345fec1ffd3c224f |
| tools | transfer_erc20 | tokenAddress | 5f337b376842aa11210c5bf5f13a9ab6290e98c42464affe6a763488ed44a6cd |
| tools | transfer_eth | description | 3547d0a0d23170576331e48c4d61755c11a5c2b2161ce5d4d0efd23af11483f7 |
| tools | transfer_eth | amount | 07f020be8012fe18e63c852a51f78394f89ddded2b877c8542aa8f4caac26609 |
| tools | transfer_eth | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | transfer_eth | privateKey | cd86e4eaf5d9842629e8e28c4c9286e9452f8aa73bb3b8d88d0a31f70c257bac |
| tools | transfer_eth | to | 33591d500e5f4b400dc57f4eec8801f24638016000ddfde672b6fdc6226e7821 |
| tools | transfer_nft | description | 2597a2a121c82a34d14cc4376b137e38a0f744c2014977a77882c8583435b21e |
| tools | transfer_nft | network | d45598e2cf567891fca8c1ca1db2edfcc6c70ebd98b212717f39d4f6f64efff7 |
| tools | transfer_nft | privateKey | b08efc6fe60ec83a98feb9cb99234e8e3f78035f64816891ee0c9f7c9dd350a0 |
| tools | transfer_nft | toAddress | 55c717e3caadb28aefc08acf6af1932b6ef97093ecff88f139af99045d013460 |
| tools | transfer_nft | tokenAddress | 132410c56f99ee8938d13355b3f1a9989a067c6d13c155931010b6f7b2280585 |
| tools | transfer_nft | tokenId | 2a7552b852a3b5b46cebfe22ebe8fc0226b3ac52191aecc6e3a8ad52719784c1 |
| tools | transfer_token | description | 0a8ab28c0b67d98986bd87ff3e5c61f5c9b35a6f85ddfe41551438c50419194c |
| tools | transfer_token | amount | f325a5df042a58bee17b88585dd6c2ab449222a9eb34c1f623b71a2d5f5da455 |
| tools | transfer_token | network | 42ab0b924d91624b134dc2577bab785de587444530013a746d9a75a77170913c |
| tools | transfer_token | privateKey | cd86e4eaf5d9842629e8e28c4c9286e9452f8aa73bb3b8d88d0a31f70c257bac |
| tools | transfer_token | toAddress | 96eee5283e60b750132d1982cd0493291c83c9213069d4625d0911e6f63ea182 |
| tools | transfer_token | tokenAddress | 0794b998612e8790ae6065c2108d7c0e3ffd9458307ea13a64ec1b3b2ded0815 |
| tools | write_contract | description | bb916f72f6e125756b0e34a6c586d1f06bb72a6c0e7981d1f4ae0da22859ab1a |
| tools | write_contract | abi | e80ba4b912f5d6fec1c0d32e1c278a27db8ee482dd6f5531ad07796f02a66c56 |
| tools | write_contract | args | ac138c6dc5cea1597647e1df8d347d8b3dbf78dc0f632b83c04b870655bdc135 |
| tools | write_contract | contractAddress | 6c3b4e8c0ccacc09e7cb6ad98d3e3f90c51c6e668f3055ee61a5d057b177e04e |
| tools | write_contract | functionName | e07bcf8f9932ca83df129af8c42cfc71eaedf30dd73e55f085023f070b7c5e8b |
| tools | write_contract | network | a523ffb0a7e725e5308cbb9b463f463f52a4e4233bad8b347aa9ea1da8942400 |
| tools | write_contract | privateKey | 08351fd90f518fa41ee8236467758bc37a5cb233f24fd77a1c58a8bccea8c6b8 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
