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


# What is mcp-server-evm?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-evm/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-evm/2.0.4?logo=docker&logoColor=fff&label=2.0.4)](https://hub.docker.com/r/acuvity/mcp-server-evm)
[![PyPI](https://img.shields.io/badge/2.0.4-3775A9?logo=pypi&logoColor=fff&label=@mcpdotdirect/evm-mcp-server)](https://github.com/mcpdotdirect/evm-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-evm/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-evm&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-evm%3A2.0.4%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-evm#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ vcart ](https://github.com/mcpdotdirect/evm-mcp-server) for application

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
  - container: `1.0.0-2.0.4`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-evm:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-evm:1.0.0-2.0.4`

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

## 🧰 Tools (25)
<details>
<summary>get_wallet_address</summary>

**Description**:

```
Get the address of the configured wallet. Use this to verify which wallet is active.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_chain_info</summary>

**Description**:

```
Get information about an EVM network: chain ID, current block number, and RPC endpoint
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name (e.g., 'ethereum', 'optimism', 'arbitrum', 'base') or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_supported_networks</summary>

**Description**:

```
Get a list of all supported EVM networks
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_gas_price</summary>

**Description**:

```
Get current gas prices (base fee, standard, and fast) for a network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>resolve_ens_name</summary>

**Description**:

```
Resolve an ENS name to an Ethereum address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ensName | string | ENS name to resolve (e.g., 'vitalik.eth') | Yes
| network | string | Network name or chain ID. ENS resolution works best on Ethereum mainnet. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>lookup_ens_address</summary>

**Description**:

```
Lookup the ENS name for an Ethereum address (reverse resolution)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | Ethereum address to lookup | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_block</summary>

**Description**:

```
Get block details by block number or hash
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| blockIdentifier | string | Block number (as string) or block hash | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_latest_block</summary>

**Description**:

```
Get the latest block from the network
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
| address | string | The wallet address or ENS name | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>get_token_balance</summary>

**Description**:

```
Get the ERC20 token balance for an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The wallet address or ENS name | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| tokenAddress | string | The ERC20 token contract address | Yes
</details>
<details>
<summary>get_allowance</summary>

**Description**:

```
Check the allowance granted to a spender for a token. This tells you how much of a token an address can spend on your behalf.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| ownerAddress | string | The owner address (defaults to the configured wallet) | No
| spenderAddress | string | The address allowed to spend the token (usually a contract address) | Yes
| tokenAddress | string | The ERC20 token contract address | Yes
</details>
<details>
<summary>get_transaction</summary>

**Description**:

```
Get transaction details by transaction hash
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| txHash | string | Transaction hash (0x...) | Yes
</details>
<details>
<summary>get_transaction_receipt</summary>

**Description**:

```
Get transaction receipt (confirmation status, gas used, logs). Use this to check if a transaction has been confirmed.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| txHash | string | Transaction hash (0x...) | Yes
</details>
<details>
<summary>wait_for_transaction</summary>

**Description**:

```
Wait for a transaction to be confirmed (mined). Polls the network until confirmation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| confirmations | number | Number of block confirmations required. Defaults to 1. | No
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| txHash | string | Transaction hash (0x...) | Yes
</details>
<details>
<summary>get_contract_abi</summary>

**Description**:

```
Fetch a contract's full ABI from Etherscan/block explorers. Use this to understand verified contracts before interacting. Requires ETHERSCAN_API_KEY. Supports 30+ EVM networks. Works best with verified contracts on block explorers.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contractAddress | string | The contract address (0x...) | Yes
| network | string | Network name or chain ID. Defaults to ethereum. Supported: ethereum, polygon, arbitrum, optimism, base, avalanche, gnosis, fantom, bsc, celo, scroll, linea, zksync, manta, blast, and testnets (sepolia, mumbai, arbitrum-sepolia, optimism-sepolia, base-sepolia, avalanche-fuji) | No
</details>
<details>
<summary>read_contract</summary>

**Description**:

```
Call read-only functions on a smart contract. Automatically fetches ABI from block explorer if not provided (requires ETHERSCAN_API_KEY). Falls back to common functions if contract is not verified. Use this to query contract state and data.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| abiJson | string | Full contract ABI as JSON string (optional - will auto-fetch verified contract ABI if not provided) | No
| args | array | Function arguments as strings (e.g., ['0xAddress'] for balanceOf) | No
| contractAddress | string | The contract address | Yes
| functionName | string | Function name (e.g., 'name', 'symbol', 'balanceOf', 'totalSupply', 'owner') | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>write_contract</summary>

**Description**:

```
Execute state-changing functions on a smart contract. Automatically fetches ABI from block explorer if not provided (requires ETHERSCAN_API_KEY). Use this to call any write function on verified contracts. Requires wallet to be configured (via private key or mnemonic).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| abiJson | string | Full contract ABI as JSON string (optional - will auto-fetch verified contract ABI if not provided) | No
| args | array | Function arguments as strings (e.g., ['0xAddress', '1000000']) | No
| contractAddress | string | The contract address | Yes
| functionName | string | Function name to call (e.g., 'mint', 'swap', 'stake', 'approve') | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| value | string | ETH value to send with transaction in ether (e.g., '0.1' for payable functions) | No
</details>
<details>
<summary>multicall</summary>

**Description**:

```
Batch multiple contract read calls into a single RPC request. Significantly reduces latency and RPC usage when querying multiple functions. Uses the Multicall3 contract deployed on all major networks. Perfect for portfolio analysis, price aggregation, and querying multiple contract states efficiently.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allowFailure | boolean | If true, returns partial results even if some calls fail. Defaults to true. | No
| calls | array | Array of contract calls to batch together | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
</details>
<details>
<summary>transfer_native</summary>

**Description**:

```
Transfer native tokens (ETH, MATIC, etc.) to an address. Uses the configured wallet.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | Amount to send in ether (e.g., '0.5' for 0.5 ETH) | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| to | string | Recipient address or ENS name | Yes
</details>
<details>
<summary>transfer_erc20</summary>

**Description**:

```
Transfer ERC20 tokens to an address. Uses the configured wallet.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | Amount to send (in token units, accounting for decimals) | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| to | string | Recipient address or ENS name | Yes
| tokenAddress | string | The ERC20 token contract address | Yes
</details>
<details>
<summary>approve_token_spending</summary>

**Description**:

```
Approve a spender (contract) to spend tokens on your behalf. Required before interacting with DEXes, lending protocols, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | string | Amount to approve (in token units). Use '0' to revoke approval. | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| spenderAddress | string | The address that will be allowed to spend tokens (usually a contract) | Yes
| tokenAddress | string | The ERC20 token contract address | Yes
</details>
<details>
<summary>get_nft_info</summary>

**Description**:

```
Get information about an ERC721 NFT including metadata URI
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contractAddress | string | The NFT contract address | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| tokenId | string | The NFT token ID | Yes
</details>
<details>
<summary>get_erc1155_balance</summary>

**Description**:

```
Get ERC1155 token balance for an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The owner address or ENS name | Yes
| contractAddress | string | The ERC1155 contract address | Yes
| network | string | Network name or chain ID. Defaults to Ethereum mainnet. | No
| tokenId | string | The token ID | Yes
</details>
<details>
<summary>sign_message</summary>

**Description**:

```
Sign an arbitrary message using the configured wallet. Useful for authentication (SIWE), meta-transactions, and off-chain signatures. The signature can be verified on-chain or off-chain.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | The message to sign (plain text or hex-encoded data) | Yes
</details>
<details>
<summary>sign_typed_data</summary>

**Description**:

```
Sign structured data (EIP-712) using the configured wallet. Used for gasless transactions, meta-transactions, permit signatures, and protocol-specific signatures. The signature follows the EIP-712 standard.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| domainJson | string | EIP-712 domain as JSON string with fields: name, version, chainId, verifyingContract, salt (all optional) | Yes
| messageJson | string | The message data to sign as JSON string | Yes
| primaryType | string | The primary type name (e.g., 'Mail', 'Permit', 'MetaTransaction') | Yes
| typesJson | string | EIP-712 types definition as JSON string (exclude EIP712Domain type - it's added automatically) | Yes
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| supported_networks | application/json | evm://networks | - |

</details>

## 📝 Prompts (10)
<details>
<summary>prepare_transfer</summary>

**Description**:

```
Safely prepare and execute a token transfer with validation checks
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| tokenType | Token type: 'native' for ETH/MATIC or 'erc20' for contract tokens |Yes |
| recipient | Recipient address or ENS name |Yes |
| amount | Amount to transfer (in ether for native, token units for ERC20) |Yes |
| network | Network name (default: ethereum) |No |
| tokenAddress | Token contract address (required for ERC20) |No |
<details>
<summary>diagnose_transaction</summary>

**Description**:

```
Analyze transaction status, failures, and provide debugging insights
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| txHash | Transaction hash to diagnose (0x...) |Yes |
| network | Network name (default: ethereum) |No |
<details>
<summary>analyze_wallet</summary>

**Description**:

```
Get comprehensive overview of wallet assets, balances, and activity
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| address | Wallet address or ENS name to analyze |Yes |
| network | Network name (default: ethereum) |No |
| tokens | Comma-separated token addresses to check |No |
<details>
<summary>audit_approvals</summary>

**Description**:

```
Review token approvals and identify security risks from unlimited spend
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| address | Wallet to audit (default: configured wallet) |No |
| tokenAddress | Token contract address to check approvals for |Yes |
| network | Network name (default: ethereum) |No |
<details>
<summary>fetch_and_analyze_abi</summary>

**Description**:

```
Fetch contract ABI from block explorer and provide comprehensive analysis
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| contractAddress | Contract address to analyze |Yes |
| network | Network name (default: ethereum) |No |
| findFunction | Specific function to analyze (e.g., 'swap', 'mint') |No |
<details>
<summary>explore_contract</summary>

**Description**:

```
Analyze contract functions and state without requiring full ABI
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| contractAddress | Contract address to explore |Yes |
| network | Network name (default: ethereum) |No |
| fetchAbi | Set to 'true' to auto-fetch ABI (requires ETHERSCAN_API_KEY) |No |
<details>
<summary>interact_with_contract</summary>

**Description**:

```
Safely execute write operations on a smart contract with validation and confirmation
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| contractAddress | Contract address to interact with |Yes |
| functionName | Function to call (e.g., 'mint', 'swap', 'stake') |Yes |
| args | Comma-separated function arguments |No |
| value | ETH value to send (for payable functions) |No |
| network | Network name (default: ethereum) |No |
<details>
<summary>explain_evm_concept</summary>

**Description**:

```
Explain EVM and blockchain concepts with examples
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| concept | Concept to explain (gas, nonce, smart contracts, MEV, etc) |Yes |
<details>
<summary>compare_networks</summary>

**Description**:

```
Compare multiple EVM networks on key metrics and characteristics
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| networks | Comma-separated network names (ethereum,polygon,arbitrum) |Yes |
<details>
<summary>check_network_status</summary>

**Description**:

```
Check current network health and conditions
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| network | Network name (default: ethereum) |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | analyze_wallet | description | 31ea3ebca7e4bac44622ad1df77aa4e40ac7844e876731ccb65cfe372ccbc984 |
| prompts | analyze_wallet | address | 34e5dcdb69360489d05a8b6f9e9ee64ffd46e58fe8c8bdbab1a0c9b853162084 |
| prompts | analyze_wallet | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | analyze_wallet | tokens | d1b48849f95d16d9add2192beb3acf901dc7eb9337361fd90e9494ccd96776af |
| prompts | audit_approvals | description | d322503f5d98818a80f2f9197265d3fd652bcc4fde4164037d331fddb347e502 |
| prompts | audit_approvals | address | adac07a8285457423e73ec0b7ea123da793be08216f954cd7d46b12018689105 |
| prompts | audit_approvals | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | audit_approvals | tokenAddress | 171a3a03d03ab2616f252070dfa0a912516f6e61eb125f98bad7b5135d0dc29a |
| prompts | check_network_status | description | 71061bab59fe8e3b83120e2f8bea66356106bbf9fbd58e339b1ad7b315ef175a |
| prompts | check_network_status | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | compare_networks | description | a81e11da8eecbd3593e96dcc54a4676d70928a416cc89917e3c8eae39d925970 |
| prompts | compare_networks | networks | e615f848da7907bde670935d434283d61d1e091028d0548de6e668032a42fe3d |
| prompts | diagnose_transaction | description | 0acf10dc8a0501ed6fc0251ab0ca05d9ec0d10aaf9782f7df1958c2daf8b1d46 |
| prompts | diagnose_transaction | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | diagnose_transaction | txHash | 65d118da625aa535b060e01e208c31212852896f73c72045e4a212a8bf381bc7 |
| prompts | explain_evm_concept | description | 98f3b3a607eac1c3314a5f08d951bd8663f99e21d06dc00c8b2b7cc89ae6760e |
| prompts | explain_evm_concept | concept | 2f9d139f391ac82151dc5971be32b947be822ce780db70b9bfc7c4b3dd28abab |
| prompts | explore_contract | description | 95e8684252016a59de83008b05846cbb1901101d931a84c06617aeb5c0025b26 |
| prompts | explore_contract | contractAddress | 8d3bcb258469d6b594d754d587d1f59853dee162352f71cfd6419e6ccfd4b902 |
| prompts | explore_contract | fetchAbi | 5f3862eff3575df9e5d21ca56a3dbdb00b3e667af5f97861ef37fb6b32c83611 |
| prompts | explore_contract | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | fetch_and_analyze_abi | description | aa93485f6ededf36890290ae44b83d749a610a4b6184a63484ce2bb269c8c96b |
| prompts | fetch_and_analyze_abi | contractAddress | f7a8b14592992126a2186142d2aca2ffcfaa7417e7c740fe94cf83d20dfca892 |
| prompts | fetch_and_analyze_abi | findFunction | 447974d503cf19ab077d66bef27786c514b6e48b0e502b601d86f44822744cd8 |
| prompts | fetch_and_analyze_abi | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | interact_with_contract | description | 93b39400399f5240586fe60b8b63226fb723563bc85e5243ada6393567b6245e |
| prompts | interact_with_contract | args | 3ec90f2ad8223927f2ae18ac15f122e25ce42cad4bce633d401452ed049878d8 |
| prompts | interact_with_contract | contractAddress | 750251bf0fa43e6af93c4e647c91781a07270fd81a4daba12c7766237a313f10 |
| prompts | interact_with_contract | functionName | f4050078182520f6847a6c208fa60442487a462fcd2c8a20ddf3349fe5b3a5f1 |
| prompts | interact_with_contract | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | interact_with_contract | value | cad0b7bec1f607ccb10737fb8f44ed83eae7129bd54d7fda17899b3ef248305a |
| prompts | prepare_transfer | description | 9234817cc3ab563d7af6fef485e03a14dd0df369b2c39dfeeed2d5b7b0bcf712 |
| prompts | prepare_transfer | amount | e1350f88cecc4204e3dc1776b046b9b102488794a10204368867fbbfc50118c7 |
| prompts | prepare_transfer | network | 0b32f64429e2e02a65bf45e2b064d7235c36f5dc9ab6079210cc6e9f9452e469 |
| prompts | prepare_transfer | recipient | 1e06538e60c849afd8ed64b6ebfcf38d99f706448726fa1c1bd58d441eac867f |
| prompts | prepare_transfer | tokenAddress | a57d3905545721a24550d69096554cc4fdcbcaa6893d294d70a9a3ee783c0d7a |
| prompts | prepare_transfer | tokenType | 164694dbb12ccd40aa5576f80f08bedadc180897c42688575991239d5ec0ef17 |
| tools | approve_token_spending | description | f7d16000695eae894a0d817db4d51e9af52ed168fc1068cf0b8eab903249f811 |
| tools | approve_token_spending | amount | 3db019d1260f68237db0955832d6874a820c57014ff6a4b3201813c5973c01ee |
| tools | approve_token_spending | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | approve_token_spending | spenderAddress | 47e28211c2c65c4468d0101e220cf16fa9cb7cf11e79129bcc00db4c84529e25 |
| tools | approve_token_spending | tokenAddress | ccb95c8622b7dd78e99d94b1aea053e6b7cbc26cc690cf808c0869b887a86d98 |
| tools | get_allowance | description | 8f2cdb097db4b42fc04f841381dc009f9d5b4d8e262e2e957c7f46a88b57bc1f |
| tools | get_allowance | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_allowance | ownerAddress | 02891fc1c0d6a9941b486cdefda3b2cd37262bdb5c20af5e5214788842e8c6cf |
| tools | get_allowance | spenderAddress | df8cebbc8f5e36e1fcff77d2d2daf16968da57a729462c0315d402d883abc112 |
| tools | get_allowance | tokenAddress | ccb95c8622b7dd78e99d94b1aea053e6b7cbc26cc690cf808c0869b887a86d98 |
| tools | get_balance | description | a6f92954c2ed11ae9698eff9b547859d53a2c17b1a7f5d6b89635c543b7f2ea6 |
| tools | get_balance | address | 71a3aeac69457e83bc898a8883f9e149126971c83a9d5902c652559024e55783 |
| tools | get_balance | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_block | description | 183621a41004bda0154b0f9125b8409500ba346ea60fd8b3c7d7b2c5587d3325 |
| tools | get_block | blockIdentifier | 52f9857ce173f5f38e50dc4cf872e4c4297da08d6b5000301bb3c3c368bda039 |
| tools | get_block | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_chain_info | description | 6193baf956d1f8aa2ac2f491ad7eeff064b3a80b72b658b1c4740cf6e9be823c |
| tools | get_chain_info | network | ceba514d5c14c2e5727d4aefb5d424bfcb887aa523559ab02eebcee3f971747d |
| tools | get_contract_abi | description | dda9e4951377ca48bd31caa186e0b586afa9e902261460cae276ae3a59611922 |
| tools | get_contract_abi | contractAddress | 3c6f59e503a53492a80f62b33a63375fd49ed7f4ae2d1f29d2078ed03946e1b3 |
| tools | get_contract_abi | network | 4b7d691211dd6b674ebb129af5f37ad423408388fb62cbf6d1d7f0415c168def |
| tools | get_erc1155_balance | description | eb06fb674cd3ab3bdaea3be52ba55ea332a15924640b034a8b73f1a985f15a6f |
| tools | get_erc1155_balance | address | 862d4e41dd85e07bfb3003b963b4ce5ba9b059ce8bb6720d4d610a480405449f |
| tools | get_erc1155_balance | contractAddress | 46917c489c008f041c0d493c5d37680378348db073fba92a6c4d4a9910fad858 |
| tools | get_erc1155_balance | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_erc1155_balance | tokenId | aac87413ee0c9982dcc9e53907fb957046cc70043b53985ffb3012442dfbf511 |
| tools | get_gas_price | description | c18f629ac7393bb9815c43818e2f40e0e6f02a56718196940625c06c5138888e |
| tools | get_gas_price | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_latest_block | description | cef8dcd519181633958644b7144747d1331a17209ba3317c54a4fdf3c8b91eba |
| tools | get_latest_block | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_nft_info | description | 44e86c725372e9b75dfe26ec1c75757d31b9a34f1ad75a183a2018612748e48a |
| tools | get_nft_info | contractAddress | c71268fb0a1f6dc2cce5c905501e91a59971b3c2fcf0f5cefccf40b9583dbe12 |
| tools | get_nft_info | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_nft_info | tokenId | 3ce0a0d657d80e72b97840b33a33a98c35916e645da0eafb05b361674d53eb81 |
| tools | get_supported_networks | description | c67a50b1002ad1082d97dd958a511c35290f0da93839be06bb231696ec5886e7 |
| tools | get_token_balance | description | 9632e4021040f05d0356aec5bd83621f25ad64c13ca5ca37538ebe12c86df3ec |
| tools | get_token_balance | address | 71a3aeac69457e83bc898a8883f9e149126971c83a9d5902c652559024e55783 |
| tools | get_token_balance | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_token_balance | tokenAddress | ccb95c8622b7dd78e99d94b1aea053e6b7cbc26cc690cf808c0869b887a86d98 |
| tools | get_transaction | description | 26bbcc0153680b340c50f7f4782a424b63fbf1c0edc410fea5e313e9d8b1df64 |
| tools | get_transaction | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_transaction | txHash | fe2942f4bd4165962626dd41489af04f03b292c1ba5bcfed764c0769ad7d0174 |
| tools | get_transaction_receipt | description | b800ccd09aa3695e9ebde2e47b78885321b89a76c16b806801e81956f7a3f690 |
| tools | get_transaction_receipt | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | get_transaction_receipt | txHash | fe2942f4bd4165962626dd41489af04f03b292c1ba5bcfed764c0769ad7d0174 |
| tools | get_wallet_address | description | a9984a5507c62ed740051fe328e4f1c3bcaebd54108262545a13c99dbddc13cb |
| tools | lookup_ens_address | description | 8c0a6050006005d9a7acd335f05d5cf1f08abd92ee97dec98c9a01556b44a117 |
| tools | lookup_ens_address | address | 7c1fb25955f82dc108a81c9918e21d1f23fe9cf1daaeabe34b4d883abd42323c |
| tools | lookup_ens_address | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | multicall | description | 3947efeff9a759fb6f563d079091938ece2f1560acf11cfc551df2f95a408377 |
| tools | multicall | allowFailure | 3a2941b085948e172a035d95d560a475f77b949e6699c3d4400ed81f466a3b28 |
| tools | multicall | calls | 35e8bb362d2d72fbc6f115924c5dc14e685867a5fe5e97c27ecc34b466937cbb |
| tools | multicall | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | read_contract | description | ab6f9e5bb130c15c85eb4be43e7bd979056a31b1956dad31afde764acf04c188 |
| tools | read_contract | abiJson | 54ffc8f9ba1b0c5f05412db6ce17cb6a25554e32619b187425201ee9f1896750 |
| tools | read_contract | args | 4f76c2e79f392e4094555bd9861ce1553be88c14a57add946e55475a34906a69 |
| tools | read_contract | contractAddress | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | read_contract | functionName | 357deab72d083c98ae8a7a77dfaea1496cf04e110fa9f9c1d02483e039d4d2b4 |
| tools | read_contract | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | resolve_ens_name | description | c5c1baae2eef139c72c06bba15bf3b0231475c83948bf724f2eac819e0f98805 |
| tools | resolve_ens_name | ensName | 63d3085dd50ca20453836ca17da2eb3f1eda5655cbb2b551f9b9b19220c838b2 |
| tools | resolve_ens_name | network | 6a8a33c2158237470a284475f83ce642b1ce7a53b3a1a14c6af6562f46360da1 |
| tools | sign_message | description | 1bd2a4aad432d85318b1d02035067e7cbae864a042dd00a8be4be0484b494d95 |
| tools | sign_message | message | 4cd4a9e942d1b8014aa71bfc4c1c4197d1e20a64dd0a1f35a8f63fad87e0ad61 |
| tools | sign_typed_data | description | 34f54404d37b1646d7f2af1ffdb1f0b1b293bff44f8a6f00e40d65bb9dbe50bd |
| tools | sign_typed_data | domainJson | 09fbcd54bd735937f8f3873745d94ebfc51a3756e6625b8236378097c5d5e474 |
| tools | sign_typed_data | messageJson | 1597afc58078b060983e388fd2e298d94ddc1ad8edf1b20e00a0bb64ba237113 |
| tools | sign_typed_data | primaryType | 471e7fb44e1e54ba2132092d00e23b9fca5e9a17fe7da23615785a3892e00783 |
| tools | sign_typed_data | typesJson | 67fd215b3b17164ae4e1dbf433a5dddac2e18eabbbce18556c25cd4350c98bcd |
| tools | transfer_erc20 | description | e73689985b7f55bc1175d14c3c9efa38a540815d8ab51455ec3905c49c6db303 |
| tools | transfer_erc20 | amount | 153a2de8ae55654505f5a403c841af4269c106d68cd5df40ba5d12d275dd70ad |
| tools | transfer_erc20 | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | transfer_erc20 | to | 1e06538e60c849afd8ed64b6ebfcf38d99f706448726fa1c1bd58d441eac867f |
| tools | transfer_erc20 | tokenAddress | ccb95c8622b7dd78e99d94b1aea053e6b7cbc26cc690cf808c0869b887a86d98 |
| tools | transfer_native | description | 197f2981af626b8c06b90d18df73aa625430e6f07f34a17a34e58d7f27e56b99 |
| tools | transfer_native | amount | ea9af2824f5566cac0006dce09f1467ac2fc3f93a20a56bf2137487b1651e226 |
| tools | transfer_native | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | transfer_native | to | 1e06538e60c849afd8ed64b6ebfcf38d99f706448726fa1c1bd58d441eac867f |
| tools | wait_for_transaction | description | 113c7024fa156009a2c16149481d447c4bb7e5eb6297f4db9099b577810f9abe |
| tools | wait_for_transaction | confirmations | 8097a4f1deeb7aea48de80caf7e8c0ffd871cb4edca910ac90ac7b6476f50908 |
| tools | wait_for_transaction | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | wait_for_transaction | txHash | fe2942f4bd4165962626dd41489af04f03b292c1ba5bcfed764c0769ad7d0174 |
| tools | write_contract | description | 8429c18bd7cfffa6d4e20164dbbb5a0ca15a5d0f20054ef41a52201e5ecc27e6 |
| tools | write_contract | abiJson | 54ffc8f9ba1b0c5f05412db6ce17cb6a25554e32619b187425201ee9f1896750 |
| tools | write_contract | args | f9fb458c60e2dc2c5a86fb6057680f3e5e48fcb9aace78887b7c9bef6d0af4f4 |
| tools | write_contract | contractAddress | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | write_contract | functionName | eddd49924737a452e3e1b186380a4c19881caf719d2d87795f9a0d7bb6def667 |
| tools | write_contract | network | 2cde386624c0885456375eaaf5ecdcf9bff8ae87ba3d434d98f2ba33de93e180 |
| tools | write_contract | value | e6ddf39f78af27226360aec6defdfb573811de0b159efb3455400164dfca8340 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
