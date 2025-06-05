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


# What is mcp-server-bankless-onchain?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-bankless-onchain/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-bankless-onchain/1.0.6?logo=docker&logoColor=fff&label=1.0.6)](https://hub.docker.com/r/acuvity/mcp-server-bankless-onchain)
[![PyPI](https://img.shields.io/badge/1.0.6-3775A9?logo=pypi&logoColor=fff&label=@bankless/onchain-mcp)](https://bankless.com)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-bankless-onchain/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-bankless-onchain&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BANKLESS_API_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-bankless-onchain%3A1.0.6%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Query Onchain data, like ERC20 tokens, transaction history, smart contract state.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @bankless/onchain-mcp original [sources](https://bankless.com).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-bankless-onchain/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bankless-onchain/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bankless-onchain/charts/mcp-server-bankless-onchain/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @bankless/onchain-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bankless-onchain/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Bankless Engineering ](https://bankless.com) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @bankless/onchain-mcp ](https://bankless.com)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @bankless/onchain-mcp ](https://bankless.com)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bankless-onchain/charts/mcp-server-bankless-onchain)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-bankless-onchain/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.6`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-bankless-onchain:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-bankless-onchain:1.0.0-1.0.6`

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
  - `BANKLESS_API_TOKEN` secret to be set as secrets.BANKLESS_API_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-bankless-onchain
```

From there your MCP server mcp-server-bankless-onchain will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-bankless-onchain` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-bankless-onchain
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-bankless-onchain` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-bankless-onchain oci://docker.io/acuvity/mcp-server-bankless-onchain --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>read_contract</summary>

**Description**:

```
Read contract state from a blockchain. important:  
                
                In case of a tuple, don't use type tuple, but specify the inner types (found in the source) in order. For nested structs, include the substructs types.
    
    Example: 
    struct DataTypeA {
    DataTypeB b;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    }
    
    struct DataTypeB {
    address token;
    }
    
    results in outputs for function with return type DataTypeA (tuple in abi): outputs: [{"type": "address"}, {"type": "uint128"}]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address | Yes
| inputs | array | Input parameters for the method call | Yes
| method | string | The contract method to call | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
| outputs | array | Expected output types for the method call. 
    In case of a tuple, don't use type tuple, but specify the inner types (found in the source) in order. For nested structs, include the substructs types.
    
    Example: 
    struct DataTypeA {
    DataTypeB b;
    //the liquidity index. Expressed in ray
    uint128 liquidityIndex;
    }
    
    struct DataTypeB {
    address token;
    }
    
    results in outputs for function with return type DataTypeA (tuple in abi): outputs: [{"type": "address"}, {"type": "uint128"}]
   | Yes
</details>
<details>
<summary>get_proxy</summary>

**Description**:

```
Gets the proxy address for a given network and contract
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address to request the proxy implementation contract for | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_abi</summary>

**Description**:

```
Gets the ABI for a given contract on a specific network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_source</summary>

**Description**:

```
Gets the source code for a given contract on a specific network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | string | The contract address | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_events</summary>

**Description**:

```
Fetches event logs for a given network and filter criteria
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| addresses | array | List of contract addresses to filter events | Yes
| fromBlock | number | Block number to start fetching logs from | No
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
| optionalTopics | array | Optional additional topics | No
| toBlock | number | Block number to stop fetching logs at | No
| topic | string | Primary topic to filter events | Yes
</details>
<details>
<summary>build_event_topic</summary>

**Description**:

```
Builds an event topic signature based on event name and arguments
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| arguments | array | Event arguments types | Yes
| name | string | Event name (e.g., "Transfer(address,address,uint256)") | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_transaction_history_for_user</summary>

**Description**:

```
Gets transaction history for a user and optional contract
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contract | [string null] | The contract address (optional) | No
| includeData | boolean | Whether to include transaction data | No
| methodId | [string null] | The method ID to filter by (optional) | No
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
| startBlock | [string null] | The starting block number (optional) | No
| user | string | The user address | Yes
</details>
<details>
<summary>get_transaction_info</summary>

**Description**:

```
Gets detailed information about a specific transaction
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network | string | The blockchain network (e.g., "ethereum", "polygon") | Yes
| txHash | string | The transaction hash to fetch details for | Yes
</details>
<details>
<summary>get_token_balances_on_network</summary>

**Description**:

```
Gets all token balances for a given address on a specific network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The address to check token balances for | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>
<details>
<summary>get_block_info</summary>

**Description**:

```
Gets detailed information about a specific block by number or hash
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| blockId | string | The block number or block hash to fetch information for | Yes
| network | string | The blockchain network (e.g., "ethereum", "base") | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | build_event_topic | description | 262f27f4028228da097205a7c410f06fa7a823b2040556a721746d1e4cf50bd0 |
| tools | build_event_topic | arguments | 67282223b6da520d3f37a9a8146cfc02993e311b1b1ec2c71473500e73e4784d |
| tools | build_event_topic | name | 6ed8951c00312e24c4e0ca6dec06cdfea75fbf486288154b923151ec5254a2d0 |
| tools | build_event_topic | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_abi | description | 49edadd258a74f8d62a9b06c2356fc8ddcebcebeade9a3fc236e46f47568f966 |
| tools | get_abi | contract | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | get_abi | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_block_info | description | cdd6ae064cb18ddd093b64ad864cf0af9ad5b6f99297510466afce477ee0c8b2 |
| tools | get_block_info | blockId | 77ebd2d66c92208bc200c76cd91ccb3fce561d3b4592fb3b7c877691840eb705 |
| tools | get_block_info | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_events | description | 11e496bebf052d4a45c1d427323e47fc0e00617e34751b195e3c38e6da7b5a84 |
| tools | get_events | addresses | f3433afc56ec432d7da942237b9838973548370a4abed0a8b52f70d8a7ff8c7f |
| tools | get_events | fromBlock | bb3f18b71d6e1a36d93340e52b54b32fab0f24676dfd3e7dc0a044f36fcec82a |
| tools | get_events | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_events | optionalTopics | df86f24833db44832dac5eff638f0df4821f303020cb9dcb7d29400c931b0cb1 |
| tools | get_events | toBlock | 8ff070ee8eb0d4a64c9f490771fcb0516ed7091ba119e91bff1088f94e0027c8 |
| tools | get_events | topic | 095440b149b2fc5b6b258519a8f32231f525a90740d929968153872ea9c608ec |
| tools | get_proxy | description | 436a19a7bf59229497f6b870fa2cf42c0bd2578592069370131071e407a112c8 |
| tools | get_proxy | contract | 3bbd104044dbad8cd8d2723283008b627f3e02c6f517e5c5d252f40f86b80980 |
| tools | get_proxy | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_source | description | 232c3246004c70ef08d9e17e72dc490270c132ab9a637c051327ca8975a1017c |
| tools | get_source | contract | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | get_source | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_token_balances_on_network | description | 28baa9b9ac94405d2bc35b0860f7d13635c73067a2f147ada97a2d170c4f430f |
| tools | get_token_balances_on_network | address | 405710c18f1099e1fbe199741ff78a9ade223cf5bde63fd6dad6f57b0ae5e684 |
| tools | get_token_balances_on_network | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_transaction_history_for_user | description | 97d03e583c1db4a6b71ed2feded2de7fc39007f3e2732298262bce1f368188b0 |
| tools | get_transaction_history_for_user | contract | db0fa3adc605fb68ab41f05976668758d6fbb9e1995f68ec49f7cd1960be22ca |
| tools | get_transaction_history_for_user | includeData | 3ccf882c87a83cdb846aebc669f3771512dbc5efccad0761e4441b20a2d709e0 |
| tools | get_transaction_history_for_user | methodId | 32660cb5cb9250dcbeb97a6c16be7878da4d98aa04e9fd78bdd6abc4c4d007f6 |
| tools | get_transaction_history_for_user | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | get_transaction_history_for_user | startBlock | c9feb1fbcecaf65a2cd51919a5adaa2272ef1b05051811d280bd454b11ed13a3 |
| tools | get_transaction_history_for_user | user | 5c7282f0c6e567a96b80b014ca83778432010c18ac6f90cd1dc8879113b3032b |
| tools | get_transaction_info | description | 3cb6ea3fc5e3c082d042ab9e3bad43752ee3049017b95b76c1862daf208374f4 |
| tools | get_transaction_info | network | 27df8fb99fdf67ada2c14cfe2ba1a6e684d6fc1affb76f4ddf6adbe297b82763 |
| tools | get_transaction_info | txHash | 108c12c4ccab2dc50c541fae3e1cad3200fa099de05555fe87b5691ac93ac9b8 |
| tools | read_contract | description | a39ce1e9dea8ace0aa384880e028dbe10062cac5975198e3d646c804ef67ff77 |
| tools | read_contract | contract | 55c251df417372575201532fe00664fbbf2477e604b99f9e8fc87222d3471c62 |
| tools | read_contract | inputs | 68674e5ff81fbba2b59057b879623f4d3b3651732f1fa0786780354da49863f8 |
| tools | read_contract | method | 9f86a9f0e03eceff52a4ff49aa79c0a85988d9357a4ac066b19dd6d91b0e2f2f |
| tools | read_contract | network | 9fe098f112c2f4c590f2d77169ce9d1fe466b4d0938191621ef751dada52bbb8 |
| tools | read_contract | outputs | 1048bd1cff242e3d62763291c1b1140f5cbe8b06e984314cbe2decc5abb189a2 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
