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


# What is mcp-server-razorpay?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-razorpay/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-razorpay/v1.1.0?logo=docker&logoColor=fff&label=v1.1.0)](https://hub.docker.com/r/acuvity/mcp-server-razorpay)
[![GitHUB](https://img.shields.io/badge/v1.1.0-3775A9?logo=github&logoColor=fff&label=razorpay/razorpay-mcp-server)](https://github.com/razorpay/razorpay-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-razorpay/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-razorpay&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22RAZORPAY_KEY_ID%22%2C%22-e%22%2C%22RAZORPAY_KEY_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-razorpay%3Av1.1.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Advanced payment processing with Razorpay APIs for devs and AI tools.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from razorpay/razorpay-mcp-server original [sources](https://github.com/razorpay/razorpay-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-razorpay/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-razorpay/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-razorpay/charts/mcp-server-razorpay/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure razorpay/razorpay-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-razorpay/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ razorpay ](https://github.com/razorpay/razorpay-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ razorpay/razorpay-mcp-server ](https://github.com/razorpay/razorpay-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ razorpay/razorpay-mcp-server ](https://github.com/razorpay/razorpay-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-razorpay/charts/mcp-server-razorpay)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-razorpay/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-v1.1.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-razorpay:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-razorpay:1.0.0-v1.1.0`

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
  - `RAZORPAY_KEY_ID` secret to be set as secrets.RAZORPAY_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `RAZORPAY_KEY_SECRET` secret to be set as secrets.RAZORPAY_KEY_SECRET either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-razorpay oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-razorpay oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-razorpay
```

From there your MCP server mcp-server-razorpay will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-razorpay` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-razorpay
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-razorpay` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-razorpay oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-razorpay oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-razorpay oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-razorpay oci://docker.io/acuvity/mcp-server-razorpay --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (37)
<details>
<summary>capture_payment</summary>

**Description**:

```
Use this tool to capture a previously authorized payment. Only payments with 'authorized' status can be captured
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | The amount to be captured (in paisa). Should be equal to the authorized amount | Yes
| currency | string | ISO code of the currency in which the payment was made (e.g., INR) | Yes
| payment_id | string | Unique identifier of the payment to be captured. Should start with 'pay_' | Yes
</details>
<details>
<summary>close_qr_code</summary>

**Description**:

```
Close a QR Code that's no longer needed
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| qr_code_id | string | Unique identifier of the QR Code to be closedThe QR code id should start with 'qr_' | Yes
</details>
<details>
<summary>create_instant_settlement</summary>

**Description**:

```
Create an instant settlement to get funds transferred to your bank account
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | The amount you want to get settled instantly in amount in the smallest currency sub-unit (e.g., for ₹295, use 29500) | Yes
| description | string | Custom note for the instant settlement. | No
| notes | object | Key-value pairs for additional information. Max 15 pairs, 256 chars each | No
| settle_full_balance | boolean | If true, Razorpay will settle the maximum amount possible and ignore amount parameter | No
</details>
<details>
<summary>create_order</summary>

**Description**:

```
Create a new order in Razorpay
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Payment amount in the smallest currency sub-unit (e.g., for ₹295, use 29500) | Yes
| currency | string | ISO code for the currency (e.g., INR, USD, SGD) | Yes
| first_payment_min_amount | number | Minimum amount for first partial payment (only if partial_payment is true) | No
| notes | object | Key-value pairs for additional information (max 15 pairs, 256 chars each) | No
| partial_payment | boolean | Whether the customer can make partial payments | No
| receipt | string | Receipt number for internal reference (max 40 chars, must be unique) | No
</details>
<details>
<summary>create_payment_link</summary>

**Description**:

```
Create a new standard payment link in Razorpay with a specified amount
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| accept_partial | boolean | Indicates whether customers can make partial payments using the Payment Link. Default: false | No
| amount | number | Amount to be paid using the link in smallest currency unit(e.g., ₹300, use 30000) | Yes
| callback_method | string | HTTP method for callback redirection. Must be 'get' if callback_url is set. | No
| callback_url | string | If specified, adds a redirect URL to the Payment Link. Customer will be redirected here after payment. | No
| currency | string | Three-letter ISO code for the currency (e.g., INR) | Yes
| customer_contact | string | Contact number of the customer. | No
| customer_email | string | Email address of the customer. | No
| customer_name | string | Name of the customer. | No
| description | string | A brief description of the Payment Link explaining the intent of the payment. | No
| expire_by | number | Timestamp, in Unix, when the Payment Link will expire. By default, a Payment Link will be valid for six months. | No
| first_min_partial_amount | number | Minimum amount that must be paid by the customer as the first partial payment. Default value is 100. | No
| notes | object | Key-value pairs that can be used to store additional information. Maximum 15 pairs, each value limited to 256 characters. | No
| notify_email | boolean | Send email notifications for the Payment Link. | No
| notify_sms | boolean | Send SMS notifications for the Payment Link. | No
| reference_id | string | Reference number tagged to a Payment Link. Must be unique for each Payment Link. Max 40 characters. | No
| reminder_enable | boolean | Enable payment reminders for the Payment Link. | No
</details>
<details>
<summary>create_qr_code</summary>

**Description**:

```
Create a new QR code in Razorpay that can be used to accept UPI payments
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| close_by | number | Unix timestamp at which QR Code should be automatically closed (min 2 mins after current time) | No
| customer_id | string | The unique identifier of the customer to link with the QR Code | No
| description | string | A brief description about the QR Code | No
| fixed_amount | boolean | Whether QR should accept only specific amount (true) or any amount (false) | No
| name | string | Label to identify the QR Code (e.g., 'Store Front Display') | No
| notes | object | Key-value pairs for additional information (max 15 pairs, 256 chars each) | No
| payment_amount | number | The specific amount allowed for transaction in smallest currency unit | No
| type | string | The type of the QR Code. Currently only supports 'upi_qr' | Yes
| usage | string | Whether QR should accept single or multiple payments. Possible values: 'single_use', 'multiple_use' | Yes
</details>
<details>
<summary>create_refund</summary>

**Description**:

```
Use this tool to create a normal refund for a payment. Amount should be in the smallest currency unit (e.g., for ₹295, use 29500)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Payment amount in the smallest currency unit (e.g., for ₹295, use 29500) | Yes
| notes | object | Key-value pairs used to store additional information. A maximum of 15 key-value pairs can be included. | No
| payment_id | string | Unique identifier of the payment which needs to be refunded. ID should have a pay_ prefix. | Yes
| receipt | string | A unique identifier provided by you for your internal reference. | No
| speed | string | The speed at which the refund is to be processed. Default is 'normal'. For instant refunds, speed is set as 'optimum'. | No
</details>
<details>
<summary>fetch_all_instant_settlements</summary>

**Description**:

```
Fetch all instant settlements with optional filtering, pagination, and payout details
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of instant settlement records to fetch (default: 10, max: 100) | No
| expand | array | Pass this if you want to fetch payout details as part of the response for all instant settlements. Supported values: ondemand_payouts | No
| from | number | Unix timestamp (in seconds) from when instant settlements are to be fetched | No
| skip | number | Number of instant settlement records to skip (default: 0) | No
| to | number | Unix timestamp (in seconds) up till when instant settlements are to be fetched | No
</details>
<details>
<summary>fetch_all_orders</summary>

**Description**:

```
Fetch all orders with optional filtering and pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| authorized | number | Filter orders based on payment authorization status. Values: 0 (orders with unauthorized payments), 1 (orders with authorized payments) | No
| count | number | Number of orders to be fetched (default: 10, max: 100) | No
| expand | array | Used to retrieve additional information. Supported values: payments, payments.card, transfers, virtual_account | No
| from | number | Timestamp (in Unix format) from when the orders should be fetched | No
| receipt | string | Filter orders that contain the provided value for receipt | No
| skip | number | Number of orders to be skipped (default: 0) | No
| to | number | Timestamp (in Unix format) up till when orders are to be fetched | No
</details>
<details>
<summary>fetch_all_payment_links</summary>

**Description**:

```
Fetch all payment links with optional filtering by payment ID or reference ID.You can specify the upi_link parameter to filter by link type.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payment_id | string | Optional: Filter by payment ID associated with payment links | No
| reference_id | string | Optional: Filter by reference ID used when creating payment links | No
| upi_link | number | Optional: Filter only upi links. Value should be 1 if you want only upi links, 0 for only standard linksIf not provided, all types of links will be returned | No
</details>
<details>
<summary>fetch_all_payments</summary>

**Description**:

```
Fetch all payments with optional filtering and pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of payments to fetch (default: 10, max: 100) | No
| from | number | Unix timestamp (in seconds) from when payments are to be fetched | No
| skip | number | Number of payments to skip (default: 0) | No
| to | number | Unix timestamp (in seconds) up till when payments are to be fetched | No
</details>
<details>
<summary>fetch_all_payouts</summary>

**Description**:

```
Fetch all payouts for a bank account number
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account_number | string | The account from which the payouts were done.For example, 7878780080316316 | Yes
| count | number | Number of payouts to be fetched. Default value is 10.Maximum value is 100. This can be used for pagination,in combination with the skip parameter | No
| skip | number | Numbers of payouts to be skipped. Default value is 0.This can be used for pagination, in combination with count | No
</details>
<details>
<summary>fetch_all_qr_codes</summary>

**Description**:

```
Fetch all QR codes with optional filtering and pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of QR Codes to be retrieved (default: 10, max: 100) | No
| from | number | Unix timestamp, in seconds, from when QR Codes are to be retrieved | No
| skip | number | Number of QR Codes to be skipped (default: 0) | No
| to | number | Unix timestamp, in seconds, till when QR Codes are to be retrieved | No
</details>
<details>
<summary>fetch_all_refunds</summary>

**Description**:

```
Use this tool to retrieve details of all refunds. By default, only the last 10 refunds are returned.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | The number of refunds to fetch. You can fetch a maximum of 100 refunds | No
| from | number | Unix timestamp at which the refunds were created | No
| skip | number | The number of refunds to be skipped | No
| to | number | Unix timestamp till which the refunds were created | No
</details>
<details>
<summary>fetch_all_settlements</summary>

**Description**:

```
Fetch all settlements with optional filtering and pagination
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of settlement records to fetch (default: 10, max: 100) | No
| from | number | Unix timestamp (in seconds) from when settlements are to be fetched | No
| skip | number | Number of settlement records to skip (default: 0) | No
| to | number | Unix timestamp (in seconds) up till when settlements are to be fetched | No
</details>
<details>
<summary>fetch_instant_settlement_with_id</summary>

**Description**:

```
Fetch details of a specific instant settlement using its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| settlement_id | string | The ID of the instant settlement to fetch. ID starts with 'setlod_' | Yes
</details>
<details>
<summary>fetch_multiple_refunds_for_payment</summary>

**Description**:

```
Use this tool to retrieve multiple refunds for a payment. By default, only the last 10 refunds are returned.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | The number of refunds to fetch for the payment. | No
| from | number | Unix timestamp at which the refunds were created. | No
| payment_id | string | Unique identifier of the payment for which refunds are to be retrieved. ID should have a pay_ prefix. | Yes
| skip | number | The number of refunds to be skipped for the payment. | No
| to | number | Unix timestamp till which the refunds were created. | No
</details>
<details>
<summary>fetch_order</summary>

**Description**:

```
Fetch an order's details using its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order_id | string | Unique identifier of the order to be retrieved | Yes
</details>
<details>
<summary>fetch_order_payments</summary>

**Description**:

```
Fetch all payments made for a specific order in Razorpay
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order_id | string | Unique identifier of the order for which payments should be retrieved. Order id should start with `order_` | Yes
</details>
<details>
<summary>fetch_payment</summary>

**Description**:

```
Use this tool to retrieve the details of a specific payment using its id. Amount returned is in paisa
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payment_id | string | payment_id is unique identifier of the payment to be retrieved. | Yes
</details>
<details>
<summary>fetch_payment_card_details</summary>

**Description**:

```
Use this tool to retrieve the details of the card used to make a payment. Only works for payments made using a card.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payment_id | string | Unique identifier of the payment for which you want to retrieve card details. Must start with 'pay_' | Yes
</details>
<details>
<summary>fetch_payment_link</summary>

**Description**:

```
Fetch payment link details using it's ID. Response contains the basic details like amount, status etc. The link could be of any type(standard or UPI)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payment_link_id | string | ID of the payment link to be fetched(ID should have a plink_ prefix). | Yes
</details>
<details>
<summary>fetch_payments_for_qr_code</summary>

**Description**:

```
Fetch all payments made on a QR code
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of payments to be fetched (default: 10, max: 100) | No
| from | number | Unix timestamp, in seconds, from when payments are to be retrieved | No
| qr_code_id | string | The unique identifier of the QR Code to fetch payments forThe QR code id should start with 'qr_' | Yes
| skip | number | Number of records to be skipped while fetching the payments | No
| to | number | Unix timestamp, in seconds, till when payments are to be fetched | No
</details>
<details>
<summary>fetch_payout_with_id</summary>

**Description**:

```
Fetch a payout's details using its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payout_id | string | The unique identifier of the payout. For example, 'pout_00000000000001' | Yes
</details>
<details>
<summary>fetch_qr_code</summary>

**Description**:

```
Fetch a QR code's details using it's ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| qr_code_id | string | Unique identifier of the QR Code to be retrievedThe QR code id should start with 'qr_' | Yes
</details>
<details>
<summary>fetch_qr_codes_by_customer_id</summary>

**Description**:

```
Fetch all QR codes for a specific customer
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customer_id | string | The unique identifier of the customer | Yes
</details>
<details>
<summary>fetch_qr_codes_by_payment_id</summary>

**Description**:

```
Fetch all QR codes for a specific payment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payment_id | string | The unique identifier of the paymentThe payment id always should start with 'pay_' | Yes
</details>
<details>
<summary>fetch_refund</summary>

**Description**:

```
Use this tool to retrieve the details of a specific refund using its id.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| refund_id | string | Unique identifier of the refund which is to be retrieved. ID should have a rfnd_ prefix. | Yes
</details>
<details>
<summary>fetch_settlement_recon_details</summary>

**Description**:

```
Fetch settlement reconciliation report for a specific time period
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Optional: Number of records to fetch (default: 10, max: 100) | No
| day | number | Optional: Day for which the settlement report is requested (DD format) | No
| month | number | Month for which the settlement report is requested (MM format) | Yes
| skip | number | Optional: Number of records to skip for pagination | No
| year | number | Year for which the settlement report is requested (YYYY format) | Yes
</details>
<details>
<summary>fetch_settlement_with_id</summary>

**Description**:

```
Fetch details of a specific settlement using its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| settlement_id | string | The ID of the settlement to fetch.ID starts with the 'setl_' | Yes
</details>
<details>
<summary>fetch_specific_refund_for_payment</summary>

**Description**:

```
Use this tool to retrieve details of a specific refund made for a payment.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payment_id | string | Unique identifier of the payment for which the refund has been made. ID should have a pay_ prefix. | Yes
| refund_id | string | Unique identifier of the refund to be retrieved. ID should have a rfnd_ prefix. | Yes
</details>
<details>
<summary>payment_link_notify</summary>

**Description**:

```
Send or resend notification for a payment link via SMS or email.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| medium | string | Medium through which to send the notification. Must be either 'sms' or 'email'. | Yes
| payment_link_id | string | ID of the payment link for which to send notification (ID should have a plink_ prefix). | Yes
</details>
<details>
<summary>payment_link_upi.create</summary>

**Description**:

```
Create a new UPI payment link in Razorpay with a specified amount and additional options.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| accept_partial | boolean | Indicates whether customers can make partial payments using the Payment Link. Default: false | No
| amount | number | Amount to be paid using the link in smallest currency unit(e.g., ₹300, use 30000), Only accepted currency is INR | Yes
| callback_method | string | HTTP method for callback redirection. Must be 'get' if callback_url is set. | No
| callback_url | string | If specified, adds a redirect URL to the Payment Link. Customer will be redirected here after payment. | No
| currency | string | Three-letter ISO code for the currency (e.g., INR). UPI links are only supported in INR | Yes
| customer_contact | string | Contact number of the customer. | No
| customer_email | string | Email address of the customer. | No
| customer_name | string | Name of the customer. | No
| description | string | A brief description of the Payment Link explaining the intent of the payment. | No
| expire_by | number | Timestamp, in Unix, when the Payment Link will expire. By default, a Payment Link will be valid for six months. | No
| first_min_partial_amount | number | Minimum amount that must be paid by the customer as the first partial payment. Default value is 100. | No
| notes | object | Key-value pairs that can be used to store additional information. Maximum 15 pairs, each value limited to 256 characters. | No
| notify_email | boolean | Send email notifications for the Payment Link. | No
| notify_sms | boolean | Send SMS notifications for the Payment Link. | No
| reference_id | string | Reference number tagged to a Payment Link. Must be unique for each Payment Link. Max 40 characters. | No
| reminder_enable | boolean | Enable payment reminders for the Payment Link. | No
</details>
<details>
<summary>update_order</summary>

**Description**:

```
Use this tool to update the notes for a specific order. Only the notes field can be modified.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| notes | object | Key-value pairs used to store additional information about the order. A maximum of 15 key-value pairs can be included, with each value not exceeding 256 characters. | Yes
| order_id | string | Unique identifier of the order which needs to be updated. ID should have an order_ prefix. | Yes
</details>
<details>
<summary>update_payment</summary>

**Description**:

```
Use this tool to update the notes field of a payment. Notes are key-value pairs that can be used to store additional information.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| notes | object | Key-value pairs that can be used to store additional information about the payment. Values must be strings or integers. | Yes
| payment_id | string | Unique identifier of the payment to be updated. Must start with 'pay_' | Yes
</details>
<details>
<summary>update_payment_link</summary>

**Description**:

```
Update any existing standard or UPI payment link with new details such as reference ID, expiry date, or notes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| accept_partial | boolean | Allow customers to make partial payments. Not allowed with UPI payment links. | No
| expire_by | number | Timestamp, in Unix format, when the payment link should expire. | No
| notes | object | Key-value pairs for additional information. Maximum 15 pairs, each value limited to 256 characters. | No
| payment_link_id | string | ID of the payment link to update (ID should have a plink_ prefix). | Yes
| reference_id | string | Adds a unique reference number to the payment link. | No
| reminder_enable | boolean | Enable or disable reminders for the payment link. | No
</details>
<details>
<summary>update_refund</summary>

**Description**:

```
Use this tool to update the notes for a specific refund. Only the notes field can be modified.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| notes | object | Key-value pairs used to store additional information. A maximum of 15 key-value pairs can be included, with each value not exceeding 256 characters. | Yes
| refund_id | string | Unique identifier of the refund which needs to be updated. ID should have a rfnd_ prefix. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | capture_payment | description | 0cb558bcef3b24d63e6f89d58c79bb1dffb51998648220b701655782c51484af |
| tools | capture_payment | amount | 93f26fb41d005ad5a5933e5abe5b82888252eb480154ac2ec9c7f92c2623dd26 |
| tools | capture_payment | currency | 7d2ac31268c1b6f065da1d7dbf2ce2f37ae3d41210032f6c61e38f4d638730ae |
| tools | capture_payment | payment_id | 57476462367db29c7770de483fa7e16b9491c06fd9f031a276cd3771d39a8d29 |
| tools | close_qr_code | description | 4a9717845a3f505592b8653482d796f4f5b5061042c1c2897d57ee2d8fe29a74 |
| tools | close_qr_code | qr_code_id | aa2c22c9da586a49253b195b892188cd65fef9a753ca440b1999723191837e35 |
| tools | create_instant_settlement | description | 8937c0a002f7970ef197c7f8340be6b816089911db35faa4baa897e0d9739768 |
| tools | create_instant_settlement | amount | 0e3f1e4b7562e038c8c430504c833ee9778459720bece73cd264476588a72c1b |
| tools | create_instant_settlement | description | 05b18f0241d04d9118678908e5b6b7ca58d28c415feaf46578baddade4bb1dec |
| tools | create_instant_settlement | notes | 76998bdb949d7dfe5990d655b83144da1af6b5bdf0ef6666e21537f5eec162ea |
| tools | create_instant_settlement | settle_full_balance | 40354b1d1a842bd146847414e5a20da9231622dee3dc793d93d4a92bec458be0 |
| tools | create_order | description | 7d82117fec42acecc41ba70b5e8cf726e307b655fa4551869ad11f9fd2aba940 |
| tools | create_order | amount | bb490265d75b06a8a5c82bf925b58e8d43bd6d33175797fc3bfa620c1155866d |
| tools | create_order | currency | 6ae3295165b77a3e14cd3b9230d16e2900fae6c77d9660c9f1d6c16ae979accf |
| tools | create_order | first_payment_min_amount | 9dbdbf0f5e0f69feaeebf039378b7b74009d619bbb75d9937608b90fcbe0f23d |
| tools | create_order | notes | 658fd3000d06e20f80d3ab2d2db0669810d45fbe5749cfd516774ff3a705b50b |
| tools | create_order | partial_payment | 8eb6e2e132177fdfef11e605d9ed60f336cbefe0eb2911f731128e11255be62a |
| tools | create_order | receipt | c82705f4e6b7ba32194af79440f25689eb8332ea2ae4d6d74954494b9dd75a56 |
| tools | create_payment_link | description | 11eb719a763a137a870f9d996cf709ce786d4c00c3d69e0e10f4b2d2d2fd79bf |
| tools | create_payment_link | accept_partial | b923ec63e4ad67fe5547d265da298eae5469abac18720beac806ab1c5eef7ac5 |
| tools | create_payment_link | amount | da4f244698a76a7caa472773c9971b9cc29f00a5b301f2ab5af951a969beae1d |
| tools | create_payment_link | callback_method | 88b90ba487239c69ef2d2e8e34ed66d2dc22f6e9b115087f7a1e0e01c9448a9b |
| tools | create_payment_link | callback_url | ecce69b9f2a9f746275764382bb4d936e2b88cd83ffd4384cb9eb256fd0d7704 |
| tools | create_payment_link | currency | d008aa386a19c1ea5a7e38e59ec6cd8f805274747ac84b80bdde9257b83bb0a1 |
| tools | create_payment_link | customer_contact | 7407de16d0c40f06063946e98fd70e3012422ec51175063734345d9058fc91d6 |
| tools | create_payment_link | customer_email | b0721bb49af91271c856326da65a94cd2b2267eeb18d0d046af132c507d7cde9 |
| tools | create_payment_link | customer_name | 32a39d7f6f048f018654a0d99228d508776b01ee73f52687f46cb122f98cfc74 |
| tools | create_payment_link | description | fbf4d0b4ace492db0ac88a472bd6287c64ddab1ace9fecbc7e474f491e61c2b1 |
| tools | create_payment_link | expire_by | abb9dec8c11662893ffa45ed15b1f20f839221a9d9cc33ad0a927ac57c122769 |
| tools | create_payment_link | first_min_partial_amount | c63b5260dbf6aa0554cf049207a8d85b256117aae07106ed0af22c80b86bc6b5 |
| tools | create_payment_link | notes | 409ea3b80ab1f52ebf5f0e45db41122e3c705edf420a36991cf0a09e04221178 |
| tools | create_payment_link | notify_email | 4d29b9ce54dd1a4a5c90889d96506345bc22a8efbb9f49eca04a754b0346438f |
| tools | create_payment_link | notify_sms | 061a3e92f96459592a103dd986350a396a36089f1e51b1432dfde297e1d3290b |
| tools | create_payment_link | reference_id | 5d451c50c3ac7b8c433665f791b608e80dbe8102649f52761b994ce6e1e89d1a |
| tools | create_payment_link | reminder_enable | 111bf5aeb9fb3c946179ddca4100d9385ea5e092bc5392e2a70aefa0f07bd215 |
| tools | create_qr_code | description | 233a6b34d7439c90719085a4996464c298e1e96782f824b5685e907fb477bc5c |
| tools | create_qr_code | close_by | 3bfc3c434f49388dacf1ce99bc7e65091c98fad480bbfae2b9a483068befe22d |
| tools | create_qr_code | customer_id | 3c8fbc691ad55c6a9418a76092f6fa71f7bd1951610152e208aad82dabed10cc |
| tools | create_qr_code | description | 30b16aa579481ee250fef376809b4ae4c40b62ba5e6c75cc433f0cdae323b55b |
| tools | create_qr_code | fixed_amount | 0dc53c9a83350ac97a4fb7329fd3f5b790c919cf364e78717fbab0501701be39 |
| tools | create_qr_code | name | d91ce95f9387fb7634c8800f1c148f7a2c9762840617198739efba3e59fe161b |
| tools | create_qr_code | notes | 658fd3000d06e20f80d3ab2d2db0669810d45fbe5749cfd516774ff3a705b50b |
| tools | create_qr_code | payment_amount | 1a5fc227bdcc289f5d74ac88775172e4319b455efe62453034586a49b73e4717 |
| tools | create_qr_code | type | b050a77c7ee65a52e0f097402d187ed5b8ae903ddcfec0f56e40a203d107a758 |
| tools | create_qr_code | usage | b3db5eb47af993d1697ede72007496d20f6c4feab5751b62632884ef9ebf5fd0 |
| tools | create_refund | description | d1f83aada1752be42abe47ceb4acd81251022a60b952ac6c779db4bff293eac7 |
| tools | create_refund | amount | 404ac7c223ab9d1e5e1991d328ccb6107456f2f67c7fc9bb936303649eb1dfa1 |
| tools | create_refund | notes | db315a3032f80d95a8f295d20b52068d16e4cf80dd9c6b23da06a4c438ece410 |
| tools | create_refund | payment_id | bc9f579768043358b4bb0a99786db04a463448277f282b22b69ba1f612be74d0 |
| tools | create_refund | receipt | 89958bcc76b0a2cacb0032fd43fc790c3135401fb78a4679cc3a582c7b1a884e |
| tools | create_refund | speed | 82b949d7e122a853b1fcc92f4c8b8166d90a785d335c9a0dea5b353b5ae94dee |
| tools | fetch_all_instant_settlements | description | 568ace594d68215c98b189dfcfb55e95958388c1a7e9d081c19c46d62c1ead39 |
| tools | fetch_all_instant_settlements | count | 1107b74478dbd6748d6dc2734004e653b077afb5092593401a9e61a9b12a48aa |
| tools | fetch_all_instant_settlements | expand | 75f1ab4f35d9c52876cafdc8181e02b744e35d496b108a65a150927fe84a1f83 |
| tools | fetch_all_instant_settlements | from | ef59615b718e40574dfa844e3f142c72040ef03b34edf3b4c2e62bdcf2c411a3 |
| tools | fetch_all_instant_settlements | skip | 4d4dd31b6fe69d2f03c2a17483a90ecb0a5dcd6bafc92c7a91214cef2f556062 |
| tools | fetch_all_instant_settlements | to | 74d1a6d512645784ef628718df48749031744527b53668a10da7a0e03f34bdea |
| tools | fetch_all_orders | description | 9c54cb1ede656fe3fe47d0d8a3196d06a49889265c71f9b4b57c08b8f96081ab |
| tools | fetch_all_orders | authorized | 371c0963fea312fdc5092aecce08b6e0fde59d4bf95e371a312d4fb39dd7c40e |
| tools | fetch_all_orders | count | e5156df571337502ac17381ff8d1443242a351886aadd057077e3d5190f1d687 |
| tools | fetch_all_orders | expand | bf9fe967a7afe941e20ed0791396d4ac4b6ba28cdd657ed3f4dd06bdcd3b06a0 |
| tools | fetch_all_orders | from | 0628ef666d191d809aa484857b68d379fa547725fcd55f07bc0cf8c2329fbf3d |
| tools | fetch_all_orders | receipt | 443307755064e50cb563987c1be6396ec3b7f25a0db66a35ee29de97b77372a3 |
| tools | fetch_all_orders | skip | 017dc893215a37ed467aef60e193ee227185608a76acc46251ccdca1f24fe7f6 |
| tools | fetch_all_orders | to | d8c55e46b428a4708faf76e497ee745f3071bd834c13f5e26f3cb484f67f6447 |
| tools | fetch_all_payment_links | description | 39de3696cf88abb7b51b64843425e6c74d1368442f55762a0b4da1992d10be1f |
| tools | fetch_all_payment_links | payment_id | ea770e865c75524ab43dbea4a8ad1ae31011a830496adbbfadad678044892c71 |
| tools | fetch_all_payment_links | reference_id | 72555761921800ac1f362c78616e3b1921bc35203d786b5b7314c50a40562936 |
| tools | fetch_all_payment_links | upi_link | 9f8297880d1df710c780e124ccb3fba113a2a8e22e29d5e5e9c6d460be5835e9 |
| tools | fetch_all_payments | description | 4ec656525a24b902e9252808e66b01fc34f8a9acc5805a7f363bd4bb70def58a |
| tools | fetch_all_payments | count | 512f6bc10d5244921ed495f98689ba12f4faf4725056a9db5b23724cd566e0d0 |
| tools | fetch_all_payments | from | f902137fc8894a29de6a2428be2fe8af6a0be015fd64ae5531f7523b7362d9c5 |
| tools | fetch_all_payments | skip | 6d07e86ab57d86e8cda6fdac80631844485ff89a21d8f6c610a61dc68018bba0 |
| tools | fetch_all_payments | to | 3a2bb24c9d70c2ce1e537088dc65e9212c171721111e6c06bbe7d24f4735391a |
| tools | fetch_all_payouts | description | a85665b4eb3ca46e424c537a6ca20ae147f07654987a36f050cff8dddbf648a2 |
| tools | fetch_all_payouts | account_number | bc94902422005380d29253c467e3d28ce6927efa2fecf7766888338a48c82733 |
| tools | fetch_all_payouts | count | 1d86c38ffa3aed4fa2bef2da7a7c864c6bf172cf0be9dbabcbd35aa4c7e9acdc |
| tools | fetch_all_payouts | skip | b061a801baa5deeabac4377f0d496f01312bd9b1ce821d42e85e2f4507bb48a3 |
| tools | fetch_all_qr_codes | description | e421076cabf056a5dd5d9fd9b6a27eda26daebab361fdb773035ba38e39171bf |
| tools | fetch_all_qr_codes | count | dddc5d2a82991f29cfeced2ba22ddd1904d234bdc740e17c749556e1d80301ae |
| tools | fetch_all_qr_codes | from | fe13479b730dcdb638ef6fe9f993a341efad3777c2a151f3ec68be79c63d9ddc |
| tools | fetch_all_qr_codes | skip | 4f8c4e8e03e37c1e8393b4945c8296409ed28ca569bdc71360c6fbc4fe42e49a |
| tools | fetch_all_qr_codes | to | 3ae02c3453c4c0f254b8e5ea4c79b3320d080509ffb13c082a208c4339d62abe |
| tools | fetch_all_refunds | description | bdc13b1864b7a7452baedd48ca824b64512a93db710c788599e8523e388709fd |
| tools | fetch_all_refunds | count | 3464f54134e421bf0906aa2a735aa2170ebffd13e59b4f5584b7544999fe99e7 |
| tools | fetch_all_refunds | from | 240dabb93b882fabd9782813b10839e1e25ecfe98574e856ef1bdb28456b215f |
| tools | fetch_all_refunds | skip | 29f827538cc780dcb72faf0d5d62e3a57ce61f879db1f76545b1ea89e356f523 |
| tools | fetch_all_refunds | to | 21c1b688ad0aee218a53a8c28cb7ed5b8917fe6d3547b605f9409fb301cd6b18 |
| tools | fetch_all_settlements | description | 1c759c75a9731013411f61cff7e1abafff74ca8b2a1b3eb3e79dce12a252a2a9 |
| tools | fetch_all_settlements | count | ee90e2a5b4f7fa6c11407a53b4d37724eafbc675ee345e49c568a9df163980b9 |
| tools | fetch_all_settlements | from | 9b0c09a7a6cc52387c9eac2dc36cd09e2cf6424d92e02a100db75b69a131043e |
| tools | fetch_all_settlements | skip | ef3293e14df45090f4d04cbb64b66d1ab1d83c74f69c8180ee282068a778aedb |
| tools | fetch_all_settlements | to | 5fbd556ef96cea0eb2a23c36bc9b159f93392d29b523683a44dec56eafe41155 |
| tools | fetch_instant_settlement_with_id | description | 7d9e8a3414fc88fd9c1d3e614e4bc52ae6f4bb88f7a782d99933b87209988fba |
| tools | fetch_instant_settlement_with_id | settlement_id | a48a33b353129c2b838dcecab118e67490ad55166e4fd07eb82080de51872d90 |
| tools | fetch_multiple_refunds_for_payment | description | aa689a9b288720373d3cb67fc09513adbb8bd62c1b6f035a1610fedba1a43ce3 |
| tools | fetch_multiple_refunds_for_payment | count | c0436ebc9ace24fb94d71f7752c01db38dfd4fd23e6b9b69564ae4f8fefce530 |
| tools | fetch_multiple_refunds_for_payment | from | cf7fcd25280c729be54ffbd95526f11039fb8e5a07f9856ccb3412edb6d2b4c4 |
| tools | fetch_multiple_refunds_for_payment | payment_id | 0e35bad7dff1d7e3e3830751d3bb4ba33cc968c2ebef67412a3816952f225ecb |
| tools | fetch_multiple_refunds_for_payment | skip | 9d31f47f45aad4d0053521518cb4422d0ac105e4664711c1ac32f2ecf10a84c6 |
| tools | fetch_multiple_refunds_for_payment | to | 6257771d1149388523203b29de9e1352c5c2d7b961a6714910bc723f19c5ce4e |
| tools | fetch_order | description | 757c62ebe885781501c412269401af0282e6bfde67df0b2333a655dc991c3e63 |
| tools | fetch_order | order_id | 504ae8d38bada98cb4c10b6275f5435ebd7c4c5a5f8d236a366b13d5024f3474 |
| tools | fetch_order_payments | description | 82f0c4cc00ffe5d61e10ea5e7d33b9a7434f4cda76105dfb4d674bb4441d169b |
| tools | fetch_order_payments | order_id | 654578d668288e90ec1fce19790bcb8170e4af87456917f3868b3ba8eebe34e2 |
| tools | fetch_payment | description | a503bf7550a65a97b3fb3ced4d73d71310e33c90a1ed9c7b08550eaa5f7c7d28 |
| tools | fetch_payment | payment_id | b52bc4aac8278fbf90c754659ce6576095506b49d40fd2e78ac4616483f68534 |
| tools | fetch_payment_card_details | description | c9b2bc41da44b73696c708cc0c3dadf26f086bdf37ed802ce5c3d51a28f53843 |
| tools | fetch_payment_card_details | payment_id | 19200f1105d62daf415a96014ae4f09a767f35dd05bef4f2bdd04a72a36f4034 |
| tools | fetch_payment_link | description | 484eb124a41052c77252a225f1dbf7e410183f0de5a19e356773c149d43f1764 |
| tools | fetch_payment_link | payment_link_id | 79de6434b664ddc757cb1df74d299933f1f5a2cc6e36bc4180ab0e81333e76e9 |
| tools | fetch_payments_for_qr_code | description | 5aa49f1afab776f40f4b51f49820ee261fb097e1a527be088878cde3ab80e4b1 |
| tools | fetch_payments_for_qr_code | count | 27f3369c13e09b85b237a7c446fac8aa8194d8d255557aeb6baad76a46fd173e |
| tools | fetch_payments_for_qr_code | from | 0bb0dbbf7e6a81e12828d083aed8fa48da4703ed49567029227c30ffb9668c09 |
| tools | fetch_payments_for_qr_code | qr_code_id | 8b437ea997a252e5e3a056ceb47d5096e69b16b0b52eb0f39c5c43c1680e8eef |
| tools | fetch_payments_for_qr_code | skip | 9419f0756836e22b14639f8ebe28b983e0f0ad92cd420d5c1ee63eb74d1204f9 |
| tools | fetch_payments_for_qr_code | to | 92412a63c077e33ab40b026555c359ca1abbb6212ff2cbb6c570d2c517630287 |
| tools | fetch_payout_with_id | description | 01b9833a6ecfe4230b4d52e95c0bddb9febd2324fbb2a12c38359743a68c3449 |
| tools | fetch_payout_with_id | payout_id | 42eb037ea89f35e0c93bfc9cf39d6a7aaac171dc28775c61d02f0e4ee569674e |
| tools | fetch_qr_code | description | 276b5cf457ce881c60828346f78d3ed036c91b09d4c46804edd2fd8d6ce2e9dd |
| tools | fetch_qr_code | qr_code_id | 2e12e1c927c7a9a0edadd04a43485a84aa72d4eb848129e64db580c888bf911d |
| tools | fetch_qr_codes_by_customer_id | description | 7a051fb601e98ef852e57dbb0b605e459569a789e5293750395c0382018a9d2d |
| tools | fetch_qr_codes_by_customer_id | customer_id | be5c6d40b5e0dc7fc4757bf06345e13308f4ff33b5bc544bf63ba37de008a4c8 |
| tools | fetch_qr_codes_by_payment_id | description | 11be879ca50fe9e0542320b91a39b359f2d7fb8f2ce2c6fd02cb4be16cac1f64 |
| tools | fetch_qr_codes_by_payment_id | payment_id | 6f4b55684f7d611ac5192cab0b9e79c9b6a0298d882343028a13c38d2fa5a8b8 |
| tools | fetch_refund | description | 502a297a4e1ecb2b820fe62f0d2e33d05e82abfcd26b4fdec8de5f89e2c44eb9 |
| tools | fetch_refund | refund_id | b0ac5145b6b32c6d6290c715c477f0b66b455d97807837c533e66ea43124f228 |
| tools | fetch_settlement_recon_details | description | 42a4cad11689aaeab3c35a92adde5315a26f8249230ce8d51c31939e7399ad91 |
| tools | fetch_settlement_recon_details | count | 3b0b0a3a9282020b1fe2ab164913b8de60996e5d204c55794a2147bc6507cb20 |
| tools | fetch_settlement_recon_details | day | dad2a92a3f2beb934db14caf8abf05c55c0ce53eb77eef8ad8858096bfc66da2 |
| tools | fetch_settlement_recon_details | month | 98274071eed703ea764dfb4bff89f9fcdea108ea3172eecb063679a11089d905 |
| tools | fetch_settlement_recon_details | skip | 081f49f7a39a8f88b001c7fe319cac0f312acb267b1821f4d9865e6bdf079081 |
| tools | fetch_settlement_recon_details | year | 239ff349b96d36c4231bb974934ce012c5bd8ee6d6b09a8f5f2186a2964ba29d |
| tools | fetch_settlement_with_id | description | 158da65697c474a3f7c8bfe5242a8af85fc8806aad271fa08bad0656c1c401a1 |
| tools | fetch_settlement_with_id | settlement_id | f1e2684044cc94600da84e0fa7abe3decf0c25f042b09055c03070896495e535 |
| tools | fetch_specific_refund_for_payment | description | 2662c9506cd893264175c86a1e48b8150e3877e3ff94ee05cdf765df145b0bc1 |
| tools | fetch_specific_refund_for_payment | payment_id | 9b26fdbcbc57574ec6a4e30d1f2dfd8c8ffbc9f8535da54bb35bbcfebd8cec5f |
| tools | fetch_specific_refund_for_payment | refund_id | 7573be1d03d2052dc3873777c1f41c1e2968960dafcf1f725d7c7a859ef7cf48 |
| tools | payment_link_notify | description | a635457a624426b2d3991ab58673eeca77f91715661efd029a5ab7a3dc64db8c |
| tools | payment_link_notify | medium | 759fd06956d74b75ba97b5c0a6fca7fe070b823cf0048c238671c0e6ec1de5b6 |
| tools | payment_link_notify | payment_link_id | a81943b1bcf5c056b287466206efbb23271639a9eca24a5a433eede63e5325b3 |
| tools | payment_link_upi.create | description | e35e601b97a50a3470a4e0eb23efa0062b2a1f0e1657f44d0dbd6fafb47e95b1 |
| tools | payment_link_upi.create | accept_partial | b923ec63e4ad67fe5547d265da298eae5469abac18720beac806ab1c5eef7ac5 |
| tools | payment_link_upi.create | amount | aa1a2f87e61363b781cc3154c73701fd9079e90dce2db0a98fc819b7006e5506 |
| tools | payment_link_upi.create | callback_method | 88b90ba487239c69ef2d2e8e34ed66d2dc22f6e9b115087f7a1e0e01c9448a9b |
| tools | payment_link_upi.create | callback_url | ecce69b9f2a9f746275764382bb4d936e2b88cd83ffd4384cb9eb256fd0d7704 |
| tools | payment_link_upi.create | currency | 705ad3d157ff248e6036ce01f8a3558cf4e1af4b927293730f77b65816694c7e |
| tools | payment_link_upi.create | customer_contact | 7407de16d0c40f06063946e98fd70e3012422ec51175063734345d9058fc91d6 |
| tools | payment_link_upi.create | customer_email | b0721bb49af91271c856326da65a94cd2b2267eeb18d0d046af132c507d7cde9 |
| tools | payment_link_upi.create | customer_name | 32a39d7f6f048f018654a0d99228d508776b01ee73f52687f46cb122f98cfc74 |
| tools | payment_link_upi.create | description | fbf4d0b4ace492db0ac88a472bd6287c64ddab1ace9fecbc7e474f491e61c2b1 |
| tools | payment_link_upi.create | expire_by | abb9dec8c11662893ffa45ed15b1f20f839221a9d9cc33ad0a927ac57c122769 |
| tools | payment_link_upi.create | first_min_partial_amount | c63b5260dbf6aa0554cf049207a8d85b256117aae07106ed0af22c80b86bc6b5 |
| tools | payment_link_upi.create | notes | 409ea3b80ab1f52ebf5f0e45db41122e3c705edf420a36991cf0a09e04221178 |
| tools | payment_link_upi.create | notify_email | 4d29b9ce54dd1a4a5c90889d96506345bc22a8efbb9f49eca04a754b0346438f |
| tools | payment_link_upi.create | notify_sms | 061a3e92f96459592a103dd986350a396a36089f1e51b1432dfde297e1d3290b |
| tools | payment_link_upi.create | reference_id | 5d451c50c3ac7b8c433665f791b608e80dbe8102649f52761b994ce6e1e89d1a |
| tools | payment_link_upi.create | reminder_enable | 111bf5aeb9fb3c946179ddca4100d9385ea5e092bc5392e2a70aefa0f07bd215 |
| tools | update_order | description | 2268a54ccb180030c66b33a78fc3bc302b4b8c9a9f12f662348f23dcbbcd4981 |
| tools | update_order | notes | 07b087a1c2ce32ca37ae9850501d4750f1e0ee4ac442e5e6025c38113f405924 |
| tools | update_order | order_id | bcba8145c15ca2e6d4637b153f03770aea34a05291133d2d34a8d8598f17d346 |
| tools | update_payment | description | a1c582ce74b49eec3e61c7e25a601247ec72f0aeab24d2c492abfdbba0cb8632 |
| tools | update_payment | notes | 20657c009890ca5d243d9f9af185db29e1f1da1c630bd6bed24c28d265b5e53d |
| tools | update_payment | payment_id | 2e727d3977244e2b51a611c974dc103b99e1c2cfc0d01efb22c1582ae7cd0e7f |
| tools | update_payment_link | description | 501514649d780f60c96434276e29018062e621631e3f60c3e2a3adf8725b7088 |
| tools | update_payment_link | accept_partial | c65498877bbd18c3973e873dc150cfffbf8278bbbfa03ee713b287aed4031b9b |
| tools | update_payment_link | expire_by | 6344133a75cf7a87a159fd81cfc6ff2c9f707ac708db6e3503bd0fceef065d3d |
| tools | update_payment_link | notes | c92c170559f58959a1be62c1cca623c6bbb44e87765b428938b97b31b0d47e11 |
| tools | update_payment_link | payment_link_id | 8aab954b8c161fb73154635d1fec0d396aefd685596f80e767914a4c4d6cc89e |
| tools | update_payment_link | reference_id | f25064195d5851262e6ec6c569071f6723757605f0ff17756fa0e5d13b6b29c8 |
| tools | update_payment_link | reminder_enable | 906be771f4fe5bfb90cae15f95efbfd5c0c1d67524fe6aa81e6f2eee777bbb49 |
| tools | update_refund | description | 1d12006957ea50f6afa8688a8ad1ebba676e65607f4748971994fdecea3e0175 |
| tools | update_refund | notes | 37f894a546ea538743c1e2953e5ba6d05d4bdc96447a4d60982d3621d39ca0d0 |
| tools | update_refund | refund_id | 466da148a355997d47bc430e3e089e0f222f7117610a70e37fcab416354df300 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
