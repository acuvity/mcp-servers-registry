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


# What is mcp-server-azure?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-azure/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-azure/0.1.2?logo=docker&logoColor=fff&label=0.1.2)](https://hub.docker.com/r/acuvity/mcp-server-azure)
[![PyPI](https://img.shields.io/badge/0.1.2-3775A9?logo=pypi&logoColor=fff&label=@azure/mcp)](https://github.com/Azure/azure-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-azure/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-azure&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22-e%22%2C%22AZURE_CLIENT_ID%22%2C%22-e%22%2C%22AZURE_CLIENT_SECRET%22%2C%22-e%22%2C%22AZURE_TENANT_ID%22%2C%22docker.io%2Facuvity%2Fmcp-server-azure%3A0.1.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates AI agents with Azure services for enhanced functionality.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @azure/mcp original [sources](https://github.com/Azure/azure-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-azure/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/charts/mcp-server-azure/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @azure/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Microsoft Corporation ](https://github.com/Azure/azure-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @azure/mcp ](https://github.com/Azure/azure-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @azure/mcp ](https://github.com/Azure/azure-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/charts/mcp-server-azure)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-azure/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-azure:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-azure:1.0.0-0.1.2`

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
  - `AZURE_CLIENT_ID` secret to be set as secrets.AZURE_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `AZURE_CLIENT_SECRET` secret to be set as secrets.AZURE_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`
  - `AZURE_TENANT_ID` secret to be set as secrets.AZURE_TENANT_ID either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-azure
```

From there your MCP server mcp-server-azure will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-azure` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-azure
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-azure` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-azure oci://docker.io/acuvity/mcp-server-azure --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (54)
<details>
<summary>azmcp-appconfig-account-list</summary>

**Description**:

```
List all App Configuration stores in a subscription. This command retrieves and displays all App Configuration
stores available in the specified subscription. Results include store names returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-appconfig-kv-delete</summary>

**Description**:

```
Delete a key-value pair from an App Configuration store. This command removes the specified key-value pair from the store.
If a label is specified, only the labeled version is deleted. If no label is specified, the key-value with the matching
key and the default label will be deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the App Configuration store (e.g., my-appconfig). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to access within the App Configuration store. | Yes
| label | string | The label to apply to the configuration key. Labels are used to group and organize settings. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-appconfig-kv-list</summary>

**Description**:

```
List all key-values in an App Configuration store. This command retrieves and displays all key-value pairs
from the specified store. Each key-value includes its key, value, label, content type, ETag, last modified
time, and lock status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the App Configuration store (e.g., my-appconfig). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | Specifies the key filter, if any, to be used when retrieving key-values. The filter can be an exact match, for example a filter of "foo" would get all key-values with a key of "foo", or the filter can include a '*' character at the end of the string for wildcard searches (e.g., 'App*'). If omitted all keys will be retrieved. | No
| label | string | Specifies the label filter, if any, to be used when retrieving key-values. The filter can be an exact match, for example a filter of "foo" would get all key-values with a label of "foo", or the filter can include a '*' character at the end of the string for wildcard searches (e.g., 'Prod*'). This filter is case-sensitive. If omitted, all labels will be retrieved. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-appconfig-kv-lock</summary>

**Description**:

```
Lock a key-value in an App Configuration store. This command sets a key-value to read-only mode,
preventing any modifications to its value. You must specify an account name and key. Optionally,
you can specify a label to lock a specific labeled version of the key-value.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the App Configuration store (e.g., my-appconfig). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to access within the App Configuration store. | Yes
| label | string | The label to apply to the configuration key. Labels are used to group and organize settings. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-appconfig-kv-set</summary>

**Description**:

```
Set a key-value setting in an App Configuration store. This command creates or updates a key-value setting
with the specified value. You must specify an account name, key, and value. Optionally, you can specify a
label otherwise the default label will be used.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the App Configuration store (e.g., my-appconfig). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to access within the App Configuration store. | Yes
| label | string | The label to apply to the configuration key. Labels are used to group and organize settings. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| value | string | The value to set for the configuration key. | Yes
</details>
<details>
<summary>azmcp-appconfig-kv-show</summary>

**Description**:

```
Show a specific key-value setting in an App Configuration store. This command retrieves and displays the value,
label, content type, ETag, last modified time, and lock status for a specific setting. You must specify an
account name and key. Optionally, you can specify a label otherwise the setting with default label will be retrieved.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the App Configuration store (e.g., my-appconfig). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to access within the App Configuration store. | Yes
| label | string | The label to apply to the configuration key. Labels are used to group and organize settings. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-appconfig-kv-unlock</summary>

**Description**:

```
Unlock a key-value setting in an App Configuration store. This command removes the read-only mode from a
key-value setting, allowing modifications to its value. You must specify an account name and key. Optionally,
you can specify a label to unlock a specific labeled version of the setting, otherwise the setting with the
default label will be unlocked.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the App Configuration store (e.g., my-appconfig). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to access within the App Configuration store. | Yes
| label | string | The label to apply to the configuration key. Labels are used to group and organize settings. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-bestpractices-get</summary>

**Description**:

```
Returns best practices for secure, production-grade Azure SDK usage. Call this command and follow its guidance before generating or suggesting any Azure SDK code. This command returns the content of the markdown file as a string array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>azmcp-cosmos-account-list</summary>

**Description**:

```
List all Cosmos DB accounts in a subscription. This command retrieves and displays all Cosmos DB accounts
available in the specified subscription. Results include account names and are returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-cosmos-database-container-item-query</summary>

**Description**:

```
Execute a SQL query against items in a Cosmos DB container. Requires account-name,
database-name, and container-name.
The query parameter accepts SQL query syntax. Results are returned as a
JSON array of documents.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Cosmos DB account to query (e.g., my-cosmos-account). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| container-name | string | The name of the container to query (e.g., my-container). | Yes
| database-name | string | The name of the database to query (e.g., my-database). | Yes
| query | string | SQL query to execute against the container. Uses Cosmos DB SQL syntax. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-cosmos-database-container-list</summary>

**Description**:

```
List all containers in a Cosmos DB database. This command retrieves and displays all containers within
the specified database and Cosmos DB account. Results include container names and are returned as a
JSON array. You must specify both an account name and a database name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Cosmos DB account to query (e.g., my-cosmos-account). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| database-name | string | The name of the database to query (e.g., my-database). | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-cosmos-database-list</summary>

**Description**:

```
List all databases in a Cosmos DB account. This command retrieves and displays all databases available
in the specified Cosmos DB account. Results include database names and are returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Cosmos DB account to query (e.g., my-cosmos-account). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-extension-az</summary>

**Description**:

```
Your job is to answer questions about an Azure environment by executing Azure CLI commands. You have the following rules:

- Use the Azure CLI to manage Azure resources and services. Do not use any other tool.
- Provide a valid Azure CLI command. For example: 'group list'.
- When deleting or modifying resources, ALWAYS request user confirmation.
- If a command fails, retry 3 times before giving up with an improved version of the code based on the returned feedback.
- When listing resources, ensure pagination is handled correctly so that all resources are returned.
- You can ONLY write code that interacts with Azure. It CANNOT generate charts, tables, graphs, etc.
- You can delete or modify resources in your Azure environment. Always be cautious and include appropriate warnings when providing commands to users.
- Be concise, professional and to the point. Do not give generic advice, always reply with detailed & contextual data sourced from the current Azure environment.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| command | string | The Azure CLI command to execute (without the 'az' prefix). For example: 'group list'. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-extension-azd</summary>

**Description**:

```
Runs Azure Developer CLI (azd) commands.
Agents and LLM's must always run this tool with the 'learn' parameter and empty 'command' on first use to learn more about 'azd' best practices and usage patterns.

This tool supports the following:
- List, search and show templates to start your project
- Create and initialize new projects and templates
- Show and manage azd configuration
- Show and manage environments and values
- Provision Azure resources
- Deploy applications
- Bring the whole project up and online
- Bring the whole project down and deallocate all Azure resources
- Setup CI/CD pipelines
- Monitor Azure applications
- Show information about the project and its resources
- Show and manage extensions and extension sources
- Show and manage templates and template sources

If unsure about available commands or their parameters, run azd help or azd <group> --help in the command to discover them.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| command | string | The Azure Developer CLI command and arguments to execute (without the 'azd' prefix).
Examples:
- up
- env list
- env get-values | No
| cwd | string | The current working directory for the command. This is the directory where the command will be executed. | Yes
| environment | string | The name of the azd environment to use. This is typically the name of the Azure environment (e.g., 'prod', 'dev', 'test', 'staging').
Always set environments for azd commands that support -e, --environment argument. | No
| learn | boolean | Flag to indicate whether to learn best practices and usage patterns for azd tool.
Always run this command with learn=true and empty command on first run. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-group-list</summary>

**Description**:

```
List all resource groups in a subscription. This command retrieves all resource groups available
in the specified subscription. Results include resource group names and IDs,
returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-keyvault-key-create</summary>

**Description**:

```
Create a new key in an Azure Key Vault. This command creates a key with the specified name and type
in the given vault.

Required arguments:
- subscription
- vault
- key
- key-type

Key types:
- RSA: RSA key pair
- EC: Elliptic Curve key pair
- OCT: ES cryptographic pair
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to retrieve/modify from the Key Vault. | Yes
| key-type | string | The type of key to create (RSA, EC). | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| vault | string | The name of the Key Vault. | Yes
</details>
<details>
<summary>azmcp-keyvault-key-get</summary>

**Description**:

```
Get a key from an Azure Key Vault. This command retrieves and displays details
about a specific key in the specified vault.

Required arguments:
- subscription
- vault
- key
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| key | string | The name of the key to retrieve/modify from the Key Vault. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| vault | string | The name of the Key Vault. | Yes
</details>
<details>
<summary>azmcp-keyvault-key-list</summary>

**Description**:

```
List all keys in an Azure Key Vault. This command retrieves and displays the names of all keys
stored in the specified vault.

Required arguments:
- subscription
- vault
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| include-managed | boolean | Whether or not to include managed keys in results. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| vault | string | The name of the Key Vault. | Yes
</details>
<details>
<summary>azmcp-kusto-cluster-get</summary>

**Description**:

```
Get details for a specific Kusto cluster. Requires `subscription` and `cluster-name`.
The response includes the `clusterUri` property for use in subsequent commands.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster-name | string | Kusto Cluster name. | No
| cluster-uri | string | Kusto Cluster URI. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-kusto-cluster-list</summary>

**Description**:

```
List all Kusto clusters in a subscription. This command retrieves all clusters
available in the specified subscription. Requires `cluster-name` and `subscription`.
Result is a list of cluster names as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-kusto-database-list</summary>

**Description**:

```
List all databases in a Kusto cluster. Requires `cluster-uri` ( or `subscription` and `cluster-name`). Result is a list of database names, returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster-name | string | Kusto Cluster name. | No
| cluster-uri | string | Kusto Cluster URI. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-kusto-query</summary>

**Description**:

```
Execute a KQL against items in a Kusto cluster.
Requires `cluster-uri` (or `cluster-name` and `subscription`), `database-name`, and `query`. 
Results are returned as a JSON array of documents, for example: `[{'Column1': val1, 'Column2': val2}, ...]`.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster-name | string | Kusto Cluster name. | No
| cluster-uri | string | Kusto Cluster URI. | No
| database-name | string | Kusto Database name. | Yes
| query | string | Kusto query to execute. Uses KQL syntax. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-kusto-sample</summary>

**Description**:

```
Return a sample of rows from the specified table in an Kusto table.
Requires `cluster-uri` (or `cluster-name`), `database-name`, and `table-name`. 
Results are returned as a JSON array of documents, for example: `[{'Column1': val1, 'Column2': val2}, ...]`.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster-name | string | Kusto Cluster name. | No
| cluster-uri | string | Kusto Cluster URI. | No
| database-name | string | Kusto Database name. | Yes
| limit | integer | The maximum number of results to return. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| table-name | string | Kusto Table name. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-kusto-table-list</summary>

**Description**:

```
List all tables in a specific Kusto database. Required `cluster-uri` (or `subscription` and `cluster-name`) and `database-name` .Returns table names as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster-name | string | Kusto Cluster name. | No
| cluster-uri | string | Kusto Cluster URI. | No
| database-name | string | Kusto Database name. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-kusto-table-schema</summary>

**Description**:

```
Get the schema of a specific table in an Kusto database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster-name | string | Kusto Cluster name. | No
| cluster-uri | string | Kusto Cluster URI. | No
| database-name | string | Kusto Database name. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| table-name | string | Kusto Table name. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-monitor-healthmodels-entity-gethealth</summary>

**Description**:

```
Gets the health of an entity from a specified Azure Monitor Health Model.
Returns entity health information.

Required arguments:
- entity: The entity to get health for
- model-name: The health model name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| entity | string | The entity to get health for. | Yes
| model-name | string | The name of the health model for which to get the health. | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-monitor-log-query</summary>

**Description**:

```
Execute a KQL query against a Log Analytics workspace. Requires workspace
and resource group. Optional hours
(default: 0) and limit
(default: 0) parameters.
The query parameter accepts KQL syntax.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| hours | integer | The number of hours to query back from now. | Yes
| limit | integer | The maximum number of results to return. | Yes
| query | string | The KQL query to execute against the Log Analytics workspace. You can use predefined queries by name:
- 'recent': Shows most recent logs ordered by TimeGenerated
- 'errors': Shows error-level logs ordered by TimeGenerated
Otherwise, provide a custom KQL query. | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| table-name | string | The name of the table to query. This is the specific table within the workspace. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| workspace | string | The Log Analytics workspace ID or name. This can be either the unique identifier (GUID) or the display name of your workspace. | Yes
</details>
<details>
<summary>azmcp-monitor-table-list</summary>

**Description**:

```
List all tables in a Log Analytics workspace. Requires workspace.
Returns table names and schemas that can be used for constructing KQL queries.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| table-type | string | The type of table to query. Options: 'CustomLog', 'AzureMetrics', etc. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| workspace | string | The Log Analytics workspace ID or name. This can be either the unique identifier (GUID) or the display name of your workspace. | Yes
</details>
<details>
<summary>azmcp-monitor-table-type-list</summary>

**Description**:

```
List available table types in a Log Analytics workspace. Returns table type names.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| workspace | string | The Log Analytics workspace ID or name. This can be either the unique identifier (GUID) or the display name of your workspace. | Yes
</details>
<details>
<summary>azmcp-monitor-workspace-list</summary>

**Description**:

```
List Log Analytics workspaces in a subscription. This command retrieves all Log Analytics workspaces
available in the specified Azure subscription, displaying their names, IDs, and other key properties.
Use this command to identify workspaces before querying their logs or tables.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-postgres-database-list</summary>

**Description**:

```
Lists all databases in the PostgreSQL server.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| server | string | The PostgreSQL server to be accessed. | Yes
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-postgres-database-query</summary>

**Description**:

```
Executes a query on the PostgreSQL database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| database | string | The PostgreSQL database to be access. | Yes
| query | string | Query to be executed against a PostgreSQL database. | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| server | string | The PostgreSQL server to be accessed. | Yes
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-postgres-server-config</summary>

**Description**:

```
Retrieve the configuration of a PostgreSQL server.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| server | string | The PostgreSQL server to be accessed. | Yes
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-postgres-server-list</summary>

**Description**:

```
Lists all PostgreSQL servers in the specified subscription.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-postgres-server-param</summary>

**Description**:

```
Retrieves a specific parameter of a PostgreSQL server.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| param | string | The PostgreSQL parameter to be accessed. | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| server | string | The PostgreSQL server to be accessed. | Yes
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-postgres-table-list</summary>

**Description**:

```
Lists all tables in the PostgreSQL database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| database | string | The PostgreSQL database to be access. | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| server | string | The PostgreSQL server to be accessed. | Yes
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-postgres-table-schema</summary>

**Description**:

```
Retrieves the schema of a specified table in a PostgreSQL database.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| database | string | The PostgreSQL database to be access. | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| server | string | The PostgreSQL server to be accessed. | Yes
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| table | string | The PostgreSQL table to be access. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| user-name | string | The user name to access PostgreSQL server. | Yes
</details>
<details>
<summary>azmcp-redis-cache-accesspolicy-list</summary>

**Description**:

```
List the Access Policies and Assignments for the specified Redis cache. Returns an array of Redis Access Policy Assignment details.
Use this command to explore which Access Policies have been assigned to which identities for your Redis cache.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cache | string | The name of the Redis cache (e.g., my-redis-cache). | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-redis-cache-list</summary>

**Description**:

```
List all Redis Cache resources in a specified subscription. Returns an array of Redis Cache details.
Use this command to explore which Redis Cache resources are available in your subscription.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-redis-cluster-database-list</summary>

**Description**:

```
List the databases in the specified Redis Cluster resource. Returns an array of Redis database details.
Use this command to explore which databases are available in your Redis Cluster.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| cluster | string | The name of the Redis cluster (e.g., my-redis-cluster). | Yes
| resource-group | string | The name of the Azure resource group. This is a logical container for Azure resources. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-redis-cluster-list</summary>

**Description**:

```
List all Redis Cluster resources in a specified subscription. Returns an array of Redis Cluster details.
Use this command to explore which Redis Cluster resources are available in your subscription.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-search-index-describe</summary>

**Description**:

```
Get the full definition of an Azure AI Search index. Returns the complete index configuration including
fields, analyzers, suggesters, scoring profiles, and other settings.

Required arguments:
- service-name: The name of the Azure AI Search service
- index-name: The name of the search index to retrieve
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| index-name | string | The name of the search index within the Azure AI Search service. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| service-name | string | The name of the Azure AI Search service (e.g., my-search-service). | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-search-index-list</summary>

**Description**:

```
List all indexes in an Azure AI Search service.

Required arguments:
- service-name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| service-name | string | The name of the Azure AI Search service (e.g., my-search-service). | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-search-index-query</summary>

**Description**:

```
Query an Azure AI Search index. Returns search results matching the specified query.

Required arguments:
- service-name: The name of the Azure AI Search service
- index-name: The name of the search index to query
- query: The search text to query with
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| index-name | string | The name of the search index within the Azure AI Search service. | Yes
| query | string | The search query to execute against the Azure AI Search index. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| service-name | string | The name of the Azure AI Search service (e.g., my-search-service). | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-search-service-list</summary>

**Description**:

```
List all Azure AI Search services in a subscription.

Required arguments:
- subscription
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-servicebus-queue-details</summary>

**Description**:

```
Get details about a Service Bus queue. Returns queue properties and runtime information. Properties returned include
lock duration, max message size, queue size, creation date, status, current message counts, etc.

Required arguments:
- namespace: The fully qualified Service Bus namespace host name. (This is usually in the form <namespace>.servicebus.windows.net)
- queue-name: Queue name to get details and runtime information for.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| namespace | string | The fully qualified Service Bus namespace host name. (This is usually in the form <namespace>.servicebus.windows.net) | Yes
| queue-name | string | The queue name to peek messages from. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-servicebus-topic-details</summary>

**Description**:

```
Get details about a Service Bus topic. Returns topic properties and runtime information. Properties returned include
number of subscriptions, max message size, max topic size, number of scheduled messages, etc.

Required arguments:
- namespace: The fully qualified Service Bus namespace host name. (This is usually in the form <namespace>.servicebus.windows.net)
- topic-name: Topic name to get information about.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| namespace | string | The fully qualified Service Bus namespace host name. (This is usually in the form <namespace>.servicebus.windows.net) | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| topic-name | string | The name of the topic containing the subscription. | Yes
</details>
<details>
<summary>azmcp-servicebus-topic-subscription-details</summary>

**Description**:

```
Get details about a Service Bus subscription. Returns subscription runtime properties including message counts, delivery settings, and other metadata.

Required arguments:
- namespace: The fully qualified Service Bus namespace host name. (This is usually in the form <namespace>.servicebus.windows.net)
- topic-name: Topic name containing the subscription
- subscription-name: Name of the subscription to get details for
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| namespace | string | The fully qualified Service Bus namespace host name. (This is usually in the form <namespace>.servicebus.windows.net) | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| subscription-name | string | The name of subscription to peek messages from. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
| topic-name | string | The name of the topic containing the subscription. | Yes
</details>
<details>
<summary>azmcp-storage-account-list</summary>

**Description**:

```
List all Storage accounts in a subscription. This command retrieves all Storage accounts available
in the specified subscription. Results include account names and are
returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-storage-blob-container-details</summary>

**Description**:

```
Get detailed properties of a storage container including metadata, lease status, and access level.
Requires account-name and container-name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Azure Storage account. This is the unique name you chose for your storage account (e.g., 'mystorageaccount'). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| container-name | string | The name of the container to access within the storage account. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-storage-blob-container-list</summary>

**Description**:

```
List all containers in a Storage account. This command retrieves and displays all containers available
in the specified account. Results include container names and are returned as a JSON array.
Requires account-name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Azure Storage account. This is the unique name you chose for your storage account (e.g., 'mystorageaccount'). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-storage-blob-list</summary>

**Description**:

```
List all blobs in a Storage container. This command retrieves and displays all blobs available
in the specified container and Storage account. Results include blob names, sizes, and content types,
returned as a JSON array. Requires account-name and
container-name.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Azure Storage account. This is the unique name you chose for your storage account (e.g., 'mystorageaccount'). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| container-name | string | The name of the container to access within the storage account. | Yes
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-storage-table-list</summary>

**Description**:

```
List all tables in a Storage account. This command retrieves and displays all tables available in the specified Storage account.
Results include table names and are returned as a JSON array. You must specify an account name and subscription ID.
Use this command to explore your Storage resources or to verify table existence before performing operations on specific tables.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account-name | string | The name of the Azure Storage account. This is the unique name you chose for your storage account (e.g., 'mystorageaccount'). | Yes
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| subscription | string | The Azure subscription ID or name. This can be either the GUID identifier or the display name of the Azure subscription to use. | Yes
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>
<details>
<summary>azmcp-subscription-list</summary>

**Description**:

```
List all Azure subscriptions accessible to your account. Optionally specify tenant
and auth-method. Results include subscription names and IDs, returned as a JSON array.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auth-method | integer | Authentication method to use. Options: 'credential' (Azure CLI/managed identity), 'key' (access key), or 'connectionString'. | No
| retry-delay | number | Initial delay in seconds between retry attempts. For exponential backoff, this value is used as the base. | No
| retry-max-delay | number | Maximum delay in seconds between retries, regardless of the retry strategy. | No
| retry-max-retries | integer | Maximum number of retry attempts for failed operations before giving up. | No
| retry-mode | integer | Retry strategy to use. 'fixed' uses consistent delays, 'exponential' increases delay between attempts. | No
| retry-network-timeout | number | Network operation timeout in seconds. Operations taking longer than this will be cancelled. | No
| tenant | string | The Azure Active Directory tenant ID or name. This can be either the GUID identifier or the display name of your Azure AD tenant. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | azmcp-appconfig-account-list | description | 5f8f6eb7269af95fffde5aa8b137b550d176c6fb9cec94e45f97f5afda7ea38b |
| tools | azmcp-appconfig-account-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-account-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-account-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-account-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-account-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-account-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-account-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-account-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-appconfig-kv-delete | description | af2118f73b07ff4fb2371c00522eda1cf0c370b280c5673353ea48fb913cad8a |
| tools | azmcp-appconfig-kv-delete | account-name | c10f3ab94cacd2abb4eb0c1ee63b40680a08ca041e8101522ea3ea61f90a5886 |
| tools | azmcp-appconfig-kv-delete | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-kv-delete | key | 8c4e074c54aff330e5352d671a8b7f2d8efcc9e19786eac13d9ec3e2b4fe4d1d |
| tools | azmcp-appconfig-kv-delete | label | c4590a051c6ae6039785458f1bf710f783677a21dba075d3b0f9dd06d7152768 |
| tools | azmcp-appconfig-kv-delete | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-kv-delete | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-kv-delete | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-kv-delete | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-kv-delete | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-kv-delete | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-kv-delete | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-appconfig-kv-list | description | 8a8dd6367453dbe913a5f4debe8be119b42b2e130296e67ab91167e95e116920 |
| tools | azmcp-appconfig-kv-list | account-name | c10f3ab94cacd2abb4eb0c1ee63b40680a08ca041e8101522ea3ea61f90a5886 |
| tools | azmcp-appconfig-kv-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-kv-list | key | 8955b0b11b3f70e0c44cbb6e2af04577fc32d55d36ffa1cf4721a59ad3ad8945 |
| tools | azmcp-appconfig-kv-list | label | 5bc4107b9e33105ab57b8459605fede628646cc405f47fa166817beda4b0e5c1 |
| tools | azmcp-appconfig-kv-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-kv-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-kv-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-kv-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-kv-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-kv-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-kv-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-appconfig-kv-lock | description | 071167e01979fa1dcb577527b0ff619a29a526a08732bdc183cabf1129499967 |
| tools | azmcp-appconfig-kv-lock | account-name | c10f3ab94cacd2abb4eb0c1ee63b40680a08ca041e8101522ea3ea61f90a5886 |
| tools | azmcp-appconfig-kv-lock | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-kv-lock | key | 8c4e074c54aff330e5352d671a8b7f2d8efcc9e19786eac13d9ec3e2b4fe4d1d |
| tools | azmcp-appconfig-kv-lock | label | c4590a051c6ae6039785458f1bf710f783677a21dba075d3b0f9dd06d7152768 |
| tools | azmcp-appconfig-kv-lock | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-kv-lock | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-kv-lock | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-kv-lock | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-kv-lock | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-kv-lock | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-kv-lock | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-appconfig-kv-set | description | c8e93bc40c1c8f49421193ba40d2c2fa111f923d0e992716dfc12dd34205cfa3 |
| tools | azmcp-appconfig-kv-set | account-name | c10f3ab94cacd2abb4eb0c1ee63b40680a08ca041e8101522ea3ea61f90a5886 |
| tools | azmcp-appconfig-kv-set | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-kv-set | key | 8c4e074c54aff330e5352d671a8b7f2d8efcc9e19786eac13d9ec3e2b4fe4d1d |
| tools | azmcp-appconfig-kv-set | label | c4590a051c6ae6039785458f1bf710f783677a21dba075d3b0f9dd06d7152768 |
| tools | azmcp-appconfig-kv-set | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-kv-set | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-kv-set | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-kv-set | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-kv-set | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-kv-set | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-kv-set | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-appconfig-kv-set | value | 4201be1465e4500d603ebdf881197cd91fef48a731f1af056b2c5beee1e0cc55 |
| tools | azmcp-appconfig-kv-show | description | c04b9c30bee4c17d6c92843404597d57b80910971e102db1b531f4913f8473ef |
| tools | azmcp-appconfig-kv-show | account-name | c10f3ab94cacd2abb4eb0c1ee63b40680a08ca041e8101522ea3ea61f90a5886 |
| tools | azmcp-appconfig-kv-show | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-kv-show | key | 8c4e074c54aff330e5352d671a8b7f2d8efcc9e19786eac13d9ec3e2b4fe4d1d |
| tools | azmcp-appconfig-kv-show | label | c4590a051c6ae6039785458f1bf710f783677a21dba075d3b0f9dd06d7152768 |
| tools | azmcp-appconfig-kv-show | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-kv-show | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-kv-show | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-kv-show | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-kv-show | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-kv-show | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-kv-show | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-appconfig-kv-unlock | description | 228a49a38b019662d15a2836b5a59043be78a97393ff4accf87d397c2dcff501 |
| tools | azmcp-appconfig-kv-unlock | account-name | c10f3ab94cacd2abb4eb0c1ee63b40680a08ca041e8101522ea3ea61f90a5886 |
| tools | azmcp-appconfig-kv-unlock | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-appconfig-kv-unlock | key | 8c4e074c54aff330e5352d671a8b7f2d8efcc9e19786eac13d9ec3e2b4fe4d1d |
| tools | azmcp-appconfig-kv-unlock | label | c4590a051c6ae6039785458f1bf710f783677a21dba075d3b0f9dd06d7152768 |
| tools | azmcp-appconfig-kv-unlock | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-appconfig-kv-unlock | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-appconfig-kv-unlock | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-appconfig-kv-unlock | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-appconfig-kv-unlock | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-appconfig-kv-unlock | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-appconfig-kv-unlock | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-bestpractices-get | description | 8c375b1789afca09a0dd90d83f21dc760b7b9cda9e109c4ad00e864ea3b5e53c |
| tools | azmcp-cosmos-account-list | description | 078f8b26134fb25376825878f2aaed5522934d360ed4108501668ed1ba35a37c |
| tools | azmcp-cosmos-account-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-cosmos-account-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-cosmos-account-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-cosmos-account-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-cosmos-account-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-cosmos-account-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-cosmos-account-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-cosmos-account-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-cosmos-database-container-item-query | description | 56ac1d8d04fb7718bdcb53b6024e6e8e17c13503fc722cc7b536834b6a6d7e96 |
| tools | azmcp-cosmos-database-container-item-query | account-name | ee01daf0f900466933de3b55c007c40858f12f572c2e278bb1970a80529aa897 |
| tools | azmcp-cosmos-database-container-item-query | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-cosmos-database-container-item-query | container-name | a8ec2b83415884acb1c120fbd246ad08edc7db2bcc31e2503f9184fcede7dffd |
| tools | azmcp-cosmos-database-container-item-query | database-name | c00ac9b4d0927427689175967c4902912c1f7b6b96fd88da3317316bff2b4486 |
| tools | azmcp-cosmos-database-container-item-query | query | 086c1864461e306444361ad09b3675bd6af90c94cc0e881bc531e2cbcef8de33 |
| tools | azmcp-cosmos-database-container-item-query | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-cosmos-database-container-item-query | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-cosmos-database-container-item-query | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-cosmos-database-container-item-query | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-cosmos-database-container-item-query | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-cosmos-database-container-item-query | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-cosmos-database-container-item-query | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-cosmos-database-container-list | description | 9f814e4c92792974b9bfc3fca93b797925f9a346c36c59e5a94d908a145c7b1a |
| tools | azmcp-cosmos-database-container-list | account-name | ee01daf0f900466933de3b55c007c40858f12f572c2e278bb1970a80529aa897 |
| tools | azmcp-cosmos-database-container-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-cosmos-database-container-list | database-name | c00ac9b4d0927427689175967c4902912c1f7b6b96fd88da3317316bff2b4486 |
| tools | azmcp-cosmos-database-container-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-cosmos-database-container-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-cosmos-database-container-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-cosmos-database-container-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-cosmos-database-container-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-cosmos-database-container-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-cosmos-database-container-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-cosmos-database-list | description | c48e521464c49397f195157c4471c5139e8410dd5a3167241fc860290aa39eda |
| tools | azmcp-cosmos-database-list | account-name | ee01daf0f900466933de3b55c007c40858f12f572c2e278bb1970a80529aa897 |
| tools | azmcp-cosmos-database-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-cosmos-database-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-cosmos-database-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-cosmos-database-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-cosmos-database-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-cosmos-database-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-cosmos-database-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-cosmos-database-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-extension-az | description | 8b00ef720e58b5666469e17955f1e2e3510ccbe1809e9160d8e605691851d799 |
| tools | azmcp-extension-az | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-extension-az | command | a57f4665be1e3f0cad3b86d577bc21f18b6984e397dff4487f3e7f8642e396cc |
| tools | azmcp-extension-az | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-extension-az | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-extension-az | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-extension-az | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-extension-az | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-extension-az | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-extension-azd | description | af969a7a09372f3b7949159bc0a6fd0ce108ca158bef0fdce8d883522e210e05 |
| tools | azmcp-extension-azd | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-extension-azd | command | dc39e38f17cbd88088e460e1b1a09e77f5f0fde176bcb2cae8cd8646f041c5e8 |
| tools | azmcp-extension-azd | cwd | eaa7aec0d34ccbc548642b182091d63b76c46690482b1c2b57f56374620b45de |
| tools | azmcp-extension-azd | environment | 5e1107f4653aca9ff9027f55c67762d937fad45a4b4f6abc482c57d44bb262ee |
| tools | azmcp-extension-azd | learn | ba4683921970147a2c2d98a7a0162b25e2e492092a164928ea9c3ad518666a89 |
| tools | azmcp-extension-azd | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-extension-azd | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-extension-azd | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-extension-azd | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-extension-azd | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-extension-azd | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-group-list | description | fb9dff1fafd90c64e21ae7271a59d3180b6a62957b28bbd32b1afb9500789336 |
| tools | azmcp-group-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-group-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-group-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-group-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-group-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-group-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-group-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-group-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-keyvault-key-create | description | 3da33cf67d4b3d6bd00ba187ededf13814379af7d9e56e6ce69dc4ac02954c61 |
| tools | azmcp-keyvault-key-create | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-keyvault-key-create | key | a7007aaadef4878e33069c0f963339b30a2170f68dde188870026b89de2e1331 |
| tools | azmcp-keyvault-key-create | key-type | 86f4048ee2fec7d950f8f7aa35181ff127836bf48a16d23cb1b902f6ccc32353 |
| tools | azmcp-keyvault-key-create | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-keyvault-key-create | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-keyvault-key-create | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-keyvault-key-create | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-keyvault-key-create | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-keyvault-key-create | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-keyvault-key-create | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-keyvault-key-create | vault | b0e45fcc1caca303050bca7eeff027862ebc772108b0cd7a3122b0c97ce0507e |
| tools | azmcp-keyvault-key-get | description | 1f5e47221ee17056ee50ad95dd50e772bfaadc677d8c77eb2f49422346fe5354 |
| tools | azmcp-keyvault-key-get | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-keyvault-key-get | key | a7007aaadef4878e33069c0f963339b30a2170f68dde188870026b89de2e1331 |
| tools | azmcp-keyvault-key-get | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-keyvault-key-get | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-keyvault-key-get | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-keyvault-key-get | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-keyvault-key-get | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-keyvault-key-get | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-keyvault-key-get | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-keyvault-key-get | vault | b0e45fcc1caca303050bca7eeff027862ebc772108b0cd7a3122b0c97ce0507e |
| tools | azmcp-keyvault-key-list | description | 0082f31968a4439dd1e670befd1178b6f9eb227d720c953a5293b6901f50dc87 |
| tools | azmcp-keyvault-key-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-keyvault-key-list | include-managed | c71871a62f225669466656924c786dcbe4a0558452ea0b3395e5fe02d8c04e84 |
| tools | azmcp-keyvault-key-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-keyvault-key-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-keyvault-key-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-keyvault-key-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-keyvault-key-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-keyvault-key-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-keyvault-key-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-keyvault-key-list | vault | b0e45fcc1caca303050bca7eeff027862ebc772108b0cd7a3122b0c97ce0507e |
| tools | azmcp-kusto-cluster-get | description | 4c33c7dcfcfa8a0be517d20c5b46792589c5d5000f8bb22fd3b55b743d62f3d7 |
| tools | azmcp-kusto-cluster-get | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-cluster-get | cluster-name | ef33dc7535b7c4c93e2f55a1df93d3847c3f130b627b5018b93cd34350a37c36 |
| tools | azmcp-kusto-cluster-get | cluster-uri | 3efe174963e3404cd51803997d692e8abed8ba51a8e3a52b556434ee7908714f |
| tools | azmcp-kusto-cluster-get | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-cluster-get | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-cluster-get | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-cluster-get | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-cluster-get | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-cluster-get | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-cluster-get | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-kusto-cluster-list | description | ebbdf5c038531e638e82f849799208b889a7ea9f8abebe25d11aa5219a664b03 |
| tools | azmcp-kusto-cluster-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-cluster-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-cluster-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-cluster-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-cluster-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-cluster-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-cluster-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-cluster-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-kusto-database-list | description | eecbffc4d5f9f9f17330b432dc0f9d8c9e4e7632a0d71b2001788fdc23b9a258 |
| tools | azmcp-kusto-database-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-database-list | cluster-name | ef33dc7535b7c4c93e2f55a1df93d3847c3f130b627b5018b93cd34350a37c36 |
| tools | azmcp-kusto-database-list | cluster-uri | 3efe174963e3404cd51803997d692e8abed8ba51a8e3a52b556434ee7908714f |
| tools | azmcp-kusto-database-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-database-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-database-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-database-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-database-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-database-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-database-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-kusto-query | description | f6d0a608fd7ce2cf4b6949ac0d872a5e912545cbd3980add446d4605aaf92d4b |
| tools | azmcp-kusto-query | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-query | cluster-name | ef33dc7535b7c4c93e2f55a1df93d3847c3f130b627b5018b93cd34350a37c36 |
| tools | azmcp-kusto-query | cluster-uri | 3efe174963e3404cd51803997d692e8abed8ba51a8e3a52b556434ee7908714f |
| tools | azmcp-kusto-query | database-name | ef3fbd057e23d656d3862fe1d38f0fbad6265eb32872ebe4337c4f9768994843 |
| tools | azmcp-kusto-query | query | de719dc7d7271030cb59a6c8f34c5a1946e55023a3a3c093499fd3a672486190 |
| tools | azmcp-kusto-query | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-query | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-query | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-query | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-query | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-query | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-query | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-kusto-sample | description | 74a06d1cd42f2d1807f670f7ffabc6813f4cfe58624beaaa06b6e98c48e8c26c |
| tools | azmcp-kusto-sample | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-sample | cluster-name | ef33dc7535b7c4c93e2f55a1df93d3847c3f130b627b5018b93cd34350a37c36 |
| tools | azmcp-kusto-sample | cluster-uri | 3efe174963e3404cd51803997d692e8abed8ba51a8e3a52b556434ee7908714f |
| tools | azmcp-kusto-sample | database-name | ef3fbd057e23d656d3862fe1d38f0fbad6265eb32872ebe4337c4f9768994843 |
| tools | azmcp-kusto-sample | limit | 119ff216459c66197845afc04ac7935e7b3fc134c2a8df27cc7c4c1fbc488ce4 |
| tools | azmcp-kusto-sample | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-sample | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-sample | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-sample | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-sample | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-sample | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-sample | table-name | 4bf23992a9c1d9c26e97e4441e57657f402dcffdaa34480e41bfcc11dddd49d3 |
| tools | azmcp-kusto-sample | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-kusto-table-list | description | 7879f144ac070405d7e295987129aa9d1294c84bfff2b3dfc6fe78c412d4112c |
| tools | azmcp-kusto-table-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-table-list | cluster-name | ef33dc7535b7c4c93e2f55a1df93d3847c3f130b627b5018b93cd34350a37c36 |
| tools | azmcp-kusto-table-list | cluster-uri | 3efe174963e3404cd51803997d692e8abed8ba51a8e3a52b556434ee7908714f |
| tools | azmcp-kusto-table-list | database-name | ef3fbd057e23d656d3862fe1d38f0fbad6265eb32872ebe4337c4f9768994843 |
| tools | azmcp-kusto-table-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-table-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-table-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-table-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-table-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-table-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-table-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-kusto-table-schema | description | 98f8a7b8db09f711c29e7fffdf9475c4b0b1efbec8de746b78f2f8e438e79296 |
| tools | azmcp-kusto-table-schema | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-kusto-table-schema | cluster-name | ef33dc7535b7c4c93e2f55a1df93d3847c3f130b627b5018b93cd34350a37c36 |
| tools | azmcp-kusto-table-schema | cluster-uri | 3efe174963e3404cd51803997d692e8abed8ba51a8e3a52b556434ee7908714f |
| tools | azmcp-kusto-table-schema | database-name | ef3fbd057e23d656d3862fe1d38f0fbad6265eb32872ebe4337c4f9768994843 |
| tools | azmcp-kusto-table-schema | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-kusto-table-schema | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-kusto-table-schema | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-kusto-table-schema | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-kusto-table-schema | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-kusto-table-schema | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-kusto-table-schema | table-name | 4bf23992a9c1d9c26e97e4441e57657f402dcffdaa34480e41bfcc11dddd49d3 |
| tools | azmcp-kusto-table-schema | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | description | 34d0e548c74762f4863f573fea2b823674a0af21e528603ecd7ec27084d35bcc |
| tools | azmcp-monitor-healthmodels-entity-gethealth | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | entity | d292e515df3c4d72f5440e231d0a32acefc31918e459b4006ef140b8348c419a |
| tools | azmcp-monitor-healthmodels-entity-gethealth | model-name | 7e3db765a059df28befce7abddfaabd9227ec8d4fd0fe035c4ad21c9085ba4fe |
| tools | azmcp-monitor-healthmodels-entity-gethealth | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-monitor-healthmodels-entity-gethealth | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-monitor-healthmodels-entity-gethealth | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-monitor-healthmodels-entity-gethealth | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-monitor-log-query | description | b0b709f15e3a5391cd4c2f302339316a0a195b1cbe68d5496e52b88feb639242 |
| tools | azmcp-monitor-log-query | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-monitor-log-query | hours | 09b69ee451dd64b2f02cc15d47509f85290f8ceeec6073dbe297f4f604322b86 |
| tools | azmcp-monitor-log-query | limit | 119ff216459c66197845afc04ac7935e7b3fc134c2a8df27cc7c4c1fbc488ce4 |
| tools | azmcp-monitor-log-query | query | 1a400c0585b782111612ba20b92cc3df9dba0bc1f5f80d111261073d0b7a677c |
| tools | azmcp-monitor-log-query | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-monitor-log-query | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-monitor-log-query | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-monitor-log-query | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-monitor-log-query | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-monitor-log-query | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-monitor-log-query | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-monitor-log-query | table-name | 0126205563b1de836e8d59041095335e12525b2734e503596c23e69192e507ce |
| tools | azmcp-monitor-log-query | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-monitor-log-query | workspace | c2ec8665ed83e1d84c6071ba65b62229e49afbed66ffa2a1203931a0f5352876 |
| tools | azmcp-monitor-table-list | description | 2b2bf2195e6eb5c952eb6f018d1a0c7bd001c3f51abb773ec8283634a531b96e |
| tools | azmcp-monitor-table-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-monitor-table-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-monitor-table-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-monitor-table-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-monitor-table-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-monitor-table-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-monitor-table-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-monitor-table-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-monitor-table-list | table-type | daee9e4627a27061cbef42cdf53dfa6de8f462e0c9fabb5264b5812c19f0f962 |
| tools | azmcp-monitor-table-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-monitor-table-list | workspace | c2ec8665ed83e1d84c6071ba65b62229e49afbed66ffa2a1203931a0f5352876 |
| tools | azmcp-monitor-table-type-list | description | ec8b0b7fba17fdf046d59139bf7091b2dbe8133fd164c4e7a4810dfa91264322 |
| tools | azmcp-monitor-table-type-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-monitor-table-type-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-monitor-table-type-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-monitor-table-type-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-monitor-table-type-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-monitor-table-type-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-monitor-table-type-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-monitor-table-type-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-monitor-table-type-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-monitor-table-type-list | workspace | c2ec8665ed83e1d84c6071ba65b62229e49afbed66ffa2a1203931a0f5352876 |
| tools | azmcp-monitor-workspace-list | description | 202b1586c7fe99593fab179ccd5ad95576642d4040e8f2a7ddcf761d4f025e86 |
| tools | azmcp-monitor-workspace-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-monitor-workspace-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-monitor-workspace-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-monitor-workspace-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-monitor-workspace-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-monitor-workspace-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-monitor-workspace-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-monitor-workspace-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-database-list | description | b661612f557cf3cb5a2aa1d359392326e7d45cf72e2dfacec8f769b9905f8bb3 |
| tools | azmcp-postgres-database-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-database-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-database-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-database-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-database-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-database-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-database-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-database-list | server | 081c83072e47b45f29a9b0e77df133cb573f20af85ff27ef67c285b69208b670 |
| tools | azmcp-postgres-database-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-database-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-database-list | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-postgres-database-query | description | f349fd43ef364db8de8d9d53449751516df9cba15950daa824346c2089610499 |
| tools | azmcp-postgres-database-query | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-database-query | database | a7871320391eb0dfc8432fc9a6e13e20a68dedc844a031eb176629b567707d50 |
| tools | azmcp-postgres-database-query | query | 6c4cb6565a1ccd820bb2fa5740510c1bd776f2443e065419c0c2028ac7ec921e |
| tools | azmcp-postgres-database-query | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-database-query | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-database-query | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-database-query | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-database-query | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-database-query | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-database-query | server | 081c83072e47b45f29a9b0e77df133cb573f20af85ff27ef67c285b69208b670 |
| tools | azmcp-postgres-database-query | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-database-query | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-database-query | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-postgres-server-config | description | 579f3ef3eea8704699c693b03160638e6b0458045fd079061158b511f4500d23 |
| tools | azmcp-postgres-server-config | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-server-config | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-server-config | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-server-config | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-server-config | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-server-config | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-server-config | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-server-config | server | 081c83072e47b45f29a9b0e77df133cb573f20af85ff27ef67c285b69208b670 |
| tools | azmcp-postgres-server-config | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-server-config | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-server-config | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-postgres-server-list | description | f34c6a43d32417ca61724453eb823306a214245a75a193c762c25fca289ea5a8 |
| tools | azmcp-postgres-server-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-server-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-server-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-server-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-server-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-server-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-server-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-server-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-server-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-server-list | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-postgres-server-param | description | 31ea1afcff9e3d365301278cbffba59ec6fd6a9a6dad1beeacad16133366b944 |
| tools | azmcp-postgres-server-param | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-server-param | param | 9e14e190f6bb0abf464fbc35c7a01ce75b6fcce3f2b7b4acbe185c98f558e7e9 |
| tools | azmcp-postgres-server-param | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-server-param | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-server-param | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-server-param | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-server-param | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-server-param | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-server-param | server | 081c83072e47b45f29a9b0e77df133cb573f20af85ff27ef67c285b69208b670 |
| tools | azmcp-postgres-server-param | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-server-param | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-server-param | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-postgres-table-list | description | 605ae72e63e4a013cb180527b10699754cd9550f4f224da6bf9f98e0098dfe5a |
| tools | azmcp-postgres-table-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-table-list | database | a7871320391eb0dfc8432fc9a6e13e20a68dedc844a031eb176629b567707d50 |
| tools | azmcp-postgres-table-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-table-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-table-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-table-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-table-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-table-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-table-list | server | 081c83072e47b45f29a9b0e77df133cb573f20af85ff27ef67c285b69208b670 |
| tools | azmcp-postgres-table-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-table-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-table-list | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-postgres-table-schema | description | 8f2a7e8f55931d73c4d9fd227180257baec8eddc818a1f46f16731fc7fb68b45 |
| tools | azmcp-postgres-table-schema | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-postgres-table-schema | database | a7871320391eb0dfc8432fc9a6e13e20a68dedc844a031eb176629b567707d50 |
| tools | azmcp-postgres-table-schema | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-postgres-table-schema | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-postgres-table-schema | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-postgres-table-schema | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-postgres-table-schema | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-postgres-table-schema | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-postgres-table-schema | server | 081c83072e47b45f29a9b0e77df133cb573f20af85ff27ef67c285b69208b670 |
| tools | azmcp-postgres-table-schema | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-postgres-table-schema | table | 1e6cda74960bfc2ce3b47c67c4eb36b188eff89cda536e22317953a53cc151ab |
| tools | azmcp-postgres-table-schema | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-postgres-table-schema | user-name | 8558e70206f542938a570dbe039e84b65e3e3471e3273948e2b49c34cad565dc |
| tools | azmcp-redis-cache-accesspolicy-list | description | 4872a3962906743ad0283ff7910bb02baffdb38f00102b5d859a968c9879cb5c |
| tools | azmcp-redis-cache-accesspolicy-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-redis-cache-accesspolicy-list | cache | 088f0cb4ddb6cc669107fa1ec55c0b12fd4d1777d89cfb0081d133f0e3f1a6bc |
| tools | azmcp-redis-cache-accesspolicy-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-redis-cache-accesspolicy-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-redis-cache-accesspolicy-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-redis-cache-accesspolicy-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-redis-cache-accesspolicy-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-redis-cache-accesspolicy-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-redis-cache-accesspolicy-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-redis-cache-accesspolicy-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-redis-cache-list | description | ad115f45657fc96c9f8f17fd2e554375d7e6346ac7599b958738464cd7a2cc7e |
| tools | azmcp-redis-cache-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-redis-cache-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-redis-cache-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-redis-cache-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-redis-cache-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-redis-cache-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-redis-cache-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-redis-cache-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-redis-cluster-database-list | description | c403ee78fdba361211b473ddf5336148733be8bf1528400741e051799ae5f184 |
| tools | azmcp-redis-cluster-database-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-redis-cluster-database-list | cluster | dc413fa4365acbb47099f0ec34217b0cb88058a1594c10168bcce4c6e8dd774b |
| tools | azmcp-redis-cluster-database-list | resource-group | b80f31cc79351fcd9d4d70aab6e22bf0246e86d2dedac99e75b3fb5caf29ce2e |
| tools | azmcp-redis-cluster-database-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-redis-cluster-database-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-redis-cluster-database-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-redis-cluster-database-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-redis-cluster-database-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-redis-cluster-database-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-redis-cluster-database-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-redis-cluster-list | description | cfe953c3eae603845a06820e229b967f8f38b4b24ba3032aad4b85e95ee8684c |
| tools | azmcp-redis-cluster-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-redis-cluster-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-redis-cluster-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-redis-cluster-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-redis-cluster-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-redis-cluster-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-redis-cluster-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-redis-cluster-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-search-index-describe | description | 614dfe19567ef5c94dd740657103cd1d154682c47a53dc4a64468306d4b49cf4 |
| tools | azmcp-search-index-describe | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-search-index-describe | index-name | b3cab56347c95e9f6e008d626c011478aebe0a3fb5b26fe1f3049e3002b64dc0 |
| tools | azmcp-search-index-describe | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-search-index-describe | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-search-index-describe | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-search-index-describe | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-search-index-describe | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-search-index-describe | service-name | a5fbfb7027a7a6361e0c450ff05d8ab73862a00b3283421e4f16059facaf33e1 |
| tools | azmcp-search-index-describe | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-search-index-list | description | c48c90095b03990a51306ae23eef338769fb0cd50433a06e8d47cc8ee2f884ff |
| tools | azmcp-search-index-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-search-index-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-search-index-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-search-index-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-search-index-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-search-index-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-search-index-list | service-name | a5fbfb7027a7a6361e0c450ff05d8ab73862a00b3283421e4f16059facaf33e1 |
| tools | azmcp-search-index-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-search-index-query | description | d32e41dfc40af8386084da282d2facc51f2550f667fd412b80665090db863769 |
| tools | azmcp-search-index-query | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-search-index-query | index-name | b3cab56347c95e9f6e008d626c011478aebe0a3fb5b26fe1f3049e3002b64dc0 |
| tools | azmcp-search-index-query | query | 246cd351180c22b456f10534f60fe9a5fb3fcbb3afb7d90284d3953c415b67c8 |
| tools | azmcp-search-index-query | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-search-index-query | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-search-index-query | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-search-index-query | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-search-index-query | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-search-index-query | service-name | a5fbfb7027a7a6361e0c450ff05d8ab73862a00b3283421e4f16059facaf33e1 |
| tools | azmcp-search-index-query | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-search-service-list | description | c123790f5d7d84672a892b43fd66c931a4c7972b24df5d7154ad937c60417851 |
| tools | azmcp-search-service-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-search-service-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-search-service-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-search-service-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-search-service-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-search-service-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-search-service-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-search-service-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-servicebus-queue-details | description | d1d5f5a9582b1ac0159ce295dbe9e7ebc85e63160e3b4aaaa174d2c463a7e69f |
| tools | azmcp-servicebus-queue-details | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-servicebus-queue-details | namespace | 86974d13ebb1ed18ea162ce156c6f7a857fd7c40ce1fdad75038c423be80f2a5 |
| tools | azmcp-servicebus-queue-details | queue-name | 7723e1a7e6f47cd107d95fa68c5460ef9f3308649b0df676fd63bd131b95d606 |
| tools | azmcp-servicebus-queue-details | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-servicebus-queue-details | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-servicebus-queue-details | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-servicebus-queue-details | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-servicebus-queue-details | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-servicebus-queue-details | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-servicebus-queue-details | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-servicebus-topic-details | description | 05dd5d926c4fcfa83c7a813805ff020f2ababeaaa28c7a69fb657361f764dc69 |
| tools | azmcp-servicebus-topic-details | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-servicebus-topic-details | namespace | 86974d13ebb1ed18ea162ce156c6f7a857fd7c40ce1fdad75038c423be80f2a5 |
| tools | azmcp-servicebus-topic-details | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-servicebus-topic-details | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-servicebus-topic-details | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-servicebus-topic-details | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-servicebus-topic-details | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-servicebus-topic-details | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-servicebus-topic-details | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-servicebus-topic-details | topic-name | 6d7ee4a4a4aff9cb8e0c9f0f8e2d6813f3476d86d660705bce48dd2502d90098 |
| tools | azmcp-servicebus-topic-subscription-details | description | d95b0398114741486c23cb9f436bca5d71b3261abafceee94c1582e247cfb3dd |
| tools | azmcp-servicebus-topic-subscription-details | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-servicebus-topic-subscription-details | namespace | 86974d13ebb1ed18ea162ce156c6f7a857fd7c40ce1fdad75038c423be80f2a5 |
| tools | azmcp-servicebus-topic-subscription-details | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-servicebus-topic-subscription-details | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-servicebus-topic-subscription-details | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-servicebus-topic-subscription-details | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-servicebus-topic-subscription-details | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-servicebus-topic-subscription-details | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-servicebus-topic-subscription-details | subscription-name | a2794883b5b896ad053147d1953e267649d6a9d12e0e213b29d8adc8f3367564 |
| tools | azmcp-servicebus-topic-subscription-details | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-servicebus-topic-subscription-details | topic-name | 6d7ee4a4a4aff9cb8e0c9f0f8e2d6813f3476d86d660705bce48dd2502d90098 |
| tools | azmcp-storage-account-list | description | 9ebbc6b627a3f7f7a8f96351d9c90fdd5caa5271034f21c8edf5806f04955fa0 |
| tools | azmcp-storage-account-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-storage-account-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-storage-account-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-storage-account-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-storage-account-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-storage-account-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-storage-account-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-storage-account-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-storage-blob-container-details | description | fa715ef87e2edaebcef6ddc424a4be7c154b775910eb5bbef3cb3da89d24925f |
| tools | azmcp-storage-blob-container-details | account-name | 227b4ec8ed8a5bb8230433e7fced9e57d50cac1097d7695015fcc7673f020a88 |
| tools | azmcp-storage-blob-container-details | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-storage-blob-container-details | container-name | 670e9f1cc408836d513409071e950a8f6f2f4717787060db6c0a050bf5426b15 |
| tools | azmcp-storage-blob-container-details | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-storage-blob-container-details | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-storage-blob-container-details | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-storage-blob-container-details | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-storage-blob-container-details | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-storage-blob-container-details | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-storage-blob-container-details | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-storage-blob-container-list | description | e93bde2e0314bcae33ea775044973ad3d67757a7052611088a46579c04b20bad |
| tools | azmcp-storage-blob-container-list | account-name | 227b4ec8ed8a5bb8230433e7fced9e57d50cac1097d7695015fcc7673f020a88 |
| tools | azmcp-storage-blob-container-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-storage-blob-container-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-storage-blob-container-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-storage-blob-container-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-storage-blob-container-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-storage-blob-container-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-storage-blob-container-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-storage-blob-container-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-storage-blob-list | description | 1a316f60b9cbc74c13d0a5bb0c06a1b18d82082368eb4ab8d19a54efb22c18e4 |
| tools | azmcp-storage-blob-list | account-name | 227b4ec8ed8a5bb8230433e7fced9e57d50cac1097d7695015fcc7673f020a88 |
| tools | azmcp-storage-blob-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-storage-blob-list | container-name | 670e9f1cc408836d513409071e950a8f6f2f4717787060db6c0a050bf5426b15 |
| tools | azmcp-storage-blob-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-storage-blob-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-storage-blob-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-storage-blob-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-storage-blob-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-storage-blob-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-storage-blob-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-storage-table-list | description | 7e3df660a698ce5dab5e6f7d9accfa22dabd494fbc7e4855345d58225f7983e0 |
| tools | azmcp-storage-table-list | account-name | 227b4ec8ed8a5bb8230433e7fced9e57d50cac1097d7695015fcc7673f020a88 |
| tools | azmcp-storage-table-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-storage-table-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-storage-table-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-storage-table-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-storage-table-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-storage-table-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-storage-table-list | subscription | 373a04236ef3ba7a3a3adae9df8843caaa3407acb9b4082c8c50df63ab250986 |
| tools | azmcp-storage-table-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |
| tools | azmcp-subscription-list | description | db43814263914f31564bf2956f13403c57f81f5eb424fb23dd32c25754495e16 |
| tools | azmcp-subscription-list | auth-method | 6b38a9b5aa2d956f3122318e595da1b40032a4e8a608bec803a4a7708de94a29 |
| tools | azmcp-subscription-list | retry-delay | 503778449ebee4a1d55543ce84adb81f114a74c4b884c52ab5cad8c37a16b5ce |
| tools | azmcp-subscription-list | retry-max-delay | edc1d5b43a081ef10441939db6ebf81e75959ed6caf20ef4667ee444a344cb88 |
| tools | azmcp-subscription-list | retry-max-retries | b3a426c91bf8196b69cbf27fd2f9d142f69a98ce22c161f836085155abd50bc2 |
| tools | azmcp-subscription-list | retry-mode | 0c0abe1418f822a219e2eda99dfb831e6c4646b6798f76f6b922ff4c71fa1084 |
| tools | azmcp-subscription-list | retry-network-timeout | 82fc44f55f68a744172de35fc9f8901090bf8bf16382265f67471bd7779344d6 |
| tools | azmcp-subscription-list | tenant | 9c091a9ea4a24c1d92a0cb2eeede1152286798ea53cc94ddff128a261dbe9df4 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
