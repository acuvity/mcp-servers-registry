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


# What is mcp-server-browserstack?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-browserstack/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-browserstack/1.1.6?logo=docker&logoColor=fff&label=1.1.6)](https://hub.docker.com/r/acuvity/mcp-server-browserstack)
[![PyPI](https://img.shields.io/badge/1.1.6-3775A9?logo=pypi&logoColor=fff&label=@browserstack/mcp-server)](https://github.com/browserstack/mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-browserstack/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-browserstack&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22BROWSERSTACK_USERNAME%22%2C%22-e%22%2C%22BROWSERSTACK_ACCESS_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-browserstack%3A1.1.6%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Access BrowserStack's Test Platform to debug, write and fix tests, do accessibility testing.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @browserstack/mcp-server original [sources](https://github.com/browserstack/mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-browserstack/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/charts/mcp-server-browserstack/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @browserstack/mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/browserstack/mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @browserstack/mcp-server ](https://github.com/browserstack/mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @browserstack/mcp-server ](https://github.com/browserstack/mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/charts/mcp-server-browserstack)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-browserstack/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.1.6`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-browserstack:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-browserstack:1.0.0-1.1.6`

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
  - `BROWSERSTACK_ACCESS_KEY` secret to be set as secrets.BROWSERSTACK_ACCESS_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `BROWSERSTACK_USERNAME` environment variable to be set by env.BROWSERSTACK_USERNAME

# How to install


Install will helm

```console
helm install mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-browserstack
```

From there your MCP server mcp-server-browserstack will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-browserstack` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-browserstack
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-browserstack` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-browserstack oci://docker.io/acuvity/mcp-server-browserstack --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (18)
<details>
<summary>runTestsOnBrowserStack</summary>

**Description**:

```
Use this tool to get instructions for running tests on BrowserStack.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| desiredPlatforms | array | The platforms the user wants to test on. Always ask this to the user, do not try to infer this. | Yes
| detectedBrowserAutomationFramework | string | The automation framework configured in the project. Example: 'playwright', 'selenium' | Yes
| detectedLanguage | string | The programming language used in the project. Example: 'nodejs', 'python' | Yes
| detectedTestingFramework | string | The testing framework used in the project. Example: 'jest', 'pytest' | Yes
</details>
<details>
<summary>runAppLiveSession</summary>

**Description**:

```
Use this tool when user wants to manually check their app on a particular mobile device using BrowserStack's cloud infrastructure. Can be used to debug crashes, slow performance, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appPath | string | The path to the .ipa or .apk file to install on the device. Always ask the user for the app path, do not assume it. | Yes
| desiredPhone | string | The full name of the device to run the app on. Example: 'iPhone 12 Pro' or 'Samsung Galaxy S20' or 'Google Pixel 6'. Always ask the user for the device they want to use, do not assume it.  | Yes
| desiredPlatform | string | Which platform to run on, examples: 'android', 'ios'. Set this based on the app path provided. | Yes
| desiredPlatformVersion | string | Specifies the platform version to run the app on. For example, use '12.0' for Android or '16.0' for iOS. If the user says 'latest', 'newest', or similar, normalize it to 'latest'. Likewise, convert terms like 'earliest' or 'oldest' to 'oldest'. | Yes
</details>
<details>
<summary>runBrowserLiveSession</summary>

**Description**:

```
Launch a BrowserStack Live session (desktop or mobile).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| desiredBrowser | string | Browser for desktop (Chrome, IE, Firefox, Safari, Edge) | Yes
| desiredBrowserVersion | string | Browser version for desktop (e.g. '133.2', 'latest'). If the user says 'latest', 'newest', or similar, normalize it to 'latest'. Likewise, convert terms like 'earliest' or 'oldest' to 'oldest'. | No
| desiredDevice | string | Device name for mobile | No
| desiredOS | string | Desktop OS ('Windows' or 'OS X') or mobile OS ('android','ios','winphone') | Yes
| desiredOSVersion | string | The OS version must be specified as a version number (e.g., '10', '14.0') or as a keyword such as 'latest' or 'oldest'. Normalize variations like 'newest' or 'most recent' to 'latest', and terms like 'earliest' or 'first' to 'oldest'. For macOS, version names (e.g., 'Sequoia') must be used instead of numeric versions. | Yes
| desiredURL | string | The URL to test | Yes
| platformType | string | Must be 'desktop' or 'mobile' | Yes
</details>
<details>
<summary>startAccessibilityScan</summary>

**Description**:

```
Start an accessibility scan via BrowserStack and retrieve a local CSV report path.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Name of the accessibility scan | Yes
| pageURL | string | The URL to scan for accessibility issues | Yes
</details>
<details>
<summary>createProjectOrFolder</summary>

**Description**:

```
Create a project and/or folder in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| folder_description | string | Description for the new folder. | No
| folder_name | string | Name of the folder to create. | No
| parent_id | number | Parent folder ID; if omitted, folder is created at root. | No
| project_description | string | Description for the new project. | No
| project_identifier | string | Existing project identifier to use for folder creation. | No
| project_name | string | Name of the project to create. | No
</details>
<details>
<summary>createTestCase</summary>

**Description**:

```
Use this tool to create a test case in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| custom_fields | object | Map of custom field names to values. | No
| description | string | Brief description of the test case. | No
| folder_id | string | The ID of the folder within the project where the test case should be created. If not provided, ask the user if they would like to create a new folder using the createProjectOrFolder tool. | Yes
| issue_tracker | object | not set | No
| issues | array | List of the linked Jira, Asana or Azure issues ID's. This should be strictly in array format not the string of json. | No
| name | string | Name of the test case. | Yes
| owner | string | Email of the test case owner. | No
| preconditions | string | Any preconditions (HTML allowed). | No
| project_identifier | string | The ID of the BrowserStack project where the test case should be created. If no project identifier is provided, ask the user if they would like to create a new project using the createProjectOrFolder tool. | Yes
| tags | array | Tags to attach to the test case. This should be strictly in array format not the string of json | No
| test_case_steps | array | List of steps and expected results. | Yes
</details>
<details>
<summary>listTestCases</summary>

**Description**:

```
List test cases in a project with optional filters (status, priority, custom fields, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| case_type | string | Comma-separated list of case types (e.g. functional,regression). | No
| folder_id | string | If provided, only return cases in this folder. | No
| p | number | Page number. | No
| priority | string | Comma-separated list of priorities (e.g. critical,medium,low). | No
| project_identifier | string | Identifier of the project to fetch test cases from. This id starts with a PR- and is followed by a number. | Yes
</details>
<details>
<summary>createTestRun</summary>

**Description**:

```
Create a test run in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project in which to create the test run. | Yes
| test_run | object | not set | Yes
</details>
<details>
<summary>listTestRuns</summary>

**Description**:

```
List test runs in a project with optional filters (date ranges, assignee, state, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project to fetch test runs from (usually starts with PR-). | Yes
| run_state | string | Return all test runs with this state (comma-separated) | No
</details>
<details>
<summary>updateTestRun</summary>

**Description**:

```
Update a test run in BrowserStack Test Management.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project (Starts with 'PR-') | Yes
| test_run | object | not set | Yes
| test_run_id | string | Test run identifier (e.g., TR-678) | Yes
</details>
<details>
<summary>addTestResult</summary>

**Description**:

```
Add a test result to a specific test run via BrowserStack Test Management API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| project_identifier | string | Identifier of the project (Starts with 'PR-') | Yes
| test_case_id | string | Identifier of the test case, e.g., 'TC-13'. | Yes
| test_result | object | not set | Yes
| test_run_id | string | Identifier of the test run (e.g., TR-678) | Yes
</details>
<details>
<summary>uploadProductRequirementFile</summary>

**Description**:

```
Upload files (e.g., PDRs, PDFs) to BrowserStack Test Management and retrieve a file mapping ID. This is utilized for generating test cases from files and is part of the Test Case Generator AI Agent in BrowserStack.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | Full path to the file that should be uploaded | Yes
| project_identifier | string | ID of the project where the file should be uploaded. Do not assume it, always ask user for it. | Yes
</details>
<details>
<summary>createTestCasesFromFile</summary>

**Description**:

```
Generate test cases from a file in BrowserStack Test Management using the Test Case Generator AI Agent.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| documentId | string | Internal document identifier | Yes
| folderId | string | BrowserStack folder ID | Yes
| projectReferenceId | string | The BrowserStack project reference ID is a unique identifier found in the project URL within the BrowserStack Test Management Platform. This ID is also returned by the Upload Document tool. | Yes
</details>
<details>
<summary>createLCASteps</summary>

**Description**:

```
Generate Low Code Automation (LCA) steps for a test case in BrowserStack Test Management using the Low Code Automation Agent.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| base_url | string | Base URL for the test (e.g., 'google.com') | Yes
| credentials | object | Optional credentials for authentication. Extract from the test case details if provided in it. This is required for the test cases which require authentication. | No
| local_enabled | boolean | Whether local testing is enabled | No
| project_identifier | string | ID of the project (Starts with 'PR-') | Yes
| test_case_details | object | Test case details including steps | Yes
| test_case_identifier | string | Identifier of the test case (e.g., 'TC-12345') | Yes
| test_name | string | Name of the test | Yes
| wait_for_completion | boolean | Whether to wait for LCA build completion (default: true) | No
</details>
<details>
<summary>takeAppScreenshot</summary>

**Description**:

```
Use this tool to take a screenshot of an app running on a BrowserStack device. This is useful for visual testing and debugging.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appPath | string | The path to the .apk or .ipa file. Required for app installation. | Yes
| desiredPhone | string | The full name of the device to run the app on. Example: 'iPhone 12 Pro' or 'Samsung Galaxy S20'. Always ask the user for the device they want to use. | Yes
| desiredPlatform | string | Platform to run the app on. Either 'android' or 'ios'. | Yes
| desiredPlatformVersion | string | The platform version to run the app on. Use 'latest' or 'oldest' for dynamic resolution. | Yes
</details>
<details>
<summary>getFailureLogs</summary>

**Description**:

```
Fetch various types of logs from a BrowserStack session. Supports both automate and app-automate sessions.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| buildId | string | Required only when sessionType is 'app-automate'. If sessionType is 'app-automate', always ask the user to provide the build ID before proceeding. | No
| logTypes | array | The types of logs to fetch. | Yes
| sessionId | string | The BrowserStack session ID. Must be explicitly provided by the user. | Yes
| sessionType | string | Type of BrowserStack session. Must be explicitly provided by the user. | Yes
</details>
<details>
<summary>fetchAutomationScreenshots</summary>

**Description**:

```
Fetch and process screenshots from a BrowserStack Automate session
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | The BrowserStack session ID to fetch screenshots from | Yes
| sessionType | string | Type of BrowserStack session | Yes
</details>
<details>
<summary>fetchSelfHealedSelectors</summary>

**Description**:

```
Retrieves AI-generated, self-healed selectors for a BrowserStack Automate session to resolve flaky tests caused by dynamic DOM changes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| sessionId | string | The session ID of the test run | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | addTestResult | description | cc2109318c2f2f439c042097bd218c02441beaba6763a50f777b45ff1f9ee532 |
| tools | addTestResult | project_identifier | 6c62157d98f3a3579f77d8d19b65b8566108202987b5120eb459dc7319bbc86b |
| tools | addTestResult | test_case_id | a0bf11cfea84003e21cf57d8e5a471b50f6cfe1bf5fd67277ad3371d3d0479fc |
| tools | addTestResult | test_run_id | dd6796e0611b2656380232abc144a619b1b74bf20bf3b22fb68f235335dfdbf0 |
| tools | createLCASteps | description | 3ab042e167faacf57685147c666092ef03afc65cce6455acbe3dbecea9e8df66 |
| tools | createLCASteps | base_url | 4c5c642f1b70dc39ffe77d1ff4f903802e7ad4ae5c745223e7d8adf159bb685e |
| tools | createLCASteps | credentials | 87b52bc90c9e6098cfa860d99603f9accf589b41839c1ce331cec252c4df0da1 |
| tools | createLCASteps | local_enabled | 72ae8ded36dc31c6da9f1be9871fe67a4ce4767445f45185a2fb4861840978c4 |
| tools | createLCASteps | project_identifier | 26c8444cca04215f8340f893afc14c7c808bff9b881341c42e724b506a104db7 |
| tools | createLCASteps | test_case_details | eb4b90368e172f31e2dd69a93a80235568e0f0f6e5eafce7d40c15133e20b5e5 |
| tools | createLCASteps | test_case_identifier | 40532c4b1b9e68fb66279c2c5e06193bcd3f18ca45fcdadcd4897cec61510f32 |
| tools | createLCASteps | test_name | 35a63342426914953ce6b18c0b896a975ae546642bb25ee9bd5818bf938111ef |
| tools | createLCASteps | wait_for_completion | 4513ed516d341581480e189e81c47994b7ec23f4de6669537dcd7932c4d3af58 |
| tools | createProjectOrFolder | description | b3e3165694a6aabfb78167fe03a224a0088fbe3dfdfc2bab6478618d2dc4cde1 |
| tools | createProjectOrFolder | folder_description | efbe2753d3d1783e698cc3c5b1c770b5b721645b91d5200aa05af31bdd87942a |
| tools | createProjectOrFolder | folder_name | 1fce48673414a3b22395d547a7e50ac225a819b36c63c91d117be6f3a2208d5b |
| tools | createProjectOrFolder | parent_id | de57230349700c0b401e5aa7981ae08b72e9de2435c39b21618c5018f3b07f0e |
| tools | createProjectOrFolder | project_description | 507f3ff1b6a036de2a0b311b1ea9d392b050f14639d9d6e4d7ac7fc4b02b593e |
| tools | createProjectOrFolder | project_identifier | bf678e9cd7bbe3bfd864e0ea804a12d70d509e66be1a51d2ce56d21936db79c8 |
| tools | createProjectOrFolder | project_name | c071c9fbe7923c941268d56c79fb0ac12e37edf18c7b68099b9c3490dbb291ef |
| tools | createTestCase | description | f79753f1cbee77f8ec15ef0b0772234e89d65c986bd6b82be0d5333d6ec5388e |
| tools | createTestCase | custom_fields | 427a06f888b38e7210021bc459b99e7d5604fd42aa1b7ed81a99c4b7750510fb |
| tools | createTestCase | description | abf1b1eee12721a67b652f322487678db003d4bdf031cb0bad27b9deb94725b0 |
| tools | createTestCase | folder_id | a4ba636aa7f77cf6f2c0be168e1902bd0e2ba5645d4292f5ce3e96acca72cb2d |
| tools | createTestCase | issues | f618b3a688e1acfcfc72f7039e6293a82d3827f2bccd0007ebe28fc87d0bee62 |
| tools | createTestCase | name | 1ac73c91df75b429d366d02ba589f8912ab3a4fd6bdf1713a20d305e1017a7a7 |
| tools | createTestCase | owner | c60877252d5b1105e70647d2787af274ba801f51a0878b547b5fc9e2e53d0042 |
| tools | createTestCase | preconditions | 5e7d050fee674a09daeb0382bd426da764d6abbfbf8397a4d7332f4ead5a5d7f |
| tools | createTestCase | project_identifier | 60f040a16f19c3ebe8151ded87b86b7b6df17cd58f7eae9cf86d0e99ae86a451 |
| tools | createTestCase | tags | 5129ca1d1104d94f1052e948d9de68d4f647ba0162d4002d8564a6d3a71f5351 |
| tools | createTestCase | test_case_steps | 4a3f566047517e2e251aeb01cf987444bde104c20afa9d7f4ece89cd844717d1 |
| tools | createTestCasesFromFile | description | 0df41168f9e6612d4cafff96da9deb7b5aba5359fe9af65f93f5e340bad4fe33 |
| tools | createTestCasesFromFile | documentId | 6bc6f69713ac4766430d61e7c818a20347c9c754e1c45eef8344768cf9221fa2 |
| tools | createTestCasesFromFile | folderId | 16c1037533e9511a8e361f5f362aa06d5313f5456d295d90363fed5522422ac1 |
| tools | createTestCasesFromFile | projectReferenceId | 6feb12c1b9b037157845cb6137b840d5da4eeb31ef3521aa5a66cb205a97a86f |
| tools | createTestRun | description | 1b5b97bcc39017fa094f26eb56806082d82f687b7a1efa49aad565ba42df580f |
| tools | createTestRun | project_identifier | 958319b90d7375b48dde33224fa823fd5b91d21ba1e2a8adc2437fcc15650186 |
| tools | fetchAutomationScreenshots | description | 077697d1de82318656d57ab7020073e07d0483261ef18c23d0eb8dd90b93c43e |
| tools | fetchAutomationScreenshots | sessionId | 4a1a35e557a51bbcc1ee1da90be86fe09b2049104723f90c8c5ccc33940da414 |
| tools | fetchAutomationScreenshots | sessionType | 7db47afe5cb3150197365c91b30448e31eaa6b95a2ba9ae4a28fcdc553b44a10 |
| tools | fetchSelfHealedSelectors | description | 90260e3fb5a7f53c23ffd7718635ccc4d2b12f173fb2855c730087ab40a4a768 |
| tools | fetchSelfHealedSelectors | sessionId | faf61902787c70137dfbc121511ed7d9b7e27502bfdf5d1125f6efd5d3031a58 |
| tools | getFailureLogs | description | 8c144b60db6fac766d3330c216f56f6c893adfd32841a14f2412b25367d0758c |
| tools | getFailureLogs | buildId | ebc09c81c8f54829422701526f8ada1e09682f4026bc3ea12d7641541e8f7035 |
| tools | getFailureLogs | logTypes | 0051404276165eb04388eee6d8b28f4e97dc5e08af7b0ce1481388311c2a13c1 |
| tools | getFailureLogs | sessionId | 9c2bf31f67fa9193f1b87daa076709c6568a01fca182d2b3e92f6c04f9535655 |
| tools | getFailureLogs | sessionType | 76cbd444d004d58836eee26668d37d1e460ea90afb29b691bdb92e1017820b9a |
| tools | listTestCases | description | 3d88760fe6762812c4279aa496a673bf02cb3ff4664b555362e5d0890ba5520a |
| tools | listTestCases | case_type | aa032f5d744848a7b7347bd0c53259f585994a7f1c7988702a37bbb95aad16bb |
| tools | listTestCases | folder_id | f53650e6ad50a57020553beb3db2c0d5671c8bddfcee542c5ba684eab7ee8f93 |
| tools | listTestCases | p | a745ce57e9292ff9dbb392ddadbf3bf815e25da6d2402079cc6cde192ff1df19 |
| tools | listTestCases | priority | 8ac604f4c95f6ad728d7bf47873d8ce4c68d939b05d487e352d991231fdb5d2a |
| tools | listTestCases | project_identifier | 3ecb09b3a6128c8d676b805165762527ed12a633d5175b6c2fba8a2be293d3b5 |
| tools | listTestRuns | description | 9deada7b36628686538fab266b3955e84eb3f95c2cadb7b84641510d2f985c40 |
| tools | listTestRuns | project_identifier | 6dd0a1641a0f0a8d1e3470f5fe14389a314d648ef4ac828c82eacf1f311819a8 |
| tools | listTestRuns | run_state | 2b4c984fc93afed3efceb0b41af2429aa7cd9d4e2baba18bdd57310f870eeb98 |
| tools | runAppLiveSession | description | ae3d94db08fe1cd4697ec588ee8e5961460bb62a91f7be76313a33f526996895 |
| tools | runAppLiveSession | appPath | 4fbc294738a75df01476e73e83ac97ae2e66f3d4470e5d04196cded374e674c7 |
| tools | runAppLiveSession | desiredPhone | c7be751f195a60a46fc6831fdb6c2291d1f418385121310479140ee45d287b25 |
| tools | runAppLiveSession | desiredPlatform | bf34e3e4a3d9557a0c4c8365c4d84c3dae56a69d2633e09a4c73bf2ceefaab69 |
| tools | runAppLiveSession | desiredPlatformVersion | a6ec6d3f7fb930f84566a347db05834ccfb042d0275afbffe67740880f448a1a |
| tools | runBrowserLiveSession | description | 15d7be2d1e8aadf64d968aa1badd1000879f571e236d3dddb6ed1e5f2bc5e33b |
| tools | runBrowserLiveSession | desiredBrowser | d089ac36240f5ff99b74e8f423a09a4a1d8cba042aaa1863bb1757eef775d26e |
| tools | runBrowserLiveSession | desiredBrowserVersion | 45106d6349643b6fde55bb0a47da6621906c0483e7e999079744b60fb2fbbc93 |
| tools | runBrowserLiveSession | desiredDevice | f5a0aff6efde9298b7d97134f88decc76ced12643074ef2799346e49e14832b7 |
| tools | runBrowserLiveSession | desiredOS | 03c7fb4ad446d553a5938aded0ebcceded249d2b3513c2628928f30642113de9 |
| tools | runBrowserLiveSession | desiredOSVersion | 2cb723b7a5534fa4dbf8768d0875779d688735b25779d95bd674d174cd328ec1 |
| tools | runBrowserLiveSession | desiredURL | b85465cef9c8da1546ccd5e2e962887a60ade65e35e5be82ca6d4c6ae63884f3 |
| tools | runBrowserLiveSession | platformType | 77536906f9cb2b3e6ab78109451efddb605ac051931011ad0db2004bf5320539 |
| tools | runTestsOnBrowserStack | description | 475f62c3969e1060fb936f8398b780cb5f713e9de99bca9cb00b24488f418c30 |
| tools | runTestsOnBrowserStack | desiredPlatforms | 681270cbcac1cce333e6026103a2042b90987f3227c648cb180afcfa5b360f8f |
| tools | runTestsOnBrowserStack | detectedBrowserAutomationFramework | d608ae51766a4ab0852a8a0526a5ae7ecd1f2df6c3017052d51875f9d6cd1c96 |
| tools | runTestsOnBrowserStack | detectedLanguage | bbc97bcd2aa36a106b9043a873898777cf56428e0ba5a40b53f4275a06a1c6ed |
| tools | runTestsOnBrowserStack | detectedTestingFramework | b8e44a5be64633d381132cf247b0504defe89a8aa724f58f7b92b2e9220e14fc |
| tools | startAccessibilityScan | description | 5c3a401cff7df900c2acc02fbb949568de1a52ba74e808767f896860fd47bbc2 |
| tools | startAccessibilityScan | name | 097628d59fa3cd14c2579fd01f92e133fab7e8f6ba709753610c19c22285a434 |
| tools | startAccessibilityScan | pageURL | 06094cfdd3276e53fb4b6d5ea609f635218b8ee5d458a2fdba645acac5b3dce3 |
| tools | takeAppScreenshot | description | 687870513f1c9e1627fc5c9cc4babe9d75b6388ef9e0554431378d09922ea90e |
| tools | takeAppScreenshot | appPath | 4f244b2c83f0c036b1e9e8e0a7b826e8c7ca36e15dd1abcdd227d1c1743c670b |
| tools | takeAppScreenshot | desiredPhone | 24f7659c53a043411bea6f4dd8b36e444e3808dc87183bf69e04d99952c28bef |
| tools | takeAppScreenshot | desiredPlatform | ac7dc0b131ce083fad560491bb400a57390ad1dda8ceab9b6338fdb80eca9859 |
| tools | takeAppScreenshot | desiredPlatformVersion | c985a19675f103fa387b9d6018be0ba68a7353a278381aa15ba7a136a57d0d0a |
| tools | updateTestRun | description | 06db6fa0b90d2ed6c5fc138cbdb6180b87a4b65295a9bbed275f00d8e8e7df57 |
| tools | updateTestRun | project_identifier | 6c62157d98f3a3579f77d8d19b65b8566108202987b5120eb459dc7319bbc86b |
| tools | updateTestRun | test_run_id | a4407ffe7486e68f2a54c7d5d9dd09272b8b5d391b2752a7253a17a27566f0bc |
| tools | uploadProductRequirementFile | description | c0e8abbdabcf86d9bec13d3dd7dcebda09971e966ace78dcb953addcc67fdda7 |
| tools | uploadProductRequirementFile | file_path | cf3b49711d7d77df068e036bd1e21dc8c2affd35eba4c7c6a40cbdcb9da52225 |
| tools | uploadProductRequirementFile | project_identifier | 44c537cceb4e4c13b69082b4bee57b363930d6bcaca13b4fc17de4502a268cc8 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
