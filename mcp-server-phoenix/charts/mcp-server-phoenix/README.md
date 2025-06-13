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


# What is mcp-server-phoenix?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-phoenix/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-phoenix/2.1.10?logo=docker&logoColor=fff&label=2.1.10)](https://hub.docker.com/r/acuvity/mcp-server-phoenix)
[![PyPI](https://img.shields.io/badge/2.1.10-3775A9?logo=pypi&logoColor=fff&label=@arizeai/phoenix-mcp)](https://github.com/Arize-ai/phoenix/tree/HEAD/js/packages/phoenix-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-phoenix/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-phoenix&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22PHOENIX_BASE_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-phoenix%3A2.1.10%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Inspect traces, manage prompts, curate datasets, and run experiments using Arize Phoenix.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @arizeai/phoenix-mcp original [sources](https://github.com/Arize-ai/phoenix/tree/HEAD/js/packages/phoenix-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-phoenix/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-phoenix/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-phoenix/charts/mcp-server-phoenix/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @arizeai/phoenix-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-phoenix/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ oss@arize.com ](https://github.com/Arize-ai/phoenix/tree/HEAD/js/packages/phoenix-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @arizeai/phoenix-mcp ](https://github.com/Arize-ai/phoenix/tree/HEAD/js/packages/phoenix-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @arizeai/phoenix-mcp ](https://github.com/Arize-ai/phoenix/tree/HEAD/js/packages/phoenix-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-phoenix/charts/mcp-server-phoenix)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-phoenix/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-2.1.10`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-phoenix:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-phoenix:1.0.0-2.1.10`

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

**Optional Secrets**:
  - `PHOENIX_API_KEY` secret to be set as secrets.PHOENIX_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `PHOENIX_BASE_URL` environment variable to be set by env.PHOENIX_BASE_URL

# How to install


Install will helm

```console
helm install mcp-server-phoenix oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-phoenix oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-phoenix
```

From there your MCP server mcp-server-phoenix will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-phoenix` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-phoenix
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-phoenix` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-phoenix oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-phoenix oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-phoenix oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-phoenix oci://docker.io/acuvity/mcp-server-phoenix --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (16)
<details>
<summary>list-prompts</summary>

**Description**:

```
Get a list of all the prompts.

Prompts (templates, prompt templates) are versioned templates for input messages to an LLM.
Each prompt includes both the input messages, but also the model and invocation parameters
to use when generating outputs.

Returns a list of prompt objects with their IDs, names, and descriptions.

Example usage: 
  List all available prompts

Expected return: 
  Array of prompt objects with metadata. 
  Example:  [{
      "name": "article-summarizer",
      "description": "Summarizes an article into concise bullet points",
      "source_prompt_id": null,
      "id": "promptid1234"
  }]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | not set | No
</details>
<details>
<summary>get-latest-prompt</summary>

**Description**:

```
Get the latest version of a prompt. Returns the prompt version with its template, model configuration, and invocation parameters.

Example usage: 
  Get the latest version of a prompt named 'article-summarizer'

Expected return: 
  Prompt version object with template and configuration. 
  Example: {
    "description": "Initial version",
    "model_provider": "OPENAI",
    "model_name": "gpt-3.5-turbo",
    "template": {
      "type": "chat",
      "messages": [
        {
          "role": "system",
          "content": "You are an expert summarizer. Create clear, concise bullet points highlighting the key information."
        },
        {
          "role": "user",
          "content": "Please summarize the following {{topic}} article:

{{article}}"
        }
      ]
    },
    "template_type": "CHAT",
    "template_format": "MUSTACHE",
    "invocation_parameters": {
      "type": "openai",
      "openai": {}
    },
    "id": "promptversionid1234"
  }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt_identifier | string | not set | Yes
</details>
<details>
<summary>get-prompt-by-identifier</summary>

**Description**:

```
Get a prompt's latest version by its identifier (name or ID). Returns the prompt version with its template, model configuration, and invocation parameters.

Example usage: 
  Get the latest version of a prompt with name 'article-summarizer'

Expected return: 
  Prompt version object with template and configuration. 
    Example: {
      "description": "Initial version",
      "model_provider": "OPENAI",
      "model_name": "gpt-3.5-turbo",
      "template": {
        "type": "chat",
        "messages": [
          {
            "role": "system",
            "content": "You are an expert summarizer. Create clear, concise bullet points highlighting the key information."
          },
          {
            "role": "user",
            "content": "Please summarize the following {{topic}} article:

{{article}}"
          }
        ]
      },
      "template_type": "CHAT",
      "template_format": "MUSTACHE",
      "invocation_parameters": {
        "type": "openai",
        "openai": {}
      },
      "id": "promptversionid1234"
    }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt_identifier | string | not set | Yes
</details>
<details>
<summary>get-prompt-version</summary>

**Description**:

```
Get a specific version of a prompt using its version ID. Returns the prompt version with its template, model configuration, and invocation parameters.

Example usage: 
  Get a specific prompt version with ID 'promptversionid1234'

Expected return: 
  Prompt version object with template and configuration. 
  Example: {
    "description": "Initial version",
    "model_provider": "OPENAI",
    "model_name": "gpt-3.5-turbo",
    "template": {
      "type": "chat",
      "messages": [
        {
          "role": "system",
          "content": "You are an expert summarizer. Create clear, concise bullet points highlighting the key information."
        },
        {
          "role": "user",
          "content": "Please summarize the following {{topic}} article:

{{article}}"
        }
      ]
    },
    "template_type": "CHAT",
    "template_format": "MUSTACHE",
    "invocation_parameters": {
      "type": "openai",
      "openai": {}
    },
    "id": "promptversionid1234"
  }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt_version_id | string | not set | Yes
</details>
<details>
<summary>upsert-prompt</summary>

**Description**:

```
Create or update a prompt with its template and configuration. Creates a new prompt and its initial version with specified model settings.

Example usage: 
  Create a new prompt named 'email_generator' with a template for generating emails

Expected return: 
  A confirmation message of successful prompt creation
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | No
| model_name | string | not set | No
| model_provider | string | not set | No
| name | string | not set | Yes
| temperature | number | not set | No
| template | string | not set | Yes
</details>
<details>
<summary>list-prompt-versions</summary>

**Description**:

```
Get a list of all versions for a specific prompt. Returns versions with pagination support.

Example usage: 
  List all versions of a prompt named 'article-summarizer'

Expected return: 
  Array of prompt version objects with IDs and configuration. 
  Example: [
    {
      "description": "Initial version",
      "model_provider": "OPENAI",
      "model_name": "gpt-3.5-turbo",
      "template": {
        "type": "chat",
        "messages": [
          {
            "role": "system",
            "content": "You are an expert summarizer. Create clear, concise bullet points highlighting the key information."
          },
          {
            "role": "user",
            "content": "Please summarize the following {{topic}} article:

{{article}}"
          }
        ]
      },
      "template_type": "CHAT",
      "template_format": "MUSTACHE",
      "invocation_parameters": {
        "type": "openai",
        "openai": {}
      },
      "id": "promptversionid1234"
    }
  ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | not set | No
| prompt_identifier | string | not set | Yes
</details>
<details>
<summary>get-prompt-version-by-tag</summary>

**Description**:

```
Get a prompt version by its tag name. Returns the prompt version with its template, model configuration, and invocation parameters.

Example usage: 
  Get the 'production' tagged version of prompt 'article-summarizer'

Expected return: 
  Prompt version object with template and configuration. 
  Example: {
      "description": "Initial version",
      "model_provider": "OPENAI",
      "model_name": "gpt-3.5-turbo",
      "template": {
        "type": "chat",
        "messages": [
          {
            "role": "system",
            "content": "You are an expert summarizer. Create clear, concise bullet points highlighting the key information."
          },
          {
            "role": "user",
            "content": "Please summarize the following {{topic}} article:

{{article}}"
          }
        ]
      },
      "template_type": "CHAT",
      "template_format": "MUSTACHE",
      "invocation_parameters": {
        "type": "openai",
        "openai": {}
      },
      "id": "promptversionid1234"
    }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| prompt_identifier | string | not set | Yes
| tag_name | string | not set | Yes
</details>
<details>
<summary>list-prompt-version-tags</summary>

**Description**:

```
Get a list of all tags for a specific prompt version. Returns tag objects with pagination support.

Example usage: 
  List all tags associated with prompt version 'promptversionid1234'

Expected return: 
  Array of tag objects with names and IDs. 
  Example: [
    {
      "name": "staging",
      "description": "The version deployed to staging",
      "id": "promptversionid1234"
    },
    {
      "name": "development",
      "description": "The version deployed for development",
      "id": "promptversionid1234"
    }
  ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | not set | No
| prompt_version_id | string | not set | Yes
</details>
<details>
<summary>add-prompt-version-tag</summary>

**Description**:

```
Add a tag to a specific prompt version. The operation returns no content on success (204 status code).

Example usage: 
  Tag prompt version 'promptversionid1234' with the name 'production'

Expected return: 
  Confirmation message of successful tag addition
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | No
| name | string | not set | Yes
| prompt_version_id | string | not set | Yes
</details>
<details>
<summary>list-experiments-for-dataset</summary>

**Description**:

```
Get a list of all the experiments run on a given dataset.

Experiments are collections of experiment runs, each experiment run corresponds to a single 
dataset example. The dataset example is passed to an implied `task` which in turn 
produces an output.

Example usage:
  Show me all the experiments I've run on dataset RGF0YXNldDox

Expected return:
  Array of experiment objects with metadata. 
  Example: [
    {
      "id": "experimentid1234",
      "dataset_id": "datasetid1234",
      "dataset_version_id": "datasetversionid1234",
      "repetitions": 1,
      "metadata": {},
      "project_name": "Experiment-abc123",
      "created_at": "YYYY-MM-DDTHH:mm:ssZ",
      "updated_at": "YYYY-MM-DDTHH:mm:ssZ"
    }
  ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dataset_id | string | not set | Yes
</details>
<details>
<summary>get-experiment-by-id</summary>

**Description**:

```
Get an experiment by its ID.

The tool returns experiment metadata in the first content block and a JSON object with the 
experiment data in the second. The experiment data contains both the results of each 
experiment run and the annotations made by an evaluator to score or label the results, 
for example, comparing the output of an experiment run to the expected output from the 
dataset example.

Example usage:
  Show me the experiment results for experiment RXhwZXJpbWVudDo4

Expected return:
  Object containing experiment metadata and results.
  Example: {
    "metadata": {
      "id": "experimentid1234",
      "dataset_id": "datasetid1234",
      "dataset_version_id": "datasetversionid1234",
      "repetitions": 1,
      "metadata": {},
      "project_name": "Experiment-abc123",
      "created_at": "YYYY-MM-DDTHH:mm:ssZ",
      "updated_at": "YYYY-MM-DDTHH:mm:ssZ"
    },
    "experimentResult": [
      {
        "example_id": "exampleid1234",
        "repetition_number": 0,
        "input": "Sample input text",
        "reference_output": "Expected output text",
        "output": "Actual output text",
        "error": null,
        "latency_ms": 1000,
        "start_time": "2025-03-20T12:00:00Z",
        "end_time": "2025-03-20T12:00:01Z",
        "trace_id": "trace-123",
        "prompt_token_count": 10,
        "completion_token_count": 20,
        "annotations": [
          {
            "name": "quality",
            "annotator_kind": "HUMAN",
            "label": "good",
            "score": 0.9,
            "explanation": "Output matches expected format",
            "trace_id": "trace-456",
            "error": null,
            "metadata": {},
            "start_time": "YYYY-MM-DDTHH:mm:ssZ",
            "end_time": "YYYY-MM-DDTHH:mm:ssZ"
          }
        ]
      }
    ]
  }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| experiment_id | string | not set | Yes
</details>
<details>
<summary>list-datasets</summary>

**Description**:

```
Get a list of all datasets.

Datasets are collections of 'dataset examples' that each example includes an input, 
(expected) output, and optional metadata. They are primarily used as inputs for experiments.

Example usage:
  Show me all available datasets

Expected return:
  Array of dataset objects with metadata.
  Example: [
    {
      "id": "RGF0YXNldDox",
      "name": "my-dataset",
      "description": "A dataset for testing",
      "metadata": {},
      "created_at": "2024-03-20T12:00:00Z",
      "updated_at": "2024-03-20T12:00:00Z"
    }
  ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | number | not set | No
</details>
<details>
<summary>get-dataset-examples</summary>

**Description**:

```
Get examples from a dataset.

Dataset examples are an array of objects that each include an input, 
(expected) output, and optional metadata. These examples are typically used to represent 
input to an application or model (e.g. prompt template variables, a code file, or image) 
and used to test or benchmark changes.

Example usage:
  Show me all examples from dataset RGF0YXNldDox

Expected return:
  Object containing dataset ID, version ID, and array of examples.
  Example: {
    "dataset_id": "datasetid1234",
    "version_id": "datasetversionid1234",
    "examples": [
      {
        "id": "exampleid1234",
        "input": {
          "text": "Sample input text"
        },
        "output": {
          "text": "Expected output text"
        },
        "metadata": {},
        "updated_at": "YYYY-MM-DDTHH:mm:ssZ"
      }
    ]
  }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasetId | string | not set | Yes
</details>
<details>
<summary>get-dataset-experiments</summary>

**Description**:

```
List experiments run on a dataset.

Example usage:
  Show me all experiments run on dataset RGF0YXNldDox

Expected return:
  Array of experiment objects with metadata.
  Example: [
    {
      "id": "experimentid1234",
      "dataset_id": "datasetid1234",
      "dataset_version_id": "datasetversionid1234",
      "repetitions": 1,
      "metadata": {},
      "project_name": "Experiment-abc123",
      "created_at": "YYYY-MM-DDTHH:mm:ssZ",
      "updated_at": "YYYY-MM-DDTHH:mm:ssZ"
    }
  ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasetId | string | not set | Yes
</details>
<details>
<summary>add-dataset-examples</summary>

**Description**:

```
Add examples to an existing dataset.

This tool adds one or more examples to an existing dataset. Each example includes an input,
output, and metadata. The metadata will automatically include information indicating that
these examples were synthetically generated via MCP. When calling this tool, check existing
examples using the "get-dataset-examples" tool to ensure that you are not adding duplicate
examples and following existing patterns for how data should be structured.

Example usage:
  Look at the analyze "my-dataset" and augment them with new examples to cover relevant edge cases

Expected return:
  Confirmation of successful addition of examples to the dataset.
  Example: {
    "dataset_name": "my-dataset",
    "message": "Successfully added examples to dataset"
  }
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasetName | string | not set | Yes
| examples | array | not set | Yes
</details>
<details>
<summary>list-projects</summary>

**Description**:

```
Get a list of all projects.

Projects are containers for organizing traces, spans, and other observability data. 
Each project has a unique name and can contain traces from different applications or experiments.

Example usage:
  Show me all available projects

Expected return:
  Array of project objects with metadata.
  Example: [
    {
      "id": "UHJvamVjdDox",
      "name": "default",
      "description": "Default project for traces"
    },
    {
      "id": "UHJvamVjdDoy", 
      "name": "my-experiment",
      "description": "Project for my ML experiment"
    }
  ]
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cursor | string | not set | No
| includeExperimentProjects | boolean | not set | No
| limit | number | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add-dataset-examples | description | e155da7f8230fe5b1bade7bb57b5a4bc07e900fc79ca68494744930fb1d5b819 |
| tools | add-prompt-version-tag | description | 5d04bf6a283ba42bfc6ac36f1d3da4ee143e236c56a303c7b9d20de4136bffd4 |
| tools | get-dataset-examples | description | d4152fd8d561e6fa1d1751cf8826aede27e1673a456c220405339aceefa9b536 |
| tools | get-dataset-experiments | description | a085efadd710053c90b9d5799f11121c70e293338c9f2480d3ad89f06e30c669 |
| tools | get-experiment-by-id | description | abbb9c44646c3e37c530486d4b2fff7dbe79540136bbaa3feba7251cc578c9d1 |
| tools | get-latest-prompt | description | 5d55c6403be695217770fb621b2adf4478a6d4daa6087ed00138a1afc6312253 |
| tools | get-prompt-by-identifier | description | 1a0323812d5c03b3354e35c6a268edbf17cc915cd37a0592f34c53f77b0c8e5d |
| tools | get-prompt-version | description | 41310657a5adff08eebf484525733aaf62bf1954977bb8dbaef41d54db7c2d9b |
| tools | get-prompt-version-by-tag | description | 425133c04c59768f6f21421781fb706057bf59dc2270ad24654334328083712a |
| tools | list-datasets | description | 08059e461d7a8d15235ecd8a680443fa05750a4ff4afe83eda532a413121334f |
| tools | list-experiments-for-dataset | description | 8d25f7a21bcfd8f2ce6dd1d5d8bc29065cd7eb8e1afb6084a51a09c58469cc42 |
| tools | list-projects | description | 13c5d94123bdffa6f6acaeb17412fef1ef9494cd0d0e1ec318250b7cd36dd9f1 |
| tools | list-prompt-version-tags | description | 58d24038d7140bcbfd6e693f6b53ead1cfb21e0c7d3ff1112a4faf9bb4e3e69a |
| tools | list-prompt-versions | description | 39c60f1f54d4f7f7286485ac6515d1aaaa81bc84eb901abc574e8e21d99e3f05 |
| tools | list-prompts | description | 999cd435fea53746496c6e325a943cadbfc797633226f801738897c11d6eacdc |
| tools | upsert-prompt | description | bb147c1de19cb25c7f6aea4fccd60de50a6b3d730c4329b3f8b61c2486e19ac0 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
