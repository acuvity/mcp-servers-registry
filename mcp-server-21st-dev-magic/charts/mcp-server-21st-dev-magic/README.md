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


# What is mcp-server-21st-dev-magic?

[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-21st-dev-magic/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-21st-dev-magic/0.0.47?logo=docker&logoColor=fff&label=0.0.47)](https://hub.docker.com/r/acuvity/mcp-server-21st-dev-magic)
[![PyPI](https://img.shields.io/badge/0.0.47-3775A9?logo=pypi&logoColor=fff&label=@21st-dev/magic)](https://github.com/21st-dev/magic-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-21st-dev-magic&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22TWENTY_FIRST_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-21st-dev-magic%3A0.0.47%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Create crafted UI components inspired by the best 21st.dev design engineers.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @21st-dev/magic original [sources](https://github.com/21st-dev/magic-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-21st-dev-magic/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/charts/mcp-server-21st-dev-magic/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @21st-dev/magic run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/charts/mcp-server-21st-dev-magic#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ serafim@21st.dev ](https://github.com/21st-dev/magic-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @21st-dev/magic ](https://github.com/21st-dev/magic-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @21st-dev/magic ](https://github.com/21st-dev/magic-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/charts/mcp-server-21st-dev-magic)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-21st-dev-magic/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.0.47`

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
  - `TWENTY_FIRST_API_KEY` secret to be set as secrets.TWENTY_FIRST_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-21st-dev-magic
```

From there your MCP server mcp-server-21st-dev-magic will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-21st-dev-magic` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-21st-dev-magic
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-21st-dev-magic` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-21st-dev-magic oci://docker.io/acuvity/mcp-server-21st-dev-magic --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (4)
<details>
<summary>21st_magic_component_builder</summary>

**Description**:

```

"Use this tool when the user requests a new UI component—e.g., mentions /ui, /21 /21st, or asks for a button, input, dialog, table, form, banner, card, or other React component.
This tool ONLY returns the text snippet for that UI component. 
After calling this tool, you must edit or add files to integrate the snippet into the codebase."

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| absolutePathToCurrentFile | string | Absolute path to the current file to which we want to apply changes | Yes
| absolutePathToProjectDirectory | string | Absolute path to the project root directory | Yes
| context | string | Extract additional context about what should be done to create a ui component/page based on the user's message, search query, and conversation history, files. Don't halucinate and be on point. | Yes
| message | string | Full users message | Yes
| searchQuery | string | Generate a search query for 21st.dev (library for searching UI components) to find a UI component that matches the user's message. Must be a two-four words max or phrase | Yes
</details>
<details>
<summary>logo_search</summary>

**Description**:

```

Search and return logos in specified format (JSX, TSX, SVG).
Supports single and multiple logo searches with category filtering.
Can return logos in different themes (light/dark) if available.

When to use this tool:
1. When user types "/logo" command (e.g., "/logo GitHub")
2. When user asks to add a company logo that's not in the local project

Example queries:
- Single company: ["discord"]
- Multiple companies: ["discord", "github", "slack"]
- Specific brand: ["microsoft office"]
- Command style: "/logo GitHub" -> ["github"]
- Request style: "Add Discord logo to the project" -> ["discord"]

Format options:
- TSX: Returns TypeScript React component
- JSX: Returns JavaScript React component
- SVG: Returns raw SVG markup

Each result includes:
- Component name (e.g., DiscordIcon)
- Component code
- Import instructions

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| format | string | Output format | Yes
| queries | array | List of company names to search for logos | Yes
</details>
<details>
<summary>21st_magic_component_inspiration</summary>

**Description**:

```

"Use this tool when the user wants to see component, get inspiration, or /21st fetch data and previews from 21st.dev. This tool returns the JSON data of matching components without generating new code. This tool ONLY returns the text snippet for that UI component. 
After calling this tool, you must edit or add files to integrate the snippet into the codebase."

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | Full users message | Yes
| searchQuery | string | Search query for 21st.dev (library for searching UI components) to find a UI component that matches the user's message. Must be a two-four words max or phrase | Yes
</details>
<details>
<summary>21st_magic_component_refiner</summary>

**Description**:

```

"Use this tool when the user requests to re-design/refine/improve current UI component with /ui or /21 commands, 
or when context is about improving, or refining UI for a React component or molecule (NOT for big pages).
This tool improves UI of components and returns redesigned version of the component and instructions on how to implement it."

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| absolutePathToRefiningFile | string | Absolute path to the file that needs to be refined | Yes
| context | string | Extract the specific UI elements and aspects that need improvement based on user messages, code, and conversation history. Identify exactly which components (buttons, forms, modals, etc.) the user is referring to and what aspects (styling, layout, responsiveness, etc.) they want to enhance. Do not include generic improvements - focus only on what the user explicitly mentions or what can be reasonably inferred from the available context. If nothing specific is mentioned or you cannot determine what needs improvement, return an empty string. | Yes
| userMessage | string | Full user's message about UI refinement | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | 21st_magic_component_builder | description | 011e0e5db60e77a06a3fd5063614b7b2b93ced2925663e8168cac8b0c6d7ae66 |
| tools | 21st_magic_component_builder | absolutePathToCurrentFile | 450130593147c19a97f2a5f0ed209a5f0b84dd8e70b7b27b62400d4ef9957a91 |
| tools | 21st_magic_component_builder | absolutePathToProjectDirectory | 6303e9e4a0b12ff5e2a097fe5f9abcbdb1ed49ec8ef42ad6fb24134ed64dc822 |
| tools | 21st_magic_component_builder | context | 512f11c1d32d3e983da308c65118d7b61486c0c73385701d20c8249f8b0cb47f |
| tools | 21st_magic_component_builder | message | 48cb03af6caea4c4c7719fdf6a43a50db0542485c3ba341a28532ef756da1652 |
| tools | 21st_magic_component_builder | searchQuery | eb695e76137317ae4778f099cfa2f0940f955b1f6fb88c5b3043e782d826b9e3 |
| tools | 21st_magic_component_inspiration | description | 3226eb3548d20e699204369a805c8e1181d3b51002d6539c0236998ec2aff33e |
| tools | 21st_magic_component_inspiration | message | 48cb03af6caea4c4c7719fdf6a43a50db0542485c3ba341a28532ef756da1652 |
| tools | 21st_magic_component_inspiration | searchQuery | fbc79e6c9c705ce4f5b8022da56323f221687b2af5d4b29478cfb72c10e0e597 |
| tools | 21st_magic_component_refiner | description | d7cd82ff345c5062c305ce6152af693a5a934c66cc7a30e0e3051d95dec2452b |
| tools | 21st_magic_component_refiner | absolutePathToRefiningFile | 35ad0e28bb9a3f39b6ef4e75caa8205ac8d06fd0d3ed51c563b5748863ec1868 |
| tools | 21st_magic_component_refiner | context | c2d8d152ce6971bcd011ba571ca71577c33831002a0cd7a05ff97b02befffab4 |
| tools | 21st_magic_component_refiner | userMessage | e6d673475625348fc2c01a43379d8688a94ad59bf976643844a160f78aaf92f6 |
| tools | logo_search | description | 4b660e35f86c0c855f48e7ec46c370e9d07f43f9908672506816aa795dd3f5c1 |
| tools | logo_search | format | 93c53d3745136c4e4e142811cdff560c8dfb4b9c4c875b7a8687dda559f688e1 |
| tools | logo_search | queries | 09c2780a768a860722317a6121664d0c3efbde797a7bf492acec147afb8b89e0 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
