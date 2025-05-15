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


# What is mcp-server-openapi-schema?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-openapi-schema/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-openapi-schema/0.0.1?logo=docker&logoColor=fff&label=0.0.1)](https://hub.docker.com/r/acuvity/mcp-server-openapi-schema)
[![PyPI](https://img.shields.io/badge/0.0.1-3775A9?logo=pypi&logoColor=fff&label=mcp-openapi-schema)](https://github.com/hannesj/mcp-openapi-schema)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-openapi-schema&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22SCHEMA_PATH%22%2C%22docker.io%2Facuvity%2Fmcp-server-openapi-schema%3A0.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Exposes OpenAPI schemas for LLMs to explore and understand APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-openapi-schema original [sources](https://github.com/hannesj/mcp-openapi-schema).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-openapi-schema/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/charts/mcp-server-openapi-schema/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-openapi-schema run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/charts/mcp-server-openapi-schema#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Hannes Junnila ](https://github.com/hannesj/mcp-openapi-schema) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-openapi-schema ](https://github.com/hannesj/mcp-openapi-schema)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-openapi-schema ](https://github.com/hannesj/mcp-openapi-schema)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/charts/mcp-server-openapi-schema)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-openapi-schema/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.0.1`

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

**Mandatory Environment variables**:
  - `SCHEMA_PATH` environment variable to be set by env.SCHEMA_PATH

# How to install


Install will helm

```console
helm install mcp-server-openapi-schema oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-openapi-schema oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-openapi-schema
```

From there your MCP server mcp-server-openapi-schema will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-openapi-schema` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-openapi-schema
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
  mcp-server-scope: native
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-openapi-schema` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-openapi-schema oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-openapi-schema oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-openapi-schema oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-openapi-schema oci://docker.io/acuvity/mcp-server-openapi-schema --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (10)
<details>
<summary>list-endpoints</summary>

**Description**:

```
Lists all API paths and their HTTP methods with summaries, organized by path
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get-endpoint</summary>

**Description**:

```
Gets detailed information about a specific API endpoint
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| method | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>get-request-body</summary>

**Description**:

```
Gets the request body schema for a specific endpoint
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| method | string | not set | Yes
| path | string | not set | Yes
</details>
<details>
<summary>get-response-schema</summary>

**Description**:

```
Gets the response schema for a specific endpoint, method, and status code
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| method | string | not set | Yes
| path | string | not set | Yes
| statusCode | string | not set | No
</details>
<details>
<summary>get-path-parameters</summary>

**Description**:

```
Gets the parameters for a specific path
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| method | string | not set | No
| path | string | not set | Yes
</details>
<details>
<summary>list-components</summary>

**Description**:

```
Lists all schema components (schemas, parameters, responses, etc.)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get-component</summary>

**Description**:

```
Gets detailed definition for a specific component
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | Component name | Yes
| type | string | Component type (e.g., schemas, parameters, responses) | Yes
</details>
<details>
<summary>list-security-schemes</summary>

**Description**:

```
Lists all available security schemes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get-examples</summary>

**Description**:

```
Gets examples for a specific component or endpoint
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| componentName | string | Component name (required for component examples) | No
| componentType | string | Component type (required for component examples) | No
| method | string | HTTP method (required for request/response examples) | No
| path | string | API path (required for request/response examples) | No
| statusCode | string | Status code (for response examples) | No
| type | string | Type of example to retrieve | Yes
</details>
<details>
<summary>search-schema</summary>

**Description**:

```
Searches across paths, operations, and schemas
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| pattern | string | Search pattern (case-insensitive) | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | get-component | description | de5f1f4cc9a08536a8727ef26311cebd1802fc4a05a9f20a00786e64d982df10 |
| tools | get-component | name | f953ec3c72207ff39906c47776fea74871179cf482a4e66df52f946c660e9063 |
| tools | get-component | type | c281fd18fa0a537f4827e26de07d8772619fcb4554a61d81699c9f57942acc01 |
| tools | get-endpoint | description | 575735d4d397846e9a935f13813a52960d936f14b8c1c9a9f8a906008e5c5b1f |
| tools | get-examples | description | 493b22116573c92e440ef22ccdbc630ec8a00e296ff753173bd31c9db2717407 |
| tools | get-examples | componentName | 98fc7fd684c284d0928364dabd1749d312e850062a1fd16bebd391384e2a9de6 |
| tools | get-examples | componentType | 26469b14044022cd40ae9b2b6545596295a2fe323e192c4e27b55962ebdac5c2 |
| tools | get-examples | method | e0d6f9ccc1532c13b2edd9299b4c768cdf8deeba86f6a9012eb3b694f301a98e |
| tools | get-examples | path | e4ba98fe5868bbf0638f1e3689d4e86e7821f7ddaa7180d36ae9c6cbbfc0fe74 |
| tools | get-examples | statusCode | 63299ccee6e031fede9f4168cb004355c0d652046f30e0c67131fa5b74871ddf |
| tools | get-examples | type | 0a72f70f39a5fa6f9577ca5f9c12cfd7b32ca7febc246a37025e22af6888221e |
| tools | get-path-parameters | description | 128e00993eb20e9e81be36d25502a3e2afade0b1df81e0e29bc4299145ccb510 |
| tools | get-request-body | description | 3827a17430a19e595e85a67d8bf9b3a3f69178c80ce9243028e6955ee4fe5180 |
| tools | get-response-schema | description | 52b17641ff2092a9bc6f9324dbc48d8e6d76c4be1abec6765f782e5b67d1f643 |
| tools | list-components | description | 71c73446a0290795290e1d4f4ca88a6e3965136aad7567c2c36ad9c5bb3a4da3 |
| tools | list-endpoints | description | 00ad8ff0da02483b475a1080cbdfce8b5e4c3d3c56225085c5904243143bef59 |
| tools | list-security-schemes | description | eaa419ff4f4f69d5d06c21d4e118d0bcd97c3754ac2f3e920cda1710ee48f9d5 |
| tools | search-schema | description | debe4fe3e88326f30db34bbffa6ca2da45b1e744408809ace9274000d48a0d4d |
| tools | search-schema | pattern | 2d1b094841bace6b9c645422bc157b2e8de381fe25b5eb95adac5922952972b7 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
