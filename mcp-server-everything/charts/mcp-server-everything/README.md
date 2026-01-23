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


# What is mcp-server-everything?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-everything/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-everything/2026.1.14?logo=docker&logoColor=fff&label=2026.1.14)](https://hub.docker.com/r/acuvity/mcp-server-everything)
[![PyPI](https://img.shields.io/badge/2026.1.14-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-everything)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-everything/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-everything&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-everything%3A2026.1.14%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server that exercises all the features of the MCP protocol

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @modelcontextprotocol/server-everything original [sources](https://modelcontextprotocol.io).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-everything/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/charts/mcp-server-everything/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-everything run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Anthropic, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @modelcontextprotocol/server-everything ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-everything ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/charts/mcp-server-everything)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-everything/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-2026.1.14`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-everything:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-everything:1.0.0-2026.1.14`

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
helm install mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-everything
```

From there your MCP server mcp-server-everything will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-everything` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-everything
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
  mcp-server-scope: standalone
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-everything` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-everything oci://docker.io/acuvity/mcp-server-everything --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>echo</summary>

**Description**:

```
Echoes back the input string
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| message | string | Message to echo | Yes
</details>
<details>
<summary>get-annotated-message</summary>

**Description**:

```
Demonstrates how annotations can be used to provide metadata about content.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| includeImage | boolean | Whether to include an example image | No
| messageType | string | Type of message to demonstrate different annotation patterns | Yes
</details>
<details>
<summary>get-env</summary>

**Description**:

```
Returns all environment variables, helpful for debugging MCP server configuration
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get-resource-links</summary>

**Description**:

```
Returns up to ten resource links that reference different types of resources
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| count | number | Number of resource links to return (1-10) | No
</details>
<details>
<summary>get-resource-reference</summary>

**Description**:

```
Returns a resource reference that can be used by MCP clients
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resourceId | number | ID of the text resource to fetch | No
| resourceType | string | not set | No
</details>
<details>
<summary>get-structured-content</summary>

**Description**:

```
Returns structured content along with an output schema for client data validation
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| location | string | Choose city | Yes
</details>
<details>
<summary>get-sum</summary>

**Description**:

```
Returns the sum of two numbers
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| a | number | First number | Yes
| b | number | Second number | Yes
</details>
<details>
<summary>get-tiny-image</summary>

**Description**:

```
Returns a tiny MCP logo image.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>gzip-file-as-resource</summary>

**Description**:

```
Compresses a single file using gzip compression. Depending upon the selected output type, returns either the compressed data as a gzipped resource or a resource link, allowing it to be downloaded in a subsequent request during the current session.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | string | URL or data URI of the file content to compress | No
| name | string | Name of the output file | No
| outputType | string | How the resulting gzipped file should be returned. 'resourceLink' returns a link to a resource that can be read later, 'resource' returns a full resource object. | No
</details>
<details>
<summary>toggle-simulated-logging</summary>

**Description**:

```
Toggles simulated, random-leveled logging on or off.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>toggle-subscriber-updates</summary>

**Description**:

```
Toggles simulated resource subscription updates on or off.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>trigger-long-running-operation</summary>

**Description**:

```
Demonstrates a long running operation with progress updates.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration | number | Duration of the operation in seconds | No
| steps | number | Number of steps in the operation | No
</details>
<details>
<summary>get-roots-list</summary>

**Description**:

```
Lists the current MCP roots provided by the client. Demonstrates the roots protocol capability even though this server doesn't access files.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>trigger-sampling-request</summary>

**Description**:

```
Trigger a Request from the Server for LLM Sampling
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| maxTokens | number | Maximum number of tokens to generate | No
| prompt | string | The prompt to send to the LLM | Yes
</details>

## 📚 Resources (7)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| architecture.md | text/markdown | demo://resource/static/document/architecture.md | - |
| extension.md | text/markdown | demo://resource/static/document/extension.md | - |
| features.md | text/markdown | demo://resource/static/document/features.md | - |
| how-it-works.md | text/markdown | demo://resource/static/document/how-it-works.md | - |
| instructions.md | text/markdown | demo://resource/static/document/instructions.md | - |
| startup.md | text/markdown | demo://resource/static/document/startup.md | - |
| structure.md | text/markdown | demo://resource/static/document/structure.md | - |

</details>

## 📝 Prompts (4)
<details>
<summary>simple-prompt</summary>

**Description**:

```
A prompt with no arguments
```
<details>
<summary>args-prompt</summary>

**Description**:

```
A prompt with two arguments, one required and one optional
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| city | Name of the city |Yes |
| state | Name of the state |No |
<details>
<summary>completable-prompt</summary>

**Description**:

```
First argument choice narrows values for second argument.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| department | Choose the department. |Yes |
| name | Choose a team member to lead the selected department. |Yes |
<details>
<summary>resource-prompt</summary>

**Description**:

```
A prompt that includes an embedded resource reference
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| resourceType | Type of resource to fetch |Yes |
| resourceId | ID of the text resource to fetch |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | args-prompt | description | 6bf9e87694814907d18376c10df390d1d026ab22dd25dc2f90c7f54fe3e872f2 |
| prompts | args-prompt | city | 6e7972358d7f0ec8764bf526b14781a42654304776ea3ad233f60bf922899155 |
| prompts | args-prompt | state | 9a5f7119fb7e49fe59783d064d75904aadf8acf32e7e60bdd5c5ace03c81df39 |
| prompts | completable-prompt | description | 440077b1101c42fe4de7f359ffe44f5428ea005d4d3003be8a7b008e4e657931 |
| prompts | completable-prompt | department | 6c1697a1528ebdd17c722c8df0be4ebc7908e0932ab9c07a29a22ea3965b11a2 |
| prompts | completable-prompt | name | 8d9a952b1921cc303f93f852d16c1975a52c1296c869e9e062fd08a3ff6b7b30 |
| prompts | resource-prompt | description | 485a9a963ffe2b74994e89a2ac741dc26ef7656974ba85d6e1a8fba8472adaca |
| prompts | resource-prompt | resourceId | 747c611eadb757cc695479ba71ad7ad30123383782d50dcae9cc923c5ff6c7f4 |
| prompts | resource-prompt | resourceType | 54b6b2f551a23a9e4909208c06a589a3fca85a290fc1cb3cfdb626346eeeaacb |
| prompts | simple-prompt | description | bd5b0cf66fbff61626808db1d4285c51cda3d933d3d05a4ad7bd7500d0ab86ba |
| tools | echo | description | 4d00e170dfb2475b38d7c595d6b83ddc873f4119814d8c3e96321a53aaf18fca |
| tools | echo | message | 2aa7ac486933d92f1de28d4b527088a577a0fe0ad5d33c0c36c1d122fc8477ba |
| tools | get-annotated-message | description | 6050c40378a145a00c1912f5904b37edb1266ce1c43fa430b6655a6f302d5222 |
| tools | get-annotated-message | includeImage | 3f577041e74ad35132f1242ae17815ed70e39bad9533b717021987963f8abb27 |
| tools | get-annotated-message | messageType | 48ca223484fb0957dc6efa4920a79cc385ab419c7c3af0309e8acb4784c58d0d |
| tools | get-env | description | 41cecdc4e2e1e3ab2be769fefe6cb155289da5ade9c381a1578bda7948111c26 |
| tools | get-resource-links | description | 0574c9e3571c77380de27d3927dbac8133e68c558150b8f0b95d2e884403613c |
| tools | get-resource-links | count | 710b4aa7c24cb2e02f1dfaaa05449a98f92d7ee2252f0da40c0685b614d00783 |
| tools | get-resource-reference | description | f65488ea8977f68a7680a0ba04efa98d742a3007664649c9e00899f43f1d89de |
| tools | get-resource-reference | resourceId | 747c611eadb757cc695479ba71ad7ad30123383782d50dcae9cc923c5ff6c7f4 |
| tools | get-roots-list | description | 3b7b19f4e04c4ca99d1475992f4b95915e7415d4261cf4cebc291b7b3def7c8d |
| tools | get-structured-content | description | 276d76ef534072c914d17df7855f06d6c44a8c5be3ee2b8eb686afdeb357d88c |
| tools | get-structured-content | location | 43ae23322301a2f94c6b19a84e30a7d2681359513b6cea1000cffeafd8ee2920 |
| tools | get-sum | description | 98b4e89d761c05f63a8acce7100a3950f49ca67537dea3716c0ba2a9431316f9 |
| tools | get-sum | a | 4d238256ad692183f3c2e945213eac5ae9e86bce06e6989360af210cae8751f4 |
| tools | get-sum | b | c079e9787b04a05e7e4dd561a044bce326711ebc3f0c90160f33823530da93d3 |
| tools | get-tiny-image | description | 7eba2275ba1ae93a58102c84bcd8f1fb29126fb998d3cbd2947457cdbe685bde |
| tools | gzip-file-as-resource | description | e74512860ba0e5a1d47699b6bc8099970a510674295e14a861287882ed715243 |
| tools | gzip-file-as-resource | data | fe50d774f0f3d2c53621ed9187fb8110a675cc16644da0368e3a94d3011f16e5 |
| tools | gzip-file-as-resource | name | fe91c771dbfa72cbd6dbd6404fb3eeb4aac574ebcbc8e111cd28b86cf882db5d |
| tools | gzip-file-as-resource | outputType | 216a80a9e4dce55bb3cf355f09d764bc7e399daa474b3aff4dc5c13da7e915f5 |
| tools | toggle-simulated-logging | description | 4ece88d0dc82c58f375c0df4229b4fad8a4ee98398486f5d3e64f8b5d1f2219d |
| tools | toggle-subscriber-updates | description | 8d2608e7a48902396a0c7b08e56cfdcf93667ecd09de825d71a6c47b207f22c8 |
| tools | trigger-long-running-operation | description | d047c3fcbcb25a9255d0bd7584d019509a8aa5a181ce7e3c6109d76ea820d125 |
| tools | trigger-long-running-operation | duration | 611a5d1b6734296bafe76d21bca6f9c984b30ae9cf9921554c4440d26b7ea431 |
| tools | trigger-long-running-operation | steps | 70c271e49e3c4217d398f502fda4be342f73aa5875a69b7f59fc749564181707 |
| tools | trigger-sampling-request | description | 807babf5b7ff34397dda42ab6ad339d82f992dc120ddb6c92165c8ee0a217a14 |
| tools | trigger-sampling-request | maxTokens | 877bc91aff3481950f61058439e2f8d8e4a15e3cfa9d1f031c94e945ba2d516e |
| tools | trigger-sampling-request | prompt | 472f849bc61d2fc5c70dac589c4cab3ee7ed1800fbc61dc1c78ba30546c40e95 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
