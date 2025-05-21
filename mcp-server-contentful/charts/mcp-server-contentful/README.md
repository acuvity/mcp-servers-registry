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


# What is mcp-server-contentful?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-contentful/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-contentful/1.16.1?logo=docker&logoColor=fff&label=1.16.1)](https://hub.docker.com/r/acuvity/mcp-server-contentful)
[![PyPI](https://img.shields.io/badge/1.16.1-3775A9?logo=pypi&logoColor=fff&label=@ivotoby/contentful-management-mcp-server)](https://github.com/ivo-toby/contentful-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-contentful/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-contentful&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CONTENTFUL_MANAGEMENT_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-contentful%3A1.16.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Update, create, delete content, content-models and assets in your Contentful Space.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @ivotoby/contentful-management-mcp-server original [sources](https://github.com/ivo-toby/contentful-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-contentful/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-contentful/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-contentful/charts/mcp-server-contentful/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @ivotoby/contentful-management-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-contentful/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/ivo-toby/contentful-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @ivotoby/contentful-management-mcp-server ](https://github.com/ivo-toby/contentful-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @ivotoby/contentful-management-mcp-server ](https://github.com/ivo-toby/contentful-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-contentful/charts/mcp-server-contentful)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-contentful/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.16.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-contentful:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-contentful:1.0.0-1.16.1`

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
  - `CONTENTFUL_MANAGEMENT_ACCESS_TOKEN` secret to be set as secrets.CONTENTFUL_MANAGEMENT_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-contentful
```

From there your MCP server mcp-server-contentful will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-contentful` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-contentful
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-contentful` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (35)
<details>
<summary>search_entries</summary>

**Description**:

```
Search for entries using query parameters. Returns a maximum of 3 items per request. Use skip parameter to paginate through results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| query | object | Query parameters for searching entries | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>create_entry</summary>

**Description**:

```
Create a new entry in Contentful. Before executing this function, you need to know the contentTypeId (not the content type NAME) and the fields of that contentType. You can get the fields definition by using the GET_CONTENT_TYPE tool. IMPORTANT: All field values MUST include a locale key (e.g., 'en-US') for each value, like: { title: { 'en-US': 'My Title' } }. Every field in Contentful requires a locale even for single-language content.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | The ID of the content type for the new entry | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | object | The fields of the entry with localized values. Example: { title: { 'en-US': 'My Title' }, description: { 'en-US': 'My Description' } } | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>get_entry</summary>

**Description**:

```
Retrieve an existing entry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>update_entry</summary>

**Description**:

```
Update an existing entry. The handler will merge your field updates with the existing entry fields, so you only need to provide the fields and locales you want to change. IMPORTANT: All field values MUST include a locale key (e.g., 'en-US') for each value, like: { title: { 'en-US': 'My Updated Title' } }. Every field in Contentful requires a locale even for single-language content.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | object | The fields to update with localized values. Example: { title: { 'en-US': 'My Updated Title' } } | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>delete_entry</summary>

**Description**:

```
Delete an entry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_entry</summary>

**Description**:

```
Publish an entry or multiple entries. Accepts either a single entryId (string) or an array of entryIds (up to 100 entries). For a single entry, it uses the standard publish operation. For multiple entries, it automatically uses bulk publishing.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | any | ID of the entry to publish, or an array of entry IDs (max: 100) | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>unpublish_entry</summary>

**Description**:

```
Unpublish an entry or multiple entries. Accepts either a single entryId (string) or an array of entryIds (up to 100 entries). For a single entry, it uses the standard unpublish operation. For multiple entries, it automatically uses bulk unpublishing.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | any | ID of the entry to unpublish, or an array of entry IDs (max: 100) | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_assets</summary>

**Description**:

```
List assets in a space. Returns a maximum of 3 items per request. Use skip parameter to paginate through results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| limit | number | Maximum number of items to return (max: 3) | Yes
| skip | number | Number of items to skip for pagination | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>upload_asset</summary>

**Description**:

```
Upload a new asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| file | object | not set | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| title | string | not set | Yes
</details>
<details>
<summary>get_asset</summary>

**Description**:

```
Retrieve an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>update_asset</summary>

**Description**:

```
Update an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| description | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| file | object | not set | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| title | string | not set | No
</details>
<details>
<summary>delete_asset</summary>

**Description**:

```
Delete an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_asset</summary>

**Description**:

```
Publish an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>unpublish_asset</summary>

**Description**:

```
Unpublish an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_content_types</summary>

**Description**:

```
List content types in a space. Returns a maximum of 10 items per request. Use skip parameter to paginate through results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| limit | number | Maximum number of items to return (max: 3) | Yes
| skip | number | Number of items to skip for pagination | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>get_content_type</summary>

**Description**:

```
Get details of a specific content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>create_content_type</summary>

**Description**:

```
Create a new content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | No
| displayField | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | array | Array of field definitions for the content type | Yes
| name | string | not set | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>update_content_type</summary>

**Description**:

```
Update an existing content type. The handler will merge your field updates with existing content type data, so you only need to provide the fields and properties you want to change.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| description | string | not set | No
| displayField | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | array | not set | Yes
| name | string | not set | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>delete_content_type</summary>

**Description**:

```
Delete a content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_content_type</summary>

**Description**:

```
Publish a content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_spaces</summary>

**Description**:

```
List all available spaces
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_space</summary>

**Description**:

```
Get details of a space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| spaceId | string | not set | Yes
</details>
<details>
<summary>list_environments</summary>

**Description**:

```
List all environments in a space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| spaceId | string | not set | Yes
</details>
<details>
<summary>create_environment</summary>

**Description**:

```
Create a new environment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | not set | Yes
| name | string | not set | Yes
| spaceId | string | not set | Yes
</details>
<details>
<summary>delete_environment</summary>

**Description**:

```
Delete an environment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | not set | Yes
| spaceId | string | not set | Yes
</details>
<details>
<summary>bulk_validate</summary>

**Description**:

```
Validate multiple entries at once
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryIds | array | Array of entry IDs to validate | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_ai_actions</summary>

**Description**:

```
List all AI Actions in a space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| limit | number | Maximum number of AI Actions to return | No
| skip | number | Number of AI Actions to skip for pagination | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| status | string | Filter AI Actions by status | No
</details>
<details>
<summary>get_ai_action</summary>

**Description**:

```
Get a specific AI Action by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to retrieve | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>create_ai_action</summary>

**Description**:

```
Create a new AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| configuration | object | The model configuration | Yes
| description | string | The description of the AI Action | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| instruction | object | The instruction object containing the template and variables | Yes
| name | string | The name of the AI Action | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| testCases | array | Optional array of test cases for the AI Action | No
</details>
<details>
<summary>update_ai_action</summary>

**Description**:

```
Update an existing AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to update | Yes
| configuration | object | The model configuration | Yes
| description | string | The description of the AI Action | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| instruction | object | The instruction object containing the template and variables | Yes
| name | string | The name of the AI Action | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| testCases | array | Optional array of test cases for the AI Action | No
</details>
<details>
<summary>delete_ai_action</summary>

**Description**:

```
Delete an AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to delete | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_ai_action</summary>

**Description**:

```
Publish an AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to publish | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>unpublish_ai_action</summary>

**Description**:

```
Unpublish an AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to unpublish | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>invoke_ai_action</summary>

**Description**:

```
Invoke an AI Action with variables
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to invoke | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| outputFormat | string | The format of the output content | No
| rawVariables | array | Array of raw variable objects (for complex variable types like references) | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| variables | object | Key-value pairs of variable IDs and their values | No
| waitForCompletion | boolean | Whether to wait for the AI Action to complete before returning | No
</details>
<details>
<summary>get_ai_action_invocation</summary>

**Description**:

```
Get the result of a previous AI Action invocation
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| invocationId | string | The ID of the specific invocation to retrieve | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>

## 📝 Prompts (14)
<details>
<summary>explain-api-concepts</summary>

**Description**:

```
Explain Contentful API concepts and relationships
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| concept | Contentful concept (Space/Environment/ContentType/Entry/Asset) |Yes |
<details>
<summary>space-identification</summary>

**Description**:

```
Guide for identifying the correct Contentful space for operations
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| operation | Operation you want to perform |Yes |
<details>
<summary>content-modeling-guide</summary>

**Description**:

```
Guide through content modeling decisions and best practices
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| useCase | Description of the content modeling scenario |Yes |
<details>
<summary>api-operation-help</summary>

**Description**:

```
Get detailed help for specific Contentful API operations
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| operation | API operation (CRUD, publish, archive, etc) |Yes |
| resourceType | Type of resource (Entry/Asset/ContentType) |Yes |
<details>
<summary>entry-management</summary>

**Description**:

```
Help with CRUD operations and publishing workflows for content entries
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (create/read/update/delete/publish/unpublish/bulk) |No |
| details | Additional context or requirements |No |
<details>
<summary>asset-management</summary>

**Description**:

```
Guidance on managing digital assets like images, videos, and documents
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (upload/process/update/delete/publish) |No |
| details | Additional context about asset types or requirements |No |
<details>
<summary>content-type-operations</summary>

**Description**:

```
Help with defining and managing content types and their fields
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (create/update/delete/publish/field configuration) |No |
| details | Additional context about field types or validations |No |
<details>
<summary>ai-actions-overview</summary>

**Description**:

```
Comprehensive overview of AI Actions in Contentful
```
<details>
<summary>ai-actions-create</summary>

**Description**:

```
Guide for creating and configuring AI Actions in Contentful
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| useCase | Purpose of the AI Action you want to create |Yes |
| modelType | AI model type (e.g., gpt-4, claude-3-opus) |No |
<details>
<summary>ai-actions-variables</summary>

**Description**:

```
Explanation of variable types and configuration for AI Actions
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| variableType | Type of variable (Text, Reference, StandardInput, etc) |No |
<details>
<summary>ai-actions-invoke</summary>

**Description**:

```
Help with invoking AI Actions and processing results
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| actionId | ID of the AI Action (if known) |No |
| details | Additional context about your invocation requirements |No |
<details>
<summary>bulk-operations</summary>

**Description**:

```
Guidance on performing actions on multiple entities simultaneously
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| operation | Bulk operation type (publish/unpublish/validate) |No |
| entityType | Type of entities to process (entries/assets) |No |
| details | Additional context about operation requirements |No |
<details>
<summary>space-environment-management</summary>

**Description**:

```
Help with managing spaces, environments, and deployment workflows
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (create/list/manage environments/aliases) |No |
| entity | Entity type (space/environment) |No |
| details | Additional context about workflow requirements |No |
<details>
<summary>mcp-tool-usage</summary>

**Description**:

```
Instructions for using Contentful MCP tools effectively
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| toolName | Specific tool name (e.g., invoke_ai_action, create_entry) |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | ai-actions-create | description | 04499ec6931bdbbaf3c31efc46867ff4d15a3265dcbc2ace61a162a708ce819b |
| prompts | ai-actions-create | modelType | 9dfcc5d7d4f46417567cad6cc2763e3c4fd846616150775df8aead5a21cf03e2 |
| prompts | ai-actions-create | useCase | b3fadad4cca866ea6a0af5ea9f4e039b1ecedb39b6fd519a394a453edd5beff0 |
| prompts | ai-actions-invoke | description | 52e8446af97f14b421401959ee22a6497b899ded39970eb21d61fe01620e230b |
| prompts | ai-actions-invoke | actionId | aceaef2f47d6f48f42b1475e35da3981185bf460497724f1f03868b88de6552d |
| prompts | ai-actions-invoke | details | 1320cdcf05919ff23e26d3345cee4d12473d6425d6a2fc853dc7e8830fa8ae14 |
| prompts | ai-actions-overview | description | ac01a2f621066d33ba866fd4bda29b67e2cbf17ea248f26187633e2b40997c4d |
| prompts | ai-actions-variables | description | cb29b5346bcf53c1b45c4c47086c199aaeb552bee81c941df59a42ad57606ce8 |
| prompts | ai-actions-variables | variableType | 61d7be4997f2965220a27b0683d008f7bf3f102990cdef003191ef2fc7d45d89 |
| prompts | api-operation-help | description | bec79ef2f1d7f1f7d5da6179c8c6aae4417101063122fa088e039c511b5f088b |
| prompts | api-operation-help | operation | 8d7c851d9342f2fc7885d6e383ef1f0371fa2414debe46eedeabd9811b19e5d7 |
| prompts | api-operation-help | resourceType | 97420bb6f450e7863a261b3f4ee1e1def0fed7c4b3e38e4d432bfc4e943b1a47 |
| prompts | asset-management | description | d6d4f3f6128ce73f7c892b137ac8a4ec32fee70c0d9532101608880649a3981c |
| prompts | asset-management | details | 481aaa4af76433ba1e711959678bf714a886318487669b2b8bb7c4c7e6085f4a |
| prompts | asset-management | task | 4c47ac467e18ba528dec44f37bda1b82a32c1597f2e348158366f981fdef2961 |
| prompts | bulk-operations | description | 6094c65ce88cdee99c15f72b80e3988d431bc0a7d49c125bccbb361881d2843b |
| prompts | bulk-operations | details | 267da141093b89c8df57b5711c0b1f0564ffe6e24ff4293e5a1ca1df5b5d76f7 |
| prompts | bulk-operations | entityType | e9e86161585d8773b014cbedeb41952e5cb4bd148ca30acebff21db3cc315636 |
| prompts | bulk-operations | operation | e953f9c8d0f275f816fb0832707d0476df143a79722e3cbb5fc750560ecad32d |
| prompts | content-modeling-guide | description | cacbd0d028478ddeac81a48491d6b4865699c726bebf0fea8f9d58b86e0ecb4f |
| prompts | content-modeling-guide | useCase | 742e58a5952e3ecf1e44aede7f946f6e5300e43d8d97feafcb2dbfbdfe4d1dce |
| prompts | content-type-operations | description | 6e109a3fd416c150e4d0cd71aa4b4124ac83779fd06443215c9b41666f8bb017 |
| prompts | content-type-operations | details | 6bc1ca6d233efa0bafb86453a95c6e9939697c65ea221fba183a894ef4d8f032 |
| prompts | content-type-operations | task | 469f4a49e5ef2ba9d69a61976cde0a8645d85e71f2f568894c4b4f5160f48b5a |
| prompts | entry-management | description | 3da363eb43fc113125caf7656cecc0b5a4305c30c31994613bd13dcee546a58f |
| prompts | entry-management | details | 25b4017796283cde87c655584d3c99a3867a801cab5c95c4e15e8eae93ae292c |
| prompts | entry-management | task | 4d6866bc18a8ea46246fc6c4db0d2cfe581d641649edab1be01e814de82ff3ab |
| prompts | explain-api-concepts | description | 4952c00f37238d1ca7e245fa82e5497248ab4c5bb2244497cf302fa9d8830b24 |
| prompts | explain-api-concepts | concept | 507f981d9d92b55ac0a3f3bd412615d9223b77fcabdc030d052b6debaa5f15e6 |
| prompts | mcp-tool-usage | description | 2c173ee0b55f51f1b348693bc9cdccc412eb68ee4b7375fa7437fd7bf81d0f11 |
| prompts | mcp-tool-usage | toolName | 8de2b1ca936682136c1723d1d4bca5cc33bea7752a326a73cc75b4c68b86be89 |
| prompts | space-environment-management | description | 8314ebadb16bbe2ad74f77957b124ba68de098562ea1d5b8fd0bb288d00a5195 |
| prompts | space-environment-management | details | 5a4d5eaea58b0e5423e15a6fce9c4af71b266a56e1c2fb2ef3cc4a6ac3dbf888 |
| prompts | space-environment-management | entity | 5184fcd64e7af348a207b4ad8954f3fe43c50a95573958a8855bf4a057c82b19 |
| prompts | space-environment-management | task | 1be912127cba1e2e9a58addade2092215288b45fd136baecb896d2d33cf40460 |
| prompts | space-identification | description | 3d70262daa49e68385713c991f479d978aaa0d60f374035dea1fef1cfb9cb8d4 |
| prompts | space-identification | operation | f86180ad94a556cc138da9712ae9c0fa612b890f28968b511b71980f303594f9 |
| tools | bulk_validate | description | 8ecb4456ace22c28b31473a59a7f7e2aafd9ad306660dfb7f5aa863f2b0339e1 |
| tools | bulk_validate | entryIds | cfb850350044490d46c9983a9681deb2b9cdbf744fffbfedd1bef58721f785fe |
| tools | bulk_validate | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | bulk_validate | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_ai_action | description | 37a11ccdfa19933c2800b850d290e68d97b066cd943c4dd8f5be8e1dde59527d |
| tools | create_ai_action | configuration | f9a3b300f3826bdb97e5ae6b377e653524cbe4cc7804ae95eb171c724a5573ef |
| tools | create_ai_action | description | 738b104b409f46bd943a50c5499f7027bf6544187b26626dc571fb29ca569253 |
| tools | create_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | create_ai_action | instruction | ebef280526abae1f91c3bbda5ec014e2406c624336fbd84e3c1b2fdb09e31e60 |
| tools | create_ai_action | name | c44e12cb538c2b6005353bdaa62fff36e89f40a1e3f98ac0c4807bbebb58fb6e |
| tools | create_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_ai_action | testCases | 195eaaf33aaf9a64981d3ae293b34297dd65614fd38592b2e4e9a8391bc056a6 |
| tools | create_content_type | description | d9744dc50d28fd896e176539b86c4d516298734c6c660c2a91a49b670b262a20 |
| tools | create_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | create_content_type | fields | 7e77d1884050a7aa4e0929815065ae045983a263c6ead31e28a0b28f1f1b7eaa |
| tools | create_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_entry | description | d1687108b7c99d63382fb9b55331150091da8baaa9d9763ec35d0d2c8ed998ea |
| tools | create_entry | contentTypeId | 957e01d15b8b4bb3a68264cc2127b3cbcfd6da3ed8cb2d7a82a9d86834d2e592 |
| tools | create_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | create_entry | fields | 33f63ffca8ba8a642db0188cf77a8ed907bb45c8a601d2325fa4cf01c9d3e057 |
| tools | create_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_environment | description | 82054b8ea3438535752e8a25bd56d0d23d304f8922bbcf9cd1905c0b5cd8cb12 |
| tools | delete_ai_action | description | acecc366a1002d97e05ae5a4223a9cdff1fc5ca008c5b99df0deeb9ef15c403c |
| tools | delete_ai_action | aiActionId | 9dd183dbe320721e68e17a97af3ebbdf738588d07f9c405d336f055c9b573eb1 |
| tools | delete_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_asset | description | 6c7c32568e6a7561f8f0415ea51e55a393f63285fe479a88c5d67a0361632b3c |
| tools | delete_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_content_type | description | dd3069640d149019bf7e31d4d2dec205214fdd3254c1b965df50548f33f3775a |
| tools | delete_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_entry | description | e035171af6f9f50e51b2a950ad298dbd11db9a3453f09c25d86e37f37657820c |
| tools | delete_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_environment | description | d71ccc7a648f021ca5e93376a7ec68e806947a2fe212f2e482e35805348e34e7 |
| tools | get_ai_action | description | 2a129b4f3e58dbb177e1ca6687be39186ff714ab86efde968e9cc5ff1c6b45b0 |
| tools | get_ai_action | aiActionId | ec6acb40764c4080207248094c332989c847a2cdfe1aa58eb46e9d3744d5c003 |
| tools | get_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_ai_action_invocation | description | 8b842c74c84b7761946264e11e6caafdf485a4fe6deed98c8c3583174bfc82be |
| tools | get_ai_action_invocation | aiActionId | 88d16fb7ad95f1013ba5b9ef34cea54f6f41ac20c380109ef0ed475fc9a6d3cb |
| tools | get_ai_action_invocation | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_ai_action_invocation | invocationId | a973285ca3b19dcf75a3df5f0475c00c0aec8d49ab0c8e97f2faa95f79a9025d |
| tools | get_ai_action_invocation | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_asset | description | f8353610a7c481ca975a62389184e981f7b3a6414a50160fa0c8cba366e254af |
| tools | get_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_content_type | description | 2a5357bc685b1b5843c2868b1124211676da3cc45550fe3c688f6a060903ec2f |
| tools | get_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_entry | description | 1de1c52a44e35412db5b7ad38ca92ae9881a2655bb5dfe1ad1d5d0aad2aaefb2 |
| tools | get_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_space | description | da364db7e6f099c12704b9793a65be4732231c51cd272e87040a287adac3dd88 |
| tools | invoke_ai_action | description | 094d76f15f911a0b16205342cab4282094fcf8ce22b465bb24ffa1745dbfcae7 |
| tools | invoke_ai_action | aiActionId | d0be2c8158fd0e42df3ebd5949fc36f009c871ac5e83a84bb39b55f58fb5b3d9 |
| tools | invoke_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | invoke_ai_action | outputFormat | 9d2301676daaafc442127528bc01d39e9695787f8ac78fd49ca42b4dedacfd03 |
| tools | invoke_ai_action | rawVariables | dca5ee1b3ec4ae493f18822b37027480ba5d1ac7c42cc06e6584350b9d735749 |
| tools | invoke_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | invoke_ai_action | variables | fd104b359a3b6aaa7245bebdfe1d6d46f79783d9488c81404bda970c2d129323 |
| tools | invoke_ai_action | waitForCompletion | a4df206ef1cb6fdc68bdcd500ac68e68c9584fb2e239a6119f12909ff37efaaf |
| tools | list_ai_actions | description | bb0323f41ba668092677e1063b6414c814301be0ce0c5e3d1cdec22677997c3d |
| tools | list_ai_actions | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | list_ai_actions | limit | daf6a199ced3432a0669924c3a8a5cb68a294de7ca010084c63acf1b933a3f81 |
| tools | list_ai_actions | skip | f4522f1436198fca9e16ad4925e9823ff67be7621a7cfbf4fb9423c8a37ec0af |
| tools | list_ai_actions | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | list_ai_actions | status | 922717d3f4a75218be2ec6a0431f85aa1cddc723e78d2b3a3ac606bdb4a964f3 |
| tools | list_assets | description | 9f9580698576ca34e3b75be7d8d08b87ec3508c743edecd8f9fb89846ce77fb1 |
| tools | list_assets | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | list_assets | limit | 50ba5c893a7c24657d068bc5f09c36af857de3ab7ef725d930ba24e60864224e |
| tools | list_assets | skip | c5afb15fad11afbacdefce188b50323f10c5399af9c5c73570f8f87e1a5e46f5 |
| tools | list_assets | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | list_content_types | description | a755d641298d1d07ce423a0be43cfa56f6676ef77a426a527bbe865941c02ad4 |
| tools | list_content_types | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | list_content_types | limit | 50ba5c893a7c24657d068bc5f09c36af857de3ab7ef725d930ba24e60864224e |
| tools | list_content_types | skip | c5afb15fad11afbacdefce188b50323f10c5399af9c5c73570f8f87e1a5e46f5 |
| tools | list_content_types | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | list_environments | description | f3e98be6e8fd140fbdd5ca858ca874c62ff2b2f70ae6661441f2ab8b451475ae |
| tools | list_spaces | description | d21f58227d879eb9c8ac5eb9c628aaf68b8d54d12086acfbe51f93ee2789f384 |
| tools | publish_ai_action | description | ac8dbb10e199ad3a414b039c6bb0aac6a2606823d048f6997da8e287e9992ef5 |
| tools | publish_ai_action | aiActionId | 548dd0d2a0fb5464800ac6df64dca7504e9a544770eed634d6dc5c61f06ad939 |
| tools | publish_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | publish_asset | description | 3e158ff99829e5cee1a52c1306c6dfc57a6dfeaf9830ddfca6ced197ff2edfe3 |
| tools | publish_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | publish_content_type | description | 9f875bfafa8380b3ca6c560343365319bb3a85525c3a6586c61bf7e041b58fdb |
| tools | publish_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | publish_entry | description | ddfe4d54604e17e0a3832f982ff339d4951017bd9e2082d4725efcb7fe614bfa |
| tools | publish_entry | entryId | 30d966f244cd5d2bef94794c9032fd33a7f81fb767b2f8aefea6fa353eda4a7d |
| tools | publish_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | search_entries | description | e169395ebfba855657162ec96336a9f2c0dffafd85f38471334f01a983adcbe4 |
| tools | search_entries | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | search_entries | query | 9c4707942dced800fc119a3c9c4fcacc9522d43e656e9cb3c638ee6cb36e5c86 |
| tools | search_entries | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | unpublish_ai_action | description | 556acf65db8245d8e9143d0cf4defdb8ab84db37bc35a7d039a1aa64d5423bd3 |
| tools | unpublish_ai_action | aiActionId | 3a850af2b4a9c08bc3123e13f376170f9a027ef07f954167d75933a6ebcffe44 |
| tools | unpublish_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | unpublish_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | unpublish_asset | description | ce18725d3b8294723b1017d325aa92c3c0edeb3f7ff51d4751478b00345bc966 |
| tools | unpublish_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | unpublish_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | unpublish_entry | description | a46a000388faf53148196363c067f30509cdc0906328bf7c3a99876e0d769ab4 |
| tools | unpublish_entry | entryId | 6af7f8142280aaad6c9b01b479a71f8cb8611c78387dd8d58aa4931d3c7d5a53 |
| tools | unpublish_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | unpublish_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_ai_action | description | 90d6a01c4004be0ed99acfd9aed6083bfc44fb958f7c3c2c1284090c5339db51 |
| tools | update_ai_action | aiActionId | ba1b82ad534e5a3b7a2ee31231ec2121b809394dd12430f9d87aa0ac51b22fa9 |
| tools | update_ai_action | configuration | f9a3b300f3826bdb97e5ae6b377e653524cbe4cc7804ae95eb171c724a5573ef |
| tools | update_ai_action | description | 738b104b409f46bd943a50c5499f7027bf6544187b26626dc571fb29ca569253 |
| tools | update_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_ai_action | instruction | ebef280526abae1f91c3bbda5ec014e2406c624336fbd84e3c1b2fdb09e31e60 |
| tools | update_ai_action | name | c44e12cb538c2b6005353bdaa62fff36e89f40a1e3f98ac0c4807bbebb58fb6e |
| tools | update_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_ai_action | testCases | 195eaaf33aaf9a64981d3ae293b34297dd65614fd38592b2e4e9a8391bc056a6 |
| tools | update_asset | description | 6e3aa72f38e0036da9795b34fb5fca4838d8fac910dbee7cb4560eddd1262825 |
| tools | update_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_content_type | description | dff46c3db47453975594cec480c7a7fa4c679f1951bedf413f43c1760b58a880 |
| tools | update_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_entry | description | 15617674da9c17fdf452373e15b9e42260a7d84b0779b0afc62d42534d2a13e0 |
| tools | update_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_entry | fields | 9f28607eac1f0d0e703890346919c6a3a77606537131e5d9d52b78f95cf68d7f |
| tools | update_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | upload_asset | description | d74192920518f1dd41465b2fded572980e31c111e90879ceb5ec5d4453e617fe |
| tools | upload_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | upload_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
