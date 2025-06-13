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


# What is mcp-server-aws-documentdb?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-documentdb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-documentdb/1.0.1?logo=docker&logoColor=fff&label=1.0.1)](https://hub.docker.com/r/acuvity/mcp-server-aws-documentdb)
[![PyPI](https://img.shields.io/badge/1.0.1-3775A9?logo=pypi&logoColor=fff&label=awslabs.documentdb-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/documentdb-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-documentdb/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-documentdb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-documentdb%3A1.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AWS DocumentDB MCP server for querying and managing MongoDB-compatible document databases

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.documentdb-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/documentdb-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-documentdb/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-documentdb/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-documentdb/charts/mcp-server-aws-documentdb/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.documentdb-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-documentdb/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, Nitin Ahuja <nitahuja@amazon.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/documentdb-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.documentdb-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/documentdb-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.documentdb-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/documentdb-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-documentdb/charts/mcp-server-aws-documentdb)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-documentdb/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-documentdb:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-documentdb:1.0.0-1.0.1`

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
helm install mcp-server-aws-documentdb oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-documentdb oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-documentdb
```

From there your MCP server mcp-server-aws-documentdb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-documentdb` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-documentdb
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-documentdb` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-documentdb oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-documentdb oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-documentdb oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-documentdb oci://docker.io/acuvity/mcp-server-aws-documentdb --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (16)
<details>
<summary>connect</summary>

**Description**:

```
Connect to an AWS DocumentDB cluster.

    This tool establishes and validates a connection to DocumentDB.
    The returned connection_id can be used with other tools instead of providing
    the full connection string each time.

    Returns:
        Dict[str, Any]: Connection details including connection_id and available databases
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_string | string | DocumentDB connection string. Example: "mongodb://user:pass@docdb-cluster.cluster-xyz.us-west-2.docdb.amazonaws.com:27017/?tls=true&tlsCAFile=global-bundle.pem" | Yes
</details>
<details>
<summary>disconnect</summary>

**Description**:

```
Close a connection to DocumentDB.

    This tool closes a previously established connection to DocumentDB.

    Returns:
        Dict[str, Any]: Confirmation of successful disconnection
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_id | string | The connection ID returned by the connect tool | Yes
</details>
<details>
<summary>find</summary>

**Description**:

```
Run a query against a DocumentDB collection.

    This tool queries documents from a specified collection based on a filter.

    Returns:
        List[Dict[str, Any]]: List of matching documents
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| limit | integer | Maximum number of documents to return (default: 10) | No
| projection | any | Fields to include/exclude (e.g., {"_id": 0, "name": 1}) | No
| query | object | Query filter (e.g., {"name": "example"}) | Yes
</details>
<details>
<summary>aggregate</summary>

**Description**:

```
Run an aggregation pipeline against a DocumentDB collection.

    This tool executes a DocumentDB aggregation pipeline on a specified collection.

    Returns:
        List[Dict[str, Any]]: List of aggregation results
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| limit | integer | Maximum number of documents to return (default: 10) | No
| pipeline | array | DocumentDB aggregation pipeline | Yes
</details>
<details>
<summary>insert</summary>

**Description**:

```
Insert one or more documents into a DocumentDB collection.

    This tool inserts new documents into a specified collection.

    Returns:
        Dict[str, Any]: Insert operation results including document IDs
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| documents | any | Document or list of documents to insert | Yes
</details>
<details>
<summary>update</summary>

**Description**:

```
Update documents in a DocumentDB collection.

    This tool updates existing documents that match a specified filter.

    Returns:
        Dict[str, Any]: Update operation results
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| filter | object | Filter to select documents to update | Yes
| many | boolean | Whether to update multiple documents (default: False) | No
| update | object | Update operations to apply. It should either include DocumentDB operators like $set, or an entire document if the entire document needs to be replaced. | Yes
| upsert | boolean | Whether to create a new document if no match is found (default: False) | No
</details>
<details>
<summary>delete</summary>

**Description**:

```
Delete documents from a DocumentDB collection.

    This tool deletes documents that match a specified filter.

    Returns:
        Dict[str, Any]: Delete operation results
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| filter | object | Filter to select documents to delete | Yes
| many | boolean | Whether to delete multiple documents (default: False) | No
</details>
<details>
<summary>listDatabases</summary>

**Description**:

```
List all available databases in the DocumentDB cluster.

    This tool returns the names of all accessible databases in the connected cluster.

    Returns:
        Dict[str, Any]: List of database names
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_id | string | The connection ID returned by the connect tool | Yes
</details>
<details>
<summary>createCollection</summary>

**Description**:

```
Create a new collection in a DocumentDB database.

    This tool creates a new collection in the specified database.

    Returns:
        Dict[str, Any]: Status of collection creation
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection to create | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
</details>
<details>
<summary>listCollections</summary>

**Description**:

```
List collections in a DocumentDB database.

    This tool returns the names of all collections in a specified database.

    Returns:
        List[str]: List of collection names
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
</details>
<details>
<summary>dropCollection</summary>

**Description**:

```
Drop a collection from a DocumentDB database.

    This tool completely removes a collection and all its documents from the specified database.
    This operation cannot be undone, so use it with caution.

    Returns:
        Dict[str, Any]: Status of the drop operation
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection to drop | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
</details>
<details>
<summary>countDocuments</summary>

**Description**:

```
Count documents in a DocumentDB collection.

    This tool counts the number of documents in a collection that match the provided filter.
    If no filter is provided, it counts all documents.

    Returns:
        Dict[str, Any]: Count result
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| filter | any | Query filter to count specific documents | No
</details>
<details>
<summary>getDatabaseStats</summary>

**Description**:

```
Get statistics about a DocumentDB database.

    This tool retrieves statistics about the specified database,
    including storage information and collection data.

    Returns:
        Dict[str, Any]: Database statistics
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
</details>
<details>
<summary>getCollectionStats</summary>

**Description**:

```
Get statistics about a DocumentDB collection.

    This tool retrieves detailed statistics about the specified collection,
    including size, document count, and storage information.

    Returns:
        Dict[str, Any]: Collection statistics
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
</details>
<details>
<summary>analyzeSchema</summary>

**Description**:

```
Analyze the schema of a collection by sampling documents.

    This tool samples documents from a collection and provides information about
    the document structure and field coverage across the sampled documents.

    Returns:
        Dict[str, Any]: Schema analysis results including field coverage
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection to analyze | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| sample_size | integer | Number of documents to sample (default: 100) | No
</details>
<details>
<summary>explainOperation</summary>

**Description**:

```
Get an explanation of how an operation will be executed.

    This tool returns the execution plan for a query or aggregation operation,
    helping you understand how DocumentDB will process your operations.

    Returns:
        Dict[str, Any]: Operation explanation
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| collection | string | Name of the collection | Yes
| connection_id | string | The connection ID returned by the connect tool | Yes
| database | string | Name of the database | Yes
| operation_type | string | Type of operation to explain (find, aggregate) | Yes
| pipeline | any | Pipeline for DocumentDB aggregation operations | No
| query | any | Query for find operations | No
| verbosity | string | Explanation verbosity level (queryPlanner, executionStats) | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | aggregate | description | a004fe3233938501fd8f90de8811e7fed89bbb41a2ac1b6b431851f02f49c44e |
| tools | aggregate | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | aggregate | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | aggregate | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | aggregate | limit | 44175ec2d168abaf933abbe6d9f9f0c3d943034b9e78bae0674c9644e229bf59 |
| tools | aggregate | pipeline | 6608b3c5289015f7fc604710c27758824ce2fc5182cf2d2e15a6812c790fc6ea |
| tools | analyzeSchema | description | bd7b4a73145546946c360a918bd63904e0b6833a3c9ae007c633f163bf48b043 |
| tools | analyzeSchema | collection | 928a109de20b6654da34df92cb7ab676730365d8785145b84b2afec8018cd3e6 |
| tools | analyzeSchema | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | analyzeSchema | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | analyzeSchema | sample_size | a9cc0b277c8d581a97791763d4290f187fa5c2203228fc202bfb2b8613e29eb8 |
| tools | connect | description | e210c06849f01f862ee6d7f145f908e6fe8db0be11a54491648bc4c35859ba8f |
| tools | connect | connection_string | 959a678145be0fad2e996832efa15ac51cfbdda4c5b93f0e8f9d0736bea28250 |
| tools | countDocuments | description | 02fde3b6d0d650f5d5adfdc2742183e6d518eee8b9e7bc5b057425c79464eab6 |
| tools | countDocuments | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | countDocuments | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | countDocuments | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | countDocuments | filter | 50726b82890ef3010156d2006c454e761b20220b638832b8fe2ce5d41c0964f5 |
| tools | createCollection | description | 4ae39b0415eac202e4ac5eb760b04c54b8cc43ed7dd202c40ee842dbd18293f7 |
| tools | createCollection | collection | a1d94d7b1c2c5fa14a726ec29730c117643114d03b0eb8c8b1fdc8f00d383826 |
| tools | createCollection | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | createCollection | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | delete | description | 0aeb8c7a2b5c0c01902653e3cf98dea6d74c6a2674866734eb26224be46554fd |
| tools | delete | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | delete | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | delete | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | delete | filter | 13cd190bccae66d5c62e69f4780560b01120486a1bf9298850d64b2348ddc8af |
| tools | delete | many | 382032a68d90f5e675bd813a595f74a95e5698b4787a806d6c63cd2fc00255f5 |
| tools | disconnect | description | bb71283b2ce36a8f4634e8f6760d7f1d0b30c3bbb2c7e1bc0919182cdf9bf94d |
| tools | disconnect | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | dropCollection | description | 3e07a777be342cdc852ee40ecf9111efd2b2da8c51912102689e34dfd4561bfe |
| tools | dropCollection | collection | 9c20403363e5c6d8dd8389dcbeb4c35efb34e5636100118290c6daaf4f1db53d |
| tools | dropCollection | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | dropCollection | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | explainOperation | description | 547e31c1b8e769c96ad8f0b1c09c8b86351b1964584ae87236f55a69b4f52022 |
| tools | explainOperation | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | explainOperation | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | explainOperation | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | explainOperation | operation_type | 2657b46b6c9e62fc1bd4b20fdfce53b84a96963ea3a9ce1139299a8c201d5402 |
| tools | explainOperation | pipeline | eac2de24da323a8d7c3b21923813bfa7b3c5e1b00c991e8edb1f12f7eb0a20a3 |
| tools | explainOperation | query | 2d5e3012a03c12bede1e826903400e8e89dc6b771e87548d44358647232377e0 |
| tools | explainOperation | verbosity | a460eec8b965febd44bf25ab6166d052adc7d12fc69c37aed992eede604de5f6 |
| tools | find | description | 6a20196b0bb50f444289c5f26427fbc99a017e3e5294d47b781cdf9e22076b66 |
| tools | find | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | find | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | find | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | find | limit | 44175ec2d168abaf933abbe6d9f9f0c3d943034b9e78bae0674c9644e229bf59 |
| tools | find | projection | 18a3480f03dd0bf13af02c7e2260e2e60b2619ec8d72e5c6bbb1c9331f95b967 |
| tools | find | query | 96b0ff697237235cb80c62698418802956a77ea650fe0b78f78bbbe81a3fa84c |
| tools | getCollectionStats | description | da7923c6cdb69c354b4d1f716f989ffe1c5e38ebe160714fc076a2ef35263d03 |
| tools | getCollectionStats | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | getCollectionStats | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | getCollectionStats | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | getDatabaseStats | description | 2f005bf2d1ef3ed30b87589837768ea7e36b1813d24cadc6241e77ec257b087f |
| tools | getDatabaseStats | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | getDatabaseStats | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | insert | description | f71d4d5eaf31508d8489c635d18d722219b4b3dc8539a23efc5b73457b5ffa4b |
| tools | insert | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | insert | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | insert | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | insert | documents | 4e03f690f6f8ca97fee1cc6f2e9291cf8e687694be36aab4914cc2e214400008 |
| tools | listCollections | description | 3426de4fad17865cdae9c55c47c7ebbc283cffaf5d58351c8e91d8f287827cea |
| tools | listCollections | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | listCollections | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | listDatabases | description | 003b37dc3c6589a51907e4c64d63082f7811b70f029b6dc6c344e5c5b891db82 |
| tools | listDatabases | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | update | description | 6c06a4956503fb531ff8a06b2455e8cc9cc1701a1de6916c8cbf0f28ac33476b |
| tools | update | collection | 59df3d6da9335ffa9c708c1a21998514ac491ce6542c1646e2143ccb27cdb26e |
| tools | update | connection_id | d48af74d3053e2064b1d1d4fad975affa713f0e879450edf3fe83dc56b582a92 |
| tools | update | database | e694428633ff95f45853dc235e0201b12329ffa0d3c24ac627f89bf89b83a721 |
| tools | update | filter | 64a12adc239bec4a9a7cef0389a080f9303e0f8ab1294fbadc0a30345b9d693a |
| tools | update | many | c51c2af62d3169bb24e7b0d38a851481f1f790a690f8d97d32cb1606c09843b9 |
| tools | update | update | 95a140f5fac828e4916880cf1165d9d726b8efcd61e0737c294436f6f20ab74c |
| tools | update | upsert | 094fe1799dfe944d9598f2a9e2cce566327f246559d8a1ec0dcc351a4bfc48bf |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
