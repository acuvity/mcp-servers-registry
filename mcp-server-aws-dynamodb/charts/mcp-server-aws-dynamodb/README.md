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


# What is mcp-server-aws-dynamodb?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-dynamodb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-dynamodb/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-aws-dynamodb)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=awslabs.dynamodb-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/dynamodb-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-dynamodb/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-dynamodb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-dynamodb%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Official MCP server for AWS DynamoDB operations, table management, and backup features

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.dynamodb-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/dynamodb-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-dynamodb/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-dynamodb/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-dynamodb/charts/mcp-server-aws-dynamodb/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.dynamodb-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-dynamodb/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, Erben Mo <moerben@amazon.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/dynamodb-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.dynamodb-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/dynamodb-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.dynamodb-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/dynamodb-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-dynamodb/charts/mcp-server-aws-dynamodb)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-dynamodb/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-dynamodb:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-dynamodb:1.0.0-1.0.2`

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
  - `AWS_ACCESS_KEY_ID` secret to be set as secrets.AWS_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `AWS_SECRET_ACCESS_KEY` secret to be set as secrets.AWS_SECRET_ACCESS_KEY either by `.value` or from existing with `.valueFrom`
  - `AWS_SESSION_TOKEN` secret to be set as secrets.AWS_SESSION_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `AWS_REGION=""` environment variable can be changed with `env.AWS_REGION=""`
  - `AWS_PROFILE=""` environment variable can be changed with `env.AWS_PROFILE=""`
  - `DDB_MCP_READONLY="true"` environment variable can be changed with `env.DDB_MCP_READONLY="true"`

# How to install


Install will helm

```console
helm install mcp-server-aws-dynamodb oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-dynamodb oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-dynamodb
```

From there your MCP server mcp-server-aws-dynamodb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-dynamodb` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-dynamodb
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-dynamodb` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-dynamodb oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-dynamodb oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-dynamodb oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-dynamodb oci://docker.io/acuvity/mcp-server-aws-dynamodb --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (29)
<details>
<summary>put_resource_policy</summary>

**Description**:

```
Attaches a resource-based policy document (max 20 KB) to a DynamoDB table or stream. You can control permissions for both tables and their indexes through the policy.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| policy | any | An AWS resource-based policy document in JSON format or dictionary. | Yes
| region_name | string | The aws region to run the tool | No
| resource_arn | string | The Amazon Resource Name (ARN) of the DynamoDB resource | Yes
</details>
<details>
<summary>get_resource_policy</summary>

**Description**:

```
Returns the resource-based policy document attached to a DynamoDB table or stream in JSON format.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| resource_arn | string | The Amazon Resource Name (ARN) of the DynamoDB resource | Yes
</details>
<details>
<summary>scan</summary>

**Description**:

```
Returns items and attributes by scanning a table or secondary index. Reads up to Limit items or 1 MB of data, with optional FilterExpression to reduce results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| exclusive_start_key | object | Use the LastEvaluatedKey from the previous call. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| expression_attribute_names | object | Substitution tokens for attribute names in an expression. | No
| expression_attribute_values | object | Values that can be substituted in an expression. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| filter_expression | string | Filter conditions expression that DynamoDB applies to filter out data | No
| index_name | string | The name of a GSI | No
| limit | integer | The maximum number of items to evaluate | No
| projection_expression | string | Attributes to retrieve, can include scalars, sets, or elements of a JSON document. | No
| region_name | string | The aws region to run the tool | No
| select | string | The attributes to be returned. Valid values: ALL_ATTRIBUTES, ALL_PROJECTED_ATTRIBUTES, SPECIFIC_ATTRIBUTES, COUNT | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>query</summary>

**Description**:

```
Returns items from a table or index matching a partition key value, with optional sort key filtering.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| exclusive_start_key | object | Use the LastEvaluatedKey from the previous call. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| expression_attribute_names | object | Substitution tokens for attribute names in an expression. | No
| expression_attribute_values | object | Values that can be substituted in an expression. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| filter_expression | string | Filter conditions expression that DynamoDB applies to filter out data | No
| index_name | string | The name of a GSI | No
| key_condition_expression | string | Key condition expression. Must perform an equality test on partition key value. | Yes
| limit | integer | The maximum number of items to evaluate | No
| projection_expression | string | Attributes to retrieve, can include scalars, sets, or elements of a JSON document. | No
| region_name | string | The aws region to run the tool | No
| scan_index_forward | boolean | Ascending (true) or descending (false). | No
| select | string | The attributes to be returned. Valid values: ALL_ATTRIBUTES, ALL_PROJECTED_ATTRIBUTES, SPECIFIC_ATTRIBUTES, COUNT | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>update_item</summary>

**Description**:

```
Edits an existing item's attributes, or adds a new item to the table if it does not already exist.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| condition_expression | string | A condition that must be satisfied in order for a conditional update to succeed. | No
| expression_attribute_names | object | Substitution tokens for attribute names in an expression. | No
| expression_attribute_values | object | Values that can be substituted in an expression. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| key | object | The primary key of an item. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | Yes
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
| update_expression | string | Defines the attributes to be updated, the action to be performed on them, and new value(s) for them. The following actions are available:
    * SET - Adds one or more attributes and values to an item. If any of these attributes already exist, they are replaced by the new values.
    * REMOVE - Removes one or more attributes from an item.
    * ADD - Only supports Number and Set data types. Adds a value to a number attribute or adds elements to a set.
    * DELETE - Only supports Set data type. Removes elements from a set.
    For example: 'SET a=:value1, b=:value2 DELETE :value3, :value4, :value5' | No
</details>
<details>
<summary>get_item</summary>

**Description**:

```
Returns attributes for an item with the given primary key. Uses eventually consistent reads by default, or set ConsistentRead=true for strongly consistent reads.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| expression_attribute_names | object | Substitution tokens for attribute names in an expression. | No
| key | object | The primary key of an item. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | Yes
| projection_expression | string | Attributes to retrieve, can include scalars, sets, or elements of a JSON document. | No
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>put_item</summary>

**Description**:

```
Creates a new item or replaces an existing item in a table. Use condition expressions to control whether to create new items or update existing ones.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| condition_expression | string | A condition that must be satisfied in order for a conditional put operation to succeed. | No
| expression_attribute_names | object | Substitution tokens for attribute names in an expression. | No
| expression_attribute_values | object | Values that can be substituted in an expression. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| item | object | A map of attribute name/value pairs, one for each attribute. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | Yes
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>delete_item</summary>

**Description**:

```
Deletes a single item in a table by primary key. You can perform a conditional delete operation that deletes the item if it exists, or if it has an expected attribute value.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| condition_expression | string | The condition that must be satisfied in order for delete to succeed. | No
| expression_attribute_names | object | Substitution tokens for attribute names in an expression. | No
| expression_attribute_values | object | Values that can be substituted in an expression. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | No
| key | object | The primary key of an item. Must use DynamoDB attribute value format (see IMPORTANT note about DynamoDB Attribute Value Format). | Yes
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>update_time_to_live</summary>

**Description**:

```
Enables or disables Time to Live (TTL) for the specified table. Note: The epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
| time_to_live_specification | any | The new TTL settings | Yes
</details>
<details>
<summary>update_table</summary>

**Description**:

```
Modifies table settings including provisioned throughput, global secondary indexes, and DynamoDB Streams configuration. This is an asynchronous operation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| attribute_definitions | array | Describe the key schema for the table and indexes. Required when adding a new GSI. | No
| billing_mode | string | Specifies if billing is PAY_PER_REQUEST or by provisioned throughput | No
| deletion_protection_enabled | boolean | Indicates whether deletion protection is to be enabled | No
| global_secondary_index_updates | array | List of GSIs to be added, updated or deleted. | No
| on_demand_throughput | any | Set the max number of read and write units. | No
| provisioned_throughput | any | The new provisioned throughput settings. | No
| region_name | string | The aws region to run the tool | No
| replica_updates | array | A list of replica update actions (create, delete, or update). | No
| sse_specification | any | The new server-side encryption settings. | No
| stream_specification | any | DynamoDB Streams configuration. | No
| table_class | string | The new table class. | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
| warm_throughput | any | The new warm throughput settings. | No
</details>
<details>
<summary>list_tables</summary>

**Description**:

```
Returns a paginated list of table names in your account.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| exclusive_start_table_name | string | The LastEvaluatedTableName value from the previous paginated call | No
| limit | integer | Max number of table names to return | No
| region_name | string | The aws region to run the tool | No
</details>
<details>
<summary>create_table</summary>

**Description**:

```
Creates a new DynamoDB table with optional secondary indexes. This is an asynchronous operation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| attribute_definitions | array | Describe the key schema for the table and indexes. | Yes
| billing_mode | string | Specifies if billing is PAY_PER_REQUEST or by provisioned throughput | No
| global_secondary_indexes | array | GSIs to be created on the table. | No
| key_schema | array | Specifies primary key attributes of the table. | Yes
| provisioned_throughput | any | Provisioned throughput settings. Required if BillingMode is PROVISIONED. | No
| region_name | string | The aws region to run the tool | No
| table_name | string | The name of the table to create. | Yes
</details>
<details>
<summary>describe_table</summary>

**Description**:

```
Returns table information including status, creation time, key schema and indexes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>create_backup</summary>

**Description**:

```
Creates a backup of a DynamoDB table.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| backup_name | string | Specified name for the backup. | Yes
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>describe_backup</summary>

**Description**:

```
Describes an existing backup of a table.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| backup_arn | string | The Amazon Resource Name (ARN) associated with the backup. | Yes
| region_name | string | The aws region to run the tool | No
</details>
<details>
<summary>list_backups</summary>

**Description**:

```
Returns a list of table backups.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| backup_type | string | Filter by backup type: USER (on-demand backup created by you), SYSTEM (automatically created by DynamoDB), AWS_BACKUP (created by AWS Backup), or ALL (all types). | No
| exclusive_start_backup_arn | string | LastEvaluatedBackupArn from a previous paginated call. | No
| limit | integer | Maximum number of backups to return. | No
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>restore_table_from_backup</summary>

**Description**:

```
Creates a new table from a backup.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| backup_arn | string | The Amazon Resource Name (ARN) associated with the backup. | Yes
| region_name | string | The aws region to run the tool | No
| target_table_name | string | The name of the new table. | Yes
</details>
<details>
<summary>describe_limits</summary>

**Description**:

```
Returns the current provisioned-capacity quotas for your AWS account and tables in a Region.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
</details>
<details>
<summary>describe_time_to_live</summary>

**Description**:

```
Returns the Time to Live (TTL) settings for a table.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>describe_endpoints</summary>

**Description**:

```
Returns DynamoDB endpoints for the current region.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
</details>
<details>
<summary>describe_export</summary>

**Description**:

```
Returns information about a table export.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| export_arn | string | The Amazon Resource Name (ARN) associated with the export. | Yes
| region_name | string | The aws region to run the tool | No
</details>
<details>
<summary>list_exports</summary>

**Description**:

```
Returns a list of table exports.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_results | integer | Maximum number of results to return per page. | No
| next_token | string | Token to fetch the next page of results. | No
| region_name | string | The aws region to run the tool | No
| table_arn | string | The Amazon Resource Name (ARN) associated with the exported table. | No
</details>
<details>
<summary>describe_continuous_backups</summary>

**Description**:

```
Returns continuous backup and point in time recovery status for a table.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>untag_resource</summary>

**Description**:

```
Removes tags from a DynamoDB resource.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| resource_arn | string | The Amazon Resource Name (ARN) of the DynamoDB resource | Yes
| tag_keys | array | List of tags to remove. | Yes
</details>
<details>
<summary>tag_resource</summary>

**Description**:

```
Adds tags to a DynamoDB resource.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| resource_arn | string | The Amazon Resource Name (ARN) of the DynamoDB resource | Yes
| tags | array | Tags to be assigned. | Yes
</details>
<details>
<summary>list_tags_of_resource</summary>

**Description**:

```
Returns tags for a DynamoDB resource.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| next_token | string | The NextToken from the previous paginated call | No
| region_name | string | The aws region to run the tool | No
| resource_arn | string | The Amazon Resource Name (ARN) of the DynamoDB resource | Yes
</details>
<details>
<summary>delete_table</summary>

**Description**:

```
The DeleteTable operation deletes a table and all of its items. This is an asynchronous operation that puts the table into DELETING state until DynamoDB completes the deletion.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>update_continuous_backups</summary>

**Description**:

```
Enables or disables point in time recovery for the specified table.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| point_in_time_recovery_enabled | boolean | Enable or disable point in time recovery. | Yes
| recovery_period_in_days | integer | Number of days to retain point in time recovery backups. | No
| region_name | string | The aws region to run the tool | No
| table_name | string | Table Name or Amazon Resource Name (ARN) | Yes
</details>
<details>
<summary>list_imports</summary>

**Description**:

```
Lists imports completed within the past 90 days.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| next_token | string | Token to fetch the next page of results. | No
| region_name | string | The aws region to run the tool | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_backup | description | aa1b0226f0ac7076e9288e1f1d8193ad195f948d15efe921ea7ca7be9d3a12f3 |
| tools | create_backup | backup_name | ae1307ea0ca79dabbf4bb87301afe36f9b8f4fc2963b0e564d8b7226417dc51e |
| tools | create_backup | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | create_backup | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | create_table | description | aa721162b973bf06e076046f926e3fbde2abb3db97978cda074c16fbe64058ad |
| tools | create_table | attribute_definitions | d7e96a467c0c389f4cdf7967898c8d20b50cf8f7f6a337f927411e04c9f505c0 |
| tools | create_table | billing_mode | 3eee37a7eff74393a33b596e1f2a34be612c6ef07e521a292accde964d558d68 |
| tools | create_table | global_secondary_indexes | 7d4cefed1904e0a3ae4f61f250d532a29354d2472fbe8783fab143ca7cf5389a |
| tools | create_table | key_schema | 8910b52595396fbcf2724e20b4b3c1f2ad3f8abdacc1023bfd8a6de220ee9219 |
| tools | create_table | provisioned_throughput | 25e8a49f7dab7dec5c96993c97d49218a62ecc88ea75a3d67e26e00d97749a62 |
| tools | create_table | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | create_table | table_name | 1cad5729788dce2942a0a8cc3405928fbb6f2ffaab092919d1a80a3a35750ca5 |
| tools | delete_item | description | 7b17cdeac116a5f9f4f79147426ab60009ce03f8c2cf4f37fa8fa4ac5a659eb9 |
| tools | delete_item | condition_expression | f1d5ddfdac764e2059a108b3e4790a46e46784769f99a157ffb805b6ce7b457b |
| tools | delete_item | expression_attribute_names | fbfc9a05a270eb29a9e22207f880b89d1b22e78f98d101ca2ce6847bd4543877 |
| tools | delete_item | expression_attribute_values | e693ddffde63e2c2669aacfaadfd2b4bd9dd492545b5c0fff3f6a6194fb38ef8 |
| tools | delete_item | key | bdc9322df1680079c038356e8d7f795c3c4c7fd76da5613d108db681fe8062cb |
| tools | delete_item | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | delete_item | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | delete_table | description | cd25679bd2dd87d70a8d5ee9f6e57dbdb5038836ece6a690b9dc8698aa70ef0f |
| tools | delete_table | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | delete_table | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | describe_backup | description | 491a390d5296ac9b317e5957d8f5454a1557a09dbe89ae54fb871ce3f1519334 |
| tools | describe_backup | backup_arn | 769e2aba68da0baa0cf2c798bd6d6ef3e96fdc150f3a889fbabe7ac06b2a4f39 |
| tools | describe_backup | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_continuous_backups | description | e2a94423b82cd186fff74ebb405e721b498421e84a7073496db13f633f4895c9 |
| tools | describe_continuous_backups | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_continuous_backups | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | describe_endpoints | description | dbcf49469586bd0b919f101c057f70230cb522d6f720df121a1f9b4e9f05b8a6 |
| tools | describe_endpoints | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_export | description | df48fde481ebf8fecc617d0fc5eb37a48ebadac51a90dcd6b60a817486c5f1a8 |
| tools | describe_export | export_arn | de9856bd774aafa5cb92a23b0280545fc74d07750d12ba1fcb035e232cb9ba29 |
| tools | describe_export | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_limits | description | b90ecabb109a064e46609ac9437a386b0731a11d0e4fcd67e685c868b37e67ae |
| tools | describe_limits | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_table | description | 05844ece187a9ece59a229c4c19eba72f6b34ee7797750c9ad04e78d44bc9321 |
| tools | describe_table | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_table | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | describe_time_to_live | description | a4125da23691b56b73d05b98c06bad54bad41c708913ba9fe2064339d4b1383f |
| tools | describe_time_to_live | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | describe_time_to_live | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | get_item | description | ca35e40d82689c7a65459b2100615e5b20e61f68aea046201213087ba3f33520 |
| tools | get_item | expression_attribute_names | fbfc9a05a270eb29a9e22207f880b89d1b22e78f98d101ca2ce6847bd4543877 |
| tools | get_item | key | bdc9322df1680079c038356e8d7f795c3c4c7fd76da5613d108db681fe8062cb |
| tools | get_item | projection_expression | cf916bb5e3ad8bfb286cbf55f4f91ded7b7f9b371e1e63463c678688214722a4 |
| tools | get_item | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | get_item | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | get_resource_policy | description | e1d831f985fa2b69c9d5a204a56a10bc8afed96e7fe8e63ca44cf3532359599e |
| tools | get_resource_policy | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | get_resource_policy | resource_arn | 663e093f078e4591588706b8e11f343b89687ba94d79ff380e71056e3554a1d2 |
| tools | list_backups | description | 1e5e9a84a1ef4abd025e4c19e045f2403a76bc1f0fb28673718ca9e1f4b73649 |
| tools | list_backups | backup_type | 5bd4ffc8dffe3cb62e3e0940ec9e1649818267802b71099a2b21dd16f29870e6 |
| tools | list_backups | exclusive_start_backup_arn | e7e194ef5b2da64867bdd96a4522ef404e63c3a719bbbef91a344095b67afaba |
| tools | list_backups | limit | bf461d1511032a651f377cad2da242a04ea076335e27d6c8c61548a74964d907 |
| tools | list_backups | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | list_backups | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | list_exports | description | cffac4868cb0e46f7f751b3dd691a765f8389073daa07c8bb341abe3d333521f |
| tools | list_exports | max_results | 62e0397a9fa5c7bc73261b6e258cf7a5534d7681a1613abf5a83500e538dc8d7 |
| tools | list_exports | next_token | 57757ac7f0ce4d56f493ebc78aa116bfefd2a939d71717f8be8660f671b46247 |
| tools | list_exports | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | list_exports | table_arn | 9483b90cfbc6c39fb0dd01b9a694fa08f6a4a7cd48443ce2162b0fbb7124a4d6 |
| tools | list_imports | description | 54ada86c79e7f3dccacd29715b9bca2c70705395e60280956b6c6bce37fdf423 |
| tools | list_imports | next_token | 57757ac7f0ce4d56f493ebc78aa116bfefd2a939d71717f8be8660f671b46247 |
| tools | list_imports | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | list_tables | description | b1e951a564fc8a9cafc19201f8cafcffd3b730e1204d4a8887931eae489d84ec |
| tools | list_tables | exclusive_start_table_name | 6641da9977d2b381b95610b3addf2c6a169354f9f5795863f72a863539555dfc |
| tools | list_tables | limit | 2d71a837894de9017b7ecb644539d9066b82ab6e60e14b2176596850a36b6a48 |
| tools | list_tables | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | list_tags_of_resource | description | 8be3befdacc9351fa04d6628c1347a6d6318a26164f134071355a5208ef39826 |
| tools | list_tags_of_resource | next_token | ebd212ea806e1aa57822383ec73acf5153f8162c515457f2c7f7b6eaba6beea5 |
| tools | list_tags_of_resource | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | list_tags_of_resource | resource_arn | 663e093f078e4591588706b8e11f343b89687ba94d79ff380e71056e3554a1d2 |
| tools | put_item | description | e65e45b7bbac3b1df5c8ca499cc6c95466b8c1da1150ba14aecc607ac70c8b39 |
| tools | put_item | condition_expression | 52adcec0cf5ea4c97e589b6020c369107a79ddf1302cfc8699026031cde78bf3 |
| tools | put_item | expression_attribute_names | fbfc9a05a270eb29a9e22207f880b89d1b22e78f98d101ca2ce6847bd4543877 |
| tools | put_item | expression_attribute_values | e693ddffde63e2c2669aacfaadfd2b4bd9dd492545b5c0fff3f6a6194fb38ef8 |
| tools | put_item | item | feacbc59bf505a1092686758ff8a8fee7b82eab7a00f2202814bceeec9297dc3 |
| tools | put_item | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | put_item | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | put_resource_policy | description | 355310950d2e9a3a1cfe19d0f2eca4aabef4cb6864b0fcade19c3b3ec7d68e86 |
| tools | put_resource_policy | policy | c9d0860c8fe5cd40a761269ce43ddf11ff4a17c11776be90e88add40bfc514e5 |
| tools | put_resource_policy | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | put_resource_policy | resource_arn | 663e093f078e4591588706b8e11f343b89687ba94d79ff380e71056e3554a1d2 |
| tools | query | description | 9c530ec3f2d652a2215e80e89c3cd74772eeb856954d8544bb7c51a81e465856 |
| tools | query | exclusive_start_key | 70965f59e5531e3901579436d6e106fb0d113a25d56e94a04fb4cf8199e0e2bf |
| tools | query | expression_attribute_names | fbfc9a05a270eb29a9e22207f880b89d1b22e78f98d101ca2ce6847bd4543877 |
| tools | query | expression_attribute_values | e693ddffde63e2c2669aacfaadfd2b4bd9dd492545b5c0fff3f6a6194fb38ef8 |
| tools | query | filter_expression | fc1aeae9a60c7a4a74973625695b822ecaf304993ffce3d6575974269e57c808 |
| tools | query | index_name | 0bb4129c170fd7bac512c85d7148c36f677f3b0031b7c9814cdb288bbd793622 |
| tools | query | key_condition_expression | d5af709a64040543adee03512dc61d64c78469c85bdcf27331fdcef6694d74dd |
| tools | query | limit | 786cb1b73ceb35acbeb9dc369020a4e588976f50e466e06e1aa4cfd8cadcedeb |
| tools | query | projection_expression | cf916bb5e3ad8bfb286cbf55f4f91ded7b7f9b371e1e63463c678688214722a4 |
| tools | query | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | query | scan_index_forward | 8e051b291ceddb0b08afbeff787643b3869bd6a6477872afe12aed8b32728bca |
| tools | query | select | c21d183115e115342ef49499edb1d2eab4add7befda4a175634f32b03f16e23a |
| tools | query | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | restore_table_from_backup | description | 1134e708923498f967a0d8a95fb567220bdbd083b28bb5afd9c45f05a5f3710e |
| tools | restore_table_from_backup | backup_arn | 769e2aba68da0baa0cf2c798bd6d6ef3e96fdc150f3a889fbabe7ac06b2a4f39 |
| tools | restore_table_from_backup | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | restore_table_from_backup | target_table_name | 629073d9aa8eb823ab721d2611153f273376809007ec877e1e4eb1ee5bde29a4 |
| tools | scan | description | 35fa3bff11499defa77db7eb59669eb23359664f48f345076d978bf6db41689a |
| tools | scan | exclusive_start_key | 70965f59e5531e3901579436d6e106fb0d113a25d56e94a04fb4cf8199e0e2bf |
| tools | scan | expression_attribute_names | fbfc9a05a270eb29a9e22207f880b89d1b22e78f98d101ca2ce6847bd4543877 |
| tools | scan | expression_attribute_values | e693ddffde63e2c2669aacfaadfd2b4bd9dd492545b5c0fff3f6a6194fb38ef8 |
| tools | scan | filter_expression | fc1aeae9a60c7a4a74973625695b822ecaf304993ffce3d6575974269e57c808 |
| tools | scan | index_name | 0bb4129c170fd7bac512c85d7148c36f677f3b0031b7c9814cdb288bbd793622 |
| tools | scan | limit | 786cb1b73ceb35acbeb9dc369020a4e588976f50e466e06e1aa4cfd8cadcedeb |
| tools | scan | projection_expression | cf916bb5e3ad8bfb286cbf55f4f91ded7b7f9b371e1e63463c678688214722a4 |
| tools | scan | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | scan | select | c21d183115e115342ef49499edb1d2eab4add7befda4a175634f32b03f16e23a |
| tools | scan | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | tag_resource | description | f49d96b828384ce532b4fc081f6df7f2e9d58a59d49721c5ed147a555dc88214 |
| tools | tag_resource | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | tag_resource | resource_arn | 663e093f078e4591588706b8e11f343b89687ba94d79ff380e71056e3554a1d2 |
| tools | tag_resource | tags | 2d16335ac2e1897be3f56965b1c4ddca4c0dd9fc1cf7a3e40d0a60b9015cac47 |
| tools | untag_resource | description | 324a144e52ade7c3f915aec8b7fe21b09aa9ed3b3ca1ff14499bc00d5934874b |
| tools | untag_resource | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | untag_resource | resource_arn | 663e093f078e4591588706b8e11f343b89687ba94d79ff380e71056e3554a1d2 |
| tools | untag_resource | tag_keys | 6cbfc2d4e74bf941d846318fa33d92cbe3db109cc48ef4cd9c685e7333d51741 |
| tools | update_continuous_backups | description | a139bc23a59445a92d7f692c01efad5ed5289e359b322daa42189bfa7eda05bd |
| tools | update_continuous_backups | point_in_time_recovery_enabled | 335ad2a33da25763b6df0ec2dd0f60cc977c742deef00e069bf675ed55d46f05 |
| tools | update_continuous_backups | recovery_period_in_days | bdd70c400553b0d77373e745f9e2b9c5e058455ecb6a0d114aeae709bbfa8f99 |
| tools | update_continuous_backups | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | update_continuous_backups | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | update_item | description | 31be0041c581722a17ad4137a7184a3cff10009408f3985e3900a4171ff1d7b6 |
| tools | update_item | condition_expression | 811990c865c1d49f9dccd6a17400defa622e433ed301d5f2c2eeec9efce89a60 |
| tools | update_item | expression_attribute_names | fbfc9a05a270eb29a9e22207f880b89d1b22e78f98d101ca2ce6847bd4543877 |
| tools | update_item | expression_attribute_values | e693ddffde63e2c2669aacfaadfd2b4bd9dd492545b5c0fff3f6a6194fb38ef8 |
| tools | update_item | key | bdc9322df1680079c038356e8d7f795c3c4c7fd76da5613d108db681fe8062cb |
| tools | update_item | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | update_item | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | update_item | update_expression | ee62f61d432f2821f214092156ae57634dd54982fcf202a5bb3fa082956c4c0d |
| tools | update_table | description | 79c8c188db8f404a297222055a04f51b527549dda6c2c2a27e226f3c999972f6 |
| tools | update_table | attribute_definitions | 0ed8d2c5b22adba789ffb133679427a33d1d81a0f7647bd05b44c5c5138ec8a7 |
| tools | update_table | billing_mode | 3eee37a7eff74393a33b596e1f2a34be612c6ef07e521a292accde964d558d68 |
| tools | update_table | deletion_protection_enabled | cb8658af12a9252f17e3c681987ce36745f86a9b62d986658067cd52af1a53af |
| tools | update_table | global_secondary_index_updates | 73ba5e1b01c737dadad2cbf8082ac0e4b982b692b94a8ab485f9fcbbd7d12644 |
| tools | update_table | on_demand_throughput | be3218b91b93d425721fd6c5c4ffb2520712f17baad2bd8b3ff9da1639f07cd8 |
| tools | update_table | provisioned_throughput | 534168f175700cb2bbece454c21051377fad16d86284a1ffd4d695d7acc83bc0 |
| tools | update_table | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | update_table | replica_updates | 51d0075240bdc432878fcf02bb807c5dfde79c4edc5ad52822ae77aa5ae58172 |
| tools | update_table | sse_specification | 21bed35c691580ffbf13e6dfa2123a712ed4aae20f3ccee5325df8101c70ade5 |
| tools | update_table | stream_specification | 484f10b1ff08a300e3ba77ca7df343cbd8799aaa6b4c8811f0efe5586eeab2b8 |
| tools | update_table | table_class | 99a5a4444f712f37fd1e97444b21deb30103da4ad0c055717da7676af8dbb590 |
| tools | update_table | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | update_table | warm_throughput | c61502b1a6a2f40a7cb0401e9c9a7b134e692bf63299079fafd54f467ed90eee |
| tools | update_time_to_live | description | bcf3ba7bbebb1e77b8b2fbc06b79ccc3688289c2fd6da287037ac738282f8686 |
| tools | update_time_to_live | region_name | ebd1e457dcbfdd50170e3180b475bc4fd801cc15e159298d4aba38a9ebcd6370 |
| tools | update_time_to_live | table_name | d39d22b659b17bfff25f5d34308e461fb02bd321fbc90e9185edb300c32c6c34 |
| tools | update_time_to_live | time_to_live_specification | 6078074b7a8f0c6cb3cf67e1c34808558872206e6f72b1311f85d1a5ef5f8ad2 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
