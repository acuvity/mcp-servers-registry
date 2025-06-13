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


# What is mcp-server-aws-timestream-influxdb?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-timestream-influxdb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-timestream-influxdb/0.0.1?logo=docker&logoColor=fff&label=0.0.1)](https://hub.docker.com/r/acuvity/mcp-server-aws-timestream-influxdb)
[![PyPI](https://img.shields.io/badge/0.0.1-3775A9?logo=pypi&logoColor=fff&label=awslabs.timestream-for-influxdb-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/timestream-for-influxdb-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-timestream-influxdb/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-timestream-influxdb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-timestream-influxdb%3A0.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Manage AWS Timestream for InfluxDB instances, clusters, parameter groups and query time-series data

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.timestream-for-influxdb-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/timestream-for-influxdb-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-timestream-influxdb/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-timestream-influxdb/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-timestream-influxdb/charts/mcp-server-aws-timestream-influxdb/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.timestream-for-influxdb-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-timestream-influxdb/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, Lokendra Panwar <lokendrp@amazon.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/timestream-for-influxdb-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.timestream-for-influxdb-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/timestream-for-influxdb-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.timestream-for-influxdb-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/timestream-for-influxdb-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-timestream-influxdb/charts/mcp-server-aws-timestream-influxdb)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-timestream-influxdb/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.0.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-timestream-influxdb:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-timestream-influxdb:1.0.0-0.0.1`

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
  - `AWS_PROFILE=""` environment variable can be changed with `env.AWS_PROFILE=""`
  - `AWS_REGION=""` environment variable can be changed with `env.AWS_REGION=""`

# How to install


Install will helm

```console
helm install mcp-server-aws-timestream-influxdb oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-timestream-influxdb oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-timestream-influxdb
```

From there your MCP server mcp-server-aws-timestream-influxdb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-timestream-influxdb` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-timestream-influxdb
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-timestream-influxdb` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-timestream-influxdb oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-timestream-influxdb oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-timestream-influxdb oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-timestream-influxdb oci://docker.io/acuvity/mcp-server-aws-timestream-influxdb --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (22)
<details>
<summary>CreateDbCluster</summary>

**Description**:

```
Create a new Timestream for InfluxDB database cluster.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allocated_storage_gb | integer | The amount of storage to allocate for your DB storage type in GiB (gibibytes). | Yes
| bucket | any | The name of the initial InfluxDB bucket. | No
| db_instance_type | string | The Timestream for InfluxDB DB instance type to run InfluxDB on. | Yes
| db_parameter_group_identifier | any | The id of the DB parameter group to assign to your DB. | No
| db_storage_type | any | The Timestream for InfluxDB DB storage type to read and write InfluxDB data. | No
| deployment_type | any | Specifies whether the DB instance will be deployed as a standalone instance or with a Multi-AZ standby for high availability. | No
| failover_mode | any | Specifies the behavior of failure recovery when the primary node of the cluster fails. | No
| log_delivery_configuration | any | Configuration for sending InfluxDB engine logs to a specified S3 bucket. | No
| name | string | The name that uniquely identifies the DB cluster when interacting with the Amazon Timestream for InfluxDB API and CLI commands. This name will also be a prefix included in the endpoint. | Yes
| networkType | any | Specifies whether the network type of the Timestream for InfluxDB cluster is IPv4 or DUAL. | No
| organization | any | The name of the initial organization for the initial admin user in InfluxDB.An InfluxDB organization is a workspace for a group of users | No
| password | string | The password of the initial admin user created in InfluxDB. This password will allow you to access the InfluxDB UI to perform various administrative task and also use the InfluxDB CLI to create an operator token. | Yes
| port | any | The port number on which InfluxDB accepts connections. Default: 8086 | No
| publicly_accessible | boolean | Configures the DB with a public IP to facilitate access from outside the VPC. | No
| tags | any | A list of tags to assign to the DB. | No
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
| username | any | The username of the initial admin user created in InfluxDB. | No
| vpc_security_group_ids | array | A list of VPC security group IDs to associate with the DB. | Yes
| vpc_subnet_ids | array | A list of VPC subnet IDs to associate with the DB. Provide at least two VPC subnet IDs in different Availability Zones when deploying with a Multi-AZ standby. | Yes
</details>
<details>
<summary>CreateDbInstance</summary>

**Description**:

```
Create a new Timestream for InfluxDB database instance
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allocated_storage_gb | integer | The amount of storage to allocate for your DB storage type in GiB (gibibytes). | Yes
| bucket | any | The name of the initial InfluxDB bucket. | No
| db_instance_name | string | The name that uniquely identifies the DB instance. This name will also be a prefix included in the endpoint. DB instance names must be unique per customer and per region. | Yes
| db_instance_type | string | The Timestream for InfluxDB DB instance type to run InfluxDB on. | Yes
| db_parameter_group_id | any | The id of the DB parameter group to assign to your DB. | No
| db_storage_type | any | The Timestream for InfluxDB DB storage type to read and write InfluxDB data. | No
| deployment_type | any | Specifies whether the DB instance will be deployed as a standalone instance or with a Multi-AZ standby for high availability. | No
| networkType | any | Specifies whether the network type of the Timestream for InfluxDB cluster is IPv4 or DUAL. | No
| organization | any | The name of the initial organization for the initial admin user in InfluxDB.An InfluxDB organization is a workspace for a group of users | No
| password | string | The password of the initial admin user created in InfluxDB. This password will allow you to access the InfluxDB UI to perform various administrative task and also use the InfluxDB CLI to create an operator token. | Yes
| port | any | The port number on which InfluxDB accepts connections. Default: 8086 | No
| publicly_accessible | boolean | Configures the DB with a public IP to facilitate access from outside the VPC. | No
| tags | any | A list of tags to assign to the DB. | No
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
| username | any | The username of the initial admin user created in InfluxDB. | No
| vpc_security_group_ids | array | A list of VPC security group IDs to associate with the DB. | Yes
| vpc_subnet_ids | array | A list of VPC subnet IDs to associate with the DB. Provide at least two VPC subnet IDs in different Availability Zones when deploying with a Multi-AZ standby. | Yes
</details>
<details>
<summary>LsInstancesOfCluster</summary>

**Description**:

```
List all Timestream for InfluxDB instances belonging to a specific DB cluster.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_cluster_id | string | Service-generated unique identifier of the DB cluster. | Yes
| max_results | any | The maximum number of items to return in the output. If the total number of items available is more than the value specified, a nextToken is provided in the output. | No
| next_token | any | The pagination token. To resume pagination, provide the next-token value as an argument of a subsequent API invocation. | No
</details>
<details>
<summary>ListDbInstances</summary>

**Description**:

```
List all Timestream for InfluxDB DB instances
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_results | any | The maximum number of items to return in the output. If the total number of items available is more than the value specified, a nextToken is provided in the output. | No
| next_token | any | The pagination token. To resume pagination, provide the next-token value as an argument of a subsequent API invocation. | No
</details>
<details>
<summary>ListDbClusters</summary>

**Description**:

```
List all Timestream for InfluxDB DB clusters.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_results | any | The maximum number of items to return in the output. If the total number of items available is more than the value specified, a nextToken is provided in the output. | No
| next_token | any | The pagination token. To resume pagination, provide the next-token value as an argument of a subsequent API invocation. | No
</details>
<details>
<summary>GetDbParameterGroup</summary>

**Description**:

```
Get a Timestream for InfluxDB DB parameter group details for a db_parameter_group_id
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | The id of the DB parameter group. | Yes
</details>
<details>
<summary>GetDbInstance</summary>

**Description**:

```
Returns a Timestream for InfluxDB DB instance details by the instance-identifier
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | The id of the DB instance. | Yes
</details>
<details>
<summary>GetDbCluster</summary>

**Description**:

```
Returns a Timestream for InfluxDB DB cluster details by the db_cluster_id
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_cluster_id | string | Service-generated unique identifier of the DB cluster. | Yes
</details>
<details>
<summary>DeleteDbInstance</summary>

**Description**:

```
Deletes a Timestream for InfluxDB DB instance by the instance-identifier
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | The id of the DB instance. | Yes
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>DeleteDbCluster</summary>

**Description**:

```
Deletes a Timestream for InfluxDB cluster by the db_cluster_id
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_cluster_id | string | Service-generated unique identifier of the DB cluster. | Yes
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>ListDbParamGroups</summary>

**Description**:

```
List all Timestream for InfluxDB DB parameter groups.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_results | any | The maximum number of items to return in the output. If the total number of items available is more than the value specified, a nextToken is provided in the output. | No
| next_token | any | The pagination token. To resume pagination, provide the next-token value as an argument of a subsequent API invocation. | No
</details>
<details>
<summary>ListTagsForResource</summary>

**Description**:

```
A list of tags applied to the resource.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resource_arn | string | The Amazon Resource Name (ARN) of the tagged resource. | Yes
</details>
<details>
<summary>TagResource</summary>

**Description**:

```
Tags are composed of a Key/Value pairs. Apply them to Timestream for InfluxDB resource.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resource_arn | string | The Amazon Resource Name (ARN) of the tagged resource. | Yes
| tags | object | A list of key-value pairs as tags. | Yes
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>UntagResource</summary>

**Description**:

```
Removes the tags, identified by the keys, from the specified resource.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resource_arn | string | The Amazon Resource Name (ARN) of the tagged resource. | Yes
| tag_keys | array | The keys used to identify the tags to remove. | Yes
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>UpdateDbCluster</summary>

**Description**:

```
Updates a Timestream for InfluxDB cluster.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| db_cluster_id | string | Service-generated unique identifier of the DB cluster. | Yes
| db_instance_type | any | Update the DB cluster to use the specified DB instance Type. | No
| db_parameter_group_identifier | any | Update the DB cluster to use the specified DB parameter group. | No
| failover_mode | any | Update the DB cluster's failover behavior. | No
| log_delivery_configuration | any | The log delivery configuration to apply to the DB cluster. | No
| port | any | Update the DB cluster to use the specified port. | No
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>UpdateDbInstance</summary>

**Description**:

```
Updates a Timestream for InfluxDB DB instance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| allocated_storage_gb | any | The amount of storage to allocate for your DB storage type (in gibibytes). | No
| db_instance_type | any | Update the DB cluster to use the specified DB instance Type. | No
| db_parameter_group_identifier | any | The id of the DB parameter group to assign to your DB. | No
| db_storage_type | any | The Timestream for InfluxDB DB storage type to read and write InfluxDB data. | No
| deployment_type | any | Specifies whether the DB instance will be deployed as a standalone instance or with a Multi-AZ standby for high availability. | No
| identifier | string | The id of the DB instance. | Yes
| log_delivery_configuration | any | Configuration for sending InfluxDB engine logs to a specified S3 bucket. | No
| port | any | The port number on which InfluxDB accepts connections. Default: 8086 | No
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>LsInstancesByStatus</summary>

**Description**:

```
Returns a list of Timestream for InfluxDB DB instances filtered by status (case-insensitive).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| status | string | The status to filter DB instances by (case-insensitive). | Yes
</details>
<details>
<summary>ListClustersByStatus</summary>

**Description**:

```
Returns a list of Timestream for InfluxDB DB clusters filtered by status (case-insensitive).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| status | string | The status to filter DB clusters by (case-insensitive). | Yes
</details>
<details>
<summary>CreateDbParamGroup</summary>

**Description**:

```
Creates a new Timestream for InfluxDB DB parameter group to associate with DB instances.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | A description of the DB parameter group. | No
| name | string | The name of the DB parameter group. The name must be unique per customer and per region. | Yes
| parameters | any | A list of the parameters that comprise the DB parameter group. | No
| tags | any | A list of tags to assign to the DB. | No
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
</details>
<details>
<summary>InfluxDBWritePoints</summary>

**Description**:

```
Write data points to InfluxDB endpoint.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| bucket | string | The name of the initial InfluxDB bucket. | Yes
| org | string | The organization name. | Yes
| points | array | List of data points to write. Each point should be a dictionary with measurement, tags, fields, and optional time. | Yes
| sync_mode | any | The synchronization mode, either 'synchronous' or 'asynchronous'. | No
| time_precision | string | The precision for the unix timestamps within the body line-protocol. One of: ns, us, ms, s (default is ns). | No
| token | string | The authentication token. | Yes
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
| url | string | The URL of the InfluxDB server. | Yes
| verify_ssl | boolean | Whether to verify SSL with https connections. | No
</details>
<details>
<summary>InfluxDBWriteLP</summary>

**Description**:

```
Write data in Line Protocol format to InfluxDB.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| bucket | string | The name of the initial InfluxDB bucket. | Yes
| data_line_protocol | string | Data in InfluxDB Line Protocol format. | Yes
| org | string | The organization name. | Yes
| sync_mode | string | The synchronization mode, either 'synchronous' or 'asynchronous'. | No
| time_precision | string | The precision for the unix timestamps within the body line-protocol. One of: ns, us, ms, s (default is ns). | No
| token | string | The authentication token. | Yes
| tool_write_mode | boolean | Tool is run in write mode and will be able to perform any create/update/delete operations. Default is read-only mode (False) | No
| url | string | The URL of the InfluxDB server. | Yes
| verify_ssl | boolean | Whether to verify SSL with https connections. | No
</details>
<details>
<summary>InfluxDBQuery</summary>

**Description**:

```
Query data from InfluxDB using Flux query language.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| org | string | The organization name. | Yes
| query | string | The Flux query string. | Yes
| token | string | The authentication token. | Yes
| url | string | The URL of the InfluxDB server. | Yes
| verify_ssl | boolean | Whether to verify SSL with https connections. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | CreateDbCluster | description | a5563b63c69213815b7bfe80c2a62dbb076fa46709f570dbca0ddbb6000dc32c |
| tools | CreateDbCluster | allocated_storage_gb | fd0d1a266754ef1e1b59653849303d2aaadbf310b87960d892a14d4e28e2935c |
| tools | CreateDbCluster | bucket | 352740f2d92b9e79d84d1d3f10e5acdd7ec207b579f108728e9c3cdfe6422198 |
| tools | CreateDbCluster | db_instance_type | cede65351eb8b957b2376de6e487158687cf0498e00be0ccebdf51184a2c7f6c |
| tools | CreateDbCluster | db_parameter_group_identifier | 2dd7c9f2ee8c9d0f768afebd07a3377fc4e10da15a25091996c1d41bfc4927df |
| tools | CreateDbCluster | db_storage_type | 28009caa9a178e0ddfc62c9265bfd8fb082ff9d026c5b4d94c7327c91b09be82 |
| tools | CreateDbCluster | deployment_type | e92f1a36e7444e1d8596fce1b1cb9d011830b5c4891d6a5da43a3fc25a68e015 |
| tools | CreateDbCluster | failover_mode | 8f406946eb44bbe297ebdef5563c335fcef6f06a881aa4b65126a74ac1640dd9 |
| tools | CreateDbCluster | log_delivery_configuration | bf20343694b4d14b8dc85910793929fc2288a40a3dce28a3c4868810f16dc5b5 |
| tools | CreateDbCluster | name | d5a83d33169c24d1a0557293d60447abd741d6fd5ed32378059fa7e0f623bb00 |
| tools | CreateDbCluster | networkType | c0967df8c1ebceaff9907eff47955b4a05e666734fbf20807e4a414e3167a3f8 |
| tools | CreateDbCluster | organization | e6fc5b673d53ccafd14b0e7a55db1508251f03c908031ad8687133f76cde002e |
| tools | CreateDbCluster | password | f9e09fef7ad486613b67452bc498d7d0aaf9531299817720150768ff9c139e10 |
| tools | CreateDbCluster | port | 219b1ba4672897f13942751b3a22d99f173d3c3916b9c926bd9fecb41ee0ebc2 |
| tools | CreateDbCluster | publicly_accessible | a242b330c0f9f46e618cf30e174c79ad96bd5a533ca1281c8e72bc757675e31d |
| tools | CreateDbCluster | tags | 4c9834f201371cfd315e516ead53d0044c1b511c6c508f986a393874c99dcfb6 |
| tools | CreateDbCluster | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | CreateDbCluster | username | cb290c2fdffc9170e870b496916298e1ec9b3b69d53f8cd805608cc70099efbf |
| tools | CreateDbCluster | vpc_security_group_ids | 479ee27f3455d53ad640b52a8c6e9987e13af3377ebe19b0a7d01450d55ea7c9 |
| tools | CreateDbCluster | vpc_subnet_ids | 378b02f71f08135a026a8808e32338d5f5562d0b8ca1b8d36872a838cef5ae20 |
| tools | CreateDbInstance | description | 2ac63c868608c8fb762eb69e86b0dbccf2f8b2178452f71e1c9017eaa5faacfd |
| tools | CreateDbInstance | allocated_storage_gb | fd0d1a266754ef1e1b59653849303d2aaadbf310b87960d892a14d4e28e2935c |
| tools | CreateDbInstance | bucket | 352740f2d92b9e79d84d1d3f10e5acdd7ec207b579f108728e9c3cdfe6422198 |
| tools | CreateDbInstance | db_instance_name | ce3d519eac4feb0c2986a22ec2064230926379b1982fce1b338a60aab53a2dca |
| tools | CreateDbInstance | db_instance_type | cede65351eb8b957b2376de6e487158687cf0498e00be0ccebdf51184a2c7f6c |
| tools | CreateDbInstance | db_parameter_group_id | 2dd7c9f2ee8c9d0f768afebd07a3377fc4e10da15a25091996c1d41bfc4927df |
| tools | CreateDbInstance | db_storage_type | 28009caa9a178e0ddfc62c9265bfd8fb082ff9d026c5b4d94c7327c91b09be82 |
| tools | CreateDbInstance | deployment_type | e92f1a36e7444e1d8596fce1b1cb9d011830b5c4891d6a5da43a3fc25a68e015 |
| tools | CreateDbInstance | networkType | c0967df8c1ebceaff9907eff47955b4a05e666734fbf20807e4a414e3167a3f8 |
| tools | CreateDbInstance | organization | e6fc5b673d53ccafd14b0e7a55db1508251f03c908031ad8687133f76cde002e |
| tools | CreateDbInstance | password | f9e09fef7ad486613b67452bc498d7d0aaf9531299817720150768ff9c139e10 |
| tools | CreateDbInstance | port | 219b1ba4672897f13942751b3a22d99f173d3c3916b9c926bd9fecb41ee0ebc2 |
| tools | CreateDbInstance | publicly_accessible | a242b330c0f9f46e618cf30e174c79ad96bd5a533ca1281c8e72bc757675e31d |
| tools | CreateDbInstance | tags | 4c9834f201371cfd315e516ead53d0044c1b511c6c508f986a393874c99dcfb6 |
| tools | CreateDbInstance | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | CreateDbInstance | username | cb290c2fdffc9170e870b496916298e1ec9b3b69d53f8cd805608cc70099efbf |
| tools | CreateDbInstance | vpc_security_group_ids | 479ee27f3455d53ad640b52a8c6e9987e13af3377ebe19b0a7d01450d55ea7c9 |
| tools | CreateDbInstance | vpc_subnet_ids | 378b02f71f08135a026a8808e32338d5f5562d0b8ca1b8d36872a838cef5ae20 |
| tools | CreateDbParamGroup | description | 2513ed0ebeb2a2c329037488bd3120adde5944aa1d73ee20c053ba21e290d661 |
| tools | CreateDbParamGroup | description | 6b90473bb92de59c8c8fda80bb3a52db88abe83dd9071a1dd6497d38faa01d68 |
| tools | CreateDbParamGroup | name | d40a7cf76305b8b0b2f4974b8d741e195cd02d44ab7d64b8de76fa9a43656d13 |
| tools | CreateDbParamGroup | parameters | fb991d3627b75c40b95d1fa2da61c3f32d3eae7daa81016ac14eff222290da8c |
| tools | CreateDbParamGroup | tags | 4c9834f201371cfd315e516ead53d0044c1b511c6c508f986a393874c99dcfb6 |
| tools | CreateDbParamGroup | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | DeleteDbCluster | description | 6b05b4946a4bddf98833260acc8df75f1000d675e75d8825b0f569ad273037fb |
| tools | DeleteDbCluster | db_cluster_id | 8f368411ea56feab48f10fc427d9617f1f6d1ddebf1aaa66871e4c5f6db30e2c |
| tools | DeleteDbCluster | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | DeleteDbInstance | description | 93384232011eddc20e457cae7ac6f06fed12b7d6e677c79e2e8d4b2321e2a9ca |
| tools | DeleteDbInstance | identifier | 009832f652b3b487514a11820811f67db68fc43b82d8f6a282fb8b807af34703 |
| tools | DeleteDbInstance | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | GetDbCluster | description | bfb84511a20b5f73050ff421794bacd920b9770e2456ba33c84114b12bea67fc |
| tools | GetDbCluster | db_cluster_id | 8f368411ea56feab48f10fc427d9617f1f6d1ddebf1aaa66871e4c5f6db30e2c |
| tools | GetDbInstance | description | 87a6fc06329ae2d4e01d6d56b954cf79e5e6f8bc21622a80006d5ba776f70c0a |
| tools | GetDbInstance | identifier | 009832f652b3b487514a11820811f67db68fc43b82d8f6a282fb8b807af34703 |
| tools | GetDbParameterGroup | description | 47cc659df7164c7579591909378989a246321d4ff58ed7614d4785940f12bda0 |
| tools | GetDbParameterGroup | identifier | 62048ccd00fff3329ccd41804a819215e11cce8c2efb3d6bd4f988d305c20dfa |
| tools | InfluxDBQuery | description | 127bb10045e41c841b258bd8c5159841199b85450ba5e1498e68fc58db45dd59 |
| tools | InfluxDBQuery | org | c2ef1ad81e200eb6813b673ca9196a80b7c5865aafa1033350aeb17065b874f1 |
| tools | InfluxDBQuery | query | 8db6c86c71a264a94d0799f24af6095823a1dba81d0fa362f5c3e9941e9f9f7e |
| tools | InfluxDBQuery | token | 2cda0df1bac11eb684a64911c39f5a7fff1d5ba7dfedeb0d829c507b97e30e80 |
| tools | InfluxDBQuery | url | 176572d6441b65e1892f5a571113b2dc5cd87e0da6b2fdca0580f79e9af285e0 |
| tools | InfluxDBQuery | verify_ssl | 0b0b938b0a9964f5f89bf3d7c512977e4052830e6d582a440479b09bce1476ea |
| tools | InfluxDBWriteLP | description | 4d2c71db449734290a8f1957dfbf59f08546a65a163720921a17e4e116e3f7b5 |
| tools | InfluxDBWriteLP | bucket | 352740f2d92b9e79d84d1d3f10e5acdd7ec207b579f108728e9c3cdfe6422198 |
| tools | InfluxDBWriteLP | data_line_protocol | 60d8268b5d54ef1109d25345932dea05ae90bcddf1c7601d604f2d00a8008423 |
| tools | InfluxDBWriteLP | org | c2ef1ad81e200eb6813b673ca9196a80b7c5865aafa1033350aeb17065b874f1 |
| tools | InfluxDBWriteLP | sync_mode | 7e48f89dafe829bb2d2166ca698d540f32d0eb28aceedf7ea867e734a76c606c |
| tools | InfluxDBWriteLP | time_precision | 983049e635576a4c6aae7078177389369ab07b3491417b683b73aa45074abab2 |
| tools | InfluxDBWriteLP | token | 2cda0df1bac11eb684a64911c39f5a7fff1d5ba7dfedeb0d829c507b97e30e80 |
| tools | InfluxDBWriteLP | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | InfluxDBWriteLP | url | 176572d6441b65e1892f5a571113b2dc5cd87e0da6b2fdca0580f79e9af285e0 |
| tools | InfluxDBWriteLP | verify_ssl | 0b0b938b0a9964f5f89bf3d7c512977e4052830e6d582a440479b09bce1476ea |
| tools | InfluxDBWritePoints | description | a54692d1bb7a26942786a9752406d6a21a0a2967b3ca29ccf8c17bd750bedff6 |
| tools | InfluxDBWritePoints | bucket | 352740f2d92b9e79d84d1d3f10e5acdd7ec207b579f108728e9c3cdfe6422198 |
| tools | InfluxDBWritePoints | org | c2ef1ad81e200eb6813b673ca9196a80b7c5865aafa1033350aeb17065b874f1 |
| tools | InfluxDBWritePoints | points | cf5881634a58c9b9f5730dfd0ec826a0c3927b77c67fff2be9068e68154b021a |
| tools | InfluxDBWritePoints | sync_mode | 7e48f89dafe829bb2d2166ca698d540f32d0eb28aceedf7ea867e734a76c606c |
| tools | InfluxDBWritePoints | time_precision | 983049e635576a4c6aae7078177389369ab07b3491417b683b73aa45074abab2 |
| tools | InfluxDBWritePoints | token | 2cda0df1bac11eb684a64911c39f5a7fff1d5ba7dfedeb0d829c507b97e30e80 |
| tools | InfluxDBWritePoints | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | InfluxDBWritePoints | url | 176572d6441b65e1892f5a571113b2dc5cd87e0da6b2fdca0580f79e9af285e0 |
| tools | InfluxDBWritePoints | verify_ssl | 0b0b938b0a9964f5f89bf3d7c512977e4052830e6d582a440479b09bce1476ea |
| tools | ListClustersByStatus | description | 3efb45f46e69127a611989a5d2d942806b2c621668476216ec62142d0a730c3f |
| tools | ListClustersByStatus | status | 5ef9ba5742a34f7e982ab51094033b416df1eb304433c7ab3d0b68def2ab5f1d |
| tools | ListDbClusters | description | d0542271dd8291930a3f011dcf9541dfdb5280591fdbdcfcd8ea2c2326dbb0cc |
| tools | ListDbClusters | max_results | e4ff96a9e0cd58f24a90970f666b3dec789d6cd7227ed2755bc219a902946e7f |
| tools | ListDbClusters | next_token | ce20a3a3ac2a5ed58156cb9a73d478a4817f236a743cb0811712d6ca0db4a16a |
| tools | ListDbInstances | description | 0dd9730b7e8eee0a187e9a4aecc78cbd34e3352c01714fa65de63d0ae067c218 |
| tools | ListDbInstances | max_results | e4ff96a9e0cd58f24a90970f666b3dec789d6cd7227ed2755bc219a902946e7f |
| tools | ListDbInstances | next_token | ce20a3a3ac2a5ed58156cb9a73d478a4817f236a743cb0811712d6ca0db4a16a |
| tools | ListDbParamGroups | description | fc37e95c6c41362172ab5fab829101c2c7e3fe8831f74f3412b5c8d770716f7d |
| tools | ListDbParamGroups | max_results | e4ff96a9e0cd58f24a90970f666b3dec789d6cd7227ed2755bc219a902946e7f |
| tools | ListDbParamGroups | next_token | ce20a3a3ac2a5ed58156cb9a73d478a4817f236a743cb0811712d6ca0db4a16a |
| tools | ListTagsForResource | description | 0fcaee43e4c7aca588f0d73267ec579fe4cc5b96dad0a52c1eb3db010895cef0 |
| tools | ListTagsForResource | resource_arn | c19b9c1e8e4b825d4ae3bf1b01a534523e89216c31f07ed16c54014597bfab0e |
| tools | LsInstancesByStatus | description | 023b16f58c7dfd000559e6dbd44ade636172c5583cb903ad4ade7a601055895b |
| tools | LsInstancesByStatus | status | db2422d9129dde28b42ad5526e423432fde838977de21a08e255dbcfada52e8c |
| tools | LsInstancesOfCluster | description | c4869aab106dce9a286f5fe5ba1b4076050a15a59876df4a4a8df6aff4d6e51a |
| tools | LsInstancesOfCluster | db_cluster_id | 8f368411ea56feab48f10fc427d9617f1f6d1ddebf1aaa66871e4c5f6db30e2c |
| tools | LsInstancesOfCluster | max_results | e4ff96a9e0cd58f24a90970f666b3dec789d6cd7227ed2755bc219a902946e7f |
| tools | LsInstancesOfCluster | next_token | ce20a3a3ac2a5ed58156cb9a73d478a4817f236a743cb0811712d6ca0db4a16a |
| tools | TagResource | description | ae141101c6ea35db28c14c73bf8bf0d9d5de4eae22688b0ca651361ca1451e57 |
| tools | TagResource | resource_arn | c19b9c1e8e4b825d4ae3bf1b01a534523e89216c31f07ed16c54014597bfab0e |
| tools | TagResource | tags | c75a87e9e56c97f6b4ef5833a514acda6a835bfe629c46ebde4f64834e2d9a2f |
| tools | TagResource | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | UntagResource | description | 359418dd40a9e5158d723b9b2470dcda4ffa54721082d98e04ec27830fe175b9 |
| tools | UntagResource | resource_arn | c19b9c1e8e4b825d4ae3bf1b01a534523e89216c31f07ed16c54014597bfab0e |
| tools | UntagResource | tag_keys | 7ab7219f24c8a6af1b70ae73cd5c3089d574068a05d60b67fe1b2e6ed38604c7 |
| tools | UntagResource | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | UpdateDbCluster | description | 58cf0cea7e6fc4d7e58f7f9be0fa6f555be604a5cce6ec85625ee02d11ccab73 |
| tools | UpdateDbCluster | db_cluster_id | 8f368411ea56feab48f10fc427d9617f1f6d1ddebf1aaa66871e4c5f6db30e2c |
| tools | UpdateDbCluster | db_instance_type | 36638bd1981dbc74f507e3977f9d600c8ab0dae84d113a56f1e16fed11ad3d74 |
| tools | UpdateDbCluster | db_parameter_group_identifier | 7a02dff3af8fa3f71e2000e3bd69d2647be92572c5dfaaacf88127165a39a90a |
| tools | UpdateDbCluster | failover_mode | 8384e9999a3884e242adb0a59af3e75ad4967220647642a603ad6e29e0730e6f |
| tools | UpdateDbCluster | log_delivery_configuration | 69a92a77873e1c778730dc186d6fb1be2ee2cd8b5caa78ae95a945c8a3b340d2 |
| tools | UpdateDbCluster | port | 33f55657fd3c726470d4b5535a1d84bf66824a8a24d4ecb73d98cb4c787d48a9 |
| tools | UpdateDbCluster | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |
| tools | UpdateDbInstance | description | ce091d29bf54a31160ef32c5cc87609f6078da94e7b34671269fd6cf44e37cb5 |
| tools | UpdateDbInstance | allocated_storage_gb | e1cd3cb571f72bc2004326a431c53ed96648fe7329db021c321164301adf3888 |
| tools | UpdateDbInstance | db_instance_type | 36638bd1981dbc74f507e3977f9d600c8ab0dae84d113a56f1e16fed11ad3d74 |
| tools | UpdateDbInstance | db_parameter_group_identifier | 2dd7c9f2ee8c9d0f768afebd07a3377fc4e10da15a25091996c1d41bfc4927df |
| tools | UpdateDbInstance | db_storage_type | 28009caa9a178e0ddfc62c9265bfd8fb082ff9d026c5b4d94c7327c91b09be82 |
| tools | UpdateDbInstance | deployment_type | e92f1a36e7444e1d8596fce1b1cb9d011830b5c4891d6a5da43a3fc25a68e015 |
| tools | UpdateDbInstance | identifier | 009832f652b3b487514a11820811f67db68fc43b82d8f6a282fb8b807af34703 |
| tools | UpdateDbInstance | log_delivery_configuration | bf20343694b4d14b8dc85910793929fc2288a40a3dce28a3c4868810f16dc5b5 |
| tools | UpdateDbInstance | port | 219b1ba4672897f13942751b3a22d99f173d3c3916b9c926bd9fecb41ee0ebc2 |
| tools | UpdateDbInstance | tool_write_mode | 97f0f4f2790ef560cf79fe75b289b7eb9fd0e245bd8d85b2d6b103e600cdeb19 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
