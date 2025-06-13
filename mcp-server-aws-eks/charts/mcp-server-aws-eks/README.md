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


# What is mcp-server-aws-eks?
[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-eks/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-eks/0.1.5?logo=docker&logoColor=fff&label=0.1.5)](https://hub.docker.com/r/acuvity/mcp-server-aws-eks)
[![PyPI](https://img.shields.io/badge/0.1.5-3775A9?logo=pypi&logoColor=fff&label=awslabs.eks-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/eks-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-eks/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-eks&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-eks%3A0.1.5%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Manages Amazon EKS clusters and Kubernetes resources with infrastructure provisioning

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.eks-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/eks-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-eks/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-eks/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-eks/charts/mcp-server-aws-eks/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.eks-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-eks/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, Amazon Web Services <githubusername@users.noreply.github.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/eks-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.eks-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/eks-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.eks-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/eks-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-eks/charts/mcp-server-aws-eks)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-eks/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.5`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-eks:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-eks:1.0.0-0.1.5`

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

**Optional Environment variables**:
  - `AWS_PROFILE=""` environment variable can be changed with `env.AWS_PROFILE=""`
  - `AWS_REGION=""` environment variable can be changed with `env.AWS_REGION=""`

# How to install


Install will helm

```console
helm install mcp-server-aws-eks oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-eks oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-eks
```

From there your MCP server mcp-server-aws-eks will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-eks` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-eks
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-eks` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-eks oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-eks oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-eks oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-eks oci://docker.io/acuvity/mcp-server-aws-eks --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (14)
<details>
<summary>get_cloudwatch_logs</summary>

**Description**:

```
Get logs from CloudWatch for a specific resource.

        This tool retrieves logs from CloudWatch for Kubernetes resources in an EKS cluster,
        allowing you to analyze application behavior, troubleshoot issues, and monitor system
        health. It supports filtering by resource type, time range, and content for troubleshooting
        application errors, investigating security incidents, and analyzing startup configuration issues.

        IMPORTANT: Use this tool instead of 'aws logs get-log-events', 'aws logs filter-log-events',
        or 'aws logs start-query' commands.

        ## Requirements
        - The server must be run with the `--allow-sensitive-data-access` flag
        - The EKS cluster must have CloudWatch logging enabled
        - The resource must exist in the specified cluster

        ## Response Information
        The response includes resource details (type, name, cluster), log group information,
        time range queried, and formatted log entries with timestamps and messages.

        ## Usage Tips
        - Start with a small time range (15-30 minutes) and expand if needed
        - Use filter_pattern to narrow down results (e.g., "ERROR", "exception")
        - For JSON logs, the tool automatically parses nested structures
        - Combine with get_k8s_events for comprehensive troubleshooting
        - Use resource_type="cluster" when querying cluster-level logs to avoid filtering by cluster name twice

        Args:
            ctx: MCP context
            resource_type: Resource type (pod, node, container, cluster). When "cluster" is specified, logs are not filtered by resource_name.
            cluster_name: Name of the EKS cluster
            log_type: Log type (application, host, performance, control-plane, or custom)
            resource_name: Resource name to search for in log messages. Optional when resource_type is "cluster".
            minutes: Number of minutes to look back
            start_time: Start time in ISO format (overrides minutes)
            end_time: End time in ISO format (defaults to now)
            limit: Maximum number of log entries to return
            filter_pattern: Additional CloudWatch Logs filter pattern
            fields: Custom fields to include in the query results

        Returns:
            CloudWatchLogsResponse with log entries and resource information
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | string | Name of the EKS cluster where the resource is located. Used to construct the CloudWatch log group name. | Yes
| end_time | any | End time in ISO format (e.g., "2023-01-01T01:00:00Z"). If not provided, defaults to current time. IMPORTANT: Use with start_time for precise time ranges. | No
| fields | any | Custom fields to include in the query results (defaults to "@timestamp, @message"). Use CloudWatch Logs Insights field syntax. IMPORTANT: Only specify if you need fields beyond the default timestamp and message. | No
| filter_pattern | any | Additional CloudWatch Logs filter pattern to apply. Uses CloudWatch Logs Insights syntax (e.g., "ERROR", "field=value"). IMPORTANT: Use this to narrow down results for specific issues. | No
| limit | integer | Maximum number of log entries to return. Use lower values (10-50) for faster queries, higher values (100-1000) for more comprehensive results. IMPORTANT: Higher values may impact performance. | No
| log_type | string | Log type to query. Options:
            - "application": Container/application logs
            - "host": Node-level system logs
            - "performance": Performance metrics logs
            - "control-plane": EKS control plane logs
            - Or provide a custom CloudWatch log group name directly | Yes
| minutes | integer | Number of minutes to look back for logs. Default: 15. Ignored if start_time is provided. Use smaller values for recent issues, larger values for historical analysis. | No
| resource_name | any | Resource name to search for in log messages (e.g., pod name, node name, container name). Used to filter logs for the specific resource. | No
| resource_type | string | Resource type to search logs for. Valid values: "pod", "node", "container". This determines how logs are filtered. | Yes
| start_time | any | Start time in ISO format (e.g., "2023-01-01T00:00:00Z"). If provided, overrides the minutes parameter. IMPORTANT: Use this for precise time ranges. | No
</details>
<details>
<summary>get_cloudwatch_metrics</summary>

**Description**:

```
Get metrics from CloudWatch for a specific resource.

        This tool retrieves metrics from CloudWatch for Kubernetes resources in an EKS cluster,
        allowing you to monitor performance, resource utilization, and system health. It supports
        various resource types and metrics with flexible time ranges and aggregation options for
        monitoring CPU/memory usage, analyzing network traffic, and identifying performance bottlenecks.

        IMPORTANT: Use this tool instead of 'aws cloudwatch get-metric-data', 'aws cloudwatch get-metric-statistics',
        or similar CLI commands.

        IMPORTANT: Use the get_eks_metrics_guidance tool first to determine the correct dimensions for metric queries.
        Do not try to infer which dimensions are needed for EKS ContainerInsights metrics.

        IMPORTANT: When using pod metrics, note that `FullPodName` has the same prefix as `PodName` but includes a
        suffix with a random string (e.g., "my-pod-abc123"). Always use the version without the suffix for `PodName`
        dimension. The pod name returned by list_k8s_resources is the `FullPodName`.

        ## Requirements
        - The EKS cluster must have CloudWatch Container Insights enabled
        - The resource must exist in the specified cluster
        - The metric must be available in the specified namespace

        ## Response Information
        The response includes resource details (cluster), metric information (name, namespace),
        time range queried, and data points with timestamps and values.

        ## Usage Tips
        - Use appropriate statistics for different metrics (e.g., Average for CPU, Maximum for memory spikes)
        - Match the period to your analysis needs (smaller for detailed graphs, larger for trends)
        - For rate metrics like network traffic, Sum is often more useful than Average
        - Combine with get_cloudwatch_logs to correlate metrics with log events

        Args:
            ctx: MCP context
            cluster_name: Name of the EKS cluster
            metric_name: Metric name (e.g., cpu_usage_total, memory_rss)
            namespace: CloudWatch namespace
            dimensions: Dimensions to use for the CloudWatch metric query
            minutes: Number of minutes to look back
            start_time: Start time in ISO format (overrides minutes)
            end_time: End time in ISO format (defaults to now)
            limit: Maximum number of data points to return
            period: Period in seconds for the metric data points
            stat: Statistic to use for the metric

        Returns:
            CloudWatchMetricsResponse with metric data points and resource information
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | string | Name of the EKS cluster to get metrics for. | Yes
| dimensions | object | Dimensions to use for the CloudWatch metric query. Must include appropriate dimensions for the resource type and metric (e.g., ClusterName, PodName, Namespace). | Yes
| end_time | any | End time in ISO format (e.g., "2023-01-01T01:00:00Z"). If not provided, defaults to current time. IMPORTANT: Use with start_time for precise time ranges. | No
| limit | integer | Maximum number of data points to return. Higher values (100-1000) provide more granular data but may impact performance. IMPORTANT: Balance between granularity and performance. | No
| metric_name | string | Metric name to retrieve. Common examples:
            - cpu_usage_total: Total CPU usage
            - memory_rss: Resident Set Size memory usage
            - network_rx_bytes: Network bytes received
            - network_tx_bytes: Network bytes transmitted | Yes
| minutes | integer | Number of minutes to look back for metrics. Default: 15. Ignored if start_time is provided. IMPORTANT: Choose a time range appropriate for the metric resolution. | No
| namespace | string | CloudWatch namespace where the metric is stored. Common values:
            - "ContainerInsights": For container metrics
            - "AWS/EC2": For EC2 instance metrics
            - "AWS/EKS": For EKS control plane metrics | Yes
| period | integer | Period in seconds for the metric data points. Default: 60 (1 minute). Lower values (1-60) provide higher resolution but may be less available. IMPORTANT: Match to your monitoring needs. | No
| start_time | any | Start time in ISO format (e.g., "2023-01-01T00:00:00Z"). If provided, overrides the minutes parameter. IMPORTANT: Use this for precise historical analysis. | No
| stat | string | Statistic to use for the metric aggregation:
            - Average: Mean value during the period
            - Sum: Total value during the period
            - Maximum: Highest value during the period
            - Minimum: Lowest value during the period
            - SampleCount: Number of samples during the period | No
</details>
<details>
<summary>search_eks_troubleshoot_guide</summary>

**Description**:

```
Search the EKS Troubleshoot Guide for troubleshooting information.

        This tool provides troubleshooting guidance for Amazon EKS issues by querying
        a specialized knowledge base of EKS troubleshooting information. It helps identify
        common problems and provides step-by-step solutions for resolving cluster creation issues,
        node group management problems, workload deployment issues, and diagnosing error messages.

        ## Requirements
        - Internet connectivity to access the EKS Knowledge Base API
        - Valid AWS credentials with permissions to access the EKS Knowledge Base
        - IAM permission: eks-mcpserver:QueryKnowledgeBase

        ## Response Information
        The response includes bullet-point instructions for troubleshooting EKS issues.

        ## Usage Tips
        - Provide specific error messages or symptoms in your query
        - Try running this tool 2-3 times with different phrasings or related queries to increase the chance of retrieving the most relevant guidance

        Args:
            query: Your specific question or issue description related to EKS troubleshooting. Question has to be less than 300 characters and can only
            contain letters, numbers, commas, periods, question marks, colons, and spaces.

        Returns:
            str: Detailed troubleshooting guidance for the EKS issue
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Your specific question or issue description related to EKS troubleshooting | Yes
</details>
<details>
<summary>manage_eks_stacks</summary>

**Description**:

```
Manage EKS CloudFormation stacks with both read and write operations.

        This tool provides operations for managing EKS CloudFormation stacks, including creating templates,
        deploying stacks, retrieving stack information, and deleting stacks. It serves as the primary
        mechanism for creating and managing EKS clusters through CloudFormation, enabling standardized
        cluster creation, configuration updates, and resource cleanup.

        IMPORTANT: Use this tool instead of 'aws eks create-cluster', 'aws eks delete-cluster',
        'eksctl create cluster', 'eksctl delete cluster', or similar CLI commands.

        IMPORTANT: Use this tool's standardized templates for creating EKS clusters with proper VPC configuration,
        networking, security groups, and EKS auto mode. DO NOT create EKS clusters by generating CloudFormation
        templates from scratch.

        ## Requirements
        - The server must be run with the `--allow-write` flag for generate, deploy, and delete operations
        - For deploy and delete operations, the stack must have been created by this tool
        - For template_file parameter, the path must be absolute and accessible to the server

        ## Operations
        - **generate**: Create a CloudFormation template at the specified absolute path with the cluster name embedded
        - **deploy**: Deploy a CloudFormation template from the specified absolute path (creates a new stack or updates an existing one)
        - **describe**: Get detailed information about a CloudFormation stack for a specific cluster
        - **delete**: Delete a CloudFormation stack for the specified cluster

        ## Response Information
        The response type varies based on the operation:
        - generate: Returns GenerateTemplateResponse with the template path
        - deploy: Returns DeployStackResponse with stack name, ARN, and cluster name
        - describe: Returns DescribeStackResponse with stack details, outputs, and status
        - delete: Returns DeleteStackResponse with stack name, ID, and cluster name

        ## Usage Tips
        - Use the describe operation first to check if a cluster already exists
        - For safety, this tool will only modify or delete stacks that it created
        - Stack creation typically takes 15-20 minutes to complete
        - Use absolute paths for template files (e.g., '/home/user/templates/eks-template.yaml')
        - The cluster name is used to derive the CloudFormation stack name

        Args:
            ctx: MCP context
            operation: Operation to perform (generate, deploy, describe, or delete)
            template_file: Absolute path for the CloudFormation template (for generate and deploy operations)
            cluster_name: Name of the EKS cluster (for all operations)

        Returns:
            Union[GenerateTemplateResponse, DeployStackResponse, DescribeStackResponse, DeleteStackResponse]:
            Response specific to the operation performed
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | any | Name of the EKS cluster (for generate, deploy, describe and delete operations).
            This name will be used to derive the CloudFormation stack name and will be embedded in the cluster resources. | No
| operation | string | Operation to perform: generate, deploy, describe, or delete. Choose "describe" for read-only operations when write access is disabled. | Yes
| template_file | any | Absolute path for the CloudFormation template (for generate and deploy operations).
            IMPORTANT: Assistant must provide the full absolute path to the template file, as the MCP client and server might not run from the same location. | No
</details>
<details>
<summary>list_k8s_resources</summary>

**Description**:

```
List Kubernetes resources of a specific kind.

        This tool lists Kubernetes resources of a specified kind in an EKS cluster,
        with options to filter by namespace, labels, and fields. It returns a summary
        of each resource including name, namespace, creation time, and metadata, useful
        for listing pods in a namespace, finding services with specific labels, or
        checking resources in a specific state.

        IMPORTANT: Use this tool instead of 'kubectl get' commands.

        ## Response Information
        The response includes a summary of each resource with name, namespace, creation timestamp,
        labels, and annotations.

        ## Usage Tips
        - Use the list_api_versions tool first to find available API versions
        - For non-namespaced resources (like Nodes), the namespace parameter is ignored
        - Combine label and field selectors for more precise filtering
        - Results are summarized to avoid overwhelming responses

        Args:
            ctx: MCP context
            cluster_name: Name of the EKS cluster
            kind: Kind of the Kubernetes resources (e.g., 'Pod', 'Service')
            api_version: API version of the Kubernetes resources (e.g., 'v1', 'apps/v1')
            namespace: Namespace of the Kubernetes resources (optional)
            label_selector: Label selector to filter resources (optional)
            field_selector: Field selector to filter resources (optional)

        Returns:
            KubernetesResourceListResponse with operation result
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api_version | string | API version of the Kubernetes resources (e.g., 'v1', 'apps/v1', 'networking.k8s.io/v1').
            Use the list_api_versions tool to find available API versions. | Yes
| cluster_name | string | Name of the EKS cluster where the resources are located. | Yes
| field_selector | any | Field selector to filter resources (e.g., 'metadata.name=my-pod,status.phase=Running').
            Uses the same syntax as kubectl's --field-selector flag. | No
| kind | string | Kind of the Kubernetes resources to list (e.g., 'Pod', 'Service', 'Deployment').
            Use the list_api_versions tool to find available resource kinds. | Yes
| label_selector | any | Label selector to filter resources (e.g., 'app=nginx,tier=frontend').
            Uses the same syntax as kubectl's --selector flag. | No
| namespace | any | Namespace of the Kubernetes resources to list.
            If not provided, resources will be listed across all namespaces (for namespaced resources). | No
</details>
<details>
<summary>get_pod_logs</summary>

**Description**:

```
Get logs from a pod in a Kubernetes cluster.

        This tool retrieves logs from a specified pod in an EKS cluster, with options
        to filter by container, time range, and size. It's useful for debugging application
        issues, monitoring behavior, investigating crashes, and verifying startup configuration.

        IMPORTANT: Use this tool instead of 'kubectl logs' commands.

        ## Requirements
        - The server must be run with the `--allow-sensitive-data-access` flag
        - The pod must exist and be accessible in the specified namespace
        - The EKS cluster must exist and be accessible

        ## Response Information
        The response includes pod name, namespace, container name (if specified),
        and log lines as an array of strings.

        Args:
            ctx: MCP context
            cluster_name: Name of the EKS cluster
            namespace: Namespace of the pod
            pod_name: Name of the pod
            container_name: Container name (optional, if pod contains more than one container)
            since_seconds: Only return logs newer than this many seconds (optional)
            tail_lines: Number of lines to return from the end of the logs (defaults to 100)
            limit_bytes: Maximum number of bytes to return (defaults to 10KB)

        Returns:
            PodLogsResponse with pod logs
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | string | Name of the EKS cluster where the pod is running. | Yes
| container_name | any | Name of the specific container to get logs from. Required only if the pod contains multiple containers. | No
| limit_bytes | integer | Maximum number of bytes to return. Default: 10KB (10240 bytes). Prevents retrieving extremely large log files. | No
| namespace | string | Kubernetes namespace where the pod is located. | Yes
| pod_name | string | Name of the pod to retrieve logs from. | Yes
| since_seconds | any | Only return logs newer than this many seconds. Useful for getting recent logs without retrieving the entire history. | No
| tail_lines | integer | Number of lines to return from the end of the logs. Default: 100. Use higher values for more context. | No
</details>
<details>
<summary>get_k8s_events</summary>

**Description**:

```
Get events related to a specific Kubernetes resource.

        This tool retrieves Kubernetes events related to a specific resource, providing
        detailed information about what has happened to the resource over time. Events
        are useful for troubleshooting pod startup failures, investigating deployment issues,
        understanding resource modifications, and diagnosing scheduling problems.

        IMPORTANT: Use this tool instead of 'kubectl describe' or 'kubectl get events' commands.

        ## Requirements
        - The server must be run with the `--allow-sensitive-data-access` flag
        - The resource must exist and be accessible in the specified namespace

        ## Response Information
        The response includes events with timestamps (first and last), occurrence counts,
        messages, reasons, reporting components, and event types (Normal or Warning).

        ## Usage Tips
        - Warning events often indicate problems that need attention
        - Normal events provide information about expected lifecycle operations
        - The count field shows how many times the same event has occurred
        - Recent events are most relevant for current issues

        Args:
            ctx: MCP context
            cluster_name: Name of the EKS cluster
            kind: Kind of the involved object
            name: Name of the involved object
            namespace: Namespace of the involved object (optional for non-namespaced resources)

        Returns:
            EventsResponse with events related to the specified object
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | string | Name of the EKS cluster where the resource is located. | Yes
| kind | string | Kind of the involved object (e.g., "Pod", "Deployment", "Service"). Must match the resource kind exactly. | Yes
| name | string | Name of the involved object to get events for. | Yes
| namespace | any | Namespace of the involved object. Required for namespaced resources (like Pods, Deployments).
            Not required for cluster-scoped resources (like Nodes, PersistentVolumes). | No
</details>
<details>
<summary>list_api_versions</summary>

**Description**:

```
List all available API versions in the Kubernetes cluster.

        This tool discovers all available API versions on the Kubernetes cluster,
        which is helpful for determining the correct apiVersion to use when
        managing Kubernetes resources. It returns both core APIs and API groups,
        useful for verifying API compatibility and discovering available resources.

        ## Response Information
        The response includes core APIs (like 'v1'), API groups with versions
        (like 'apps/v1'), extension APIs (like 'networking.k8s.io/v1'), and
        any Custom Resource Definition (CRD) APIs installed in the cluster.

        ## Usage Tips
        - Use this tool before creating or updating resources to ensure API compatibility
        - Different Kubernetes versions may have different available APIs
        - Some APIs may be deprecated or removed in newer Kubernetes versions
        - Custom resources will only appear if their CRDs are installed in the cluster

        Args:
            ctx: MCP context
            cluster_name: Name of the EKS cluster

        Returns:
            ApiVersionsResponse with list of available API versions
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | string | Name of the EKS cluster to query for available API versions. | Yes
</details>
<details>
<summary>manage_k8s_resource</summary>

**Description**:

```
Manage a single Kubernetes resource with various operations.

        This tool provides complete CRUD (Create, Read, Update, Delete) operations
        for Kubernetes resources in an EKS cluster. It supports all resource types
        and allows for precise control over individual resources, enabling you to create
        custom resources, update specific fields, read detailed information, and delete
        resources that are no longer needed.

        IMPORTANT: Use this tool instead of 'kubectl create', 'kubectl edit', 'kubectl patch',
        'kubectl delete', or 'kubectl get' commands.

        ## Requirements
        - The server must be run with the `--allow-write` flag for mutating operations
        - The server must be run with the `--allow-sensitive-data-access` flag for Secret resources
        - The EKS cluster must exist and be accessible

        ## Operations
        - **create**: Create a new resource with the provided definition
        - **replace**: Replace an existing resource with a new definition
        - **patch**: Update specific fields of an existing resource
        - **delete**: Remove an existing resource
        - **read**: Get details of an existing resource

        ## Usage Tips
        - Use list_api_versions to find available API versions
        - For namespaced resources, always provide the namespace
        - When creating resources, ensure the name in the body matches the name parameter
        - For patch operations, only include the fields you want to update

        Args:
            ctx: MCP context
            operation: Operation to perform (create, replace, patch, delete, read)
            cluster_name: Name of the EKS cluster
            kind: Kind of the Kubernetes resource (e.g., 'Pod', 'Service')
            api_version: API version of the Kubernetes resource (e.g., 'v1', 'apps/v1')
            name: Name of the Kubernetes resource
            namespace: Namespace of the Kubernetes resource (optional)
            body: Resource definition

        Returns:
            KubernetesResourceResponse with operation result
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api_version | string | API version of the Kubernetes resource (e.g., "v1", "apps/v1", "networking.k8s.io/v1"). | Yes
| body | any | Resource definition as a dictionary. Required for create, replace, and patch operations.
            For create and replace, this should be a complete resource definition.
            For patch, this should contain only the fields to update. | No
| cluster_name | string | Name of the EKS cluster where the resource is located or will be created. | Yes
| kind | string | Kind of the Kubernetes resource (e.g., "Pod", "Service", "Deployment"). | Yes
| name | any | Name of the Kubernetes resource. Required for all operations except create (where it can be specified in the body). | No
| namespace | any | Namespace of the Kubernetes resource. Required for namespaced resources.
            Not required for cluster-scoped resources (like Nodes, PersistentVolumes). | No
| operation | string | Operation to perform on the resource. Valid values:
            - create: Create a new resource
            - replace: Replace an existing resource
            - patch: Update specific fields of an existing resource
            - delete: Delete an existing resource
            - read: Get details of an existing resource
            Use list_k8s_resources for listing multiple resources. | Yes
</details>
<details>
<summary>apply_yaml</summary>

**Description**:

```
Apply a Kubernetes YAML from a local file.

        This tool applies Kubernetes resources defined in a YAML file to an EKS cluster,
        similar to the `kubectl apply` command. It supports multi-document YAML files
        and can create or update resources, useful for deploying applications, creating
        Kubernetes resources, and applying complete application stacks.

        IMPORTANT: Use this tool instead of 'kubectl apply -f' commands.

        ## Requirements
        - The server must be run with the `--allow-write` flag
        - The YAML file must exist and be accessible to the server
        - The path must be absolute (e.g., '/home/user/manifests/app.yaml')
        - The EKS cluster must exist and be accessible

        ## Response Information
        The response includes the number of resources created, number of resources
        updated (when force=True), and whether force was applied.

        Args:
            ctx: MCP context
            yaml_path: Absolute path to the YAML file to apply
            cluster_name: Name of the EKS cluster
            namespace: Default namespace to use for resources
            force: Whether to update resources if they already exist (like kubectl apply)

        Returns:
            ApplyYamlResponse with operation result
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cluster_name | string | Name of the EKS cluster where the resources will be created or updated. | Yes
| force | boolean | Whether to update resources if they already exist (similar to kubectl apply). Set to false to only create new resources. | No
| namespace | string | Kubernetes namespace to apply resources to. Will be used for namespaced resources that do not specify a namespace. | Yes
| yaml_path | string | Absolute path to the YAML file to apply.
            IMPORTANT: Must be an absolute path (e.g., '/home/user/manifests/app.yaml') as the MCP client and server might not run from the same location. | Yes
</details>
<details>
<summary>generate_app_manifest</summary>

**Description**:

```
Generate Kubernetes manifest for a deployment and service.

        This tool generates Kubernetes manifests for deploying an application to an EKS cluster,
        creating both a Deployment and a LoadBalancer Service. The generated manifest can be
        applied to a cluster using the apply_yaml tool, useful for deploying containerized
        applications, creating load-balanced services, and standardizing deployment configurations.

        ## Requirements
        - The server must be run with the `--allow-write` flag

        ## Generated Resources
        - **Deployment**: Manages the application pods with specified replicas and resource requests
        - **Service**: LoadBalancer type service that exposes the application externally

        ## Usage Tips
        - Use 2 or more replicas for production workloads
        - Set appropriate resource requests based on application needs
        - Use internal load balancers for services that should only be accessible within the VPC
        - The generated manifest can be modified before applying if needed

        Args:
            ctx: MCP context
            app_name: Name of the application (used for deployment and service names)
            image_uri: Full ECR image URI with tag
            port: Container port that the application listens on
            replicas: Number of replicas to deploy
            cpu: CPU request for each container
            memory: Memory request for each container
            namespace: Kubernetes namespace to deploy to
            load_balancer_scheme: AWS load balancer scheme (internal or internet-facing)
            output_dir: Directory to save the manifest file

        Returns:
            GenerateAppManifestResponse: The complete Kubernetes manifest content and output file path
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_name | string | Name of the application. Used for deployment and service names, and for labels. | Yes
| cpu | string | CPU request for each container (e.g., "100m" for 0.1 CPU cores, "500m" for half a core). | No
| image_uri | string | Full ECR image URI with tag (e.g., 123456789012.dkr.ecr.region.amazonaws.com/repo:tag).
            Must include the full repository path and tag. | Yes
| load_balancer_scheme | string | AWS load balancer scheme. Options: "internal" (private VPC only) or "internet-facing" (public access). | No
| memory | string | Memory request for each container (e.g., "128Mi" for 128 MiB, "1Gi" for 1 GiB). | No
| namespace | string | Kubernetes namespace to deploy the application to. Default: "default" | No
| output_dir | string | Absolute path to the directory to save the manifest file | Yes
| port | integer | Container port that the application listens on | No
| replicas | integer | Number of replicas to deploy | No
</details>
<details>
<summary>add_inline_policy</summary>

**Description**:

```
Add a new inline policy to an IAM role.

        This tool creates a new inline policy with the specified permissions and adds it to an IAM role.
        Inline policies are embedded within the role and cannot be attached to multiple roles. Commonly used
        for granting EKS clusters access to AWS services, enabling worker nodes to access resources, and
        configuring permissions for CloudWatch logging and ECR access.

        IMPORTANT: Use this tool instead of 'aws iam put-role-policy' commands.

        ## Requirements
        - The server must be run with the `--allow-write` flag
        - The role must exist in your AWS account
        - The policy name must be unique within the role
        - You cannot modify existing policies with this tool

        ## Permission Format
        The permissions parameter can be either a single policy statement or a list of statements.

        ### Single Statement Example
        ```json
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::example-bucket/*"
        }
        ```

        ## Usage Tips
        - Follow the principle of least privilege by granting only necessary permissions
        - Use specific resources rather than "*" whenever possible
        - Consider using conditions to further restrict permissions
        - Group related permissions into logical policies with descriptive names

        Args:
            ctx: The MCP context
            policy_name: Name of the new inline policy to create
            role_name: Name of the role to add the policy to
            permissions: Permissions to include in the policy (in JSON format)

        Returns:
            AddInlinePolicyResponse: Information about the created policy
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| permissions | any | Permissions to include in the policy as IAM policy statements in JSON format.
            Can be either a single statement object or an array of statement objects. | Yes
| policy_name | string | Name of the inline policy to create. Must be unique within the role. | Yes
| role_name | string | Name of the IAM role to add the policy to. The role must exist. | Yes
</details>
<details>
<summary>get_policies_for_role</summary>

**Description**:

```
Get all policies attached to an IAM role.

        This tool retrieves all policies associated with an IAM role, providing a comprehensive view
        of the role's permissions and trust relationships. It helps you understand the current
        permissions, identify missing or excessive permissions, troubleshoot EKS cluster issues,
        and verify trust relationships for service roles.

        IMPORTANT: Use this tool instead of 'aws iam get-role', 'aws iam list-attached-role-policies',
        'aws iam list-role-policies', and 'aws iam get-role-policy' commands.

        ## Requirements
        - The role must exist in your AWS account
        - Valid AWS credentials with permissions to read IAM role information

        ## Response Information
        The response includes role ARN, assume role policy document (trust relationships),
        role description, managed policies with their documents, and inline policies with
        their documents.

        ## Usage Tips
        - Use this tool before adding new permissions to understand existing access
        - Check the assume role policy to verify which services or roles can assume this role
        - Look for overly permissive policies that might pose security risks
        - Use with add_inline_policy to implement least-privilege permissions

        Args:
            ctx: The MCP context
            role_name: Name of the IAM role to get policies for

        Returns:
            RoleDescriptionResponse: Detailed information about the role's policies
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| role_name | string | Name of the IAM role to get policies for. The role must exist in your AWS account. | Yes
</details>
<details>
<summary>get_eks_metrics_guidance</summary>

**Description**:

```
Get CloudWatch metrics guidance for specific resource types in EKS clusters.

        This tool provides information about available CloudWatch metrics that are in the `ContainerInsights` naemspace for different resource types
        in EKS clusters, including metric names, dimensions, and descriptions to help with monitoring and troubleshooting.
        It's particularly useful for determining the correct dimensions to use with the get_cloudwatch_metrics tool.

        ## Response Information
        The response includes a list of metrics with their names, descriptions, and required dimensions
        for the specified resource type.

        ## Usage Tips
        - Use this tool before calling get_cloudwatch_metrics to determine the correct dimensions
        - For pod metrics, note that FullPodName has a random suffix while PodName doesn't
        - Different metrics require different dimension combinations

        Args:
            ctx: MCP context
            resource_type: Type of resource to get metrics for (cluster, node, pod, namespace, service)

        Returns:
            List of metrics with their details
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| resource_type | string | Type of resource to get metrics for (cluster, node, pod, namespace, service) | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_inline_policy | description | da301ba8e5cf8d21adcea91395101bbd4eb375dfdfee6715e2f97a94071cb9d2 |
| tools | add_inline_policy | permissions | 5991ad79e60e52e84251ae238c1045ac71a583c3e19214f29fa8c93a70286d14 |
| tools | add_inline_policy | policy_name | e439b46fe7ad5c9f14f955a3ce6c6eb525f96dfb4e4588ebdaf479e2f6da63c7 |
| tools | add_inline_policy | role_name | 6d2533203d55a5c35206e85536961c8bd5f0f5f0eaec86b2295f81531ec4b484 |
| tools | apply_yaml | description | 7f558ba822c62a0fdb907a7a3439f31ac7bce441a74782cdf9105954e72f4a17 |
| tools | apply_yaml | cluster_name | d5507a2b38304fe0e14eae0cdf061160de2efdd55a9a8d99fb8d5621e25f4787 |
| tools | apply_yaml | force | a9f2994011def415d247fb229cd30da862968d424821b3a67f9a1b0b26a88fa8 |
| tools | apply_yaml | namespace | 5783d9eae3ff18f88eec6ed8886f9f901bcd1658f81a4c9e20be34b9166f9c57 |
| tools | apply_yaml | yaml_path | 5b7687cc13ceee58b6534f3b4ec127896f06ae1a938b6c086dafe4c7671941d3 |
| tools | generate_app_manifest | description | f9e5c84f28f5532d2dbf89046f12eaa98f55da1bc14132fea7ee7a21d2790aeb |
| tools | generate_app_manifest | app_name | ab9ba39d6c303a51de07261968965a664b75118dd1681cf03430f77f715b839a |
| tools | generate_app_manifest | cpu | d3fd2ca58c0334f145d6723a6469d53dba86378bdbc22d53ff1d45108f62fdbb |
| tools | generate_app_manifest | image_uri | 329e1d1d84012d68c4d84fce8645e8c7bc23a86ddc3196a21087b3889061f879 |
| tools | generate_app_manifest | load_balancer_scheme | a737d7fb36ada0bbe2445309f85d7996e1e00f5f1866bacc4b20a7c8adc41672 |
| tools | generate_app_manifest | memory | 5cf5901274ed7d15d281ea6d53dfd4d2e87c199d9aca21395be04a21e460b9ca |
| tools | generate_app_manifest | namespace | 107365ffda6a6879b1e09d416069500a80ce2da172f0183ae7cc5f9dde4ccb75 |
| tools | generate_app_manifest | output_dir | 3412476fdbcf9e8516e23b3a112ab74982e795cd0bcfb9d1977187a53bbdf07a |
| tools | generate_app_manifest | port | c24928999b45d2f8f97607766f7a37a69a50632257b44d258c49005bb1bad695 |
| tools | generate_app_manifest | replicas | 770f11c27aaff3be62bb85c2eb260061153f72f7c2f76faa923011cb6d1266fb |
| tools | get_cloudwatch_logs | description | 702890a983ea63a5ce02c90bd8d65c33786df1793caba2d11ffa8d0f76878aff |
| tools | get_cloudwatch_logs | cluster_name | 9d72c09b08c2a972875f333cba5fc3cb447d7a7131260ec477c45c8b1e28867b |
| tools | get_cloudwatch_logs | end_time | effd1b3e99eb0dbf853c7594b23b3440813162e1ebab136985f0ae883ee5f88a |
| tools | get_cloudwatch_logs | fields | 851a15a27e44cd182e1df844aa1173f127932100b683f96c94138d074babf536 |
| tools | get_cloudwatch_logs | filter_pattern | 6f2ec9f67bc2e446d02675fb7acd7a83eebd9434edb5e667547912425457a192 |
| tools | get_cloudwatch_logs | limit | ef5f8b6e3e506d9b67d07bf7a09a2bb66ef9210f50448c423fdfec1ee0385038 |
| tools | get_cloudwatch_logs | log_type | 90989b45919b18deaca293cb8cb327b1df338b2c96439950fa302d70920497e2 |
| tools | get_cloudwatch_logs | minutes | 7ad7d066c23a2b1c3450b73c5890ad2ef10c86ea8ac45dae32e8e42453254824 |
| tools | get_cloudwatch_logs | resource_name | 177563c456dd2371f4242416a62f293104646adb4f1fa9d405b16a8df3c148d7 |
| tools | get_cloudwatch_logs | resource_type | ac07f6f25eb833efed1bf9edf686efe3e11a7630813bfbf15bf1e45de7a47a49 |
| tools | get_cloudwatch_logs | start_time | 345cfc9928d8a8780033abfdc8220a059b588bdcae47c0d00fc5fd147ce4658d |
| tools | get_cloudwatch_metrics | description | d4621c2b3978b2adac4e727c8069683cae3c61e7f2b057e8bca7fc56db251626 |
| tools | get_cloudwatch_metrics | cluster_name | 3166f584348fa12e0b4237fc7ce2989ddb0efcc7d5cefe8fe4ca3061c5187537 |
| tools | get_cloudwatch_metrics | dimensions | 9c321f359fbb5296f86c7e87f5e1f4de0c260fa4c64baafba45a88ad5fd677a8 |
| tools | get_cloudwatch_metrics | end_time | effd1b3e99eb0dbf853c7594b23b3440813162e1ebab136985f0ae883ee5f88a |
| tools | get_cloudwatch_metrics | limit | 5350af31a9088d70cc05a888aedc8506d99839bb8b710ea144a8689d672ba788 |
| tools | get_cloudwatch_metrics | metric_name | db8520cd92449acebf12920bfd6708c80da6eed404501c6a870fdf2a8babb85d |
| tools | get_cloudwatch_metrics | minutes | 3dff7ac2fc3d232c2c078e1b9ee4bdfae7015d40c7c1180ed151d2a749841612 |
| tools | get_cloudwatch_metrics | namespace | c05631850d5f59ec2f1671f1e97850cc47a0765e1135b60db6993a6506d95550 |
| tools | get_cloudwatch_metrics | period | 13798fa2b1a88309998e76bb87430b64d58831d83f928963802574f7c39a88f5 |
| tools | get_cloudwatch_metrics | start_time | 47c6a9e8190fbee525143ea669453f4fd142196aec9850849b490ad6f1618829 |
| tools | get_cloudwatch_metrics | stat | b9c6313701361449a4d2d71ab2648aa0cfdcf66491c43455858c5663db522440 |
| tools | get_eks_metrics_guidance | description | be908f414c3d7faad3cd7ced2e4dc837dcaeee787b5aa154fa593fe209c7e02d |
| tools | get_eks_metrics_guidance | resource_type | 57984c9a8a28106bf794031d55de11469651a2989fc231666b1650c6c5309b08 |
| tools | get_k8s_events | description | 0331d84aaa95c5711eb31e20b6eb1ee0c99f4ffcf77908565c5f778c5065c587 |
| tools | get_k8s_events | cluster_name | 132c6b41e0f5decbccbfdf54615ab707d4cd9044e647f48452438ba0cb78c15f |
| tools | get_k8s_events | kind | 8d65e384bcfb5153af1e3b951ef24a691aee5046be7e1752ad91ac4e1408a19d |
| tools | get_k8s_events | name | eef9c3e70fa1cb6481789d2ff0bf66da5dcee1cce960ff641d28dcb2c3956326 |
| tools | get_k8s_events | namespace | a59ce840425069d4821a59c1aadabd6808fdebe36154ebb11520d95d88618410 |
| tools | get_pod_logs | description | cfc4efa5109d5cd3d560f0b7567a692a76dd56ad77122fb962c837ac36a00fdf |
| tools | get_pod_logs | cluster_name | edf1e441cc205c94bb847047f8be4de4c4a16d668a2e2068cc688e0185819bba |
| tools | get_pod_logs | container_name | 3f5b2d3222b8e69be54079d23aa61b115b398959564aed4a23573eff654e7c4f |
| tools | get_pod_logs | limit_bytes | 11abfe011f8a74c61597c3ecc5d74a8e8c2d4952efca310f9fc1a1a97d0899fd |
| tools | get_pod_logs | namespace | 294f6735992dbaf16cb3a48987de09fa0ffa343dcbf4ab69ee258cfccb1bf075 |
| tools | get_pod_logs | pod_name | a3b2839c8810075aeea411347cf78ee5fcd62e20fd80d2f365a8779e109b47cb |
| tools | get_pod_logs | since_seconds | 25ec0c4a85cb524d081847671ba412674b60c1d51c0ff27605a2b9d7fdc016fc |
| tools | get_pod_logs | tail_lines | 7faaf53e8fbf0051835a8ddb16684995b240e384d6baa7517a8a625ceb35a163 |
| tools | get_policies_for_role | description | 8f5390680772e7ea94a62676161e2634b488816c3b47f1930b27acaf6b7f7f79 |
| tools | get_policies_for_role | role_name | 3bcc4b6d25cce08a96c158a72a7d69f961ffc45829446254e292fcceced0fbd8 |
| tools | list_api_versions | description | c844a4fb2aa027810089f19027080f200162cbca65fe1de8b42b8cdbbc4c04c7 |
| tools | list_api_versions | cluster_name | caa90278c0b2429f8f24c310127eb0028fdd04f8887e856eb3f6a2e4cd6e6202 |
| tools | list_k8s_resources | description | 35bec1e42d19c1c2250280c2e0960cba482c078835ca22ee70b4010c8b75a607 |
| tools | list_k8s_resources | api_version | cb0583b775e01b5cfa1868ae3f0f3c5409d3fd11e4b8df48a75075e44310090e |
| tools | list_k8s_resources | cluster_name | 00039a6eed6c1187db0ed695492ac1d611561ee6d94a4a9907a9004e38dabf5d |
| tools | list_k8s_resources | field_selector | 615cfbf7e9dc3373a10672728d666a58d7cb0053513cf543c4c0d0697d2e6ecb |
| tools | list_k8s_resources | kind | 631781e78c2f65cd36de4469c4238685064f073650068111c0b682caca0cde94 |
| tools | list_k8s_resources | label_selector | 13ba5c6be3d704e9859ac149b6caa81f4979cdd8a871a833f5aaee321ba8089c |
| tools | list_k8s_resources | namespace | 22597b36142f07ca97ac1c63885cec38d91f332d4a338f15186399bbb82608bc |
| tools | manage_eks_stacks | description | 70c921830c7962d51e0508cdeac5bc878096b6022d3505ac10b89d9488eedd9a |
| tools | manage_eks_stacks | cluster_name | 839d6e3dd8e60d59ef76b3aac725e54d7866062f45b427655cb0cf9346e49901 |
| tools | manage_eks_stacks | operation | 6a7fcd59f70a803aee7688460cd79bdf34f321c811f3c543c2999e1c917f9a30 |
| tools | manage_eks_stacks | template_file | b97aabe3467f13a3d6f9f4d75bc12772bf927812cde2ce9fde50dec2b55220ed |
| tools | manage_k8s_resource | description | c3b7532c502e8a2fb413cb7d3de7a597d559619f95e76803dc287203e664c9e9 |
| tools | manage_k8s_resource | api_version | 7b26ceb1c6e4965d5969a7e22acbce57abc7965b4019719144a2f22f4184af92 |
| tools | manage_k8s_resource | body | eb44cd308ddb282a31b787115b78112d683f73b961a905ac16b9f051aaf4eb62 |
| tools | manage_k8s_resource | cluster_name | ff269ba252c8048b14aee42e8cf6eb70eb487b0d315fe60c677cabc595e2e78f |
| tools | manage_k8s_resource | kind | a3b8057fe42f10b3b9662a5def704dbfd5210ee5cedee941ea983ad8555dcc4d |
| tools | manage_k8s_resource | name | 1e70eacb39e755f02a74852d9abd12cf54ad6101f589eef563163c9b87a6a3d5 |
| tools | manage_k8s_resource | namespace | 1192416f48f5d6b86471078cbbf9056dc199ad77b12abbab9c2c6120e7335fd5 |
| tools | manage_k8s_resource | operation | e850aec68a701cec81de606694a536382986c45cfbcfb396d4ac4010dc75f709 |
| tools | search_eks_troubleshoot_guide | description | 78fbc16014e6bd9090aaa6a60cae72fbc8ffbc79e12be34af197d08818b7c6e5 |
| tools | search_eks_troubleshoot_guide | query | c2ff234f78e9325c8908cc3a6e6203474ee6c26669cae552313d6bfbcac7dad2 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
