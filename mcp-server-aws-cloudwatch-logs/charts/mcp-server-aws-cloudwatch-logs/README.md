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


# What is mcp-server-aws-cloudwatch-logs?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-cloudwatch-logs/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-cloudwatch-logs/0.0.8?logo=docker&logoColor=fff&label=0.0.8)](https://hub.docker.com/r/acuvity/mcp-server-aws-cloudwatch-logs)
[![PyPI](https://img.shields.io/badge/0.0.8-3775A9?logo=pypi&logoColor=fff&label=awslabs.cloudwatch-logs-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/cloudwatch-logs-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-cloudwatch-logs/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-cloudwatch-logs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-cloudwatch-logs%3A0.0.8%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AWS CloudWatch Logs MCP server for querying and analyzing log data with CloudWatch Logs Insights

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.cloudwatch-logs-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/cloudwatch-logs-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-cloudwatch-logs/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cloudwatch-logs/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cloudwatch-logs/charts/mcp-server-aws-cloudwatch-logs/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.cloudwatch-logs-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cloudwatch-logs/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cloudwatch-logs#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com>, Isaiah Lemmon <ilemmon@amazon.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/cloudwatch-logs-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.cloudwatch-logs-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/cloudwatch-logs-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.cloudwatch-logs-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/cloudwatch-logs-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cloudwatch-logs/charts/mcp-server-aws-cloudwatch-logs)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-cloudwatch-logs/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.0.8`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-cloudwatch-logs:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-cloudwatch-logs:1.0.0-0.0.8`

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
helm install mcp-server-aws-cloudwatch-logs oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-cloudwatch-logs oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-cloudwatch-logs
```

From there your MCP server mcp-server-aws-cloudwatch-logs will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-cloudwatch-logs` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-cloudwatch-logs
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-cloudwatch-logs` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-cloudwatch-logs oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-cloudwatch-logs oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-cloudwatch-logs oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-cloudwatch-logs oci://docker.io/acuvity/mcp-server-aws-cloudwatch-logs --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (5)
<details>
<summary>describe_log_groups</summary>

**Description**:

```
IMPORTANT: This tool is deprecated. Please use the describe_log_groups tool in the cloudwatch MCP server instead.

    Lists AWS CloudWatch log groups and saved queries associated with them, optionally filtering by a name prefix.

    This tool retrieves information about log groups in the account, or log groups in accounts linked to this account as a monitoring account.
    If a prefix is provided, only log groups with names starting with the specified prefix are returned.

    Additionally returns any user saved queries that are associated with any of the returned log groups.

    Usage: Use this tool to discover log groups that you'd retrieve or query logs from and queries that have been saved by the user.

    Returns:
    --------
    List of log group metadata dictionaries and saved queries associated with them
       Each log group metadata contains details such as:
            - logGroupName: The name of the log group.
            - creationTime: Timestamp when the log group was created
            - retentionInDays: Retention period, if set
            - storedBytes: The number of bytes stored.
            - kmsKeyId: KMS Key Id used for data encryption, if set
            - dataProtectionStatus: Displays whether this log group has a protection policy, or whether it had one in the past, if set
            - logGroupClass: Type of log group class
            - logGroupArn: The Amazon Resource Name (ARN) of the log group. This version of the ARN doesn't include a trailing :* after the log group name.
        Any saved queries that are applicable to the returned log groups are also included.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| account_identifiers | any | When include_linked_accounts is set to True, use this parameter to specify the list of accounts to search. IMPORTANT: Only has affect if include_linked_accounts is True | No
| include_linked_accounts | any | If the AWS account is a monitoring account, set this to True to have the tool return log groups in the accounts listed in account_identifiers.
            If this parameter is set to true and account_identifiers contains a null value, the tool returns all log groups in the monitoring account and all log groups in all source accounts that are linked to the monitoring account. | No
| log_group_class | any | If specified, filters for only log groups of the specified class. | No
| log_group_name_prefix | any | An exact prefix to filter log groups by name. IMPORTANT: Only log groups with names starting with this prefix will be returned. | No
| max_items | any | The maximum number of log groups to return. | No
</details>
<details>
<summary>analyze_log_group</summary>

**Description**:

```
IMPORTANT: This tool is deprecated. Please use the analyze_log_group tool in the cloudwatch MCP server instead.

    Analyzes a CloudWatch log group for anomalies, message patterns, and error patterns within a specified time window.

    This tool performs an analysis of the specified log group by:
    1. Discovering and checking log anomaly detectors associated with the log group
    2. Retrieving anomalies from those detectors that fall within the specified time range
    3. Identifying the top 5 most common message patterns
    4. Finding the top 5 patterns containing error-related terms

    Usage: Use this tool to detect anomalies and understand common patterns in your log data, particularly
    focusing on error patterns that might indicate issues. This can help identify potential problems and
    understand the typical behavior of your application.

    Returns:
    --------
    A LogAnalysisResult object containing:
        - log_anomaly_results: Information about anomaly detectors and their findings
            * anomaly_detectors: List of anomaly detectors for the log group
            * anomalies: List of anomalies that fall within the specified time range
        - top_patterns: Results of the query for most common message patterns
        - top_patterns_containing_errors: Results of the query for patterns containing error-related terms
            (error, exception, fail, timeout, fatal)
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end_time | string | ISO 8601 formatted end time for the CloudWatch Logs Insights query window (e.g., "2025-04-19T21:00:00+00:00"). | Yes
| log_group_arn | string | The log group arn to look for anomalies in, as returned by the describe_log_groups tools | Yes
| start_time | string | ISO 8601 formatted start time for the CloudWatch Logs Insights query window (e.g., "2025-04-19T20:00:00+00:00"). | Yes
</details>
<details>
<summary>execute_log_insights_query</summary>

**Description**:

```
IMPORTANT: This tool is deprecated. Please use the execute_log_insights_query tool in the cloudwatch MCP server instead.

    Executes a CloudWatch Logs Insights query and waits for the results to be available.

    IMPORTANT: The operation must include exactly one of the following parameters: log_group_names, or log_group_identifiers.

    CRITICAL: The volume of returned logs can easily overwhelm the agent context window. Always include a limit in the query
    (| limit 50) or using the limit parameter.

    Usage: Use to query, filter, collect statistics, or find patterns in one or more log groups. For example, the following
    query lists exceptions per hour.

    ```
    filter @message like /Exception/
    | stats count(*) as exceptionCount by bin(1h)
    | sort exceptionCount desc
    ```

    Returns:
    --------
        A dictionary containing the final query results, including:
            - status: The current status of the query (e.g., Scheduled, Running, Complete, Failed, etc.)
            - results: A list of the actual query results if the status is Complete.
            - statistics: Query performance statistics
            - messages: Any informational messages about the query
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end_time | string | ISO 8601 formatted end time for the CloudWatch Logs Insights query window (e.g., "2025-04-19T21:00:00+00:00"). | Yes
| limit | any | The maximum number of log events to return. It is critical to use either this parameter or a `| limit <int>` operator in the query to avoid consuming too many tokens of the agent. | No
| log_group_identifiers | any | The list of up to 50 logGroupIdentifiers to query. You can specify them by the log group name or ARN. If a log group that you're querying is in a source account and you're using a monitoring account, you must use the ARN. CRITICAL: Exactly one of [log_group_names, log_group_identifiers] should be non-null. | No
| log_group_names | any | The list of up to 50 log group names to be queried. CRITICAL: Exactly one of [log_group_names, log_group_identifiers] should be non-null. | No
| max_timeout | integer | Maximum time in second to poll for complete results before giving up | No
| query_string | string | The query string in the Cloudwatch Log Insights Query Language. See https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html. | Yes
| start_time | string | ISO 8601 formatted start time for the CloudWatch Logs Insights query window (e.g., "2025-04-19T20:00:00+00:00"). | Yes
</details>
<details>
<summary>get_query_results</summary>

**Description**:

```
IMPORTANT: This tool is deprecated. Please use the get_logs_insight_query_results tool in the cloudwatch MCP server instead.

    Retrieves the results of a previously started CloudWatch Logs Insights query.

    Usage: If a log query is started by execute_log_insights_query tool and has a polling time out, this tool can be used to try to retrieve
    the query results again.

    Returns:
    --------
        A dictionary containing the final query results, including:
            - status: The current status of the query (e.g., Scheduled, Running, Complete, Failed, etc.)
            - results: A list of the actual query results if the status is Complete.
            - statistics: Query performance statistics
            - messages: Any informational messages about the query
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query_id | string | The unique ID of the query to retrieve the results for. CRITICAL: This ID is returned by the execute_log_insights_query tool. | Yes
</details>
<details>
<summary>cancel_query</summary>

**Description**:

```
IMPORTANT: This tool is deprecated. Please use the cancel_logs_insight_query tool in the cloudwatch MCP server instead.

    Cancels an ongoing CloudWatch Logs Insights query. If the query has already ended, returns an error that the given query is not running.

    Usage: If a log query is started by execute_log_insights_query tool and has a polling time out, this tool can be used to cancel
    it prematurely to avoid incurring additional costs.

    Returns:
    --------
        A CancelQueryResult with a "success" key, which is True if the query was successfully cancelled.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query_id | string | The unique ID of the ongoing query to cancel. CRITICAL: This ID is returned by the execute_log_insights_query tool. | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | analyze_log_group | description | 462b467faa9ce1d1f7c2be2a7e9a3e4345ec763cfdb72cb1259c90254564beb7 |
| tools | analyze_log_group | end_time | 3997ade440faa04356dfb3f7c0a1a0cccbe568a338ec31bdd5fd091035266abc |
| tools | analyze_log_group | log_group_arn | 44892253f50f07a601e9583bf9502367b3034501dbc08a1cc1d2eed74e501959 |
| tools | analyze_log_group | start_time | 49bf533ca10effa3f21b09eec50ebb963dbc52aca8dafc2c1d2aeb7ce34906fc |
| tools | cancel_query | description | b5facdcca801b6598de1aeaed3a70f7d8dded1d0e82b2913426b5d447119be91 |
| tools | cancel_query | query_id | 79fad18616ddd05c6a9560772663bbf763bf65335452fdb4c999a946aa179539 |
| tools | describe_log_groups | description | d21ffa52a0b67215b42cad25cbb21ca3b8f9a2859724e0a66d8ad47bb5ed5bde |
| tools | describe_log_groups | account_identifiers | 0616284372483ee4ad11aba76ff4c8f46b0736a1b6fbf31574ccba79b2362dee |
| tools | describe_log_groups | include_linked_accounts | 5fdf06d5ffd7e43e181ecaf2099f8c710c27f1b0a3f9d3a1c1b38f706c90cad6 |
| tools | describe_log_groups | log_group_class | 752ca49ce2fadc956614dd8c95c6aff96c3e6c64bb4b2243d840989d9fa231c7 |
| tools | describe_log_groups | log_group_name_prefix | bd8ff3a5c657d796931b6d5a31f42aa36c670fc268df9407d3da84dff3632747 |
| tools | describe_log_groups | max_items | c569f53a761c02f086964d52af16c9696a4f81db5bfc309fe10b478741de9b60 |
| tools | execute_log_insights_query | description | a4757de9e9c01cca5b19d4cf1500342ef8275e53912828a2f5a916897630d48f |
| tools | execute_log_insights_query | end_time | 3997ade440faa04356dfb3f7c0a1a0cccbe568a338ec31bdd5fd091035266abc |
| tools | execute_log_insights_query | limit | d940667b4b08ab5a35d2ec445e53694c4959be7d25aa4760670c364902c2b8e9 |
| tools | execute_log_insights_query | log_group_identifiers | af232cda048f555aa016db2522c8f8f6e97c9a4952fde5943324d661875a2acf |
| tools | execute_log_insights_query | log_group_names | a43c603e8310b5c4bc3cbd5111c13d0ba838e34f5291471a2a1974d8c417f9c6 |
| tools | execute_log_insights_query | max_timeout | b45b4133d5bba05b49f313454c665de0bee4d795a7b7918ac2a11ca2b955cb2b |
| tools | execute_log_insights_query | query_string | 43ff19874e958b4856b0b5e86a00f7aa31d2dae93ce8d753ad59cec09df533e6 |
| tools | execute_log_insights_query | start_time | 49bf533ca10effa3f21b09eec50ebb963dbc52aca8dafc2c1d2aeb7ce34906fc |
| tools | get_query_results | description | 0f45077406a559a1a12ed135a70c8a21e163fd58f0b74ba301c1cec8bdda7185 |
| tools | get_query_results | query_id | 7aebb7c77b5a50a722a34d7658ea6de80d1a7c5f4e6103c9d679fbb6e19ea443 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
