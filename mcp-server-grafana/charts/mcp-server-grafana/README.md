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


# What is mcp-server-grafana?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-grafana/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-grafana/v0.8.2?logo=docker&logoColor=fff&label=v0.8.2)](https://hub.docker.com/r/acuvity/mcp-server-grafana)
[![GitHUB](https://img.shields.io/badge/v0.8.2-3775A9?logo=github&logoColor=fff&label=grafana/mcp-grafana)](https://github.com/grafana/mcp-grafana)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-grafana/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-grafana&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GRAFANA_API_KEY%22%2C%22-e%22%2C%22GRAFANA_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-grafana%3Av0.8.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Access and manage Grafana dashboards and datasources.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from grafana/mcp-grafana original [sources](https://github.com/grafana/mcp-grafana).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-grafana/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana/charts/mcp-server-grafana/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure grafana/mcp-grafana run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ grafana ](https://github.com/grafana/mcp-grafana) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ grafana/mcp-grafana ](https://github.com/grafana/mcp-grafana)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ grafana/mcp-grafana ](https://github.com/grafana/mcp-grafana)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana/charts/mcp-server-grafana)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-v0.8.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-grafana:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-grafana:1.0.0-v0.8.2`

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
  - `GRAFANA_API_KEY` secret to be set as secrets.GRAFANA_API_KEY either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `GRAFANA_URL` environment variable to be set by env.GRAFANA_URL

# How to install


Install will helm

```console
helm install mcp-server-grafana oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-grafana oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-grafana
```

From there your MCP server mcp-server-grafana will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-grafana` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-grafana
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-grafana` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-grafana oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-grafana oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-grafana oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-grafana oci://docker.io/acuvity/mcp-server-grafana --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (55)
<details>
<summary>add_activity_to_incident</summary>

**Description**:

```
Add a note (userNote activity) to an existing incident's timeline using its ID. The note body can include URLs which will be attached as context. Use this to add context to an incident.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| body | string | The body of the activity. URLs will be parsed and attached as context | No
| eventTime | string | The time that the activity occurred. If not provided, the current time will be used | No
| incidentId | string | The ID of the incident to add the activity to | No
</details>
<details>
<summary>create_alert_rule</summary>

**Description**:

```
Creates a new Grafana alert rule with the specified configuration. Requires title, rule group, folder UID, condition, query data, no data state, execution error state, and duration settings.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| annotations | object | Optional annotations | No
| condition | string | The query condition identifier (e.g. 'A', 'B') | Yes
| data | array | Array of query data objects | Yes
| disableProvenance | boolean | If true, the alert will remain editable in the Grafana UI (sets X-Disable-Provenance header). If false, the alert will be marked with provenance 'api' and locked from UI editing. Defaults to true. | No
| execErrState | string | State on execution error (NoData, Alerting, OK) | Yes
| folderUID | string | The folder UID where the rule will be created | Yes
| for | string | Duration before alert fires (e.g. '5m') | Yes
| labels | object | Optional labels | No
| noDataState | string | State when no data (NoData, Alerting, OK) | Yes
| orgID | integer | The organization ID | Yes
| ruleGroup | string | The rule group name | Yes
| title | string | The title of the alert rule | Yes
| uid | string | Optional UID for the alert rule | No
</details>
<details>
<summary>create_annotation</summary>

**Description**:

```
Create a new annotation on a dashboard or panel.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dashboardId | integer | Deprecated. Use dashboardUID | No
| dashboardUID | string | Preferred dashboard UID | No
| data | object | Optional JSON payload | No
| panelId | integer | Panel ID | No
| tags | array | Optional list of tags | No
| text | string | Annotation text required | No
| time | integer | Start time epoch ms | No
| timeEnd | integer | End time epoch ms | No
</details>
<details>
<summary>create_folder</summary>

**Description**:

```
Create a Grafana folder. Provide a title and optional UID. Returns the created folder.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| parentUid | string | Optional parent folder UID. If set, the folder will be created under this parent. | No
| title | string | The title of the folder. | Yes
| uid | string | Optional folder UID. If omitted, Grafana will generate one. | No
</details>
<details>
<summary>create_graphite_annotation</summary>

**Description**:

```
Create an annotation using Graphite annotation format.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | string | Optional payload | No
| tags | array | Optional list of tags | No
| what | string | Annotation text | No
| when | integer | Epoch ms timestamp | No
</details>
<details>
<summary>create_incident</summary>

**Description**:

```
Create a new Grafana incident. Requires title, severity, and room prefix. Allows setting status and labels. This tool should be used judiciously and sparingly, and only after confirmation from the user, as it may notify or alarm lots of people.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| attachCaption | string | The caption of the attachment | No
| attachUrl | string | The URL of the attachment | No
| isDrill | boolean | Whether the incident is a drill incident | No
| labels | array | The labels to add to the incident | No
| roomPrefix | string | The prefix of the room to create the incident in | No
| severity | string | The severity of the incident | No
| status | string | The status of the incident | No
| title | string | The title of the incident | No
</details>
<details>
<summary>delete_alert_rule</summary>

**Description**:

```
Deletes a Grafana alert rule by its UID. This action cannot be undone.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uid | string | The UID of the alert rule to delete | Yes
</details>
<details>
<summary>fetch_pyroscope_profile</summary>

**Description**:

```

Fetches a profile from a Pyroscope data source for a given time range. By default, the time range is tha past 1 hour.
The profile type is required, available profile types can be fetched via the list_pyroscope_profile_types tool. Not all
profile types are available for every service. Expect some queries to return empty result sets, this indicates the
profile type does not exist for that query. In such a case, consider trying a related profile type or giving up.
Matchers are not required, but highly recommended, they are generally used to select an application by the service_name
label (e.g. {service_name="foo"}). Use the list_pyroscope_label_names tool to fetch available label names, and the
list_pyroscope_label_values tool to fetch available label values. The returned profile is in DOT format.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data_source_uid | string | The UID of the datasource to query | Yes
| end_rfc_3339 | string | Optionally, the end time of the query in RFC3339 format (defaults to now) | No
| matchers | string | Optionally, Prometheus style matchers used to filter the result set (defaults to: {}) | No
| max_node_depth | integer | Optionally, the maximum depth of nodes in the resulting profile. Less depth results in smaller profiles that execute faster, more depth result in larger profiles that have more detail. A value of -1 indicates to use an unbounded node depth (default: 100). Reducing max node depth from the default will negatively impact the accuracy of the profile | No
| profile_type | string | Type profile type, use the list_pyroscope_profile_types tool to fetch available profile types | Yes
| start_rfc_3339 | string | Optionally, the start time of the query in RFC3339 format (defaults to 1 hour ago) | No
</details>
<details>
<summary>find_error_pattern_logs</summary>

**Description**:

```
Searches Loki logs for elevated error patterns compared to the last day's average, waits for the analysis to complete, and returns the results including any patterns found.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end | string | End time for the investigation. Defaults to now if not specified. | No
| labels | object | Labels to scope the analysis | Yes
| name | string | The name of the investigation | Yes
| start | string | Start time for the investigation. Defaults to 30 minutes ago if not specified. | No
</details>
<details>
<summary>find_slow_requests</summary>

**Description**:

```
Searches relevant Tempo datasources for slow requests, waits for the analysis to complete, and returns the results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end | string | End time for the investigation. Defaults to now if not specified. | No
| labels | object | Labels to scope the analysis | Yes
| name | string | The name of the investigation | Yes
| start | string | Start time for the investigation. Defaults to 30 minutes ago if not specified. | No
</details>
<details>
<summary>generate_deeplink</summary>

**Description**:

```
Generate deeplink URLs for Grafana resources. Supports dashboards (requires dashboardUid), panels (requires dashboardUid and panelId), and Explore queries (requires datasourceUid). Optionally accepts time range and additional query parameters.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dashboardUid | string | Dashboard UID (required for dashboard and panel types) | No
| datasourceUid | string | Datasource UID (required for explore type) | No
| panelId | integer | Panel ID (required for panel type) | No
| queryParams | object | Additional query parameters | No
| resourceType | string | Type of resource: dashboard, panel, or explore | Yes
| timeRange | object | Time range for the link | No
</details>
<details>
<summary>get_alert_group</summary>

**Description**:

```
Get a specific alert group from Grafana OnCall by its ID. Returns the full alert group details.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| alertGroupId | string | The ID of the alert group to retrieve | Yes
</details>
<details>
<summary>get_alert_rule_by_uid</summary>

**Description**:

```
Retrieves the full configuration and detailed status of a specific Grafana alert rule identified by its unique ID (UID). The response includes fields like title, condition, query data, folder UID, rule group, state settings (no data, error), evaluation interval, annotations, and labels.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uid | string | The uid of the alert rule | Yes
</details>
<details>
<summary>get_annotation_tags</summary>

**Description**:

```
Returns annotation tags with optional filtering by tag name. Only the provided filters are applied.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | string | Max results, default 100 | No
| tag | string | Optional filter by tag name | No
</details>
<details>
<summary>get_annotations</summary>

**Description**:

```
Fetch Grafana annotations using filters such as dashboard UID, time range and tags.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| AlertID | integer | Deprecated. Use AlertUID | No
| AlertUID | string | Filter by alert UID | No
| DashboardID | integer | Deprecated. Use DashboardUID | No
| DashboardUID | string | Filter by dashboard UID | No
| From | integer | Epoch ms start time | No
| Limit | integer | Max results default 100 | No
| MatchAny | boolean | true OR tag match false AND | No
| PanelID | integer | Filter by panel ID | No
| Tags | array | Multiple tags allowed tags=tag1&tags=tag2 | No
| To | integer | Epoch ms end time | No
| Type | string | annotation or alert | No
| UserID | integer | Filter by creator user ID | No
</details>
<details>
<summary>get_assertions</summary>

**Description**:

```
Get assertion summary for a given entity with its type, name, env, site, namespace, and a time range
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| endTime | string | The end time in RFC3339 format | Yes
| entityName | string | The name of the entity to list | No
| entityType | string | The type of the entity to list (e.g. Service, Node, Pod, etc.) | No
| env | string | The env of the entity to list | No
| namespace | string | The namespace of the entity to list | No
| site | string | The site of the entity to list | No
| startTime | string | The start time in RFC3339 format | Yes
</details>
<details>
<summary>get_current_oncall_users</summary>

**Description**:

```
Get the list of users currently on-call for a specific Grafana OnCall schedule ID. Returns the schedule ID, name, and a list of detailed user objects for those currently on call.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| scheduleId | string | The ID of the schedule to get current on-call users for | Yes
</details>
<details>
<summary>get_dashboard_by_uid</summary>

**Description**:

```
Retrieves the complete dashboard, including panels, variables, and settings, for a specific dashboard identified by its UID. WARNING: Large dashboards can consume significant context window space. Consider using get_dashboard_summary for overview or get_dashboard_property for specific data instead.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uid | string | The UID of the dashboard | Yes
</details>
<details>
<summary>get_dashboard_panel_queries</summary>

**Description**:

```
Use this tool to retrieve panel queries and information from a Grafana dashboard. When asked about panel queries, queries in a dashboard, or what queries a dashboard contains, call this tool with the dashboard UID. The datasource is an object with fields `uid` (which may be a concrete UID or a template variable like "$datasource") and `type`. If the datasource UID is a template variable, it won't be usable directly for queries. Returns an array of objects, each representing a panel, with fields: title, query, and datasource (an object with uid and type).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uid | string | The UID of the dashboard | Yes
</details>
<details>
<summary>get_dashboard_property</summary>

**Description**:

```
Get specific parts of a dashboard using JSONPath expressions to minimize context window usage. Common paths: '$.title' (title)\, '$.panels[*].title' (all panel titles)\, '$.panels[0]' (first panel)\, '$.templating.list' (variables)\, '$.tags' (tags)\, '$.panels[*].targets[*].expr' (all queries). Use this instead of get_dashboard_by_uid when you only need specific dashboard properties.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| jsonPath | string | JSONPath expression to extract specific data (e.g., '$.panels[0].title' for first panel title, '$.panels[*].title' for all panel titles, '$.templating.list' for variables) | Yes
| uid | string | The UID of the dashboard | Yes
</details>
<details>
<summary>get_dashboard_summary</summary>

**Description**:

```
Get a compact summary of a dashboard including title\, panel count\, panel types\, variables\, and other metadata without the full JSON. Use this for dashboard overview and planning modifications without consuming large context windows.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uid | string | The UID of the dashboard | Yes
</details>
<details>
<summary>get_datasource_by_name</summary>

**Description**:

```
Retrieves detailed information about a specific datasource using its name. Returns the full datasource model, including UID, type, URL, access settings, JSON data, and secure JSON field status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | The name of the datasource | Yes
</details>
<details>
<summary>get_datasource_by_uid</summary>

**Description**:

```
Retrieves detailed information about a specific datasource using its UID. Returns the full datasource model, including name, type, URL, access settings, JSON data, and secure JSON field status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| uid | string | The uid of the datasource | Yes
</details>
<details>
<summary>get_incident</summary>

**Description**:

```
Get a single incident by ID. Returns the full incident details including title, status, severity, labels, timestamps, and other metadata.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The ID of the incident to retrieve | No
</details>
<details>
<summary>get_oncall_shift</summary>

**Description**:

```
Get detailed information for a specific Grafana OnCall shift using its ID. A shift represents a designated time period within a schedule when users are actively on-call. Returns the full shift details.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| shiftId | string | The ID of the shift to get details for | Yes
</details>
<details>
<summary>get_panel_image</summary>

**Description**:

```
Render a Grafana dashboard panel or full dashboard as a PNG image. Returns the image as base64 encoded data. Requires the Grafana Image Renderer service to be installed. Use this for generating visual snapshots of dashboards for reports\, alerts\, or presentations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dashboardUid | string | The UID of the dashboard containing the panel | Yes
| height | integer | Height of the rendered image in pixels. Defaults to 500 | No
| panelId | integer | The ID of the panel to render. If omitted, the entire dashboard is rendered | No
| scale | integer | Scale factor for the image (1-3). Defaults to 1 | No
| theme | string | Theme for the rendered image: light or dark. Defaults to dark | No
| timeRange | object | Time range for the rendered image | No
| timeout | integer | Rendering timeout in seconds. Defaults to 60 | No
| variables | object | Dashboard variables to apply (e.g., {"var-datasource": "prometheus"}) | No
| width | integer | Width of the rendered image in pixels. Defaults to 1000 | No
</details>
<details>
<summary>get_sift_analysis</summary>

**Description**:

```
Retrieves a specific analysis from an investigation by its UUID. The investigation ID and analysis ID should be provided as strings in UUID format.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| analysisId | string | The UUID of the specific analysis to retrieve | Yes
| investigationId | string | The UUID of the investigation as a string (e.g. '02adab7c-bf5b-45f2-9459-d71a2c29e11b') | Yes
</details>
<details>
<summary>get_sift_investigation</summary>

**Description**:

```
Retrieves an existing Sift investigation by its UUID. The ID should be provided as a string in UUID format (e.g. '02adab7c-bf5b-45f2-9459-d71a2c29e11b').
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The UUID of the investigation as a string (e.g. '02adab7c-bf5b-45f2-9459-d71a2c29e11b') | Yes
</details>
<details>
<summary>list_alert_groups</summary>

**Description**:

```
List alert groups from Grafana OnCall with filtering options. Supports filtering by alert group ID, route ID, integration ID, state (new, acknowledged, resolved, silenced), team ID, time range, labels, and name. For time ranges, use format '{start}_{end}' ISO 8601 timestamp range (e.g., '2025-01-19T00:00:00_2025-01-19T23:59:59' for a specific day). For labels, use format 'key:value' (e.g., ['env:prod', 'severity:high']). Returns a list of alert group objects with their details. Supports pagination.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | Filter by specific alert group ID | No
| integrationId | string | Filter by integration ID | No
| labels | array | Filter by labels in format key:value (e.g., ['env:prod', 'severity:high']) | No
| name | string | Filter by alert group name | No
| page | integer | The page number to return | No
| routeId | string | Filter by route ID | No
| startedAt | string | Filter by time range in format '{start}_{end}' ISO 8601 timestamp range (UTC assumed, no timezone indicator needed) (e.g., '2025-01-19T00:00:00_2025-01-19T23:59:59') | No
| state | string | Filter by alert group state (one of: new, acknowledged, resolved, silenced) | No
| teamId | string | Filter by team ID | No
</details>
<details>
<summary>list_alert_rules</summary>

**Description**:

```
Lists Grafana alert rules, returning a summary including UID, title, current state (e.g., 'pending', 'firing', 'inactive'), and labels. Optionally query datasource-managed rules from Prometheus or Loki by providing datasourceUid. Supports filtering by labels using selectors and pagination. Example label selector: `[{'name': 'severity', 'type': '=', 'value': 'critical'}]`. Inactive state means the alert state is normal, not firing
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | Optional: UID of a Prometheus or Loki datasource to query for datasource-managed alert rules. If omitted, returns Grafana-managed rules. | No
| label_selectors | array | Optionally, a list of matchers to filter alert rules by labels | No
| limit | integer | The maximum number of results to return | No
| page | integer | The page number to return | No
</details>
<details>
<summary>list_contact_points</summary>

**Description**:

```
Lists Grafana notification contact points, returning a summary including UID, name, and type for each. Optionally query Alertmanager receivers by providing datasourceUid. Supports filtering by name - exact match - and limiting the number of results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | Optional: UID of an Alertmanager-compatible datasource to query for receivers. If omitted, returns Grafana-managed contact points. | No
| limit | integer | The maximum number of results to return. Default is 100. | No
| name | string | Filter contact points by name | No
</details>
<details>
<summary>list_datasources</summary>

**Description**:

```
List available Grafana datasources. Optionally filter by datasource type (e.g., 'prometheus', 'loki'). Returns a summary list including ID, UID, name, type, and default status.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| type | string | The type of datasources to search for. For example, 'prometheus', 'loki', 'tempo', etc... | No
</details>
<details>
<summary>list_incidents</summary>

**Description**:

```
List Grafana incidents. Allows filtering by status ('active', 'resolved') and optionally including drill incidents. Returns a preview list with basic details.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| drill | boolean | Whether to include drill incidents | No
| limit | integer | The maximum number of incidents to return | No
| status | string | The status of the incidents to include. Valid values: 'active', 'resolved' | No
</details>
<details>
<summary>list_loki_label_names</summary>

**Description**:

```
Lists all available label names (keys) found in logs within a specified Loki datasource and time range. Returns a list of unique label strings (e.g., `["app", "env", "pod"]`). If the time range is not provided, it defaults to the last hour.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endRfc3339 | string | Optionally, the end time of the query in RFC3339 format (defaults to now) | No
| startRfc3339 | string | Optionally, the start time of the query in RFC3339 format (defaults to 1 hour ago) | No
</details>
<details>
<summary>list_loki_label_values</summary>

**Description**:

```
Retrieves all unique values associated with a specific `labelName` within a Loki datasource and time range. Returns a list of string values (e.g., for `labelName="env"`, might return `["prod", "staging", "dev"]`). Useful for discovering filter options. Defaults to the last hour if the time range is omitted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endRfc3339 | string | Optionally, the end time of the query in RFC3339 format (defaults to now) | No
| labelName | string | The name of the label to retrieve values for (e.g. 'app', 'env', 'pod') | Yes
| startRfc3339 | string | Optionally, the start time of the query in RFC3339 format (defaults to 1 hour ago) | No
</details>
<details>
<summary>list_oncall_schedules</summary>

**Description**:

```
List Grafana OnCall schedules, optionally filtering by team ID. If a specific schedule ID is provided, retrieves details for only that schedule. Returns a list of schedule summaries including ID, name, team ID, timezone, and shift IDs. Supports pagination.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | integer | The page number to return (1-based) | No
| scheduleId | string | The ID of the schedule to get details for. If provided, returns only that schedule's details | No
| teamId | string | The ID of the team to list schedules for | No
</details>
<details>
<summary>list_oncall_teams</summary>

**Description**:

```
List teams configured in Grafana OnCall. Returns a list of team objects with their details. Supports pagination.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | integer | The page number to return | No
</details>
<details>
<summary>list_oncall_users</summary>

**Description**:

```
List users from Grafana OnCall. Can retrieve all users, a specific user by ID, or filter by username. Returns a list of user objects with their details. Supports pagination.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | integer | The page number to return | No
| userId | string | The ID of the user to get details for. If provided, returns only that user's details | No
| username | string | The username to filter users by. If provided, returns only the user matching this username | No
</details>
<details>
<summary>list_prometheus_label_names</summary>

**Description**:

```
List label names in a Prometheus datasource. Allows filtering by series selectors and time range.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endRfc3339 | string | Optionally, the end time of the time range to filter the results by | No
| limit | integer | Optionally, the maximum number of results to return | No
| matches | array | Optionally, a list of label matchers to filter the results by | No
| startRfc3339 | string | Optionally, the start time of the time range to filter the results by | No
</details>
<details>
<summary>list_prometheus_label_values</summary>

**Description**:

```
Get the values for a specific label name in Prometheus. Allows filtering by series selectors and time range.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endRfc3339 | string | Optionally, the end time of the query | No
| labelName | string | The name of the label to query | Yes
| limit | integer | Optionally, the maximum number of results to return | No
| matches | array | Optionally, a list of selectors to filter the results by | No
| startRfc3339 | string | Optionally, the start time of the query | No
</details>
<details>
<summary>list_prometheus_metric_metadata</summary>

**Description**:

```
List Prometheus metric metadata. Returns metadata about metrics currently scraped from targets. Note: This endpoint is experimental.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| limit | integer | The maximum number of metrics to return | No
| limitPerMetric | integer | The maximum number of metrics to return per metric | No
| metric | string | The metric to query | No
</details>
<details>
<summary>list_prometheus_metric_names</summary>

**Description**:

```
List metric names in a Prometheus datasource. Retrieves all metric names and then filters them locally using the provided regex. Supports pagination.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| limit | integer | The maximum number of results to return | No
| page | integer | The page number to return | No
| regex | string | The regex to match against the metric names | No
</details>
<details>
<summary>list_pyroscope_label_names</summary>

**Description**:

```

Lists all available label names (keys) found in profiles within a specified Pyroscope datasource, time range, and
optional label matchers. Label matchers are typically used to qualify a service name ({service_name="foo"}). Returns a
list of unique label strings (e.g., ["app", "env", "pod"]). Label names with double underscores (e.g. __name__) are
internal and rarely useful to users. If the time range is not provided, it defaults to the last hour.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data_source_uid | string | The UID of the datasource to query | Yes
| end_rfc_3339 | string | Optionally, the end time of the query in RFC3339 format (defaults to now) | No
| matchers | string | not set | No
| start_rfc_3339 | string | Optionally, the start time of the query in RFC3339 format (defaults to 1 hour ago) | No
</details>
<details>
<summary>list_pyroscope_label_values</summary>

**Description**:

```

Lists all available label values for a particular label name found in profiles within a specified Pyroscope datasource,
time range, and optional label matchers. Label matchers are typically used to qualify a service name ({service_name="foo"}).
Returns a list of unique label strings (e.g. for label name "env": ["dev", "staging", "prod"]). If the time range
is not provided, it defaults to the last hour.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data_source_uid | string | The UID of the datasource to query | Yes
| end_rfc_3339 | string | Optionally, the end time of the query in RFC3339 format (defaults to now) | No
| matchers | string | Optionally, Prometheus style matchers used to filter the result set (defaults to: {}) | No
| name | string | A label name | Yes
| start_rfc_3339 | string | Optionally, the start time of the query in RFC3339 format (defaults to 1 hour ago) | No
</details>
<details>
<summary>list_pyroscope_profile_types</summary>

**Description**:

```

Lists all available profile types available in a specified Pyroscope datasource and time range. Returns a list of all
available profile types (example profile type: "process_cpu:cpu:nanoseconds:cpu:nanoseconds"). A profile type has the
following structure: <name>:<sample type>:<sample unit>:<period type>:<period unit>. Not all profile types are available
for every service. If the time range is not provided, it defaults to the last hour.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data_source_uid | string | The UID of the datasource to query | Yes
| end_rfc_3339 | string | Optionally, the end time of the query in RFC3339 format (defaults to now) | No
| start_rfc_3339 | string | Optionally, the start time of the query in RFC3339 format (defaults to 1 hour ago) | No
</details>
<details>
<summary>list_sift_investigations</summary>

**Description**:

```
Retrieves a list of Sift investigations with an optional limit. If no limit is specified, defaults to 10 investigations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Maximum number of investigations to return | No
</details>
<details>
<summary>patch_annotation</summary>

**Description**:

```
Updates only the provided properties of an annotation. Fields omitted are not modified. Use update_annotation for full replacement.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Optional metadata | No
| id | integer | Annotation ID | No
| tags | array | Optional replace tags | No
| text | string | Optional new text | No
| time | integer | Optional new start epoch ms | No
| timeEnd | integer | Optional new end epoch ms | No
</details>
<details>
<summary>query_loki_logs</summary>

**Description**:

```
Executes a LogQL query against a Loki datasource to retrieve log entries or metric values. Returns a list of results, each containing a timestamp, labels, and either a log line (`line`) or a numeric metric value (`value`). Defaults to the last hour, a limit of 10 entries, and 'backward' direction (newest first). Supports full LogQL syntax for log and metric queries (e.g., `{app="foo"} |= "error"`, `rate({app="bar"}[1m])`). Prefer using `query_loki_stats` first to check stream size and `list_loki_label_names` and `list_loki_label_values` to verify labels exist.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| direction | string | Optionally, the direction of the query: 'forward' (oldest first) or 'backward' (newest first, default) | No
| endRfc3339 | string | Optionally, the end time of the query in RFC3339 format | No
| limit | integer | Optionally, the maximum number of log lines to return (max: 100) | No
| logql | string | The LogQL query to execute against Loki. This can be a simple label matcher or a complex query with filters, parsers, and expressions. Supports full LogQL syntax including label matchers, filter operators, pattern expressions, and pipeline operations. | Yes
| startRfc3339 | string | Optionally, the start time of the query in RFC3339 format | No
</details>
<details>
<summary>query_loki_stats</summary>

**Description**:

```
Retrieves statistics about log streams matching a given LogQL *selector* within a Loki datasource and time range. Returns an object containing the count of streams, chunks, entries, and total bytes (e.g., `{"streams": 5, "chunks": 50, "entries": 10000, "bytes": 512000}`). The `logql` parameter **must** be a simple label selector (e.g., `{app="nginx", env="prod"}`) and does not support line filters, parsers, or aggregations. Defaults to the last hour if the time range is omitted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endRfc3339 | string | Optionally, the end time of the query in RFC3339 format | No
| logql | string | The LogQL matcher expression to execute. This parameter only accepts label matcher expressions and does not support full LogQL queries. Line filters, pattern operations, and metric aggregations are not supported by the stats API endpoint. Only simple label selectors can be used here. | Yes
| startRfc3339 | string | Optionally, the start time of the query in RFC3339 format | No
</details>
<details>
<summary>query_prometheus</summary>

**Description**:

```
Query Prometheus using a PromQL expression. Supports both instant queries (at a single point in time) and range queries (over a time range). Time can be specified either in RFC3339 format or as relative time expressions like 'now', 'now-1h', 'now-30m', etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endTime | string | The end time. Required if queryType is 'range', ignored if queryType is 'instant' Supported formats are RFC3339 or relative to now (e.g. 'now', 'now-1.5h', 'now-2h45m'). Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h', 'd'. | No
| expr | string | The PromQL expression to query | Yes
| queryType | string | The type of query to use. Either 'range' or 'instant' | No
| startTime | string | The start time. Supported formats are RFC3339 or relative to now (e.g. 'now', 'now-1.5h', 'now-2h45m'). Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h', 'd'. | Yes
| stepSeconds | integer | The time series step size in seconds. Required if queryType is 'range', ignored if queryType is 'instant' | No
</details>
<details>
<summary>search_dashboards</summary>

**Description**:

```
Search for Grafana dashboards by a query string. Returns a list of matching dashboards with details like title, UID, folder, tags, and URL.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The query to search for | No
</details>
<details>
<summary>search_folders</summary>

**Description**:

```
Search for Grafana folders by a query string. Returns matching folders with details like title, UID, and URL.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The query to search for | No
</details>
<details>
<summary>update_alert_rule</summary>

**Description**:

```
Updates an existing Grafana alert rule identified by its UID. Requires all the same parameters as creating a new rule.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| annotations | object | Optional annotations | No
| condition | string | The query condition identifier (e.g. 'A', 'B') | Yes
| data | array | Array of query data objects | Yes
| disableProvenance | boolean | If true, the alert will remain editable in the Grafana UI (sets X-Disable-Provenance header). If false, the alert will be marked with provenance 'api' and locked from UI editing. Defaults to true. | No
| execErrState | string | State on execution error (NoData, Alerting, OK) | Yes
| folderUID | string | The folder UID where the rule will be created | Yes
| for | string | Duration before alert fires (e.g. '5m') | Yes
| labels | object | Optional labels | No
| noDataState | string | State when no data (NoData, Alerting, OK) | Yes
| orgID | integer | The organization ID | Yes
| ruleGroup | string | The rule group name | Yes
| title | string | The title of the alert rule | Yes
| uid | string | The UID of the alert rule to update | Yes
</details>
<details>
<summary>update_annotation</summary>

**Description**:

```
Updates all properties of an annotation that matches the specified ID. Sends a full update (PUT). For partial updates, use patch_annotation instead.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Optional JSON payload | No
| id | integer | Annotation ID to update | No
| tags | array | Tags to replace existing tags | No
| text | string | Annotation text | No
| time | integer | Start time epoch ms | No
| timeEnd | integer | End time epoch ms | No
</details>
<details>
<summary>update_dashboard</summary>

**Description**:

```
Create or update a dashboard using either full JSON or efficient patch operations. For new dashboards\, provide the 'dashboard' field. For updating existing dashboards\, use 'uid' + 'operations' for better context window efficiency. Patch operations support complex JSONPaths like '$.panels[0].targets[0].expr'\, '$.panels[1].title'\, '$.panels[2].targets[0].datasource'\, etc. Supports appending to arrays using '/- ' syntax: '$.panels/- ' appends to panels array\, '$.panels[2]/- ' appends to nested array at index 2.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dashboard | object | The full dashboard JSON. Use for creating new dashboards or complete updates. Large dashboards consume significant context - consider using patches for small changes. | No
| folderUid | string | The UID of the dashboard's folder | No
| message | string | Set a commit message for the version history | No
| operations | array | Array of patch operations for targeted updates. More efficient than full dashboard JSON for small changes. | No
| overwrite | boolean | Overwrite the dashboard if it exists. Otherwise create one | No
| uid | string | UID of existing dashboard to update. Required when using patch operations. | No
| userId | integer | ID of the user making the change | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_activity_to_incident | description | 610552ea63617a74fd015f4a67b3a5c8e1fe3c0979922a1c235ec2cc6a9de2aa |
| tools | add_activity_to_incident | body | 4f2ae7b4e5dbb0246bd049bc943119942ea2a8444e11af741d23c3455308e76f |
| tools | add_activity_to_incident | eventTime | c90be1aee29eac2cbe9efd8f0ce87246de26fd726ea69a93bfdc9cea7e4e1930 |
| tools | add_activity_to_incident | incidentId | 59a43b22ccdd6198f3a3c93a4c6434dd8f764ebbc906ac32b37c0f480bf313a8 |
| tools | create_alert_rule | description | c38904ec04e8a848b8a60d1db09a0b7d8b15795d2aa183a0d95b84657a19647c |
| tools | create_alert_rule | annotations | d2228ef66e752c3c9580d9e3a00b78b8d92fac797e116d00697d043f608facd5 |
| tools | create_alert_rule | condition | ad2b3f4e58c519395b91312161782e860ddee28a610b0a0c6459e8820988d231 |
| tools | create_alert_rule | data | 5c2374e0401e98245730e593e294bd592743e07e4a5c6f1c950eaaafbc52d635 |
| tools | create_alert_rule | disableProvenance | 317ecf94ae3b3b0822cede54e74ad55508e648033a0ae2262bbed8a8117088f8 |
| tools | create_alert_rule | execErrState | 7599fdfe035f82bdb8126c3888f481488ca8d06745b57d797f594b8f12ee2368 |
| tools | create_alert_rule | folderUID | 450d49f34ddf25ad7d43a4b82976fc85583285214acc3a363edaaa28a33d9223 |
| tools | create_alert_rule | for | b961b1cb007da234f517a77492f9497db06f44599d5abcd9ddb484aa9d73ebc1 |
| tools | create_alert_rule | labels | bcd0b6bb6a741d22956599b28f574978d1c8ebe1d40a2b8146df3a442d59f4e9 |
| tools | create_alert_rule | noDataState | dcd1109194e1830e4d1eccad9615fb1a4533607c8a0767ca8037aac394bd77e6 |
| tools | create_alert_rule | orgID | 38592c32d6c55b342614f31e363b9ac32a96bbe4070fbb2f09c2cffb7c4fad36 |
| tools | create_alert_rule | ruleGroup | a594843135e3285a266c5fd7f085a1ce7d1656cf314ea869066c77d5f007fcd1 |
| tools | create_alert_rule | title | 8bc7d75270b512b2f0987762a67534ca07956960e5a9c211909084ea46332c3c |
| tools | create_alert_rule | uid | a631eb8514bff9bd049b5e0dcc89ae161daa875ac401fbf75d73c333cd9e03ca |
| tools | create_annotation | description | eab4b6e7d7802180473db9009431dd60673472add2ca8f9256963bf4ebddd20c |
| tools | create_annotation | dashboardId | a23809ee02795cc7ca8ef4a3e4188ee3343dae161901d4174a8e9a4a6e494098 |
| tools | create_annotation | dashboardUID | 4c57d813691b5b28a58319b0b4160d308e9e36cc9472d8424ab697bf51c52b48 |
| tools | create_annotation | data | 27db5aec9935bf854da920af32eae050ee14e1ed3840af9ef792a1e927e99026 |
| tools | create_annotation | panelId | e738d52375d65eb02067cf41e0807c06c4e21f391d5334bb5bed79e9a2e61daf |
| tools | create_annotation | tags | fb0b8ad480c45b3057b065417b097913446789053521f6b0c54a4e48f45e6367 |
| tools | create_annotation | text | 10566b235ceaec6a0bfa0bdccd7af9e0e6f00a597d8e3021f288ce0d449f8943 |
| tools | create_annotation | time | 0e94c35e90a8f514519532f9d0d041b12bb69e8afa122fe0823a25ec0f88ad11 |
| tools | create_annotation | timeEnd | 047ae1cfe87622f803c53506a2a64be0cb44f8140ba40bcf1e475e4b3621154e |
| tools | create_folder | description | af7e3a8d1006d9befb6ee29b7f47a862d67112876b6ab89c2e6c25fed33504f7 |
| tools | create_folder | parentUid | 2fa44fc91a58dc677884f1c0a40e2d41db748bb89e6f012b295fa4e3e106f76f |
| tools | create_folder | title | 9f21d57e1b9547574d57faa30b0721d3fdf08a2b9e9d0b160047255c76340294 |
| tools | create_folder | uid | 19eab6f35553b61db31d2e040af79dc2fe7779de4505984a62bdaa036f27a183 |
| tools | create_graphite_annotation | description | e694920bd0878a5ef607eeebef4dbdaa47f28b59a7b6ae21b311a2bb1d7be086 |
| tools | create_graphite_annotation | data | 1450f2699bfa45316ed5b8da5976eafbf5f7610035640a73b7d03ee1e8ca9de8 |
| tools | create_graphite_annotation | tags | fb0b8ad480c45b3057b065417b097913446789053521f6b0c54a4e48f45e6367 |
| tools | create_graphite_annotation | what | 20ea579a8f895bce2ca82cd408d97a98ba274b944062131b3411671f49982667 |
| tools | create_graphite_annotation | when | 250662bcac6022b9052b6d86443af06aa08c1ca48a2d834a3c3f48e0b0d7be0f |
| tools | create_incident | description | a2228ba3f1644395aa75ee218bc2baec8f9566e577b57edadda2ff95cc0c2e80 |
| tools | create_incident | attachCaption | 6ec6551fcfd6921f479963ca5f5fe0aea79a54e18f384dbeea9b730a8dc5c0ab |
| tools | create_incident | attachUrl | 46c8ed77659ce812078a18400b6e1a0c577344a1cbdcc4126646c4c47936bc23 |
| tools | create_incident | isDrill | 2ac103f8fd1202e0d33f77b65610eaab778a6a5364d0aef510933b82758d6234 |
| tools | create_incident | labels | 65fc74a7acdd9f44cf155dbff26a85f5738a1cbc5f4177857dab9cea779e84cd |
| tools | create_incident | roomPrefix | e10bbd57589e4550f7c2e78c9c282472a8483d35aa0be3d576275892174277f5 |
| tools | create_incident | severity | 20a6cddd98286182ed0f693abe5003aa11928afde75c775ff6744c65f2ba53ea |
| tools | create_incident | status | 879aecbbf80e7a0380b8a85c4597cb725247a67b36a53fb197e24ac3dcc32251 |
| tools | create_incident | title | 90902805e58ea7f007150ed8ae10150fd92cc5996b6ad68abdbf145dd8fe0143 |
| tools | delete_alert_rule | description | cf01928aff1437aedbc507c6d76d0b86901f6db5ebfeb2e5247d749d5a41ffdf |
| tools | delete_alert_rule | uid | 6c0e1a57a023e5b3d9df933cf7e1dc0128034a9a0425eb088fd6a69647d5b100 |
| tools | fetch_pyroscope_profile | description | 2fff6f697ba5d4ec1d17ad0f839d91f8326b0d1908d8f2ef070b87aa325c1d12 |
| tools | fetch_pyroscope_profile | data_source_uid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | fetch_pyroscope_profile | end_rfc_3339 | 5c050f729007ebdea18a414ed0fb9fdb31be9f2a63eb87f5bba9707273ed8df2 |
| tools | fetch_pyroscope_profile | matchers | 4d6b17885b5d87e16b80eb71860a15b7982c5dd24d129c88b9bd594b1609e77f |
| tools | fetch_pyroscope_profile | max_node_depth | d44145640f4506c9ee5671eaf816e0cecf04d9806b0ec9ef0069351ba16cad90 |
| tools | fetch_pyroscope_profile | profile_type | fe7faaca4f4005d7e80473670178f537ffdd9e8feb972f4268f51cfc5cccb835 |
| tools | fetch_pyroscope_profile | start_rfc_3339 | e93ead65fef426f987915ecb159e06412a589c2ce3b47fe5f58b105870172a5c |
| tools | find_error_pattern_logs | description | fa47e666d5bb315bb4a3fc51d6e316b9d65b10e175be7d681bb73270c72a9c19 |
| tools | find_error_pattern_logs | end | ccb76e275799b1078482ad33ba3199e103d60bfb527c293f59fbaa92e43b38f0 |
| tools | find_error_pattern_logs | labels | 5d4e65048a0c8393cc5f32605e62a76cfd1fec46777f84c37b92bcda9c56023f |
| tools | find_error_pattern_logs | name | c59b0f4f120e19db3b16052e1867319d8082cc9bfa4fa5702608c0075d7ca17f |
| tools | find_error_pattern_logs | start | a64b2c75b4e69697ebdaf5e93fd27e58639d019cf5e5442dd3b0621ac4f56c3f |
| tools | find_slow_requests | description | d2693a5b0198c7482fd27658f09afa284ea8ff1316d9b14f0f67b2fba97af7d5 |
| tools | find_slow_requests | end | ccb76e275799b1078482ad33ba3199e103d60bfb527c293f59fbaa92e43b38f0 |
| tools | find_slow_requests | labels | 5d4e65048a0c8393cc5f32605e62a76cfd1fec46777f84c37b92bcda9c56023f |
| tools | find_slow_requests | name | c59b0f4f120e19db3b16052e1867319d8082cc9bfa4fa5702608c0075d7ca17f |
| tools | find_slow_requests | start | a64b2c75b4e69697ebdaf5e93fd27e58639d019cf5e5442dd3b0621ac4f56c3f |
| tools | generate_deeplink | description | d61ef07027b8f146d49f401fffb1df9091b5e46e9e8a9d2e078798c089e5bbf8 |
| tools | generate_deeplink | dashboardUid | 997a3f8b63af738e0995b77ed21a4daec1268ef43483772231014fdd1964f740 |
| tools | generate_deeplink | datasourceUid | b1217f9a10f43f0bfa3681ff729416cdfb61bf04878c89c58790f3fe63d6bd5b |
| tools | generate_deeplink | panelId | 3019502d87ae498499ab74cbf2aa87505fd0e897c50b77f99db81d47c07e5ba6 |
| tools | generate_deeplink | queryParams | b3007a9b3dccc195358f9e003aa267987a987fb267a3bdf214898ff10296fb7f |
| tools | generate_deeplink | resourceType | 93179303e3bc04f5ae0c372ce4ef88a2ff5755345c8924dd1da269f49dfe1065 |
| tools | generate_deeplink | timeRange | 0c353fb70fa4523fa4be118a520c2a7b4272ecdf1eba53867f63406f3d510592 |
| tools | get_alert_group | description | f6f20e6d6e30fac6b8f7f7f1d1123cb926468ad0e66f74a92b354e282114ac22 |
| tools | get_alert_group | alertGroupId | ea9ee5c44da79fab2f0a7e5288d833e3565ab0e64096a464b8c799813122b30e |
| tools | get_alert_rule_by_uid | description | c69f515c7b9a915e35d99fc2bbb70d8f79da64a4fa7532c940402a2c2f321106 |
| tools | get_alert_rule_by_uid | uid | 2b20b8723d35fa58fa40a4ed72a4c5f8537437076a83fe964d6a59cb1626f2f8 |
| tools | get_annotation_tags | description | 5ab6358c2f960a2bd8fac5ed029669859956298cd011e1d5e9b155ccc68367c7 |
| tools | get_annotation_tags | limit | 376a1005c8f7f777342e647f2ff370a88fb361f1dd1a8f76fd3e2683c03a9431 |
| tools | get_annotation_tags | tag | 6823377d6a0a57aeb74f2775daf41fcbf921615780deb5b0da6ef7cff4495543 |
| tools | get_annotations | description | 168dc0c1612fc22444ccdbf6ea48273cce26a90020505061154c201345d04a81 |
| tools | get_annotations | AlertID | 3ac551fef763179ac494be4c9cdbec21c6e501421d62c8f03ed0ec3030a064f7 |
| tools | get_annotations | AlertUID | 4d5321361eb95c23a48cec13e33c8d8259ef31ad0013444ba52c8b56d9d1aba4 |
| tools | get_annotations | DashboardID | 9e3b411876719d0b2875b3767005767f383d8225e9f408dd54dd9f1488a2909d |
| tools | get_annotations | DashboardUID | 956e30d36775bbe32c34beb073d3d8e73a0e3267899bf6e22a33666dca29332b |
| tools | get_annotations | From | 729f11a57dff9fdca4f8f3653f87456c43218650091dabe3648c32dd8a386c61 |
| tools | get_annotations | Limit | 19ca01f4bdf925bd73fda3447b6c54264ffc1a618d30ab37d518c8e9c5051764 |
| tools | get_annotations | MatchAny | b15786290e5c74afa30e29806fe19853311c84ac8349132518b9e65e85e21a61 |
| tools | get_annotations | PanelID | 7ad0e3a57253e0cb489452878c1f2269f0ba8374fa7c4b73346260763a60a8f7 |
| tools | get_annotations | Tags | ec3df56b7442e42dcc42c13219e1501a89036ee077cc5e65a3e37abd836bea25 |
| tools | get_annotations | To | d9c71ada5073e7e325065cf8e11882a9f83695d1cd795bb114414eb14d681ea0 |
| tools | get_annotations | Type | 95cf2472d2b3c0930220b0c44fd589c788d28d4aee1ee2d4d74886870b904d37 |
| tools | get_annotations | UserID | ba4c812b2afc475f3d936391b7095d12d58bad53a6057fe6bdabcec82c8f690b |
| tools | get_assertions | description | 5d4f98d1a0957d3341cbc8fdbf4ebb8d807f18a49aeb963ef1017c9bfd5f5a45 |
| tools | get_assertions | endTime | 1fcf7dd086413698b6846e22b86c4693001d2ffcc7dfa89633a074a2d845c5a7 |
| tools | get_assertions | entityName | 3f63ab34f932e99286199604e4f5131542e0cb9037e3da211528f961f72c945a |
| tools | get_assertions | entityType | c9b0915ea38bf4edc68d24b91be9af46d50f942ce50fd2a425930a0ba0c0227e |
| tools | get_assertions | env | b59041eb0851ffb827fb6dc44d1787ed061bf5c817399060127debf181b3b6d4 |
| tools | get_assertions | namespace | 826901ccd29a9570b734e9fa20622cf174a72bed8e052d89fb2e88f864f88474 |
| tools | get_assertions | site | 3d387a2e827f859535e3d8fdc8ff24ebc5af781fe97a7aa8595712580315217f |
| tools | get_assertions | startTime | 13ba7a11b929754ca04718ceb5017df289f55e690796da5a0fe151ad65f8e3a5 |
| tools | get_current_oncall_users | description | 7f186ce2d78680fc622fb8d0817a0a83d3625aa8651fcf2c90688f5af583c9cf |
| tools | get_current_oncall_users | scheduleId | e449393009af366a05b28c1e3a74927a385969308f419d68546a445fd4508631 |
| tools | get_dashboard_by_uid | description | 90c5c2e737040bf50809bf55241255e523ab5f87c4bc81f472cdc7d804bfec59 |
| tools | get_dashboard_by_uid | uid | a5663f54c0d36ef714da821bb2097dd6808a8fd3e27d1d16af28f85b999a1d62 |
| tools | get_dashboard_panel_queries | description | 642fc66665276b86f1852308040c7717e6560872f8a9dbd36ae246743343a8b9 |
| tools | get_dashboard_panel_queries | uid | a5663f54c0d36ef714da821bb2097dd6808a8fd3e27d1d16af28f85b999a1d62 |
| tools | get_dashboard_property | description | 9f877be771fd893538f7f3f4142bffac892f09c77b44b3c7d4d23fc7b26cab74 |
| tools | get_dashboard_property | jsonPath | 7152af11f2a5c5c3c074d77c6e2b4116ddfc42cd1f236a0b3d1e0b96876937ed |
| tools | get_dashboard_property | uid | a5663f54c0d36ef714da821bb2097dd6808a8fd3e27d1d16af28f85b999a1d62 |
| tools | get_dashboard_summary | description | f014addfe0a65281a18e3cf19add5fe2f8b0dd7b7dac8e5f8abd046791d107e4 |
| tools | get_dashboard_summary | uid | a5663f54c0d36ef714da821bb2097dd6808a8fd3e27d1d16af28f85b999a1d62 |
| tools | get_datasource_by_name | description | b0344ad3d9c9928ae54fedcbdd5c0745223b7bbdffdd302268fb3ab9b55f121c |
| tools | get_datasource_by_name | name | a25821cfd50f370f8978c50e86779c8e3f5f85b0ac61048aa6faa5d63c46703b |
| tools | get_datasource_by_uid | description | 88461427672ce15e88a831f7edeeeb9712841baccde3a669b1345c49915d71f7 |
| tools | get_datasource_by_uid | uid | 1fb37ce58fc9ed3f190cb80d768b797637a69ad3df1d5a0a5b491a79d2c573fb |
| tools | get_incident | description | 1a0d1c1d0b9d4292f0dc54a358c03abf7c6aded92c8d86dbc64aa53d9d978145 |
| tools | get_incident | id | 2e366f8aaf4953c4ed902746a39abcb24750bccc27a3ca9cab790dd868c13bd5 |
| tools | get_oncall_shift | description | 554ebc8791e077e334947b97d694ead30aa7d54a9d88175d77b7ecdf83fd9fab |
| tools | get_oncall_shift | shiftId | bf009f7f59eadbfa53cfacdbeba406a1807be39718e207204bf0d8fa87217df3 |
| tools | get_panel_image | description | 1c4d86de9216bcc237e1f3163422ef6b884a62dd5d8c4a532322eff28c0cc693 |
| tools | get_panel_image | dashboardUid | aabbcf7e4f840d99913b1c604794fbe100f7ba427cb0b14d8cad2fc90e5371ab |
| tools | get_panel_image | height | 2d41a05c7578b489680c89efe846ff64daa67f8e77d9f777d5c4ba7430090025 |
| tools | get_panel_image | panelId | 517b60452be9f20a1c728cee9acbcccb8967a7aaeec86836d9f09b4a8a711f6c |
| tools | get_panel_image | scale | d5f8afc63dd1fa8c4ed859b0f22aec457ffceca259881f809fdef30929cfa0fa |
| tools | get_panel_image | theme | a4f180325a7fdff629c917626e0a9b7d6a8cf50bc25b6facb029939a25add3f9 |
| tools | get_panel_image | timeRange | 93a05d0cd138b5f2a322f0fef59a2b648e34e7dcc61e42887f3815f5ed321f08 |
| tools | get_panel_image | timeout | 276a6cb117a61f9213596013a2b34a9f0eef917ef27f0eb486b34e4b2fb0b52d |
| tools | get_panel_image | variables | 98f8f9d0b15f9e2f67ff39bfdf50a05bb30a9f2fa03dc895713f22adc43e1d48 |
| tools | get_panel_image | width | 7459f534e11f7d7bb1fdf96d1718365aeff2e34c1b0e3c48568e7d95590544f4 |
| tools | get_sift_analysis | description | 3fb36a7a963fd6fe938ebfc25cbd8b8365ec970391db5c047cda85014594a38b |
| tools | get_sift_analysis | analysisId | d31cc9712d0e0fbe607df52f56b7b28672a33939f1df6466443dcdb41d192fa2 |
| tools | get_sift_analysis | investigationId | e93954e3229bb1f1e682080864dc442473cf498633e13f3a5190094da58723d0 |
| tools | get_sift_investigation | description | d12373019135e755340b1ce5d93f763c91ca1a67c6620239a5f939c029e3672c |
| tools | get_sift_investigation | id | e93954e3229bb1f1e682080864dc442473cf498633e13f3a5190094da58723d0 |
| tools | list_alert_groups | description | 58495671156603f9b5c7a230e0ab55b12135857d181b2e3636cc90c2037b87cb |
| tools | list_alert_groups | id | dffcc5d80ee71cad8fe6d1a5fc740962013017de4b0032f00d217d7ad7745f8a |
| tools | list_alert_groups | integrationId | ff3c663c6d3fcc07b8ccda1fc0d091201613103167a19ddb8f88789b15d741d4 |
| tools | list_alert_groups | labels | 7953428e2b788a9a5912f70adbfe6a428580f07a67443a0e4b9181ef25bf7d15 |
| tools | list_alert_groups | name | d1f063c52f421ad88dca4ec2909b83a2b7ae7e7ef09c588661fe3220f953d6eb |
| tools | list_alert_groups | page | f82cfd6308c98134db56e04c8630103359ebd9997c2942d1a108f76147496448 |
| tools | list_alert_groups | routeId | 9b27e8f9a7585ff64c182d1c4692798668cd6c8f09b566ea32bc0112602d7616 |
| tools | list_alert_groups | startedAt | 3bd6322d0c73200a76009209acfb65693e854ec97398c053058e2def930de821 |
| tools | list_alert_groups | state | 0349d5797485c8df8bcf60f18d9c5270959162260b882c891a27b04ed638720e |
| tools | list_alert_groups | teamId | 105c1f974d19eec9a37bc4b654079546e992863c60c700f4c9ea442467c1cde6 |
| tools | list_alert_rules | description | 823c1db9855c9f00d3e42ab96d9675fc12e83f264cb99e5fdc9d51727e617dbd |
| tools | list_alert_rules | datasourceUid | 5b6b75c84739abf39e2a9959d8f41691c30f972c5ba370c7342d1692822f7c79 |
| tools | list_alert_rules | label_selectors | 0c742ac7a8ec5d4348e453d391442a3d4cd06d3a872a31a01391e6af8b62e911 |
| tools | list_alert_rules | limit | ef543377c9a76b66c089a4223caddede715c7a9863fda55aef8cfd2acb9efe30 |
| tools | list_alert_rules | page | f82cfd6308c98134db56e04c8630103359ebd9997c2942d1a108f76147496448 |
| tools | list_contact_points | description | e479a03f84a3a5a0582797b4d2ed2ecdc485afcc4131e9e2d501dfd24b79abd7 |
| tools | list_contact_points | datasourceUid | 00276d83e0ea01d8b400df1370f8ad90f439534e2dde8725b6879e57c1ec8567 |
| tools | list_contact_points | limit | 5756eab87185a3d495e50c1a0912a3c24c71b8059a294b6eb296986bb1f3b53e |
| tools | list_contact_points | name | 4018f5ce5f101a9d5f497495a40c015323d21229aefe9c7e94536d8a4345c0dd |
| tools | list_datasources | description | e703feda135105addad822509510a962593d6d5c84d42e1484a8f8b2a82ed97f |
| tools | list_datasources | type | e3f724e5421f436c72b37570160f0ce2b8ef9a3d5ef6925e293569375ad4c146 |
| tools | list_incidents | description | 352be4fcbd2e3540a452fc09e90a4fc866b287c8358f9377dca7e25280052abe |
| tools | list_incidents | drill | 36ad498cf69a59b6728eff37d823a14e5c0936b3a7dee3e414d0d70a9ab47e62 |
| tools | list_incidents | limit | 11e914016c6fca5c315ecca8c4db698c90a18721750a0723d2f9b8019b0fb7f3 |
| tools | list_incidents | status | 331729598e1faa2d15d370b680e7105b8c58db9d77092dfd62c6aab09e2c88ad |
| tools | list_loki_label_names | description | d1f7d27a7bcd300febf5a6e0896a1d34ece0e11482b810468a8b8a182e62463a |
| tools | list_loki_label_names | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_loki_label_names | endRfc3339 | 5c050f729007ebdea18a414ed0fb9fdb31be9f2a63eb87f5bba9707273ed8df2 |
| tools | list_loki_label_names | startRfc3339 | e93ead65fef426f987915ecb159e06412a589c2ce3b47fe5f58b105870172a5c |
| tools | list_loki_label_values | description | b1bb4dfda78f17a23779d1ae8afa4b3900caa667690a7b634b4cbc7579fc6eda |
| tools | list_loki_label_values | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_loki_label_values | endRfc3339 | 5c050f729007ebdea18a414ed0fb9fdb31be9f2a63eb87f5bba9707273ed8df2 |
| tools | list_loki_label_values | labelName | 7143291d7cbbf35431ffa3b925204dd4ebe834b8364437e36c64abaf443e3991 |
| tools | list_loki_label_values | startRfc3339 | e93ead65fef426f987915ecb159e06412a589c2ce3b47fe5f58b105870172a5c |
| tools | list_oncall_schedules | description | 27f76080114a392e4d3481d5784af2f64765ae53b451ed3259eca0d0ddc23f1a |
| tools | list_oncall_schedules | page | 2f095f82ec9ab99ca733ddd28e1bf874e37c6333fd6129d69a8b45a902df4287 |
| tools | list_oncall_schedules | scheduleId | 18f447eef353aaca4e4425228569426fea36cd6bc437f80bac576c077392b74f |
| tools | list_oncall_schedules | teamId | 4364dc3bce8751d810084f38c8b9df45e78d18ada174f641d6f679d3164f3722 |
| tools | list_oncall_teams | description | b632dee562d8c7bef5948ea77f77481e945f6a5c6942739150fc7b470722624a |
| tools | list_oncall_teams | page | f82cfd6308c98134db56e04c8630103359ebd9997c2942d1a108f76147496448 |
| tools | list_oncall_users | description | 73b9e8b172eb83a0d265d00b61d08b8564651f83cd282ff81ea69de1359f154d |
| tools | list_oncall_users | page | f82cfd6308c98134db56e04c8630103359ebd9997c2942d1a108f76147496448 |
| tools | list_oncall_users | userId | 9195168b4df085eb81ad0e96c6c5d8ab132f5d97553aa9b6eab4e326bc91cdcf |
| tools | list_oncall_users | username | 518274a2b1d97b16d0a8bfbce16b060add4686a6a31aa2a0478786b36f75bfc7 |
| tools | list_prometheus_label_names | description | e144bdd60dfe65c06f669d0176071ad0ac01ec575224bf65cf130795cd60a757 |
| tools | list_prometheus_label_names | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_prometheus_label_names | endRfc3339 | 4ff73901d75e1c98d74fdcb0d69a6417ec21169fe4732b020ecbe6c34784d18a |
| tools | list_prometheus_label_names | limit | bf7ab671a64d774ddd8e15229452989617005505959fbc1199cfec907eb3e709 |
| tools | list_prometheus_label_names | matches | e34fe5e837fd833404b5f9e1622ad82ba202591942f7f45c6eb781508f508114 |
| tools | list_prometheus_label_names | startRfc3339 | bdeb7bf4f8fe8bc64ad86ce2d9ccfdae22d3a3d7381c502c485faab5b6513c9f |
| tools | list_prometheus_label_values | description | a299f523ed2190714983a7d8791064850b5b98cd496750b5baa134472cfae2ca |
| tools | list_prometheus_label_values | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_prometheus_label_values | endRfc3339 | 19067113d353feed2376680a52cdccd4402174bbab999f653ddca4fddd968e26 |
| tools | list_prometheus_label_values | labelName | 0843450703790ae5bb4e2629d4d590e762205b46ac1826eecb6adbdc30cc3347 |
| tools | list_prometheus_label_values | limit | bf7ab671a64d774ddd8e15229452989617005505959fbc1199cfec907eb3e709 |
| tools | list_prometheus_label_values | matches | 1613aab3408d8a2a5f03bec0b023427dc22127c6ec1e4724fcc46f3deb5715cf |
| tools | list_prometheus_label_values | startRfc3339 | e53b349be19e0d9742203bdea569ee40fb88f24366c16148b91621b57d3f0371 |
| tools | list_prometheus_metric_metadata | description | a18093f138529287b1f9a3f8d8dd58c70360513dab4de4e3e712869e04e4b2c9 |
| tools | list_prometheus_metric_metadata | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_prometheus_metric_metadata | limit | 20b490763580dc859e4db9bd5ce06058a4cab1a2ec12b841539fbbf10bf854cc |
| tools | list_prometheus_metric_metadata | limitPerMetric | 5af27f4da1a6bc53e2ff5be96e2ad2fa6403d891553a7b1d110d4c89ed77d33e |
| tools | list_prometheus_metric_metadata | metric | eeac2b11308674bc8d5e82d61f8e3d2bf0e4ffeba246c8382413da0e6f8a68c9 |
| tools | list_prometheus_metric_names | description | 2562177a03aaa63900f4b9f97bb3cff2835e5e33c08d17c4af78c2fafd4ac212 |
| tools | list_prometheus_metric_names | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_prometheus_metric_names | limit | ef543377c9a76b66c089a4223caddede715c7a9863fda55aef8cfd2acb9efe30 |
| tools | list_prometheus_metric_names | page | f82cfd6308c98134db56e04c8630103359ebd9997c2942d1a108f76147496448 |
| tools | list_prometheus_metric_names | regex | 9c607bf38cb3528eb6a5a470b0f555b270faabf59ec1cb5eb281611f5d21a0b9 |
| tools | list_pyroscope_label_names | description | dc4d9e22c630e092aed2aae0da6cf18b068a6dfa61056eeae3b14018b8f42356 |
| tools | list_pyroscope_label_names | data_source_uid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_pyroscope_label_names | end_rfc_3339 | 5c050f729007ebdea18a414ed0fb9fdb31be9f2a63eb87f5bba9707273ed8df2 |
| tools | list_pyroscope_label_names | start_rfc_3339 | e93ead65fef426f987915ecb159e06412a589c2ce3b47fe5f58b105870172a5c |
| tools | list_pyroscope_label_values | description | bd9926358319a223d74552a36900ef0c11f4940586f4671b0cfdc873fec623c1 |
| tools | list_pyroscope_label_values | data_source_uid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_pyroscope_label_values | end_rfc_3339 | 5c050f729007ebdea18a414ed0fb9fdb31be9f2a63eb87f5bba9707273ed8df2 |
| tools | list_pyroscope_label_values | matchers | 4d6b17885b5d87e16b80eb71860a15b7982c5dd24d129c88b9bd594b1609e77f |
| tools | list_pyroscope_label_values | name | 9d69234b937165b41118c015b216364a6738c7386c78a08d770811ca12126cce |
| tools | list_pyroscope_label_values | start_rfc_3339 | e93ead65fef426f987915ecb159e06412a589c2ce3b47fe5f58b105870172a5c |
| tools | list_pyroscope_profile_types | description | 9e3ba009ed3a09b2b1d88d6cd61f500bc598cfcfd036d318d55506597fcdff11 |
| tools | list_pyroscope_profile_types | data_source_uid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | list_pyroscope_profile_types | end_rfc_3339 | 5c050f729007ebdea18a414ed0fb9fdb31be9f2a63eb87f5bba9707273ed8df2 |
| tools | list_pyroscope_profile_types | start_rfc_3339 | e93ead65fef426f987915ecb159e06412a589c2ce3b47fe5f58b105870172a5c |
| tools | list_sift_investigations | description | a0fc1bf7ceec12627b8a5b8d29bf4cd544097bfab33c540e9bf49c34c6171c73 |
| tools | list_sift_investigations | limit | 119e50a19872dab3abd6c5a42336c3482b1cf7353971b84f998ce0c7480a8b87 |
| tools | patch_annotation | description | 346997c1381e1385f77315591be9d051ff684a6711ef1ef664a671840364d95a |
| tools | patch_annotation | data | 6a032e26cf4c93dde032fcdcf13bb59ea09e1b7cdd681fe64025eba96b8298eb |
| tools | patch_annotation | id | d805f425a62acdd3d339ccfb7bdd8a27ad0b6f8fbca471057dbf234f48e7674d |
| tools | patch_annotation | tags | ec899eca2cd28aecf7d6b6110f8de7890a3069772e8b7d67d77bbdff99827609 |
| tools | patch_annotation | text | e7412f5bd5c82b334d232bf8b897bea2be064e4dba9b6a51085b91179b1f4ee2 |
| tools | patch_annotation | time | 8c9abb7b3dab30de73153dc86eacb958b0f23906ecefeeaf70f640977f96c39c |
| tools | patch_annotation | timeEnd | b75acb03a36b47008c455b0dbf8a2cbd48feafdfb53e7f144c293182f67e74dc |
| tools | query_loki_logs | description | 75b0101f4900d7a6abc2b3595d205681b518bdaa9803612a66a295fa1e3c90e6 |
| tools | query_loki_logs | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | query_loki_logs | direction | 8aae097b31b454059a9c719b8fa773652a562e3dbfeaa9d4d9b98c2d692590e9 |
| tools | query_loki_logs | endRfc3339 | b618361cdd496306c5cfbc4d384e44d2c6cd48d624b6d2fec78de761e56e5818 |
| tools | query_loki_logs | limit | 840a73562e628ff8af1138fdb81c7cf8517e46cb4818718802bef47db7df1849 |
| tools | query_loki_logs | logql | ac3cedf35f2a8233b96e8d5aad2b5759810893f39ff956df3fd4c9a076ca1e53 |
| tools | query_loki_logs | startRfc3339 | ed7f8cb2448a6c576c7999f83de2785df5535248e84d6113db964774c9f75b59 |
| tools | query_loki_stats | description | 37be653caef8277c823702266f05dc23869a11c0467c69f9e9b1892713a9a50a |
| tools | query_loki_stats | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | query_loki_stats | endRfc3339 | b618361cdd496306c5cfbc4d384e44d2c6cd48d624b6d2fec78de761e56e5818 |
| tools | query_loki_stats | logql | b1cb3a4200c20a0a08054e149ea9188b7f37c8d23608a6eac0e5bec2c6d28ce7 |
| tools | query_loki_stats | startRfc3339 | ed7f8cb2448a6c576c7999f83de2785df5535248e84d6113db964774c9f75b59 |
| tools | query_prometheus | description | 0f299afb58bc160f93b1427d81a89825ee0ebef53ef13c9f9c998572b531fc71 |
| tools | query_prometheus | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | query_prometheus | endTime | 1206835ea56ae6132122e47a6f40d5d44dcbfbfd3a97272d7f0ab7c228c82787 |
| tools | query_prometheus | expr | 0fbbbd21644810e13385b56d28c235f33aab15e382cf55df948ea18dce96c9fb |
| tools | query_prometheus | queryType | 68992fcd7b78c539691ace13028afb104f600f51a1b38639d589cda4f798186a |
| tools | query_prometheus | startTime | 7a1f2accb25dffeee7dcab00e69763d0af9ce9053d8f3af8c6872836c301d40f |
| tools | query_prometheus | stepSeconds | 1503b1866c552d1fcbf827adfc059026ca099ea8b76cc90e713fa99b311e7b16 |
| tools | search_dashboards | description | 5caec921e743f522aff3d7890a1980ff92d350deb92204f9b157890890f5fac7 |
| tools | search_dashboards | query | 15d8dcc87d5f0e8cbf7ba4fe2425ce1e3b529f578238702762b120aa66050378 |
| tools | search_folders | description | bbad4437ada599429be33fa52904780e46eee20a93989a09e06769a110b20d68 |
| tools | search_folders | query | 15d8dcc87d5f0e8cbf7ba4fe2425ce1e3b529f578238702762b120aa66050378 |
| tools | update_alert_rule | description | 72f202e83a095348b83bbac1583ea6c07bd8a74d522b86839b3a1864ae67057b |
| tools | update_alert_rule | annotations | d2228ef66e752c3c9580d9e3a00b78b8d92fac797e116d00697d043f608facd5 |
| tools | update_alert_rule | condition | ad2b3f4e58c519395b91312161782e860ddee28a610b0a0c6459e8820988d231 |
| tools | update_alert_rule | data | 5c2374e0401e98245730e593e294bd592743e07e4a5c6f1c950eaaafbc52d635 |
| tools | update_alert_rule | disableProvenance | 317ecf94ae3b3b0822cede54e74ad55508e648033a0ae2262bbed8a8117088f8 |
| tools | update_alert_rule | execErrState | 7599fdfe035f82bdb8126c3888f481488ca8d06745b57d797f594b8f12ee2368 |
| tools | update_alert_rule | folderUID | 450d49f34ddf25ad7d43a4b82976fc85583285214acc3a363edaaa28a33d9223 |
| tools | update_alert_rule | for | b961b1cb007da234f517a77492f9497db06f44599d5abcd9ddb484aa9d73ebc1 |
| tools | update_alert_rule | labels | bcd0b6bb6a741d22956599b28f574978d1c8ebe1d40a2b8146df3a442d59f4e9 |
| tools | update_alert_rule | noDataState | dcd1109194e1830e4d1eccad9615fb1a4533607c8a0767ca8037aac394bd77e6 |
| tools | update_alert_rule | orgID | 38592c32d6c55b342614f31e363b9ac32a96bbe4070fbb2f09c2cffb7c4fad36 |
| tools | update_alert_rule | ruleGroup | a594843135e3285a266c5fd7f085a1ce7d1656cf314ea869066c77d5f007fcd1 |
| tools | update_alert_rule | title | 8bc7d75270b512b2f0987762a67534ca07956960e5a9c211909084ea46332c3c |
| tools | update_alert_rule | uid | 7f21cb5a4064941626f3c7e700b88c65183fba62ea7cf070004538c9873c18ba |
| tools | update_annotation | description | 40f18411b40176ff32d0cca9b96a0ec405377fa258c55f419e52ff649e01d00c |
| tools | update_annotation | data | 27db5aec9935bf854da920af32eae050ee14e1ed3840af9ef792a1e927e99026 |
| tools | update_annotation | id | f402778b52f1a504107b6b2d665a3df2b473d87114ec1c19ece218a64d7d25b3 |
| tools | update_annotation | tags | 831c78752f894605752eb53b407d226a1fb85f19922c06221aadeb914b4068e4 |
| tools | update_annotation | text | 20ea579a8f895bce2ca82cd408d97a98ba274b944062131b3411671f49982667 |
| tools | update_annotation | time | 0e94c35e90a8f514519532f9d0d041b12bb69e8afa122fe0823a25ec0f88ad11 |
| tools | update_annotation | timeEnd | 047ae1cfe87622f803c53506a2a64be0cb44f8140ba40bcf1e475e4b3621154e |
| tools | update_dashboard | description | ec8e733a5130d9fa1d72d91db0b98997540971a8fb2905b9e0b96404a063e167 |
| tools | update_dashboard | dashboard | f37e032e14154540f10170e0525d4f9cb6f270b2327f37b11d4dbb5a611b8894 |
| tools | update_dashboard | folderUid | 377c80ad5e30c6d847c8a00a14e5c7161429b12e943833c9c45e9889453301aa |
| tools | update_dashboard | message | 5dd1b01491dc7de6c7bbc85d259f4377f2bc2414bc1169856bdf1dfc11389c15 |
| tools | update_dashboard | operations | 28b5d46d2bdbf8b4029876433bfbd7e7a86222affd06f257e5cd100d600b056c |
| tools | update_dashboard | overwrite | 84debefaefeb5cd688da186378b3efc1409999d8b79f3038ae75b6048938d44c |
| tools | update_dashboard | uid | 44c7297eea9f089a1c6f724103cde68210bdc16ba594e4d707df2065fd999c9f |
| tools | update_dashboard | userId | 628a44b4cefdc96bcd5b921338481ec55391dd325dfdda436740612c923493f3 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
