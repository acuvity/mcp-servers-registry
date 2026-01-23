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


# What is mcp-server-chart?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chart/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chart/0.9.7?logo=docker&logoColor=fff&label=0.9.7)](https://hub.docker.com/r/acuvity/mcp-server-chart)
[![PyPI](https://img.shields.io/badge/0.9.7-3775A9?logo=pypi&logoColor=fff&label=@antv/mcp-server-chart)](https://github.com/antvis/mcp-server-chart)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-chart/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chart&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-chart%3A0.9.7%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** A Model Context Protocol server for generating visual charts using AntV.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @antv/mcp-server-chart original [sources](https://github.com/antvis/mcp-server-chart).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-chart/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/charts/mcp-server-chart/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @antv/mcp-server-chart run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ AntV ](https://github.com/antvis/mcp-server-chart) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ @antv/mcp-server-chart ](https://github.com/antvis/mcp-server-chart)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @antv/mcp-server-chart ](https://github.com/antvis/mcp-server-chart)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/charts/mcp-server-chart)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.9.7`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-chart:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-chart:1.0.0-0.9.7`

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
helm install mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-chart --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-chart
```

From there your MCP server mcp-server-chart will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-chart` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-chart
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-chart` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (26)
<details>
<summary>generate_area_chart</summary>

**Description**:

```
Generate a area chart to show data trends under continuous independent variables and observe the overall data trend, such as, displacement = velocity (average or instantaneous) × time: s = v × t. If the x-axis is time (t) and the y-axis is velocity (v) at each moment, an area chart allows you to observe the trend of velocity over time and infer the distance traveled by the area's size.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for area chart, it should be an array of objects, each object contains a `time` field and a `value` field, such as, [{ time: '2015', value: 23 }, { time: '2016', value: 32 }], when stacking is needed for area, the data should contain a `group` field, such as, [{ time: '2015', value: 23, group: 'A' }, { time: '2015', value: 32, group: 'B' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, area charts require a 'group' field in the data. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_bar_chart</summary>

**Description**:

```
Generate a horizontal bar chart to show data for numerical comparisons among different categories, such as, comparing categorical data and for horizontal comparisons.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for bar chart, such as, [{ category: '分类一', value: 10 }, { category: '分类二', value: 20 }], when grouping or stacking is needed for bar, the data should contain a `group` field, such as, when [{ category: '北京', value: 825, group: '油车' }, { category: '北京', value: 1000, group: '电车' }]. | Yes
| group | boolean | Whether grouping is enabled. When enabled, bar charts require a 'group' field in the data. When `group` is true, `stack` should be false. | No
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, bar charts require a 'group' field in the data. When `stack` is true, `group` should be false. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_boxplot_chart</summary>

**Description**:

```
Generate a boxplot chart to show data for statistical summaries among different categories, such as, comparing the distribution of data points across categories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for boxplot chart, such as, [{ category: '分类一', value: 10 }] or [{ category: '分类二', value: 20, group: '组别一' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_column_chart</summary>

**Description**:

```
Generate a column chart, which are best for comparing categorical data, such as, when values are close, column charts are preferable because our eyes are better at judging height than other visual elements like area or angles.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for column chart, such as, [{ category: 'Category A', value: 10 }, { category: 'Category B', value: 20 }], when grouping or stacking is needed for column, the data should contain a 'group' field, such as, [{ category: 'Beijing', value: 825, group: 'Gas Car' }, { category: 'Beijing', value: 1000, group: 'Electric Car' }]. | Yes
| group | boolean | Whether grouping is enabled. When enabled, column charts require a 'group' field in the data. When `group` is true, `stack` should be false. | No
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, column charts require a 'group' field in the data. When `stack` is true, `group` should be false. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_district_map</summary>

**Description**:

```
Generates regional distribution maps, which are usually used to show the administrative divisions and coverage of a dataset. It is not suitable for showing the distribution of specific locations, such as urban administrative divisions, GDP distribution maps of provinces and cities across the country, etc. This tool is limited to generating data maps within China.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Administrative division data, lower-level administrative divisions are optional. There are usually two scenarios: one is to simply display the regional composition, only `fillColor` needs to be configured, and all administrative divisions are consistent, representing that all blocks are connected as one; the other is the regional data distribution scenario, first determine the `dataType`, `dataValueUnit` and `dataLabel` configurations, `dataValue` should be a meaningful value and consistent with the meaning of dataType, and then determine the style configuration. The `fillColor` configuration represents the default fill color for areas without data. Lower-level administrative divisions do not need `fillColor` configuration, and their fill colors are determined by the `colors` configuration (If `dataType` is "number", only one base color (warm color) is needed in the list to calculate the continuous data mapping color band; if `dataType` is "enum", the number of color values in the list is equal to the number of enumeration values (contrast colors)). If `subdistricts` has a value, `showAllSubdistricts` must be set to true. For example, {"title": "陕西省地级市分布图", "data": {"name": "陕西省", "showAllSubdistricts": true, "dataLabel": "城市", "dataType": "enum", "colors": ["#4ECDC4", "#A5D8FF"], "subdistricts": [{"name": "西安市", "dataValue": "省会"}, {"name": "宝鸡市", "dataValue": "地级市"}, {"name": "咸阳市", "dataValue": "地级市"}, {"name": "铜川市", "dataValue": "地级市"}, {"name": "渭南市", "dataValue": "地级市"}, {"name": "延安市", "dataValue": "地级市"}, {"name": "榆林市", "dataValue": "地级市"}, {"name": "汉中市", "dataValue": "地级市"}, {"name": "安康市", "dataValue": "地级市"}, {"name": "商洛市", "dataValue": "地级市"}]}, "width": 1000, "height": 1000}. | Yes
| height | number | Set the height of map, default is 1000. | No
| title | string | The map title should not exceed 16 characters. The content should be consistent with the information the map wants to convey and should be accurate, rich, creative, and attractive. | Yes
| width | number | Set the width of map, default is 1600. | No
</details>
<details>
<summary>generate_dual_axes_chart</summary>

**Description**:

```
Generate a dual axes chart which is a combination chart that integrates two different chart types, typically combining a bar chart with a line chart to display both the trend and comparison of data, such as, the trend of sales and profit over time.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| categories | array | Categories for dual axes chart, such as, ['2015', '2016', '2017']. | Yes
| height | number | Set the height of chart, default is 400. | No
| series | array | Series for dual axes chart, such as, [{ type: 'column', data: [91.9, 99.1, 101.6, 114.4, 121], axisYTitle: '销售额' }, { type: 'line', data: [0.055, 0.06, 0.062, 0.07, 0.075], 'axisYTitle': '利润率' }]. | Yes
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_fishbone_diagram</summary>

**Description**:

```
Generate a fishbone diagram chart to uses a fish skeleton, like structure to display the causes or effects of a core problem, with the problem as the fish head and the causes/effects as the fish bones. It suits problems that can be split into multiple related factors.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Data for fishbone diagram chart which is a hierarchical structure, such as, { name: 'main topic', children: [{ name: 'topic 1', children: [{ name: 'subtopic 1-1' }] }] }, and the maximum depth is 3. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_flow_diagram</summary>

**Description**:

```
Generate a flow diagram chart to show the steps and decision points of a process or system, such as, scenarios requiring linear process presentation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Data for flow diagram chart, such as, { nodes: [{ name: 'node1' }, { name: 'node2' }], edges: [{ source: 'node1', target: 'node2', name: 'edge1' }] }. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_funnel_chart</summary>

**Description**:

```
Generate a funnel chart to visualize the progressive reduction of data as it passes through stages, such as, the conversion rates of users from visiting a website to completing a purchase.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Data for funnel chart, such as, [{ category: '浏览网站', value: 50000 }, { category: '放入购物车', value: 35000 }, { category: '生成订单', value: 25000 }, { category: '支付订单', value: 15000 }, { category: '完成交易', value: 8000 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_histogram_chart</summary>

**Description**:

```
Generate a histogram chart to show the frequency of data points within a certain range. It can observe data distribution, such as, normal and skewed distributions, and identify data concentration areas and extreme points.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| binNumber | number | Number of intervals to define the number of intervals in a histogram, when not specified, a built-in value will be used. | No
| data | array | Data for histogram chart, it should be an array of numbers, such as, [78, 88, 60, 100, 95]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_line_chart</summary>

**Description**:

```
Generate a line chart to show trends over time, such as, the ratio of Apple computer sales to Apple's profits changed from 2000 to 2016.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for line chart, it should be an array of objects, each object contains a `time` field and a `value` field, such as, [{ time: '2015', value: 23 }, { time: '2016', value: 32 }], when the data is grouped by time, the `group` field should be used to specify the group, such as, [{ time: '2015', value: 23, group: 'A' }, { time: '2015', value: 32, group: 'B' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_liquid_chart</summary>

**Description**:

```
Generate a liquid chart to visualize a single value as a percentage, such as, the current occupancy rate of a reservoir or the completion percentage of a project.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | Set the height of chart, default is 400. | No
| percent | number | The percentage value to display in the liquid chart, should be a number between 0 and 1, where 1 represents 100%. For example, 0.75 represents 75%. | Yes
| shape | string | The shape of the liquid chart, can be 'circle', 'rect', 'pin', or 'triangle'. Default is 'circle'. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_mind_map</summary>

**Description**:

```
Generate a mind map chart to organizes and presents information in a hierarchical structure with branches radiating from a central topic, such as, a diagram showing the relationship between a main topic and its subtopics.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Data for mind map chart which is a hierarchical structure, such as, { name: 'main topic', children: [{ name: 'topic 1', children: [{ name:'subtopic 1-1' }] }, and the maximum depth is 3. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_network_graph</summary>

**Description**:

```
Generate a network graph chart to show relationships (edges) between entities (nodes), such as, relationships between people in social networks.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Data for network graph chart, such as, { nodes: [{ name: 'node1' }, { name: 'node2' }], edges: [{ source: 'node1', target: 'node2', name: 'edge1' }] } | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_organization_chart</summary>

**Description**:

```
Generate an organization chart to visualize the hierarchical structure of an organization, such as, a diagram showing the relationship between a CEO and their direct reports.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | object | Data for organization chart which is a hierarchical structure, such as, { name: 'CEO', description: 'Chief Executive Officer', children: [{ name: 'CTO', description: 'Chief Technology Officer', children: [{ name: 'Dev Manager', description: 'Development Manager' }] }] }, and the maximum depth is 3. | Yes
| height | number | Set the height of chart, default is 400. | No
| orient | string | Orientation of the organization chart, either horizontal or vertical. Default is vertical, when the level of the chart is more than 3, it is recommended to use horizontal orientation. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_path_map</summary>

**Description**:

```
Generate a route map to display the user's planned route, such as travel guide routes.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Routes, each group represents all POIs along a route. For example, [{ "data": ["西安钟楼", "西安大唐不夜城", "西安大雁塔"] }, { "data": ["西安曲江池公园", "西安回民街"] }] | Yes
| height | number | Set the height of map, default is 1000. | No
| title | string | The map title should not exceed 16 characters. The content should be consistent with the information the map wants to convey and should be accurate, rich, creative, and attractive. | Yes
| width | number | Set the width of map, default is 1600. | No
</details>
<details>
<summary>generate_pie_chart</summary>

**Description**:

```
Generate a pie chart to show the proportion of parts, such as, market share and budget allocation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Data for pie chart, it should be an array of objects, each object contains a `category` field and a `value` field, such as, [{ category: '分类一', value: 27 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| innerRadius | number | Set the innerRadius of pie chart, the value between 0 and 1. Set the pie chart as a donut chart. Set the value to 0.6 or number in [0 ,1] to enable it. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_pin_map</summary>

**Description**:

```
Generate a point map to display the location and distribution of point data on the map, such as the location distribution of attractions, hospitals, supermarkets, etc.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | A list of keywords for the names of points of interest (POIs) in Chinese. These POIs usually contain a group of places with similar locations, so the names should be more descriptive, must adding attributives to indicate that they are different places in the same area, such as "北京市" is better than "北京", "杭州西湖" is better than "西湖"; in addition, if you can determine that a location may appear in multiple areas, you can be more specific, such as "杭州西湖的苏堤春晓" is better than "苏堤春晓". The tool will use these keywords to search for specific POIs and query their detailed data, such as latitude and longitude, location photos, etc. For example, ["西安钟楼", "西安大唐不夜城", "西安大雁塔"]. | Yes
| height | number | Set the height of map, default is 1000. | No
| markerPopup | object | Marker type, one is simple mode, which is just an icon and does not require `markerPopup` configuration; the other is image mode, which displays location photos and requires `markerPopup` configuration. Among them, `width`/`height`/`borderRadius` can be combined to realize rectangular photos and square photos. In addition, when `borderRadius` is half of the width and height, it can also be a circular photo. | No
| title | string | The map title should not exceed 16 characters. The content should be consistent with the information the map wants to convey and should be accurate, rich, creative, and attractive. | Yes
| width | number | Set the width of map, default is 1600. | No
</details>
<details>
<summary>generate_radar_chart</summary>

**Description**:

```
Generate a radar chart to display multidimensional data (four dimensions or more), such as, evaluate Huawei and Apple phones in terms of five dimensions: ease of use, functionality, camera, benchmark scores, and battery life.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Data for radar chart, it should be an array of objects, each object contains a `name` field and a `value` field, such as, [{ name: 'Design', value: 70 }], when the data is grouped by `group`, the `group` field is required, such as, [{ name: 'Design', value: 70, group: 'Huawei' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_sankey_chart</summary>

**Description**:

```
Generate a sankey chart to visualize the flow of data between different stages or categories, such as, the user journey from landing on a page to completing a purchase.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Date for sankey chart, such as, [{ source: 'Landing Page', target: 'Product Page', value: 50000 }, { source: 'Product Page', target: 'Add to Cart', value: 35000 }, { source: 'Add to Cart', target: 'Checkout', value: 25000 }, { source: 'Checkout', target: 'Payment', value: 15000 }, { source: 'Payment', target: 'Purchase Completed', value: 8000 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| nodeAlign | string | Alignment of nodes in the sankey chart, such as, 'left', 'right', 'justify', or 'center'. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_scatter_chart</summary>

**Description**:

```
Generate a scatter chart to show the relationship between two variables, helps discover their relationship or trends, such as, the strength of correlation, data distribution patterns.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for scatter chart, such as, [{ x: 10, y: 15 }], when the data is grouped, the group name can be specified in the `group` field, such as, [{ x: 10, y: 15, group: 'Group A' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_treemap_chart</summary>

**Description**:

```
Generate a treemap chart to display hierarchical data and can intuitively show comparisons between items at the same level, such as, show disk space usage with treemap.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Data for treemap chart which is a hierarchical structure, such as, [{ name: 'Design', value: 70, children: [{ name: 'Tech', value: 20 }] }], and the maximum depth is 3. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_venn_chart</summary>

**Description**:

```
Generate a Venn diagram to visualize the relationships between different sets, showing how they intersect and overlap, such as the commonalities and differences between various groups.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Data for venn chart, such as, [{ label: 'A', value: 10, sets: ['A'] }, { label: 'B', value: 20, sets: ['B'] }, { label: 'C', value: 30, sets: ['C'] }, { label: 'AB', value: 5, sets: ['A', 'B'] }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_violin_chart</summary>

**Description**:

```
Generate a violin chart to show data for statistical summaries among different categories, such as, comparing the distribution of data points across categories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for violin chart, such as, [{ category: 'Category A', value: 10 }], when the data is grouped, the 'group' field is required, such as, [{ category: 'Category B', value: 20, group: 'Group A' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_waterfall_chart</summary>

**Description**:

```
Generate a waterfall chart to visualize the cumulative effect of sequentially introduced positive or negative values, such as showing how an initial value is affected by a series of intermediate positive or negative values leading to a final result. Waterfall charts are ideal for financial analysis, budget tracking, profit and loss statements, and understanding the composition of changes over time or categories.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for waterfall chart, it should be an array of objects. Each object must contain a `category` field. For regular items, a `value` field is also required. The `isIntermediateTotal` field marks intermediate subtotals, and the `isTotal` field marks the final total. For example, [{ category: 'Initial', value: 100 }, { category: 'Increase', value: 50 }, { category: 'Subtotal', isIntermediateTotal: true }, { category: 'Decrease', value: -30 }, { category: 'Total', isTotal: true }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_word_cloud_chart</summary>

**Description**:

```
Generate a word cloud chart to show word frequency or weight through text size variation, such as, analyzing common words in social media, reviews, or feedback.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data | array | Data for word cloud chart, it should be an array of objects, each object contains a `text` field and a `value` field, such as, [{ value: 4.272, text: '形成' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| style | object | Style configuration for the chart with a JSON object, optional. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | generate_area_chart | description | f96bc61c1cd1f2516048ff2311911a27ad3c51ee90e35535248a31ed719dc626 |
| tools | generate_area_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_area_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_area_chart | data | 560953ef7122474c7f71020eae681facfe6a34666d09a3eab0d8674349bec171 |
| tools | generate_area_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_area_chart | stack | da57ecb43f91bd7f5d6eec67c321b2e0ae8a8714c3e0719902b2adedfb56e6d4 |
| tools | generate_area_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_area_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_area_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_area_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_bar_chart | description | 851c20fedf7a1229f4acae0a81ae9aeee4a6f43da18a9bf6b485f28a3ed8fc78 |
| tools | generate_bar_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_bar_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_bar_chart | data | 9b21ea889e48d9bca8a26dec5067876b5afd5fcde819a571c45bea7e6ca8559c |
| tools | generate_bar_chart | group | 28c99d957f8cbf0ef9a17588214a037f24348e4600bc6a783404ae6cde52df93 |
| tools | generate_bar_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_bar_chart | stack | d37095b67bd434c0d79727cb8f0c8261dddb092008eeb538ace5a33047c4e000 |
| tools | generate_bar_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_bar_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_bar_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_bar_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_boxplot_chart | description | 07995874c0d1f1cd79b52f95bf250e12cb052a2cb7c4aecbd2a34a4098637189 |
| tools | generate_boxplot_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_boxplot_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_boxplot_chart | data | 600db11fd569238599ce8d88b2710ae6647172de207b3b9bf8051187c8635988 |
| tools | generate_boxplot_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_boxplot_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_boxplot_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_boxplot_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_boxplot_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_column_chart | description | cb9505024eff95786bd632bbca3f11f798bd7826f25cdb56a52145ac52899d7f |
| tools | generate_column_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_column_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_column_chart | data | 22616ddf122b403692ff8be61a8f4cf22a189ba2cb8649835d7850723a45de3b |
| tools | generate_column_chart | group | e9c5ca4b064abeb534b1990d67e0c526b8aeddda1f0350f76a0a15bc7b9e2d63 |
| tools | generate_column_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_column_chart | stack | a3c00e77509d640c44a25a688a7a979e5806b9437976686bc59a26d2e0985a12 |
| tools | generate_column_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_column_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_column_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_column_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_district_map | description | 15a409da16b9b29e64dd73edc58ca6f58690d5c610aeec3e810c0aa24f1c8c48 |
| tools | generate_district_map | data | 028cf4c76450b2eea6cbb1fbdda956acdfa5aaf37ed28886cd0658fa00a43c79 |
| tools | generate_district_map | height | c9a0d8d3ee4f41be74633dbda07bbf3e02400df6c867a2d6efdbbfeffb611393 |
| tools | generate_district_map | title | 9123a63a370db83a3be5d6f523acbdabf6a95dae5a0b613404b4c39920f37492 |
| tools | generate_district_map | width | 0b25dfadd07901720b3faca28648134e5dadf09281a0118ffd8e26ae6126fb23 |
| tools | generate_dual_axes_chart | description | ebb7a6509b51f64850dc552ca3e3f6f8e1f62dce81eb77f86b5d71f9f2f27706 |
| tools | generate_dual_axes_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_dual_axes_chart | categories | 9a3a8ed51be4fe1fbb4bd4a0c55d31489fe24aad87972ad88902a46b0e1198fe |
| tools | generate_dual_axes_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_dual_axes_chart | series | cb4d9c990dccaa254b9661138fb7392d301dd6ad5a0f4cb1a39b6f498eee9c98 |
| tools | generate_dual_axes_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_dual_axes_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_dual_axes_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_dual_axes_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_fishbone_diagram | description | b4c25d22c4d78e4617ac92578a8979d41fa401ff31eee777bd54ae6c4bff38bb |
| tools | generate_fishbone_diagram | data | b7c4bf8e4d66ccd7ceff5644e6901db8122f033d76903c7ebe035e82b920f0cb |
| tools | generate_fishbone_diagram | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_fishbone_diagram | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_fishbone_diagram | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_fishbone_diagram | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_flow_diagram | description | be9973fdcd389ee607dfd0dbd8472b1e343a83d126c1614ce35f686aa40cf40c |
| tools | generate_flow_diagram | data | b447ba10d924a13155650d6643b8a7a20bd3c4e79a5a56a9b531d533fd5a7b75 |
| tools | generate_flow_diagram | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_flow_diagram | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_flow_diagram | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_flow_diagram | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_funnel_chart | description | be676a3685d3a918573a39e733e9f9b849184d3bd37e370c64c1346bf577d4d2 |
| tools | generate_funnel_chart | data | edbce43e3a8a256f518dec7ed37c74b39cfa74e73acf897a5bb1f704af6e6694 |
| tools | generate_funnel_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_funnel_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_funnel_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_funnel_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_funnel_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_histogram_chart | description | 912a3265e2729b0a7c984e7604e4676200b6b37fd72d338ba939b79584cdeb9e |
| tools | generate_histogram_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_histogram_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_histogram_chart | binNumber | 3829b0f436a69e0e7d19aefc53baf2b59ba1d9764a7059294862db7fcfd2a697 |
| tools | generate_histogram_chart | data | 481a8195d88797be2220c8663c542180057b23e3883780bdfb60997c6f4e2ed0 |
| tools | generate_histogram_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_histogram_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_histogram_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_histogram_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_histogram_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_line_chart | description | 9d6966e9e2e13f6da7e4a741a1da19c396cc3fcefddfe7783508e34eece6ea19 |
| tools | generate_line_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_line_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_line_chart | data | 12bca6ce159aa9821ba1751cc2c9bf40f5ce873684f614c42a18fb2d6fdaaa3a |
| tools | generate_line_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_line_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_line_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_line_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_line_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_liquid_chart | description | 3c347b33afb200989bdd91ade58dd3541a0c3bb29227289f3b721f5e4401ca2d |
| tools | generate_liquid_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_liquid_chart | percent | 74d77eec8a15a3b9bc9f3429317a3fbfac1ace5ff3e2503612d41442b96654fc |
| tools | generate_liquid_chart | shape | 45442be6c731955de95c299b160029b7b02179bd90f6c204f3295a375b3bd7b4 |
| tools | generate_liquid_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_liquid_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_liquid_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_liquid_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_mind_map | description | 69bf6897ec2bef7cc910002af1f7cf7d92502920473bae8ab6f9adefbc94a628 |
| tools | generate_mind_map | data | 0d86a00c89e2d5a1f6d15d035c521a5f6c1bc4d5fbfd99a8e033e35c3f092c13 |
| tools | generate_mind_map | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_mind_map | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_mind_map | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_mind_map | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_network_graph | description | e9aa42fc72e3246243577e7be1f5c47ee4a10d74bcac5a0a140ff33719e18f44 |
| tools | generate_network_graph | data | c79e86bb596a8000143c5580d53b59f9a9d3a751b78db2429740b39e610ee359 |
| tools | generate_network_graph | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_network_graph | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_network_graph | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_network_graph | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_organization_chart | description | 289dd34ffc7324f7ed60f6792c72af43f3d32889ea72eaf497d591a5a105d61e |
| tools | generate_organization_chart | data | 7db2731ac872d8863e4f5d8846a8f8e330c70981a45d85686c906115d09e8077 |
| tools | generate_organization_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_organization_chart | orient | 28e240ab627fc10bcb0890ce59af27af9c275772c92d636b13b3c9a8d0c14bb1 |
| tools | generate_organization_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_organization_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_organization_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_path_map | description | 8d4be394b0bd92144adb04a29538b63182b7089e284efcd0b152ebaf3e2146f1 |
| tools | generate_path_map | data | 8a8d8fef1bd66677372a9a5477e1c3247a04e33f8bbbac6cac57b76ce8dfeec2 |
| tools | generate_path_map | height | c9a0d8d3ee4f41be74633dbda07bbf3e02400df6c867a2d6efdbbfeffb611393 |
| tools | generate_path_map | title | 9123a63a370db83a3be5d6f523acbdabf6a95dae5a0b613404b4c39920f37492 |
| tools | generate_path_map | width | 0b25dfadd07901720b3faca28648134e5dadf09281a0118ffd8e26ae6126fb23 |
| tools | generate_pie_chart | description | 2dc22593f3f742f01a0862cca0c664c9021840501d3f83b27f73f40690a742c6 |
| tools | generate_pie_chart | data | 2a7e1329057fc0f8e60fe13e9791613f62dc96ff88ebac75c317e1099235157e |
| tools | generate_pie_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_pie_chart | innerRadius | 1c0986959a56de7933a38d7d8781a68e883cc6b31b1fa82d74a82c5ba07ff4c5 |
| tools | generate_pie_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_pie_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_pie_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_pie_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_pin_map | description | 1a011a30084f03310c49cb900d22d0dfb2d72ea89d00481fafd12d32e432b721 |
| tools | generate_pin_map | data | 8f72b1ca3af36780c951edbfeb0988096079b687d77f4f9113d0e9ab103fa34a |
| tools | generate_pin_map | height | c9a0d8d3ee4f41be74633dbda07bbf3e02400df6c867a2d6efdbbfeffb611393 |
| tools | generate_pin_map | markerPopup | d72ae5658cea39e133c3fc7f7df07101a5e84d75e10d1992a92454f45936a099 |
| tools | generate_pin_map | title | 9123a63a370db83a3be5d6f523acbdabf6a95dae5a0b613404b4c39920f37492 |
| tools | generate_pin_map | width | 0b25dfadd07901720b3faca28648134e5dadf09281a0118ffd8e26ae6126fb23 |
| tools | generate_radar_chart | description | eadcd1d7352898155e8664e2c4ab360f4030c7c2f4f68eff86bbd984c4a891ab |
| tools | generate_radar_chart | data | c1ad898fe9e30a782fcf718e73813fde2142c899b4b628df71502d08b1b82018 |
| tools | generate_radar_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_radar_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_radar_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_radar_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_radar_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_sankey_chart | description | 5f9a8142686a1debb1b325fb0cc6059df3ba37eecda11e2c79f0f94258ee5df9 |
| tools | generate_sankey_chart | data | 3f95d75e7c51d046f862eb2c4433b0e1a3b340347f48cd75cc8962aa0b8750e7 |
| tools | generate_sankey_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_sankey_chart | nodeAlign | a5452b2f630749f107e6e32924971733c463ec2a8ecec5a8c21e7b4a36469c8b |
| tools | generate_sankey_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_sankey_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_sankey_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_sankey_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_scatter_chart | description | d75c8ea04f633bdc1f2c1b7a74d9bc24ea7ca1d14138ed75a3b6096321e529cf |
| tools | generate_scatter_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_scatter_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_scatter_chart | data | 14e28fc132d7ee496b2b35f34b1a1e3411b8b19012984780ac09fc32c93ef3f8 |
| tools | generate_scatter_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_scatter_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_scatter_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_scatter_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_scatter_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_treemap_chart | description | 83973c4e02a8d3109dbd82dc491127008f3cf58a550bcc15bff98a583972ad40 |
| tools | generate_treemap_chart | data | 7e769732039e3e42e9acbda7e53191f962bd5df767c6ee07c8b288189319eece |
| tools | generate_treemap_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_treemap_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_treemap_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_treemap_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_treemap_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_venn_chart | description | bcaaf72c3b69af041b609746d42c91b224af686b96f8dfe1f7806dd8e020747d |
| tools | generate_venn_chart | data | c9fad0039556dd92eeb7e750505054c5580b830f7cce615e9f3338ac304a52c7 |
| tools | generate_venn_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_venn_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_venn_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_venn_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_venn_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_violin_chart | description | f5d77608a39c3e8aede033a230595a09c63fe5e253d077625da08d436ec99080 |
| tools | generate_violin_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_violin_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_violin_chart | data | 379192e6341eaf3bbb6052bba2fbc3840c2e4e316f1a2eb96ca1a2f805ecc580 |
| tools | generate_violin_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_violin_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_violin_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_violin_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_violin_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_waterfall_chart | description | 3856b83c61c30371206c511cec560c114903436696fe9515ebb173d2a1e0353c |
| tools | generate_waterfall_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_waterfall_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_waterfall_chart | data | 85d0c7ea4d4b05ad26d9dbb3cf3d1f2dd8cda5f5a78e2e6a500bdb54bf683965 |
| tools | generate_waterfall_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_waterfall_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_waterfall_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_waterfall_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_waterfall_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_word_cloud_chart | description | e1661a55c9801f53cd0c3683458fc3dd1b78b0f8bc3e331550603262e2e02a8a |
| tools | generate_word_cloud_chart | data | 9c123f82a7bd569c3c1ef20a04f96c33c9cf7021b4ca6f1d133d1b95be2c9731 |
| tools | generate_word_cloud_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_word_cloud_chart | style | e869f017a053f39667a120b3c32b2be93cc0dbe03f0eac400bc56ce9295fbf2e |
| tools | generate_word_cloud_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_word_cloud_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_word_cloud_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
