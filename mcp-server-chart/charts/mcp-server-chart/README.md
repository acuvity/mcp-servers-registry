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


# What is mcp-server-chart?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chart/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chart/0.6.1?logo=docker&logoColor=fff&label=0.6.1)](https://hub.docker.com/r/acuvity/mcp-server-chart)
[![PyPI](https://img.shields.io/badge/0.6.1-3775A9?logo=pypi&logoColor=fff&label=@antv/mcp-server-chart)](https://github.com/antvis/mcp-server-chart)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-chart/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chart&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-chart%3A0.6.1%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - container: `1.0.0-0.6.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-chart:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-chart:1.0.0-0.6.1`

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

## 🧰 Tools (22)
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
| data | array | Data for area chart, such as, [{ time: '2018', value: 99.9 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, area charts require a 'group' field in the data. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_bar_chart</summary>

**Description**:

```
Generate a bar chart to show data for numerical comparisons among different categories, such as, comparing categorical data and for horizontal comparisons.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for bar chart, such as, [{ category: '分类一', value: 10 }]. | Yes
| group | boolean | Whether grouping is enabled. When enabled, bar charts require a 'group' field in the data. When `group` is true, `stack` should be false. | No
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, bar charts require a 'group' field in the data. When `stack` is true, `group` should be false. | No
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
| data | array | Data for column chart, such as, [{ category: '北京', value: 825, group: '油车' }]. | Yes
| group | boolean | Whether grouping is enabled. When enabled, column charts require a 'group' field in the data. When `group` is true, `stack` should be false. | No
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, column charts require a 'group' field in the data. When `stack` is true, `group` should be false. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
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
| data | object | Data for fishbone diagram chart, such as, { name: 'main topic', children: [{ name: 'topic 1', children: [{ name: 'subtopic 1-1' }] }. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| binNumber | any | Number of intervals to define the number of intervals in a histogram. | No
| data | array | Data for histogram chart, such as, [78, 88, 60, 100, 95]. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| data | array | Data for line chart, such as, [{ time: '2015', value: 23 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, line charts require a 'group' field in the data. | No
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
| data | object | Data for mind map chart, such as, { name: 'main topic', children: [{ name: 'topic 1', children: [{ name:'subtopic 1-1' }] }. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| data | object | Data for organization chart, such as, { name: 'CEO', description: 'Chief Executive Officer', children: [{ name: 'CTO', description: 'Chief Technology Officer', children: [{ name: 'Dev Manager', description: 'Development Manager' }] }] }. | Yes
| height | number | Set the height of chart, default is 400. | No
| orient | string | Orientation of the organization chart, either horizontal or vertical. Default is vertical, when the level of the chart is more than 3, it is recommended to use horizontal orientation. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| width | number | Set the width of chart, default is 600. | No
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
| data | array | Data for pie chart, such as, [{ category: '分类一', value: 27 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| innerRadius | number | Set the innerRadius of pie chart, the value between 0 and 1. Set the pie chart as a donut chart. Set the value to 0.6 or number in [0 ,1] to enable it. | No
| theme | string | Set the theme for the chart, optional, default is 'default'. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
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
| data | array | Data for radar chart, such as, [{ name: 'Design', value: 70 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| data | array | Data for scatter chart, such as, [{ x: 10, y: 15 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| data | array | Data for treemap chart, such as, [{ name: 'Design', value: 70, children: [{ name: 'Tech', value: 20 }] }]. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| data | array | Data for violin chart, such as, [{ category: '分类一', value: 10 }] or [{ category: '分类二', value: 20, group: '组别一' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| data | array | Data for word cloud chart, such as, [{ value: 4.272, text: '形成' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
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
| tools | generate_area_chart | data | 11f7f679e2f6845cffb1445ee7fd7d5c7f167a29e991d7f50c7609234af52d81 |
| tools | generate_area_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_area_chart | stack | da57ecb43f91bd7f5d6eec67c321b2e0ae8a8714c3e0719902b2adedfb56e6d4 |
| tools | generate_area_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_area_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_area_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_bar_chart | description | 54908b15980cd5eedf85551873c79cfb332ae31ec5e34e8348676a74b815f856 |
| tools | generate_bar_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_bar_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_bar_chart | data | b6f1bfd3a0b5ef1f273fef685cc47d125fe3cdab2ab989407eca2065e336408f |
| tools | generate_bar_chart | group | 28c99d957f8cbf0ef9a17588214a037f24348e4600bc6a783404ae6cde52df93 |
| tools | generate_bar_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_bar_chart | stack | d37095b67bd434c0d79727cb8f0c8261dddb092008eeb538ace5a33047c4e000 |
| tools | generate_bar_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_bar_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_bar_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_boxplot_chart | description | 07995874c0d1f1cd79b52f95bf250e12cb052a2cb7c4aecbd2a34a4098637189 |
| tools | generate_boxplot_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_boxplot_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_boxplot_chart | data | 600db11fd569238599ce8d88b2710ae6647172de207b3b9bf8051187c8635988 |
| tools | generate_boxplot_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_boxplot_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_boxplot_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_boxplot_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_column_chart | description | cb9505024eff95786bd632bbca3f11f798bd7826f25cdb56a52145ac52899d7f |
| tools | generate_column_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_column_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_column_chart | data | e3fcfeb0b22c9163bdf59863d78ba7cdaa5c1840506c7c3e532b6a7d3ccddfc6 |
| tools | generate_column_chart | group | e9c5ca4b064abeb534b1990d67e0c526b8aeddda1f0350f76a0a15bc7b9e2d63 |
| tools | generate_column_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_column_chart | stack | a3c00e77509d640c44a25a688a7a979e5806b9437976686bc59a26d2e0985a12 |
| tools | generate_column_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_column_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_column_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_dual_axes_chart | description | ebb7a6509b51f64850dc552ca3e3f6f8e1f62dce81eb77f86b5d71f9f2f27706 |
| tools | generate_dual_axes_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_dual_axes_chart | categories | 9a3a8ed51be4fe1fbb4bd4a0c55d31489fe24aad87972ad88902a46b0e1198fe |
| tools | generate_dual_axes_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_dual_axes_chart | series | cb4d9c990dccaa254b9661138fb7392d301dd6ad5a0f4cb1a39b6f498eee9c98 |
| tools | generate_dual_axes_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_dual_axes_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_dual_axes_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_fishbone_diagram | description | b4c25d22c4d78e4617ac92578a8979d41fa401ff31eee777bd54ae6c4bff38bb |
| tools | generate_fishbone_diagram | data | 1671c924f3b8dc62b4fe72aefe34b1fa65d6258a04ccf440dbd075b64c898aa6 |
| tools | generate_fishbone_diagram | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_fishbone_diagram | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_fishbone_diagram | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_flow_diagram | description | be9973fdcd389ee607dfd0dbd8472b1e343a83d126c1614ce35f686aa40cf40c |
| tools | generate_flow_diagram | data | b447ba10d924a13155650d6643b8a7a20bd3c4e79a5a56a9b531d533fd5a7b75 |
| tools | generate_flow_diagram | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_flow_diagram | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_flow_diagram | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_funnel_chart | description | be676a3685d3a918573a39e733e9f9b849184d3bd37e370c64c1346bf577d4d2 |
| tools | generate_funnel_chart | data | edbce43e3a8a256f518dec7ed37c74b39cfa74e73acf897a5bb1f704af6e6694 |
| tools | generate_funnel_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_funnel_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_funnel_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_funnel_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_histogram_chart | description | 912a3265e2729b0a7c984e7604e4676200b6b37fd72d338ba939b79584cdeb9e |
| tools | generate_histogram_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_histogram_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_histogram_chart | binNumber | aed7fd9c76b22c81f123e8354e8a1fab5474cf785057e597c82846271da1ed68 |
| tools | generate_histogram_chart | data | 35385c4971063de47636b64aef28b82403c3d801c27f2b668d5f895577df95f3 |
| tools | generate_histogram_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_histogram_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_histogram_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_histogram_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_line_chart | description | 9d6966e9e2e13f6da7e4a741a1da19c396cc3fcefddfe7783508e34eece6ea19 |
| tools | generate_line_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_line_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_line_chart | data | 336d1ef1d3875e1bde3df2f0314264aaa6ec864c307cdbfe853b1c2b905861b2 |
| tools | generate_line_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_line_chart | stack | 94ebe7342735fc11d93fead5b58d420f17706a780cfd3774c1d7169a9c1361af |
| tools | generate_line_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_line_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_line_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_liquid_chart | description | 3c347b33afb200989bdd91ade58dd3541a0c3bb29227289f3b721f5e4401ca2d |
| tools | generate_liquid_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_liquid_chart | percent | 74d77eec8a15a3b9bc9f3429317a3fbfac1ace5ff3e2503612d41442b96654fc |
| tools | generate_liquid_chart | shape | 45442be6c731955de95c299b160029b7b02179bd90f6c204f3295a375b3bd7b4 |
| tools | generate_liquid_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_liquid_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_liquid_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_mind_map | description | 69bf6897ec2bef7cc910002af1f7cf7d92502920473bae8ab6f9adefbc94a628 |
| tools | generate_mind_map | data | cca0ddf655078bcf4928cb016d35454fa6c0dcfe46d04490d03add67a9e8879a |
| tools | generate_mind_map | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_mind_map | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_mind_map | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_network_graph | description | e9aa42fc72e3246243577e7be1f5c47ee4a10d74bcac5a0a140ff33719e18f44 |
| tools | generate_network_graph | data | c79e86bb596a8000143c5580d53b59f9a9d3a751b78db2429740b39e610ee359 |
| tools | generate_network_graph | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_network_graph | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_network_graph | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_organization_chart | description | 289dd34ffc7324f7ed60f6792c72af43f3d32889ea72eaf497d591a5a105d61e |
| tools | generate_organization_chart | data | ef239d04adec0211c07d0fec477515ac5786c2399c5a645a3abc10b251a061ec |
| tools | generate_organization_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_organization_chart | orient | 28e240ab627fc10bcb0890ce59af27af9c275772c92d636b13b3c9a8d0c14bb1 |
| tools | generate_organization_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_organization_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_pie_chart | description | 2dc22593f3f742f01a0862cca0c664c9021840501d3f83b27f73f40690a742c6 |
| tools | generate_pie_chart | data | ef5c746f17b2bd8a099aa0d34fe884dd7039bb83f1d96aefadd8bc709d5431e4 |
| tools | generate_pie_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_pie_chart | innerRadius | 1c0986959a56de7933a38d7d8781a68e883cc6b31b1fa82d74a82c5ba07ff4c5 |
| tools | generate_pie_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_pie_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_pie_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_radar_chart | description | eadcd1d7352898155e8664e2c4ab360f4030c7c2f4f68eff86bbd984c4a891ab |
| tools | generate_radar_chart | data | 56d2c3632be9ccd0c97126c9fde5ca4869a3de8368178a7f8832d213ac259f26 |
| tools | generate_radar_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_radar_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_radar_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_radar_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_sankey_chart | description | 5f9a8142686a1debb1b325fb0cc6059df3ba37eecda11e2c79f0f94258ee5df9 |
| tools | generate_sankey_chart | data | 3f95d75e7c51d046f862eb2c4433b0e1a3b340347f48cd75cc8962aa0b8750e7 |
| tools | generate_sankey_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_sankey_chart | nodeAlign | a5452b2f630749f107e6e32924971733c463ec2a8ecec5a8c21e7b4a36469c8b |
| tools | generate_sankey_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_sankey_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_sankey_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_scatter_chart | description | d75c8ea04f633bdc1f2c1b7a74d9bc24ea7ca1d14138ed75a3b6096321e529cf |
| tools | generate_scatter_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_scatter_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_scatter_chart | data | fb0e6070681773230652c9023313d6abe8653f710c54ddea6db7d4af7408eab1 |
| tools | generate_scatter_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_scatter_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_scatter_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_scatter_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_treemap_chart | description | 83973c4e02a8d3109dbd82dc491127008f3cf58a550bcc15bff98a583972ad40 |
| tools | generate_treemap_chart | data | 46418098a4acbdde40f7809faae1b5c912d4834c99f098f8d6fa57eb1876a0d1 |
| tools | generate_treemap_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_treemap_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_treemap_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_treemap_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_venn_chart | description | bcaaf72c3b69af041b609746d42c91b224af686b96f8dfe1f7806dd8e020747d |
| tools | generate_venn_chart | data | c9fad0039556dd92eeb7e750505054c5580b830f7cce615e9f3338ac304a52c7 |
| tools | generate_venn_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_venn_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_venn_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_venn_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_violin_chart | description | f5d77608a39c3e8aede033a230595a09c63fe5e253d077625da08d436ec99080 |
| tools | generate_violin_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_violin_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_violin_chart | data | ad7ad5687541d6b89fab722f074db1ea69a13e1b0f670d0b0ca786ace7fbd8bc |
| tools | generate_violin_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_violin_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_violin_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_violin_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_word_cloud_chart | description | e1661a55c9801f53cd0c3683458fc3dd1b78b0f8bc3e331550603262e2e02a8a |
| tools | generate_word_cloud_chart | data | 96cefdd74b2a99e0ea12f31dd504b58d37f9111d393feb6e25642a1cfc0db0d4 |
| tools | generate_word_cloud_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_word_cloud_chart | theme | d294ce9e6fbe864837ac20965f6041140f5e728ef7a3860e5ff519ef72a55985 |
| tools | generate_word_cloud_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_word_cloud_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
