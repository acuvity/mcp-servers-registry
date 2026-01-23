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


# What is mcp-server-vizro?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-vizro/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-vizro/0.1.3?logo=docker&logoColor=fff&label=0.1.3)](https://hub.docker.com/r/acuvity/mcp-server-vizro)
[![PyPI](https://img.shields.io/badge/0.1.3-3775A9?logo=pypi&logoColor=fff&label=vizro-mcp)](https://github.com/mckinsey/vizro)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-vizro/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-vizro&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-vizro%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** provides tools and templates to create a functioning Vizro chart or dashboard step by step

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from vizro-mcp original [sources](https://github.com/mckinsey/vizro).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-vizro/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-vizro/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-vizro/charts/mcp-server-vizro/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure vizro-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-vizro/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-vizro#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Vizro Team ](https://github.com/mckinsey/vizro) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ vizro-mcp ](https://github.com/mckinsey/vizro)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ vizro-mcp ](https://github.com/mckinsey/vizro)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-vizro/charts/mcp-server-vizro)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-vizro/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.3`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-vizro:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-vizro:1.0.0-0.1.3`

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
helm install mcp-server-vizro oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-vizro oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-vizro
```

From there your MCP server mcp-server-vizro will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-vizro` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-vizro
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-vizro` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-vizro oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-vizro oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-vizro oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-vizro oci://docker.io/acuvity/mcp-server-vizro --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (6)
<details>
<summary>get_vizro_chart_or_dashboard_plan</summary>

**Description**:

```
Get instructions for creating a Vizro chart or dashboard. Call FIRST when asked to create Vizro things.

    Must be ALWAYS called FIRST with advanced_mode=False, then call again with advanced_mode=True
    if the JSON config does not suffice anymore.

    Returns:
        Instructions for creating a Vizro chart or dashboard
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| advanced_mode | boolean | Only call if you need to use custom CSS, custom components or custom actions.
No need to call this with advanced_mode=True if you need advanced charts,
use `custom_charts` in the `validate_dashboard_config` tool instead. | No
| user_host | string | The host the user is using, if 'ide' you can use the IDE/editor to run python code | Yes
| user_plan | string | The type of Vizro thing the user wants to create | Yes
</details>
<details>
<summary>get_model_json_schema</summary>

**Description**:

```
Get the JSON schema for the specified Vizro model. Server Vizro version: 0.1.50
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| model_name | string | Name of the Vizro model to get schema for (e.g., 'Card', 'Dashboard', 'Page') | Yes
</details>
<details>
<summary>get_sample_data_info</summary>

**Description**:

```
If user provides no data, use this tool to get sample data information.

    Use the following data for the below purposes:
        - iris: mostly numerical with one categorical column, good for scatter, histogram, boxplot, etc.
        - tips: contains mix of numerical and categorical columns, good for bar, pie, etc.
        - stocks: stock prices, good for line, scatter, generally things that change over time
        - gapminder: demographic data, good for line, scatter, generally things with maps or many categories

    Returns:
        Data info object containing information about the dataset.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| data_name | string | Name of the dataset to get sample data for | Yes
</details>
<details>
<summary>load_and_analyze_data</summary>

**Description**:

```
Use to understand local or remote data files. Must be called with absolute paths or URLs.

    Supported formats:
    - CSV (.csv)
    - JSON (.json)
    - HTML (.html, .htm)
    - Excel (.xls, .xlsx)
    - OpenDocument Spreadsheet (.ods)
    - Parquet (.parquet)

    Returns:
        DataAnalysisResults object containing DataFrame information and metadata
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| path_or_url | string | Absolute (important!) local file path or URL to a data file | Yes
</details>
<details>
<summary>validate_dashboard_config</summary>

**Description**:

```
Validate Vizro model configuration. Run ALWAYS when you have a complete dashboard configuration.

    If successful, the tool will return the python code and, if it is a remote file, the py.cafe link to the chart.
    The PyCafe link will be automatically opened in your default browser if auto_open is True.

    Returns:
        ValidationResults object with status and dashboard details
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_open | boolean | Whether to automatically open the PyCafe link in a browser | No
| custom_charts | array | List of ChartPlan objects containing information about the custom charts in the dashboard | Yes
| dashboard_config | object | Either a JSON string or a dictionary representing a Vizro dashboard model configuration | Yes
| data_infos | array | List of DFMetaData objects containing information about the data files | Yes
</details>
<details>
<summary>validate_chart_code</summary>

**Description**:

```
Validate the chart code created by the user and optionally open the PyCafe link in a browser.

    Returns:
        ValidationResults object with status and dashboard details
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_open | boolean | Whether to automatically open the PyCafe link in a browser | No
| chart_config | any | A ChartPlan object with the chart configuration | Yes
| data_info | any | Metadata for the dataset to be used in the chart | Yes
</details>

## 📝 Prompts (3)
<details>
<summary>create_starter_dashboard</summary>

**Description**:

```
Prompt template for getting started with Vizro.
```
<details>
<summary>create_dashboard</summary>

**Description**:

```
Prompt template for creating an EDA dashboard based on one dataset.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| file_path_or_url | The absolute path or URL to the data file you want to use. |Yes |
| context | (Optional) Describe the dashboard you want to create. |No |
<details>
<summary>create_vizro_chart</summary>

**Description**:

```
Prompt template for creating a Vizro chart.
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| file_path_or_url | The absolute path or URL to the data file you want to use. |Yes |
| context | (Optional) Describe the chart you want to create. |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | create_dashboard | description | f49688252b0e6994d4e5af8a373bb1f230daaa547a7715292f638d096b6f5d5e |
| prompts | create_dashboard | context | 93d09e9c0d9e1927d050755dac7286088e9ec0d0c19a392f30758bc0b07b1a91 |
| prompts | create_dashboard | file_path_or_url | a58f60107d39fbdba8feb44e77dd10eb212fb83713989ab23f4da6e6981aeb2d |
| prompts | create_starter_dashboard | description | 3db6c73803667f67b738d9001648a03089d29457869df85b5f9d52d9549f994b |
| prompts | create_vizro_chart | description | faa5f0d0a03c730d8b4d3cb0c684ffa46739ac0027b47aa54d9b3967e1f350b6 |
| prompts | create_vizro_chart | context | 92b8e05b55d9f5054be7636a59d7e00e524b124b6b6bad0c7c8fb3d14add14b9 |
| prompts | create_vizro_chart | file_path_or_url | a58f60107d39fbdba8feb44e77dd10eb212fb83713989ab23f4da6e6981aeb2d |
| tools | get_model_json_schema | description | 2687eb83add50dc4bfc4f44d5324019ca670201bc8785196c6b7907fe74664a7 |
| tools | get_model_json_schema | model_name | ff559139f4d9f677ce2796785f52b5e48758d8cf4251b27601930a3facb60d3c |
| tools | get_sample_data_info | description | 2fccc91729d60d68da58c9099a6f082760f0028bdb3f26fda9bf38980efa3403 |
| tools | get_sample_data_info | data_name | 6d9d841dd22fba2afd9a508e67dae1e667edbe3f80a7b260a6fae1684dbd37af |
| tools | get_vizro_chart_or_dashboard_plan | description | 1e5a3655f1cce22cf8147c3578121a98bd182fd734b8bc89454fe11aa62caf5e |
| tools | get_vizro_chart_or_dashboard_plan | advanced_mode | 661788646d39324e8a446b3c4136846f3184d610b6ddf03a19ffb239fbc00d32 |
| tools | get_vizro_chart_or_dashboard_plan | user_host | b0bc4f4cc19b3a014238acd74bb1b8598a9caa3e5491f3b14e55483bd7ed22f7 |
| tools | get_vizro_chart_or_dashboard_plan | user_plan | 7875047bbda1622ab6ae1b3d4fc07b00398450bb3e49d55e814cac82c704f907 |
| tools | load_and_analyze_data | description | a0eb17a8ea994b5afe49ced92b98c4287cc1099b2c704d249abb18140f7997b2 |
| tools | load_and_analyze_data | path_or_url | 6688808dbaa85881d7ea1bd6bbc1777d439a798f2b17062cf2ec4bfa29c9e5e7 |
| tools | validate_chart_code | description | 080716bf7fc2aeffa83aead5079822694c5e63e05d62f3db591e7ddfab12abb7 |
| tools | validate_chart_code | auto_open | 2ca8629dbc322d890b3bf2270c0bbb8659fc6f8106f27f0e9b447fb732f17912 |
| tools | validate_chart_code | chart_config | 4d81d7c5f0d10fbc06831ccee1cd423ec39addd07dcc8a85269c97ba7a520736 |
| tools | validate_chart_code | data_info | ae06a1ad2f8d9a88141d674385d3653a62e5f7c687c8ac3c31684833dcd8e189 |
| tools | validate_dashboard_config | description | b3a994041c55a3b7ebf9cfefead2566ed81da48431295e1253976cd0adaef056 |
| tools | validate_dashboard_config | auto_open | 2ca8629dbc322d890b3bf2270c0bbb8659fc6f8106f27f0e9b447fb732f17912 |
| tools | validate_dashboard_config | custom_charts | 74f22cf1dfb3ff0959a797c17e8d94f9ff91a0f6283c9588da598eaa89a99476 |
| tools | validate_dashboard_config | dashboard_config | 391d74fbc496ffa3287e9584596b7cf5c1f68ba1787759e465965456813d7f6a |
| tools | validate_dashboard_config | data_infos | c9177be8106582d0230bf935ce8739d069c9088ffec5e40b48eb32d650c47e04 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
