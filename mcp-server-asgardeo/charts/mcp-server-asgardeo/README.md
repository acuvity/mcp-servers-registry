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


# What is mcp-server-asgardeo?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-asgardeo/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-asgardeo/v0.2.0?logo=docker&logoColor=fff&label=v0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-asgardeo)
[![GitHUB](https://img.shields.io/badge/v0.2.0-3775A9?logo=github&logoColor=fff&label=asgardeo/asgardeo-mcp-server)](https://github.com/asgardeo/asgardeo-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-asgardeo/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-asgardeo&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ASGARDEO_BASE_URL%22%2C%22-e%22%2C%22ASGARDEO_CLIENT_ID%22%2C%22-e%22%2C%22ASGARDEO_CLIENT_SECRET%22%2C%22docker.io%2Facuvity%2Fmcp-server-asgardeo%3Av0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** MCP server to interact with your Asgardeo organization through LLM tools.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from asgardeo/asgardeo-mcp-server original [sources](https://github.com/asgardeo/asgardeo-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-asgardeo/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/charts/mcp-server-asgardeo/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure asgardeo/asgardeo-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ asgardeo ](https://github.com/asgardeo/asgardeo-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ asgardeo/asgardeo-mcp-server ](https://github.com/asgardeo/asgardeo-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ asgardeo/asgardeo-mcp-server ](https://github.com/asgardeo/asgardeo-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/charts/mcp-server-asgardeo)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-asgardeo/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-v0.2.0`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-asgardeo:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-asgardeo:1.0.0-v0.2.0`

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
  - `ASGARDEO_CLIENT_ID` secret to be set as secrets.ASGARDEO_CLIENT_ID either by `.value` or from existing with `.valueFrom`
  - `ASGARDEO_CLIENT_SECRET` secret to be set as secrets.ASGARDEO_CLIENT_SECRET either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `ASGARDEO_BASE_URL` environment variable to be set by env.ASGARDEO_BASE_URL

# How to install


Install will helm

```console
helm install mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-asgardeo
```

From there your MCP server mcp-server-asgardeo will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-asgardeo` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-asgardeo
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-asgardeo` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-asgardeo oci://docker.io/acuvity/mcp-server-asgardeo --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>authorize_api</summary>

**Description**:

```
Authorize API to an application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| appId | string | This is the id of the application. | Yes
| id | string | This is the id of the API resource to be authorized. | Yes
| policyIdentifier | string | This indicates the authorization policy of the API authorization. | Yes
| scopes | array | This is the list of scope names for the API resource. | Yes
</details>
<details>
<summary>create_api_resource</summary>

**Description**:

```
Create an API Resource in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | This is the identifier for the API resource. | Yes
| name | string | This is the name of the API resource. | Yes
| requiresAuthorization | boolean | This indicates whether the API resource requires authorization. | Yes
| scopes | array | This is the list of scopes for the API resource. Eg: [{"name": "scope1", "displayName": "Scope 1", "description": "Description for scope 1"}, {"name": "scope2", "displayName": "Scope 2", "description": "Description for scope 2"}] | Yes
</details>
<details>
<summary>create_m2m_app</summary>

**Description**:

```
Create a new M2M Application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
</details>
<details>
<summary>create_mobile_app</summary>

**Description**:

```
Create a new Mobile Application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
| redirect_url | string | Redirect URL of the application | Yes
</details>
<details>
<summary>create_single_page_app</summary>

**Description**:

```
Create a new Single Page Application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
| redirect_url | string | Redirect URL of the application | Yes
</details>
<details>
<summary>create_user</summary>

**Description**:

```
Create a user in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| email | string | This is the email of the user. | Yes
| first_name | string | This is the first name of the user. | Yes
| last_name | string | This is the last name of the user. | Yes
| password | string | This is the password of the user. Eg; atGHL1234# | Yes
| username | string | This is the username of the user. This should be an email address. | Yes
| userstore_domain | string | This is the userstore domain of the user. | No
</details>
<details>
<summary>create_webapp_with_ssr</summary>

**Description**:

```
Create a new regular web application that implements server side rendring in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
| redirect_url | string | Redirect URL of the application | Yes
</details>
<details>
<summary>get_api_resource_by_identifier</summary>

**Description**:

```
Get API Resource by identifier registered in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| identifier | string | This is the identifier of the API resource. | Yes
</details>
<details>
<summary>get_application_by_client_id</summary>

**Description**:

```
Get details of an application by client ID in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| client_id | string | Client ID of the application | Yes
</details>
<details>
<summary>get_application_by_name</summary>

**Description**:

```
Get details of an application by name in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_name | string | Name of the application | Yes
</details>
<details>
<summary>list_api_resources</summary>

**Description**:

```
List API Resources registered in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| after | string | Base64 encoded cursor value for forward pagination. | No
| before | string | Base64 encoded cursor value for backward pagination. | No
| filter | string | Filter expression to apply, e.g., name eq Payments API, identifier eq payments_api. Supports 'sw', 'co', 'ew' and 'eq' operations. | No
| limit | number | The maximum number of results to return. It is recommended to set this value to 100 or less. | No
</details>
<details>
<summary>list_applications</summary>

**Description**:

```
List all applications in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_authorized_api</summary>

**Description**:

```
List authorized API resources of an application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_id | string | This is the id of the application. | Yes
</details>
<details>
<summary>list_claims</summary>

**Description**:

```
List all claims in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>search_api_resources_by_name</summary>

**Description**:

```
Search API Resources by name registered in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | This is the name of the API resource. | Yes
</details>
<details>
<summary>update_application_basic_info</summary>

**Description**:

```
Update basic information of an application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| access_url | string | Access URL of the application | No
| description | string | Description of the application | No
| id | string | ID of the application | Yes
| image_url | string | URL of the application image icon | No
| logout_return_url | string | A URL of the application to return upon logout | No
| name | string | Name of the application | No
</details>
<details>
<summary>update_application_claim_config</summary>

**Description**:

```
Update claim configurations of an application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| claims | array | List of claims to be added as requested claims in the application. Eg: list of URIs like http://wso2.org/claims/username, http://wso2.org/claims/emailaddress | Yes
| id | string | ID of the application | Yes
</details>
<details>
<summary>update_application_oauth_config</summary>

**Description**:

```
Update OAuth/OIDC configurations of an application in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| access_token_attributes | array | Access token attributes | No
| allowed_origins | array | Allowed origins for CORS | No
| application_access_token_expiry_time | number | Expiry time of the access token issued on behalf of the application | No
| id | string | ID of the application | Yes
| redirect_urls | array | Redirect URLs of the application | No
| refresh_token_expiry_time | number | Expiry time of the refresh token | No
| revoke_tokens_when_idp_session_terminated | boolean | Revoke tokens when IDP session is terminated | No
| user_access_token_expiry_time | number | Expiry time of the access token issued on behalf of the user | No
</details>
<details>
<summary>update_login_flow</summary>

**Description**:

```
Update login flow in an application for given user prompt in Asgardeo
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| app_id | string | This is the id of the application for which the login flow is updated. | Yes
| user_prompt | string | This is the user prompt for the login flow. Eg: "Username and password as first factor and Email OTP as second factor" | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | authorize_api | description | 632815c9d3127e053d8aa9a4af90ddf2a6121b6dd657957499fc722c10a9158f |
| tools | authorize_api | appId | e98139e2fa215f0a072d3d7762cb2ac1074ff7ab5022f126c10ec3880a1e87c8 |
| tools | authorize_api | id | d45c372d22b78e9573a7319c60397e8a9e7c7cf1e04ecaf5c7ea4e95cedf2d74 |
| tools | authorize_api | policyIdentifier | c3e47001e7992c954b45880aa7d240de28e309f066843bffd88dfff9d6976fb5 |
| tools | authorize_api | scopes | db76fe2e7bd14b99f328e48ea820565f689c764a7dab5228f155399aba32b583 |
| tools | create_api_resource | description | e3ed425ac72630fdc39ba3adc014dc17cd596374785aa349b10881c84df130bb |
| tools | create_api_resource | identifier | d7ee7df5e3b35e4a6313f3d62b3882a37bb9b1a2705463a7aa7569c40a59355d |
| tools | create_api_resource | name | ffa76c55c412e5d5c02c03cc8b7d7d9a010a345689cb2947ac376854d278873b |
| tools | create_api_resource | requiresAuthorization | 6e96314b055ea57a1f2059237b464e1e3b5e0759ce49d86e9557aec409d9b633 |
| tools | create_api_resource | scopes | 290be0099907e23b8fe41a38c19ff01b3091aa0cb8e8b60e5ee0fb44759b2edb |
| tools | create_m2m_app | description | de93d576c132cd59000c8b750a1fb4711b74b5c6e84caf1578614e7e1fd4c856 |
| tools | create_m2m_app | application_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | create_mobile_app | description | 7e88580345493a0938e5f5b93e6f7e723788921c836d22899e41b066f235af3d |
| tools | create_mobile_app | application_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | create_mobile_app | redirect_url | dcecbabd4baa9cae323de7f2314b8a49ff1b2ebe09eb73923ca2955845fa2aa6 |
| tools | create_single_page_app | description | 03466ca6e9de34bd3820fecb932b7a65a16f3c1c1c3b85bf96a5d97a6f7f422b |
| tools | create_single_page_app | application_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | create_single_page_app | redirect_url | dcecbabd4baa9cae323de7f2314b8a49ff1b2ebe09eb73923ca2955845fa2aa6 |
| tools | create_user | description | d1fb75d82f6377c19d58b4c166c61777631a00a387d4e55b00295ce4a13d3b0a |
| tools | create_user | email | 7db36d84895e8d1062cf1a73fdd36d11d304aac83a56af7893a68a9c9dbac2b5 |
| tools | create_user | first_name | 38f09cc25f465ee8abef03fa637c0079523d6bda43c8bee9fee4a4f10995f0f5 |
| tools | create_user | last_name | ad70e5b9d7f703085cddb673ae80530427f0829e1f71a0a0231d6f28a12415d6 |
| tools | create_user | password | b8d132e4895e8d87bbd1d0ca32e5debaabbfcaf05a262cb258f95c5748d8ad28 |
| tools | create_user | username | d7a81c9572fceb444f6685b897556ca1cfba8402baa61178f479e4e003908254 |
| tools | create_user | userstore_domain | 39dc32034370a104e9a107c75a9d3a32cefa38e031e0c2d8c8590d8a91a96b36 |
| tools | create_webapp_with_ssr | description | da28eb707cd9ddb6bf1c436b160c20a8edcd3f27c348c43d8fc31c948d937cf9 |
| tools | create_webapp_with_ssr | application_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | create_webapp_with_ssr | redirect_url | dcecbabd4baa9cae323de7f2314b8a49ff1b2ebe09eb73923ca2955845fa2aa6 |
| tools | get_api_resource_by_identifier | description | 8edfb2190c5a61b95a0f4bcb3e4efd70992e852819e564cf6d9280e3818bfced |
| tools | get_api_resource_by_identifier | identifier | 62250c9d5d907511e9a103ae959b8c6a7ca9f86138661b52213a8b6921224bcd |
| tools | get_application_by_client_id | description | aaa6d8292736aebf9786c3ba53e1ce9fad220b090dc1e9726b378159559907fc |
| tools | get_application_by_client_id | client_id | fea2d22bb147c48919635b211da578c6a7b7d29dd7612ece3804f0e9a7a129e3 |
| tools | get_application_by_name | description | f0a6b530cb6c16428331e22b95663c74bdb758805839ae6c28424e3f82bb4853 |
| tools | get_application_by_name | application_name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | list_api_resources | description | 5d75e47271ead93fcfac97c3a646c13af1acf2c77d51008b47f0fcb8ba741aea |
| tools | list_api_resources | after | 43872afe8214bcceb7f862baae29bea7df4f75668d4965494f4279efd0254ee8 |
| tools | list_api_resources | before | f14f2bbb351e539d4c508c285529a7567db84876f7f3d444aa9c498fbe3a7e1c |
| tools | list_api_resources | filter | 67b69db33dcfb01704ae26fb67ca65598780980066991b27464e11776fd0feb1 |
| tools | list_api_resources | limit | e3f232832c027402616aa0c999d16bf03bedaa0cfd2bedd1c5e31ff3dc238fda |
| tools | list_applications | description | 9e29dc2147acf8538dd821da7f340d94d58f92c349f4856755d40daf1da2da71 |
| tools | list_authorized_api | description | f71cc2e6840655e115e18e3ee05dc665a0c3c4a6dc9fef3244f4ab1d1690f427 |
| tools | list_authorized_api | app_id | e98139e2fa215f0a072d3d7762cb2ac1074ff7ab5022f126c10ec3880a1e87c8 |
| tools | list_claims | description | aa699da0c2c65c1032ffe0e7a2064a1abd6d70ad21da0c51ce015a4f519d5f6e |
| tools | search_api_resources_by_name | description | 9331d63a6f2cdb874481c8897905af6835488c838e0ab6bb5b2bee784ba00d39 |
| tools | search_api_resources_by_name | name | ffa76c55c412e5d5c02c03cc8b7d7d9a010a345689cb2947ac376854d278873b |
| tools | update_application_basic_info | description | 88e00324edec52e53e7882756a3ff5e45948f6de0bd94f2a5b0576df25d18a5b |
| tools | update_application_basic_info | access_url | d0ed95af1a92f0e787dc62bc3ab5d7c0f28bf0b15710193693624f454d9fa664 |
| tools | update_application_basic_info | description | 75b4d38aa3857aae5d5cd0e512126b6b994d83a7c69c68b9a1e95d65c33de17a |
| tools | update_application_basic_info | id | eecfbec6a67cade85c8b06efb06c7d6ae8a89f259414633f613d285120070845 |
| tools | update_application_basic_info | image_url | 487e288ae8ff0644b796138a95b1a9d2a637c65ce226bcb337ded907949970c0 |
| tools | update_application_basic_info | logout_return_url | 6f16daf9a57fdaa457bcf3954e8d447234e359f9f060808ae78c4ade1acbde59 |
| tools | update_application_basic_info | name | 8683f3f7c6b1c2b761f455d6aedfda0c6769028ec5b8047bf2cace524866e21c |
| tools | update_application_claim_config | description | 42d50ed0537bbfc3d8c9bf5f9a171f499f06bee31b7194122f74d93f6d3bde95 |
| tools | update_application_claim_config | claims | cfe540b561695d147e9b4c80507426f28dc9645368f9d1d95d22dc43f333c057 |
| tools | update_application_claim_config | id | eecfbec6a67cade85c8b06efb06c7d6ae8a89f259414633f613d285120070845 |
| tools | update_application_oauth_config | description | 861462abdf7c83390b13f2ae78f12eab79c68b33a403859b29aae0567c316708 |
| tools | update_application_oauth_config | access_token_attributes | d6d672675cca47b87d557f9a9c20af97215b1670019774ca3e224664bfc13baa |
| tools | update_application_oauth_config | allowed_origins | c36c4ef2af7557bb7f1d8400b7478dd9aa4767cf7743ffe8a577e1ed9c9b5401 |
| tools | update_application_oauth_config | application_access_token_expiry_time | 9a50c9518cf8abe607d1831045c83d52f6200cab6027a4f29fd83be2141b544b |
| tools | update_application_oauth_config | id | eecfbec6a67cade85c8b06efb06c7d6ae8a89f259414633f613d285120070845 |
| tools | update_application_oauth_config | redirect_urls | 05ba046a1d21fc8b6b14ef7164f7a3924851b5f62434f01abf0c3e2cac339c27 |
| tools | update_application_oauth_config | refresh_token_expiry_time | cbf42c0e7a43066f49d5dc7457e6914c3a8dd626d461469b00ab3accf5e76285 |
| tools | update_application_oauth_config | revoke_tokens_when_idp_session_terminated | aff0abf9840d6e03186a2a0e35f7dff42c1577058296dec56d492449a55e2059 |
| tools | update_application_oauth_config | user_access_token_expiry_time | 64a5472ff10a64fbfcf6497582419759bcd01ffba241edacd4ca3c272a8df4cd |
| tools | update_login_flow | description | 5e363a6927a6468a5e05f74f1685d9cdf0c322d45b3e8b0bba489b34d5e7dbbf |
| tools | update_login_flow | app_id | 3b34b6e531c94f40d5d5faf05e2508898bec1f28ebfe5a4cac3bd9c539f950a2 |
| tools | update_login_flow | user_prompt | 2c5150d6bbf061ef70610f487f2cf747fa710c970a504160f8a35a0036940db1 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
