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


# What is mcp-server-grafana?

[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-grafana/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-grafana/v0.4.1?logo=docker&logoColor=fff&label=v0.4.1)](https://hub.docker.com/r/acuvity/mcp-server-grafana)
[![GitHUB](https://img.shields.io/badge/v0.4.1-3775A9?logo=github&logoColor=fff&label=grafana/mcp-grafana)](https://github.com/grafana/mcp-grafana)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-grafana/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-grafana&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22GRAFANA_API_KEY%22%2C%22-e%22%2C%22GRAFANA_URL%22%2C%22docker.io%2Facuvity%2Fmcp-server-grafana%3Av0.4.1%22%5D%2C%22command%22%3A%22docker%22%7D)

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-grafana/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - container: `1.0.0-v0.4.1`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-grafana:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-grafana:1.0.0-v0.4.1`

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

## 🧰 Tools (35)
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
Retrieves the complete dashboard, including panels, variables, and settings, for a specific dashboard identified by its UID.
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
Get the title, query string, and datasource information for each panel in a dashboard. The datasource is an object with fields `uid` (which may be a concrete UID or a template variable like "$datasource") and `type`. If the datasource UID is a template variable, it won't be usable directly for queries. Returns an array of objects, each representing a panel, with fields: title, query, and datasource (an object with uid and type).
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
<summary>list_alert_rules</summary>

**Description**:

```
Lists Grafana alert rules, returning a summary including UID, title, current state (e.g., 'pending', 'firing', 'inactive'), and labels. Supports filtering by labels using selectors and pagination. Example label selector: `[{'name': 'severity', 'type': '=', 'value': 'critical'}]`. Inactive state means the alert state is normal, not firing
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| label_selectors | array | Optionally, a list of matchers to filter alert rules by labels | No
| limit | integer | The maximum number of results to return. Default is 100. | No
| page | integer | The page number to return. | No
</details>
<details>
<summary>list_contact_points</summary>

**Description**:

```
Lists Grafana notification contact points, returning a summary including UID, name, and type for each. Supports filtering by name - exact match - and limiting the number of results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
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
<summary>list_sift_investigations</summary>

**Description**:

```
Retrieves a list of Sift investigations with an optional limit. If no limit is specified, defaults to 10 investigations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | Maximum number of investigations to return. Defaults to 10 if not specified. | No
</details>
<details>
<summary>list_teams</summary>

**Description**:

```
Search for Grafana teams by a query string. Returns a list of matching teams with details like name, ID, and URL.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | The query to search for teams. Can be left empty to fetch all teams | No
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
| limit | integer | Optionally, the maximum number of log lines to return (default: 10, max: 100) | No
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
Query Prometheus using a PromQL expression. Supports both instant queries (at a single point in time) and range queries (over a time range).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| datasourceUid | string | The UID of the datasource to query | Yes
| endRfc3339 | string | The end time in RFC3339 format. Required if queryType is 'range', ignored if queryType is 'instant' | No
| expr | string | The PromQL expression to query | Yes
| queryType | string | The type of query to use. Either 'range' or 'instant' | No
| startRfc3339 | string | The start time in RFC3339 format | Yes
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
<summary>update_dashboard</summary>

**Description**:

```
Create or update a dashboard
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dashboard | object | The full dashboard JSON | Yes
| folderUid | string | The UID of the dashboard's folder | No
| message | string | Set a commit message for the version history | No
| overwrite | boolean | Overwrite the dashboard if it exists. Otherwise create one | No
| userId | integer | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_activity_to_incident | description | 610552ea63617a74fd015f4a67b3a5c8e1fe3c0979922a1c235ec2cc6a9de2aa |
| tools | add_activity_to_incident | body | 4f2ae7b4e5dbb0246bd049bc943119942ea2a8444e11af741d23c3455308e76f |
| tools | add_activity_to_incident | eventTime | c90be1aee29eac2cbe9efd8f0ce87246de26fd726ea69a93bfdc9cea7e4e1930 |
| tools | add_activity_to_incident | incidentId | 59a43b22ccdd6198f3a3c93a4c6434dd8f764ebbc906ac32b37c0f480bf313a8 |
| tools | create_incident | description | a2228ba3f1644395aa75ee218bc2baec8f9566e577b57edadda2ff95cc0c2e80 |
| tools | create_incident | attachCaption | 6ec6551fcfd6921f479963ca5f5fe0aea79a54e18f384dbeea9b730a8dc5c0ab |
| tools | create_incident | attachUrl | 46c8ed77659ce812078a18400b6e1a0c577344a1cbdcc4126646c4c47936bc23 |
| tools | create_incident | isDrill | 2ac103f8fd1202e0d33f77b65610eaab778a6a5364d0aef510933b82758d6234 |
| tools | create_incident | labels | 65fc74a7acdd9f44cf155dbff26a85f5738a1cbc5f4177857dab9cea779e84cd |
| tools | create_incident | roomPrefix | e10bbd57589e4550f7c2e78c9c282472a8483d35aa0be3d576275892174277f5 |
| tools | create_incident | severity | 20a6cddd98286182ed0f693abe5003aa11928afde75c775ff6744c65f2ba53ea |
| tools | create_incident | status | 879aecbbf80e7a0380b8a85c4597cb725247a67b36a53fb197e24ac3dcc32251 |
| tools | create_incident | title | 90902805e58ea7f007150ed8ae10150fd92cc5996b6ad68abdbf145dd8fe0143 |
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
| tools | get_alert_rule_by_uid | description | c69f515c7b9a915e35d99fc2bbb70d8f79da64a4fa7532c940402a2c2f321106 |
| tools | get_alert_rule_by_uid | uid | 2b20b8723d35fa58fa40a4ed72a4c5f8537437076a83fe964d6a59cb1626f2f8 |
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
| tools | get_dashboard_by_uid | description | 2201877e137b554aaf6064acbf3a7fcc298b47b663b801d2d22256257914d9e4 |
| tools | get_dashboard_by_uid | uid | a5663f54c0d36ef714da821bb2097dd6808a8fd3e27d1d16af28f85b999a1d62 |
| tools | get_dashboard_panel_queries | description | 34108e120069387f96de176f102995828115d2887e8e6b6253545930b75c854a |
| tools | get_dashboard_panel_queries | uid | a5663f54c0d36ef714da821bb2097dd6808a8fd3e27d1d16af28f85b999a1d62 |
| tools | get_datasource_by_name | description | b0344ad3d9c9928ae54fedcbdd5c0745223b7bbdffdd302268fb3ab9b55f121c |
| tools | get_datasource_by_name | name | a25821cfd50f370f8978c50e86779c8e3f5f85b0ac61048aa6faa5d63c46703b |
| tools | get_datasource_by_uid | description | 88461427672ce15e88a831f7edeeeb9712841baccde3a669b1345c49915d71f7 |
| tools | get_datasource_by_uid | uid | 1fb37ce58fc9ed3f190cb80d768b797637a69ad3df1d5a0a5b491a79d2c573fb |
| tools | get_incident | description | 1a0d1c1d0b9d4292f0dc54a358c03abf7c6aded92c8d86dbc64aa53d9d978145 |
| tools | get_incident | id | 2e366f8aaf4953c4ed902746a39abcb24750bccc27a3ca9cab790dd868c13bd5 |
| tools | get_oncall_shift | description | 554ebc8791e077e334947b97d694ead30aa7d54a9d88175d77b7ecdf83fd9fab |
| tools | get_oncall_shift | shiftId | bf009f7f59eadbfa53cfacdbeba406a1807be39718e207204bf0d8fa87217df3 |
| tools | get_sift_analysis | description | 3fb36a7a963fd6fe938ebfc25cbd8b8365ec970391db5c047cda85014594a38b |
| tools | get_sift_analysis | analysisId | d31cc9712d0e0fbe607df52f56b7b28672a33939f1df6466443dcdb41d192fa2 |
| tools | get_sift_analysis | investigationId | e93954e3229bb1f1e682080864dc442473cf498633e13f3a5190094da58723d0 |
| tools | get_sift_investigation | description | d12373019135e755340b1ce5d93f763c91ca1a67c6620239a5f939c029e3672c |
| tools | get_sift_investigation | id | e93954e3229bb1f1e682080864dc442473cf498633e13f3a5190094da58723d0 |
| tools | list_alert_rules | description | a86101b69d0f43e75498291d0b4c3bb6a509fe70aa4b5b7cc8e3f9354d51e1ea |
| tools | list_alert_rules | label_selectors | 0c742ac7a8ec5d4348e453d391442a3d4cd06d3a872a31a01391e6af8b62e911 |
| tools | list_alert_rules | limit | 5756eab87185a3d495e50c1a0912a3c24c71b8059a294b6eb296986bb1f3b53e |
| tools | list_alert_rules | page | 66206a2e698ca8960cfda7d91b1a1bfc032149ff459c2520e14a7c2dd516903a |
| tools | list_contact_points | description | 5e7eb8b6bab772ccdcdd40415403eaf27fcaf7f37f4a944cac4c5f547f15f4ac |
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
| tools | list_sift_investigations | description | a0fc1bf7ceec12627b8a5b8d29bf4cd544097bfab33c540e9bf49c34c6171c73 |
| tools | list_sift_investigations | limit | 3a3b5d7cfe0f285d0140975abc8e2c3106a1d0acb757cb469aa597cee680b9ca |
| tools | list_teams | description | cb20afbd38b81f349cf7b665effb6daf231df8ddfdd1aaa37ed22534eb9551b4 |
| tools | list_teams | query | a5ea81fb1f75051f4a7e873b2cc939d05778e0e1898fbe186902fb41e220bd21 |
| tools | query_loki_logs | description | 75b0101f4900d7a6abc2b3595d205681b518bdaa9803612a66a295fa1e3c90e6 |
| tools | query_loki_logs | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | query_loki_logs | direction | 8aae097b31b454059a9c719b8fa773652a562e3dbfeaa9d4d9b98c2d692590e9 |
| tools | query_loki_logs | endRfc3339 | b618361cdd496306c5cfbc4d384e44d2c6cd48d624b6d2fec78de761e56e5818 |
| tools | query_loki_logs | limit | b93591d4048ec3b154e6da7358aedc5ef3e8d2feaff10d3df7d83ca59ca77ec5 |
| tools | query_loki_logs | logql | ac3cedf35f2a8233b96e8d5aad2b5759810893f39ff956df3fd4c9a076ca1e53 |
| tools | query_loki_logs | startRfc3339 | ed7f8cb2448a6c576c7999f83de2785df5535248e84d6113db964774c9f75b59 |
| tools | query_loki_stats | description | 37be653caef8277c823702266f05dc23869a11c0467c69f9e9b1892713a9a50a |
| tools | query_loki_stats | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | query_loki_stats | endRfc3339 | b618361cdd496306c5cfbc4d384e44d2c6cd48d624b6d2fec78de761e56e5818 |
| tools | query_loki_stats | logql | b1cb3a4200c20a0a08054e149ea9188b7f37c8d23608a6eac0e5bec2c6d28ce7 |
| tools | query_loki_stats | startRfc3339 | ed7f8cb2448a6c576c7999f83de2785df5535248e84d6113db964774c9f75b59 |
| tools | query_prometheus | description | 05c0d365b03fd420ebea7ed035e84d64f6cb06ffeeee9441a23992751f6a59fb |
| tools | query_prometheus | datasourceUid | cdfa18054a432407c4dfe44b49781c6c2019c055bf589949ff66cdc974c5e5aa |
| tools | query_prometheus | endRfc3339 | a2154a6a8d6804bd21fd3532b4ac48fc04f526740efbfdebab4da5495b5be917 |
| tools | query_prometheus | expr | 0fbbbd21644810e13385b56d28c235f33aab15e382cf55df948ea18dce96c9fb |
| tools | query_prometheus | queryType | 68992fcd7b78c539691ace13028afb104f600f51a1b38639d589cda4f798186a |
| tools | query_prometheus | startRfc3339 | 13ba7a11b929754ca04718ceb5017df289f55e690796da5a0fe151ad65f8e3a5 |
| tools | query_prometheus | stepSeconds | 1503b1866c552d1fcbf827adfc059026ca099ea8b76cc90e713fa99b311e7b16 |
| tools | search_dashboards | description | 5caec921e743f522aff3d7890a1980ff92d350deb92204f9b157890890f5fac7 |
| tools | search_dashboards | query | 15d8dcc87d5f0e8cbf7ba4fe2425ce1e3b529f578238702762b120aa66050378 |
| tools | update_dashboard | description | 5aef59c4fdeea6c603120b0530d2c76eb8197be85d40a95edb0baeb797579372 |
| tools | update_dashboard | dashboard | 83233ebe7a9cacc2054524bf1c4ed830d5994f6edecd8ca182ebd8ee918a79ed |
| tools | update_dashboard | folderUid | 377c80ad5e30c6d847c8a00a14e5c7161429b12e943833c9c45e9889453301aa |
| tools | update_dashboard | message | 5dd1b01491dc7de6c7bbc85d259f4377f2bc2414bc1169856bdf1dfc11389c15 |
| tools | update_dashboard | overwrite | 84debefaefeb5cd688da186378b3efc1409999d8b79f3038ae75b6048938d44c |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
