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


# What is mcp-server-3d-printer?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-3d-printer/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-3d-printer/1.0.2?logo=docker&logoColor=fff&label=1.0.2)](https://hub.docker.com/r/acuvity/mcp-server-3d-printer)
[![PyPI](https://img.shields.io/badge/1.0.2-3775A9?logo=pypi&logoColor=fff&label=mcp-3d-printer-server)](https://github.com/DMontgomery40/mcp-3D-printer-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-3d-printer/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-3d-printer&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-3d-printer%3A1.0.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connects to various 3D printers for management and STL manipulation.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-3d-printer-server original [sources](https://github.com/DMontgomery40/mcp-3D-printer-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-3d-printer/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-3d-printer/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-3d-printer/charts/mcp-server-3d-printer/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-3d-printer-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-3d-printer/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

For example adding:
- `-e GUARDRAILS="secrets-redaction covert-instruction-detection"`
to your docker arguments will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


## 🔒 Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

To turn on Basic Authentication, add `BASIC_AUTH_SECRET` like:
- `-e BASIC_AUTH_SECRET="supersecret"`
to your docker arguments. This will enable the Basic Authentication check.

> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ David Montgomery ](https://github.com/DMontgomery40/mcp-3D-printer-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-3d-printer-server ](https://github.com/DMontgomery40/mcp-3D-printer-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-3d-printer-server ](https://github.com/DMontgomery40/mcp-3D-printer-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-3d-printer/charts/mcp-server-3d-printer)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-3d-printer/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.2`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-3d-printer:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-3d-printer:1.0.0-1.0.2`

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
  - `API_KEY` secret to be set as secrets.API_KEY either by `.value` or from existing with `.valueFrom`
  - `BAMBU_TOKEN` secret to be set as secrets.BAMBU_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `BAMBU_SERIAL=""` environment variable can be changed with `env.BAMBU_SERIAL=""`
  - `PRINTER_HOST=""` environment variable can be changed with `env.PRINTER_HOST=""`
  - `PRINTER_TYPE=""` environment variable can be changed with `env.PRINTER_TYPE=""`
  - `TEMP_DIR="/tmp"` environment variable can be changed with `env.TEMP_DIR="/tmp"`

# How to install


Install will helm

```console
helm install mcp-server-3d-printer oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-3d-printer oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-3d-printer
```

From there your MCP server mcp-server-3d-printer will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-3d-printer` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-3d-printer
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-3d-printer` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-3d-printer oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-3d-printer oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-3d-printer oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-3d-printer oci://docker.io/acuvity/mcp-server-3d-printer --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (15)
<details>
<summary>get_printer_status</summary>

**Description**:

```
Get the current status of the 3D printer
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api_key | string | API key for authentication (default: value from env) | No
| bambu_serial | string | Serial number for Bambu Lab printers (default: value from env) | No
| bambu_token | string | Access token for Bambu Lab printers (default: value from env) | No
| host | string | Hostname or IP address of the printer (default: value from env) | No
| port | string | Port of the printer API (default: value from env) | No
| type | string | Type of printer management system (octoprint, klipper, duet, repetier, bambu, prusa, creality) (default: value from env) | No
</details>
<details>
<summary>extend_stl_base</summary>

**Description**:

```
Extend the base of an STL file by a specified amount
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| extension_inches | number | Amount to extend the base in inches | Yes
| stl_path | string | Path to the STL file to modify | Yes
</details>
<details>
<summary>slice_stl</summary>

**Description**:

```
Slice an STL file to generate G-code
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| slicer_path | string | Path to the slicer executable (default: value from env) | No
| slicer_profile | string | Profile to use for slicing (default: value from env) | No
| slicer_type | string | Type of slicer to use (prusaslicer, cura, slic3r, orcaslicer) (default: value from env) | No
| stl_path | string | Path to the STL file to slice | Yes
</details>
<details>
<summary>confirm_temperatures</summary>

**Description**:

```
Confirm temperature settings in a G-code file
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| bed_temp | number | Expected bed temperature | No
| extruder_temp | number | Expected extruder temperature | No
| gcode_path | string | Path to the G-code file | Yes
</details>
<details>
<summary>process_and_print_stl</summary>

**Description**:

```
Process an STL file (extend base), slice it, confirm temperatures, and start printing
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| api_key | string | API key for authentication (default: value from env) | No
| bed_temp | number | Expected bed temperature | No
| extension_inches | number | Amount to extend the base in inches | Yes
| extruder_temp | number | Expected extruder temperature | No
| host | string | Hostname or IP address of the printer (default: value from env) | No
| port | string | Port of the printer API (default: value from env) | No
| stl_path | string | Path to the STL file to process | Yes
| type | string | Type of printer management system (default: value from env) | No
</details>
<details>
<summary>get_stl_info</summary>

**Description**:

```
Get detailed information about an STL file
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stl_path | string | Path to the STL file | Yes
</details>
<details>
<summary>scale_stl</summary>

**Description**:

```
Scale an STL model uniformly or along specific axes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| scale_factor | number | Uniform scaling factor to apply | No
| scale_x | number | X-axis scaling factor (overrides scale_factor for X axis) | No
| scale_y | number | Y-axis scaling factor (overrides scale_factor for Y axis) | No
| scale_z | number | Z-axis scaling factor (overrides scale_factor for Z axis) | No
| stl_path | string | Path to the STL file | Yes
</details>
<details>
<summary>rotate_stl</summary>

**Description**:

```
Rotate an STL model around specific axes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| rotate_x | number | Rotation around X-axis in degrees | No
| rotate_y | number | Rotation around Y-axis in degrees | No
| rotate_z | number | Rotation around Z-axis in degrees | No
| stl_path | string | Path to the STL file | Yes
</details>
<details>
<summary>translate_stl</summary>

**Description**:

```
Move an STL model along specific axes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stl_path | string | Path to the STL file | Yes
| translate_x | number | Translation along X-axis in millimeters | No
| translate_y | number | Translation along Y-axis in millimeters | No
| translate_z | number | Translation along Z-axis in millimeters | No
</details>
<details>
<summary>modify_stl_section</summary>

**Description**:

```
Apply a specific transformation to a selected section of an STL file
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| custom_max_x | number | Maximum X for custom section bounds | No
| custom_max_y | number | Maximum Y for custom section bounds | No
| custom_max_z | number | Maximum Z for custom section bounds | No
| custom_min_x | number | Minimum X for custom section bounds | No
| custom_min_y | number | Minimum Y for custom section bounds | No
| custom_min_z | number | Minimum Z for custom section bounds | No
| section | string | Section to modify: 'top', 'bottom', 'center', or custom bounds | Yes
| stl_path | string | Path to the STL file | Yes
| transformation_type | string | Type of transformation to apply | Yes
| value_x | number | Transformation value for X axis | No
| value_y | number | Transformation value for Y axis | No
| value_z | number | Transformation value for Z axis | No
</details>
<details>
<summary>generate_stl_visualization</summary>

**Description**:

```
Generate an SVG visualization of an STL file from multiple angles
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | Height of each view in pixels (default: 300) | No
| stl_path | string | Path to the STL file | Yes
| width | number | Width of each view in pixels (default: 300) | No
</details>
<details>
<summary>print_3mf</summary>

**Description**:

```
Print a 3MF file on a Bambu Lab printer, potentially overriding settings.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ams_mapping | object | Override AMS filament mapping (e.g., {"Generic PLA": 0, "Generic PETG": 1}). | No
| bambu_serial | string | Serial number for the Bambu Lab printer (default: value from env) | No
| bambu_token | string | Access token for the Bambu Lab printer (default: value from env) | No
| bed_temperature | number | Override bed temperature (°C). | No
| host | string | Hostname or IP address of the Bambu printer (default: value from env) | No
| layer_height | number | Override layer height (mm). | No
| nozzle_temperature | number | Override nozzle temperature (°C). | No
| support_enabled | boolean | Override support generation. | No
| three_mf_path | string | Path to the 3MF file to print. | Yes
</details>
<details>
<summary>merge_vertices</summary>

**Description**:

```
Merge vertices in an STL file that are closer than the specified tolerance.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stl_path | string | Path to the STL file to modify. | Yes
| tolerance | number | Maximum distance between vertices to merge (in mm, default: 0.01). | No
</details>
<details>
<summary>center_model</summary>

**Description**:

```
Translate the model so its geometric center is at the origin (0,0,0).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stl_path | string | Path to the STL file to center. | Yes
</details>
<details>
<summary>lay_flat</summary>

**Description**:

```
Attempt to rotate the model so its largest flat face lies on the XY plane (Z=0).
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| stl_path | string | Path to the STL file to lay flat. | Yes
</details>

## 📚 Resources (2)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| 3D Printer Status | application/json | printer://localhost/status | - |
| 3D Printer Files | application/json | printer://localhost/files | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | center_model | description | dafb5d93a8eca42ba429e5b739c02b5e5358667cb030589d8a979808eb4dfb08 |
| tools | center_model | stl_path | a1afac6b4541fe19d6db09a7a0a33159c99e7cd716c072254594af2155c1e6f0 |
| tools | confirm_temperatures | description | 229590b7889062c06dccf56880d17a6ea2ab8c77eb5da059fcdc56942514e162 |
| tools | confirm_temperatures | bed_temp | 0a03213f24991732375d67c04dc4b2f2ba8f8eea27558c06baa6850c23f4094e |
| tools | confirm_temperatures | extruder_temp | 56b347004fff69ff10d422a03de0c28a9986069b954ffc51ae5cd97e463a4a9f |
| tools | confirm_temperatures | gcode_path | 4ab9f019cf5a10eb189f78251b1327d0d15ff07583bc358e63d384885d874ffc |
| tools | extend_stl_base | description | 46c4ba63dbec933bab20249309b0b52865a3d91337f27e29e56588a94afad5e6 |
| tools | extend_stl_base | extension_inches | fc2ee78563954015feed8836f2a2be68bffa55e7e24d42d9df2fa3e539dc1119 |
| tools | extend_stl_base | stl_path | c7980f76d0c6381fb123e2fe23ff8b80c8f9b3db66900d91ef44778868fb93c8 |
| tools | generate_stl_visualization | description | c0c720b85a4ba18c4650d761581ea22950e54e99cd476674983d9e3d5a25dd4e |
| tools | generate_stl_visualization | height | 72a98c7d2c4e21481f80a90be7456e8824adcc40716ff34a539e6402e344cab9 |
| tools | generate_stl_visualization | stl_path | 6785f01a1abddbbc76bc0f8a9541c2d5f9c935daac8c833d6eeb487d72527c9c |
| tools | generate_stl_visualization | width | 47434a77f1ac63ad8aac1ad0d6121ae85c3deb8fa6865ce5ce2576a22b2689ea |
| tools | get_printer_status | description | 5c43cf255975f3a92de8d22b3d891b7a9fa462a7e11a66fd5bd58594a4430a70 |
| tools | get_printer_status | api_key | e37086e8614c87435c9b7125b35d054988ae55158f2312c587ce072a3d9fc810 |
| tools | get_printer_status | bambu_serial | 4684ecb65a303176287b3eea9884742a290c01445a3f8ff7b080ea1e420f91a3 |
| tools | get_printer_status | bambu_token | baa357da38c6ff3a4df2f3f20d244e465c5bcd4614939ebc9eee8fb25f36dd7d |
| tools | get_printer_status | host | 4ed906b275207af3d89f8c690c40b5382d70a0ffb66f25171e01893e7d5fdf58 |
| tools | get_printer_status | port | 9e2e3042fdb2f77449fc91b38cf7c96b67342285c84912afe44c68e2c4a35493 |
| tools | get_printer_status | type | b90438c026c0dbde857431132e669c5cc4ae470efdcde6343eac4e8aa7442fbf |
| tools | get_stl_info | description | 31d786b12bb7e7b8ed7bf74c59cf23300887fb95eab86c3ce56063a0b3834633 |
| tools | get_stl_info | stl_path | 6785f01a1abddbbc76bc0f8a9541c2d5f9c935daac8c833d6eeb487d72527c9c |
| tools | lay_flat | description | e15dd0257299b1c194c0e59e1540165f890a5eeecf6ad08c016f7983d4596a04 |
| tools | lay_flat | stl_path | 2fcf80af0a6015b0661b710ce78f18e076cfddb67c1f34725fc5d8f42081b3f6 |
| tools | merge_vertices | description | b366bb3bf4f3577a448bcc20c28a7aa484c7bc42088fc29f49c3c4fbd1e044b3 |
| tools | merge_vertices | stl_path | b5aa901123129c77556b12bd624c2217e8c53760b64e2734c341bd763c94a5b6 |
| tools | merge_vertices | tolerance | fc585774cc4972c61772b2e5d7761daee6510906336f688e2b6d022737a7cc4d |
| tools | modify_stl_section | description | b7024ed8514af82ad23f6a525aa0e4e6108e875ca1637b7092c07dae5fd84ea8 |
| tools | modify_stl_section | custom_max_x | d555a5d5a5865bc9483b4d2f0559be3cbdb0270c5c43cd92d4b0d09beb42ab68 |
| tools | modify_stl_section | custom_max_y | 7506e1d78333689b14cfe76e5f30a88895679d166b0d39d5f60433545e6fe2e1 |
| tools | modify_stl_section | custom_max_z | 7436d587313670993bf4057db756feedf4a37beccf4ececad7d0ac63ce38f647 |
| tools | modify_stl_section | custom_min_x | acba0b714146ff290b8ebf800d71f6767b2a7e76bc577ffef940e3e14ecab9f9 |
| tools | modify_stl_section | custom_min_y | 33bb9619c85c0932f9945ce683cf7e5c32e416f4cbb171f4813c8ba67801539a |
| tools | modify_stl_section | custom_min_z | b20c107bd6538c02d2ace031ad1642bd40407cfa4c97cdefd4026b7133720d01 |
| tools | modify_stl_section | section | a2e49b2cc6c656f21ecc3ce2834f5175458c8cee3444989461fa2d23d23cd655 |
| tools | modify_stl_section | stl_path | 6785f01a1abddbbc76bc0f8a9541c2d5f9c935daac8c833d6eeb487d72527c9c |
| tools | modify_stl_section | transformation_type | 9aea0e4a5bfda5d367b3d872dc40f85ee757963543f47c42f3a78da46d266a89 |
| tools | modify_stl_section | value_x | edb6ed222269d87dc02af2701668a6821982db6ab17a525fff04287660af90c3 |
| tools | modify_stl_section | value_y | df93468fb2ee192fa3b1715012960197b26458e8775ab59d7f4de2d305ffb4d8 |
| tools | modify_stl_section | value_z | 4187e0d9caf1328ad747c1552e81ba62d9e026e160d747c06d2ad88e003425b6 |
| tools | print_3mf | description | 317d9138286632d3265ca36512c042d6b164bbbd46a085c74a5b8b7ee70df3b0 |
| tools | print_3mf | ams_mapping | dac332670a1395b606a57296dd20db6511cea94c3c1d7d68eb62b018327c9ffa |
| tools | print_3mf | bambu_serial | de545581264cf974f2fde41aa88c00053faca66155d11f5a2af7ff56224ea566 |
| tools | print_3mf | bambu_token | cc6db9eeab4c09669b08af3e093eef244ded66d9f761e08e7ed50c1411f90326 |
| tools | print_3mf | bed_temperature | 4650ff8155e799107c5ae69c60beb5bd33656bb8364fc422c81076718e265307 |
| tools | print_3mf | host | 2dff41681fa8e74072d88ff7d03650b8db256ee7babdb3973981afbe843611ee |
| tools | print_3mf | layer_height | 10468dd24d82e3f53acb0507b2931059377b0e497ce7b34ff81581deade6daf9 |
| tools | print_3mf | nozzle_temperature | 43cb44d5110c69ee2ac3c598a465bb9b7c82914dc1f2f675edf2c3e56b185ebc |
| tools | print_3mf | support_enabled | 06d630c50505617ddee7f0188e06e8989016fcbe03a43ceea4a3e809e45cc0b3 |
| tools | print_3mf | three_mf_path | 3f933d4432808bc8ffc9643929653aedb0eeffccda114b6747c45e43b9fc11ba |
| tools | process_and_print_stl | description | 725ca78b6091ca324e34e2cf5eb7e89dc38cac0d5ec4ee1034327e11d46af282 |
| tools | process_and_print_stl | api_key | e37086e8614c87435c9b7125b35d054988ae55158f2312c587ce072a3d9fc810 |
| tools | process_and_print_stl | bed_temp | 0a03213f24991732375d67c04dc4b2f2ba8f8eea27558c06baa6850c23f4094e |
| tools | process_and_print_stl | extension_inches | fc2ee78563954015feed8836f2a2be68bffa55e7e24d42d9df2fa3e539dc1119 |
| tools | process_and_print_stl | extruder_temp | 56b347004fff69ff10d422a03de0c28a9986069b954ffc51ae5cd97e463a4a9f |
| tools | process_and_print_stl | host | 4ed906b275207af3d89f8c690c40b5382d70a0ffb66f25171e01893e7d5fdf58 |
| tools | process_and_print_stl | port | 9e2e3042fdb2f77449fc91b38cf7c96b67342285c84912afe44c68e2c4a35493 |
| tools | process_and_print_stl | stl_path | 83e41b4375ea1e6120630d366b43911a61cb39e7e2807f73b912f32713227ac4 |
| tools | process_and_print_stl | type | 4d832d2988b7ed5ab0c18b21980285b495ed2a4bbb28a4b15d8eb143ca096318 |
| tools | rotate_stl | description | b5f100daa2b3711ce46d4d62b2164189d54b70a1489a18bec5b57d134ff559ca |
| tools | rotate_stl | rotate_x | dac8c418a6dfad44ee57494191f5c09b95d8992f21b0269b3e3715e87b58cb0a |
| tools | rotate_stl | rotate_y | e2368e0ea7083f900a7f0fd1d59918ff6dfaf12fb5825c5baaedafa04c80addb |
| tools | rotate_stl | rotate_z | d655972045ebb9724fe6320adaff1b0467ea34c163428f479a3799a4c2e9af07 |
| tools | rotate_stl | stl_path | 6785f01a1abddbbc76bc0f8a9541c2d5f9c935daac8c833d6eeb487d72527c9c |
| tools | scale_stl | description | a9b4a9a34289a4b0d007a0c38a183f6a9205a14958bf3ce30ddb4d14f3d8f7d4 |
| tools | scale_stl | scale_factor | 0f6106e39ff10384220f7ee52844f9c4c43cb32e09aa6e3bff7ad06d0b1e977c |
| tools | scale_stl | scale_x | c744551bef65ce63e5b0cbc8b181d23d8c60f1832e995078b0705a592f0493b6 |
| tools | scale_stl | scale_y | 84b707a53bc996a09397587aa360b138ef49b0c1be82324d6d7fc7f30bd354c8 |
| tools | scale_stl | scale_z | fabef66a9023f876d1ee6e4ec7ddee6f891749deeb3839f853b8f58fac86ab12 |
| tools | scale_stl | stl_path | 6785f01a1abddbbc76bc0f8a9541c2d5f9c935daac8c833d6eeb487d72527c9c |
| tools | slice_stl | description | 2cceed482dd49913fc2e5c77c888eff0d521d2e49260ff990038c540d3193bcb |
| tools | slice_stl | slicer_path | e11525b997e451f0e23902fc43fefdf67c2254e42ac6e885f406085b95b86be2 |
| tools | slice_stl | slicer_profile | a2be24e7c8ffa0285dede6e87e2c7892464344a113246157769b5260e28d85f4 |
| tools | slice_stl | slicer_type | ce61148d505dc1abaf2fe16e466f5562404aee3e331a5763b0fb3c3875c4c758 |
| tools | slice_stl | stl_path | 0975865279090abb86b219b6744d941cd62aa67492de64157b108247843cc941 |
| tools | translate_stl | description | 99da2ddc27ea4deae5aa28cf86c55b15a66b5b24ac6b70c8e4eec1fe5650f69c |
| tools | translate_stl | stl_path | 6785f01a1abddbbc76bc0f8a9541c2d5f9c935daac8c833d6eeb487d72527c9c |
| tools | translate_stl | translate_x | 461297929979d5b28ee301baa34c5c60ab3f84c7bac53bdb324769d5f8f55718 |
| tools | translate_stl | translate_y | 0640ae27aa5bc272e08e42833cc8d7c849eacf2f96f69e52350207b15b2f9d05 |
| tools | translate_stl | translate_z | 9747588f0f863d2e44eebe210e59512d24e055f4718108369db983575d0ac622 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
