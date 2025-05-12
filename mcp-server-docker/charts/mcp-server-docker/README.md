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


# What is mcp-server-docker?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-docker/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-docker/0.2.0?logo=docker&logoColor=fff&label=0.2.0)](https://hub.docker.com/r/acuvity/mcp-server-docker)
[![PyPI](https://img.shields.io/badge/0.2.0-3775A9?logo=pypi&logoColor=fff&label=mcp-server-docker)](https://github.com/ckreiling/mcp-server-docker)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-docker&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22%2Fvar%2Frun%2Fdocker.sock%3A%2Fvar%2Frun%2Fdocker.sock%22%2C%22docker.io%2Facuvity%2Fmcp-server-docker%3A0.2.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrate with Docker to manage containers, images, volumes, and networks.

Packaged by Acuvity from mcp-server-docker original [sources](https://github.com/ckreiling/mcp-server-docker).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-docker/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/charts/mcp-server-docker/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-server-docker run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Gardrails

### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

## Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/charts/mcp-server-docker#minibridge) for Helm charts).


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Christian Kreiling <kreiling@hey.com> ](https://github.com/ckreiling/mcp-server-docker) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-server-docker ](https://github.com/ckreiling/mcp-server-docker)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-server-docker ](https://github.com/ckreiling/mcp-server-docker)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/charts/mcp-server-docker)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-docker/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.2.0`

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
helm install mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-docker
```

From there your MCP server mcp-server-docker will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-docker` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-docker
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
  mcp-server-scope: native
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-docker` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-docker oci://docker.io/acuvity/mcp-server-docker --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>list_containers</summary>

**Description**:

```
List all Docker containers
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| all | boolean | Show all containers (default shows just running) | No
| filters | any | Filter containers | No
</details>
<details>
<summary>create_container</summary>

**Description**:

```
Create a new Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_remove | boolean | Automatically remove the container | No
| command | any | Command to run in container | No
| detach | boolean | Run container in the background. Should be True for long-running containers, can be false for short-lived containers | No
| entrypoint | any | Entrypoint to run in container | No
| environment | any | Environment variables dictionary | No
| image | string | Docker image name | Yes
| labels | any | Container labels, either as a dictionary or a list of key=value strings | No
| name | any | Container name | No
| network | any | Network to attach the container to | No
| ports | any | A map whose keys are the container port, and the values are the host port(s) to bind to. | No
| volumes | any | Volume mappings | No
</details>
<details>
<summary>run_container</summary>

**Description**:

```
Run an image in a new Docker container (preferred over `create_container` + `start_container`)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_remove | boolean | Automatically remove the container | No
| command | any | Command to run in container | No
| detach | boolean | Run container in the background. Should be True for long-running containers, can be false for short-lived containers | No
| entrypoint | any | Entrypoint to run in container | No
| environment | any | Environment variables dictionary | No
| image | string | Docker image name | Yes
| labels | any | Container labels, either as a dictionary or a list of key=value strings | No
| name | any | Container name | No
| network | any | Network to attach the container to | No
| ports | any | A map whose keys are the container port, and the values are the host port(s) to bind to. | No
| volumes | any | Volume mappings | No
</details>
<details>
<summary>recreate_container</summary>

**Description**:

```
Stop and remove a container, then run a new container. Fails if the container does not exist.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| auto_remove | boolean | Automatically remove the container | No
| command | any | Command to run in container | No
| container_id | any | Container ID to recreate. The `name` parameter will be used if this is not provided | No
| detach | boolean | Run container in the background. Should be True for long-running containers, can be false for short-lived containers | No
| entrypoint | any | Entrypoint to run in container | No
| environment | any | Environment variables dictionary | No
| image | string | Docker image name | Yes
| labels | any | Container labels, either as a dictionary or a list of key=value strings | No
| name | any | Container name | No
| network | any | Network to attach the container to | No
| ports | any | A map whose keys are the container port, and the values are the host port(s) to bind to. | No
| volumes | any | Volume mappings | No
</details>
<details>
<summary>start_container</summary>

**Description**:

```
Start a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
</details>
<details>
<summary>fetch_container_logs</summary>

**Description**:

```
Fetch logs for a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
| tail | any | Number of lines to show from the end | No
</details>
<details>
<summary>stop_container</summary>

**Description**:

```
Stop a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
</details>
<details>
<summary>remove_container</summary>

**Description**:

```
Remove a Docker container
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| container_id | string | Container ID or name | Yes
| force | boolean | Force remove the container | No
</details>
<details>
<summary>list_images</summary>

**Description**:

```
List Docker images
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| all | boolean | Show all images (default hides intermediate) | No
| filters | any | Filter images | No
| name | any | Filter images by repository name, if desired | No
</details>
<details>
<summary>pull_image</summary>

**Description**:

```
Pull a Docker image
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repository | string | Image repository | Yes
| tag | any | Image tag | No
</details>
<details>
<summary>push_image</summary>

**Description**:

```
Push a Docker image
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| repository | string | Image repository | Yes
| tag | any | Image tag | No
</details>
<details>
<summary>build_image</summary>

**Description**:

```
Build a Docker image from a Dockerfile
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dockerfile | any | Path to Dockerfile | No
| path | string | Path to build context | Yes
| tag | string | Image tag | Yes
</details>
<details>
<summary>remove_image</summary>

**Description**:

```
Remove a Docker image
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| force | boolean | Force remove the image | No
| image | string | Image ID or name | Yes
</details>
<details>
<summary>list_networks</summary>

**Description**:

```
List Docker networks
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filters | any | Filter networks | No
</details>
<details>
<summary>create_network</summary>

**Description**:

```
Create a Docker network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| driver | any | Network driver | No
| internal | boolean | Create an internal network | No
| labels | any | Network labels | No
| name | string | Network name | Yes
</details>
<details>
<summary>remove_network</summary>

**Description**:

```
Remove a Docker network
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| network_id | string | Network ID or name | Yes
</details>
<details>
<summary>list_volumes</summary>

**Description**:

```
List Docker volumes
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_volume</summary>

**Description**:

```
Create a Docker volume
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| driver | any | Volume driver | No
| labels | any | Volume labels | No
| name | string | Volume name | Yes
</details>
<details>
<summary>remove_volume</summary>

**Description**:

```
Remove a Docker volume
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| force | boolean | Force remove the volume | No
| volume_name | string | Volume name | Yes
</details>

## 📝 Prompts (1)
<details>
<summary>docker_compose</summary>

**Description**:

```
Treat the LLM like a Docker Compose manager
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| name | Unique name of the project |Yes |
| containers | Describe containers you want |Yes |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | docker_compose | description | 1747f0fcc38ce43987a5add1ec0c842f005ff7c543f4bd448707600397805be8 |
| prompts | docker_compose | containers | 54248a6c7bcf5fccbf66bfedebccf37bb90163dfa2b4bd5418f587b81883ca58 |
| prompts | docker_compose | name | e037ff48f8d7aea7707d027e85290c86c6187a9cf8b65f50ad115e2cb4ea38b1 |
| tools | build_image | description | 705c2a1603d119dd8ecdf6ab10334a19192312197dfedc0baf5e7ea096f03f21 |
| tools | build_image | dockerfile | a26f7529cdb6b02baa0fe3f86868d7bdf0b1d61d8df03f9331e3f28dcd4cec88 |
| tools | build_image | path | a4807fcee1dddfc2d8a8105415e6f2a314f2a258039ea62290272c75476c7014 |
| tools | build_image | tag | c4a77afa3d5cd701f32b5f09c195c635b256db8595687828c3ea0785ab5b72f4 |
| tools | create_container | description | b815a8ce79ac0ab46eef91d033a96a6298aaee44fba2209f038df0f290067a30 |
| tools | create_container | auto_remove | 19d5467374321dbf428f0bcbe1dedc6b4ccb3a42c727be97b8d212a3a31952a0 |
| tools | create_container | command | 88bc0bd30d1b7cd4fb79d98d7afca13530d2e8dbec00725d82f7d4cb1664ae95 |
| tools | create_container | detach | 2eee111e7b30a2e387a1079c743fcfd43199452fb08b127186983d60368e1d36 |
| tools | create_container | entrypoint | c938459cad356a96aa690ff14d85f9285ffafee1178de254930aa60269fc3ee7 |
| tools | create_container | environment | 75678c388925b748d3a4156df724c332fb18cfd2800ef5f0f8b506fc6312769d |
| tools | create_container | image | f8dee27723d20cda724d41bf47ef4f5e915948d4f790d7ec7fb9883aa8907439 |
| tools | create_container | labels | 0c9da99b2d6a5801da677fcc8ae643c33730cd34bca0529bff7f0bbe1f092fe5 |
| tools | create_container | name | 8d3a5415ee22e30f39114240c191b98b52f67ea8d52a6d8fede1ed76768cba98 |
| tools | create_container | network | 278df666180dcee703e0ec0372aeb3f2d58aa723d718f0e93554a2d1f3adddce |
| tools | create_container | ports | 1de7c6d7ac848432c94231b4b5900034f268aad3391d2f554ee25d7a87a46ed6 |
| tools | create_container | volumes | 952112ecfb6d84475c049817196f529385c4f70b1edd7b7c7a4612d76ead514d |
| tools | create_network | description | eca09860101dcc7683b41d9a49f27c25828b461cb9eb20602d30bc4ebcb20377 |
| tools | create_network | driver | f331e050c8e9f40de9b06ce2d03672069350da23bc10e56a9ec0e597acf34c71 |
| tools | create_network | internal | 8610f22d1f97f12965e975a97ee7d61185214850ea7d28b97a2fd13a0e988ebf |
| tools | create_network | labels | 03073866f417fa0943fbde2ebb822876a88f2be18d5e8f07a16925677eb589bb |
| tools | create_network | name | b97af01289460424250ff6ffae944f3b692f478e4fe678e05d4a1ba4859990dc |
| tools | create_volume | description | fb7b9660e6b26608d8ba47910fd565c5a6ebd014957bf8675be01a866064f383 |
| tools | create_volume | driver | 8e0db59b3494cbff0ee006edb671dd0554f10d5e178c88d58aff60563a0a0ce3 |
| tools | create_volume | labels | 123172e579a0d2fde759eddc7fe3f90ea9528809ff31dd22b3dac84332101824 |
| tools | create_volume | name | 6f7dd2eff222a379423cc7b906910b3bb1473dbd7b145c1ca3c053dfc8ce5c43 |
| tools | fetch_container_logs | description | a230664008063599fa40b21841e1a2039bfd1c53a9117edaec3cc4ffe85804e5 |
| tools | fetch_container_logs | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |
| tools | fetch_container_logs | tail | e923fbedccdbc7fc6c8c9cc82b95f01fb6eee2d6d9205186aa96ec9e1fa42985 |
| tools | list_containers | description | b2aaef42684012a93ed74f4ae1470bcd33d0d09fd885bbb25a0d6a3cc298a349 |
| tools | list_containers | all | 25217765ac89ca0c21562a18af0b7d06cea3dd6f35f7db05ace677745e8be292 |
| tools | list_containers | filters | 12cce9715b61b46554fe483591ecd0eb1442bbe3acf6afde384c0aa4b064aace |
| tools | list_images | description | 897691804adfd369ab4f463158e458d988823292bc1bd988f437380dde1bdfe3 |
| tools | list_images | all | 1797445beff70492315c96d517fe2c694e9fb4271338fb6f3cea05532d7841b7 |
| tools | list_images | filters | 5a46660ef3acccf6234f7ca539018dd595a3bc0100452356a8adec594deed7bb |
| tools | list_images | name | 49ec60d56114d10bbf4a2318e2096f2bdcb9f1e9dc43267693a95e7430a53eb0 |
| tools | list_networks | description | e0f48e9f0094db78a2fac13454951125b26eac6cd465ba99161f419b4118a6b1 |
| tools | list_networks | filters | 89f87a5ab141b2985d9202a8ee7336fad0558361f0aa55e3a76c169692368961 |
| tools | list_volumes | description | 7eb1265481e78bde4d9cb61ce4e6bd2aa072aedc28e0c468c37deced52ef7ecb |
| tools | pull_image | description | 2dafd1dba3147223f0a035eb647289c88a66a84b93a1f088869efd81c950ed74 |
| tools | pull_image | repository | 9d059b146668a6b686684942d7e00e84a4519e4a2950015ceadc13aa4d651a9d |
| tools | pull_image | tag | c4a77afa3d5cd701f32b5f09c195c635b256db8595687828c3ea0785ab5b72f4 |
| tools | push_image | description | e6664cd117075eb7632367ee61f0a714b6caed15be2bbe73ca8f8c58efa18382 |
| tools | push_image | repository | 9d059b146668a6b686684942d7e00e84a4519e4a2950015ceadc13aa4d651a9d |
| tools | push_image | tag | c4a77afa3d5cd701f32b5f09c195c635b256db8595687828c3ea0785ab5b72f4 |
| tools | recreate_container | description | 4cd16e24bbc67a32475afde1b1443954d95c17f762e9ef642b1f3491765495d8 |
| tools | recreate_container | auto_remove | 19d5467374321dbf428f0bcbe1dedc6b4ccb3a42c727be97b8d212a3a31952a0 |
| tools | recreate_container | command | 88bc0bd30d1b7cd4fb79d98d7afca13530d2e8dbec00725d82f7d4cb1664ae95 |
| tools | recreate_container | container_id | fe957695c0472192c71de78c4a4246f0057b5c5712bd12cdabb4b8d51db2b47c |
| tools | recreate_container | detach | 2eee111e7b30a2e387a1079c743fcfd43199452fb08b127186983d60368e1d36 |
| tools | recreate_container | entrypoint | c938459cad356a96aa690ff14d85f9285ffafee1178de254930aa60269fc3ee7 |
| tools | recreate_container | environment | 75678c388925b748d3a4156df724c332fb18cfd2800ef5f0f8b506fc6312769d |
| tools | recreate_container | image | f8dee27723d20cda724d41bf47ef4f5e915948d4f790d7ec7fb9883aa8907439 |
| tools | recreate_container | labels | 0c9da99b2d6a5801da677fcc8ae643c33730cd34bca0529bff7f0bbe1f092fe5 |
| tools | recreate_container | name | 8d3a5415ee22e30f39114240c191b98b52f67ea8d52a6d8fede1ed76768cba98 |
| tools | recreate_container | network | 278df666180dcee703e0ec0372aeb3f2d58aa723d718f0e93554a2d1f3adddce |
| tools | recreate_container | ports | 1de7c6d7ac848432c94231b4b5900034f268aad3391d2f554ee25d7a87a46ed6 |
| tools | recreate_container | volumes | 952112ecfb6d84475c049817196f529385c4f70b1edd7b7c7a4612d76ead514d |
| tools | remove_container | description | 42bba4e113755275e7e176ee6cf3577ac652910e39c870d4268799cfcc0325cf |
| tools | remove_container | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |
| tools | remove_container | force | 6dd6aa3ffa2b44f62d669a63ee5edfd12aceec7d6d54eac1cef101c6a92fb986 |
| tools | remove_image | description | 48678674b4fa9965fdefb4d8df4b1e9ae411da607c095f21c9633e00e7194483 |
| tools | remove_image | force | ad53029af2640459dd4ef4293274b1b3237ef4bbcb399797f0da6203faeb65b9 |
| tools | remove_image | image | 2c0ca53ceec83f918f22377d3c79850a2aff203b019ed223c633adce802929cd |
| tools | remove_network | description | 05d6a28c8bdd792facc3ae7610477b6e0e15d9493eb71eb14020a69b7e5a57da |
| tools | remove_network | network_id | 662f55d08dfc2dbe245e4118b04bc4df1dd65c37d0c2640f6600619034b6e511 |
| tools | remove_volume | description | 418a93d2135bec9250d71bac6c05ee7ca63d295450e9deebacdb906d61b4e1c5 |
| tools | remove_volume | force | 21f06736c937cacab95a23aaade6aabc81c7f3fe0888c3eb80e2e56bcee4d363 |
| tools | remove_volume | volume_name | 6f7dd2eff222a379423cc7b906910b3bb1473dbd7b145c1ca3c053dfc8ce5c43 |
| tools | run_container | description | be3965a693f5235851dfd36772819a6ac3868f43dbed3f6fdcce0baa89e86eaf |
| tools | run_container | auto_remove | 19d5467374321dbf428f0bcbe1dedc6b4ccb3a42c727be97b8d212a3a31952a0 |
| tools | run_container | command | 88bc0bd30d1b7cd4fb79d98d7afca13530d2e8dbec00725d82f7d4cb1664ae95 |
| tools | run_container | detach | 2eee111e7b30a2e387a1079c743fcfd43199452fb08b127186983d60368e1d36 |
| tools | run_container | entrypoint | c938459cad356a96aa690ff14d85f9285ffafee1178de254930aa60269fc3ee7 |
| tools | run_container | environment | 75678c388925b748d3a4156df724c332fb18cfd2800ef5f0f8b506fc6312769d |
| tools | run_container | image | f8dee27723d20cda724d41bf47ef4f5e915948d4f790d7ec7fb9883aa8907439 |
| tools | run_container | labels | 0c9da99b2d6a5801da677fcc8ae643c33730cd34bca0529bff7f0bbe1f092fe5 |
| tools | run_container | name | 8d3a5415ee22e30f39114240c191b98b52f67ea8d52a6d8fede1ed76768cba98 |
| tools | run_container | network | 278df666180dcee703e0ec0372aeb3f2d58aa723d718f0e93554a2d1f3adddce |
| tools | run_container | ports | 1de7c6d7ac848432c94231b4b5900034f268aad3391d2f554ee25d7a87a46ed6 |
| tools | run_container | volumes | 952112ecfb6d84475c049817196f529385c4f70b1edd7b7c7a4612d76ead514d |
| tools | start_container | description | 8344d6c6b50cf0415a88139fb79566833b8d4f54e151641f604f31b1e1571549 |
| tools | start_container | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |
| tools | stop_container | description | 6e5bdc513791aed6ed64f05478f41f6470937dcd4aab044b4564b7b02fc1a09a |
| tools | stop_container | container_id | 6958c0cf044f0a06dc71decbbc4e3b71fd44bb6a6f57123fc14b5a2f811a7ea6 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
