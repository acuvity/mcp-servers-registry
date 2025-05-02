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
</p>


# What is mcp-server-anilist?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-anilist/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-anilist/1.2.4?logo=docker&logoColor=fff&label=1.2.4)](https://hub.docker.com/r/acuvity/mcp-server-anilist)
[![PyPI](https://img.shields.io/badge/1.2.4-3775A9?logo=pypi&logoColor=fff&label=anilist-mcp)](https://github.com/yuna0x0/anilist-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-anilist&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ANILIST_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-anilist%3A1.2.4%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AniList MCP server for accessing AniList API data

> [!NOTE]
> `anilist-mcp` has been repackaged by Acuvity from yuna0x0 original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure anilist-mcp run reliably and safely.

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
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails that protect MCP server integrity and detect suspicious behaviors in real-time.:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions - or call arguments - reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognised tokens formats with `[REDACTED]` in outbound content.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ yuna0x0 ](https://github.com/yuna0x0/anilist-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ anilist-mcp ](https://github.com/yuna0x0/anilist-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ anilist-mcp ](https://github.com/yuna0x0/anilist-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-anilist/charts/mcp-server-anilist)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-anilist/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.2.4`

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
  - `ANILIST_TOKEN` secret to be set as secrets.ANILIST_TOKEN either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install helm install mcp-server-anilist oci://docker.io/acuvity/mcp-server-anilist --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-anilist --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-anilist --version 1.0.0
````
From there your MCP server mcp-server-anilist will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-anilist` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-anilist
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
args:
```

Passes arbitrary command‑line arguments into the container.


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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-anilist` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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

  # Policier configuration
  policer:
    # Instruct to enforce policies if enabled
    # otherwise it will jsut log the verdict as a warning
    # message in logs
    enforce: false
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
# 🧠 Server features

## 🧰 Tools (44)
<details>
<summary>favourite_studio</summary>

**Description**:

```
[Requires Login] Favourite or unfavourite a studio by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the studio to favourite/unfavourite | Yes
</details>
<details>
<summary>get_genres</summary>

**Description**:

```
Get all available genres on AniList
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_media_tags</summary>

**Description**:

```
Get all available media tags on AniList
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_site_statistics</summary>

**Description**:

```
Get AniList site statistics over the last seven days
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_studio</summary>

**Description**:

```
Get information about a studio by its AniList ID or name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| studio | [string number] | The studio ID or name | Yes
</details>
<details>
<summary>delete_activity</summary>

**Description**:

```
[Requires Login] Delete the current authorized user's activity post
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList activity ID to delete | Yes
</details>
<details>
<summary>get_activity</summary>

**Description**:

```
Get a specific AniList activity by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| activityID | number | The AniList activity ID | Yes
</details>
<details>
<summary>get_user_activity</summary>

**Description**:

```
Fetch activities from a user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | The page number to display | No
| perPage | number | How many entries to display on one page (max 25) | No
| user | number | The user's AniList ID | Yes
</details>
<details>
<summary>post_message_activity</summary>

**Description**:

```
[Requires Login] Post a new message activity or update an existing one
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | [number null] | AniList Activity ID (null to create new, number to update) | Yes
| isPrivate | boolean | Set to true if it is a private message | No
| recipientId | number | The target user to send the message to | Yes
| text | string | The activity message text | Yes
</details>
<details>
<summary>post_text_activity</summary>

**Description**:

```
[Requires Login] Post a new text activity or update an existing one
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | [number null] | AniList Activity ID (null to create new, number to update) | Yes
| text | string | The content of the activity | Yes
</details>
<details>
<summary>add_list_entry</summary>

**Description**:

```
[Requires Login] Add an entry to the authorized user's list
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the media entry to add | Yes
| options | object | Values to save with the entry | Yes
</details>
<details>
<summary>get_user_anime_list</summary>

**Description**:

```
Get a user's anime list
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | [number string] | Username or user ID | Yes
</details>
<details>
<summary>get_user_manga_list</summary>

**Description**:

```
Get a user's manga list
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | [number string] | Username or user ID | Yes
</details>
<details>
<summary>remove_list_entry</summary>

**Description**:

```
[Requires Login] Remove an entry from the authorized user's list
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList list ID of the entry to remove | Yes
</details>
<details>
<summary>update_list_entry</summary>

**Description**:

```
[Requires Login] Update an entry on the authorized user's list
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList list ID of the entry to edit | Yes
| options | object | Values to save with the entry | Yes
</details>
<details>
<summary>get_anime</summary>

**Description**:

```
Get detailed information about an anime by its AniList ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the anime | Yes
</details>
<details>
<summary>favourite_anime</summary>

**Description**:

```
[Requires Login] Favourite or unfavourite an anime by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the anime to favourite/unfavourite | Yes
</details>
<details>
<summary>favourite_manga</summary>

**Description**:

```
[Requires Login] Favourite or unfavourite a manga by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the manga to favourite/unfavourite | Yes
</details>
<details>
<summary>get_manga</summary>

**Description**:

```
Get detailed information about a manga by its AniList ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the manga | Yes
</details>
<details>
<summary>get_character</summary>

**Description**:

```
Get information about a character by their AniList ID or name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | [number string] | The AniList ID of the character | Yes
</details>
<details>
<summary>favourite_character</summary>

**Description**:

```
[Requires Login] Favourite or unfavourite a character by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the character to favourite/unfavourite | Yes
</details>
<details>
<summary>favourite_staff</summary>

**Description**:

```
[Requires Login] Favourite or unfavourite a staff member by their ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the staff member to favourite/unfavourite | Yes
</details>
<details>
<summary>get_todays_birthday_characters</summary>

**Description**:

```
Get all characters whose birthday is today
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | What page in the search to target | No
</details>
<details>
<summary>get_todays_birthday_staff</summary>

**Description**:

```
Get all staff members whose birthday is today
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | What page in the search to target | No
</details>
<details>
<summary>get_staff</summary>

**Description**:

```
Get information about staff member by their AniList ID or name
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | [number string] | The AniList ID or name of the staff member | Yes
</details>
<details>
<summary>get_recommendation</summary>

**Description**:

```
Get an AniList recommendation by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| recommendID | number | The AniList recommendation ID | Yes
</details>
<details>
<summary>get_recommendations_for_media</summary>

**Description**:

```
Get AniList recommendations for a specific media
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| mediaID | number | The AniList media ID | Yes
| page | number | Target a specific page number for recommendations | No
| perPage | number | Limit the page amount (max 25 per AniList limits) | No
</details>
<details>
<summary>search_activity</summary>

**Description**:

```
Search for activities on AniList
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| activityID | number | The activity ID to lookup (leave it as undefined for no specific ID) | No
| filter | object | Filter object for searching activities (leave it as undefined for no specific filter) | No
| page | number | Page number for results | No
| perPage | number | Results per page (max 25) | No
</details>
<details>
<summary>search_anime</summary>

**Description**:

```
Search for anime with query term and filters
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Results per page (max 25) | No
| filter | object | Filter object for searching anime.
You MUST NOT include "{ "type": "ANIME" }" in the filter object. As it is already included in the API call.
When no sorting method or any filter is specified, you SHOULD use the site default: "{ "sort": ["SEARCH_MATCH"] }".
Otherwise, request is likely to fail or return no results. | No
| page | number | Page number for results | No
| term | string | Query term for finding anime (leave it as undefined when no query term specified.)
Query term is used for searching with specific word or title in mind.

You SHOULD not include things that can be found in the filter object, such as genre or tag.
Those things should be included in the filter object instead.

To check whether a user requested term should be considered as a query term or a filter term.
It is recommended to use tools like 'get_genres' and 'get_media_tags' first. | No
</details>
<details>
<summary>search_character</summary>

**Description**:

```
Search for characters based on a query term
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Results per page (max 25) | No
| page | number | Page number for results | No
| term | string | Search term for finding characters | Yes
</details>
<details>
<summary>search_manga</summary>

**Description**:

```
Search for manga with query term and filters
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Results per page (max 25) | No
| filter | object | Filter object for searching manga.
You MUST NOT include "{ "type": "MANGA" }" in the filter object. As it is already included in the API call.
When no sorting method or any filter is specified, you SHOULD use the site default: "{ "sort": ["SEARCH_MATCH"] }".
Otherwise, request is likely to fail or return no results. | No
| page | number | Page number for results | No
| term | string | Query term for finding manga (leave it as undefined when no query term specified.)
Query term is used for searching with specific word or title in mind.

You SHOULD not include things that can be found in the filter object, such as genre or tag.
Those things should be included in the filter object instead.

To check whether a user requested term should be considered as a query term or a filter term.
It is recommended to use tools like 'get_genres' and 'get_media_tags' first. | No
</details>
<details>
<summary>search_staff</summary>

**Description**:

```
Search for staff members based on a query term
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Results per page (max 25) | No
| page | number | Page number for results | No
| term | string | Search term for finding staff members | Yes
</details>
<details>
<summary>search_studio</summary>

**Description**:

```
Search for studios based on a query term
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Results per page (max 25) | No
| page | number | Page number for results | No
| term | string | Search term for finding studios | Yes
</details>
<details>
<summary>search_user</summary>

**Description**:

```
Search for users on AniList
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | number | Results per page (max 25) | No
| page | number | Page number for results | No
| term | string | Search term for finding users | Yes
</details>
<details>
<summary>delete_thread</summary>

**Description**:

```
[Requires Login] Delete a thread by its ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList thread ID to delete | Yes
</details>
<details>
<summary>get_thread</summary>

**Description**:

```
Get a specific thread by its AniList ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList ID of the thread | Yes
</details>
<details>
<summary>get_thread_comments</summary>

**Description**:

```
Get comments for a specific thread
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | number | The AniList thread ID | Yes
| page | number | The page number | No
| perPage | number | How many comments per page | No
</details>
<details>
<summary>get_full_user_info</summary>

**Description**:

```
Get a user's complete profile and stats information
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | [number string] | Username or user ID | Yes
</details>
<details>
<summary>follow_user</summary>

**Description**:

```
[Requires Login] Follow or unfollow a user by their ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| userID | number | The user ID of the account to follow/unfollow | Yes
</details>
<details>
<summary>get_authorized_user</summary>

**Description**:

```
[Requires Login] Get profile information of the currently authorized user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_user_recent_activity</summary>

**Description**:

```
Get recent activity from a user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | number | The user's AniList ID (Number ID only, DO NOT use username, any kind of string or other types except for numbers.) | Yes
</details>
<details>
<summary>get_user_profile</summary>

**Description**:

```
Get a user's AniList profile
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | [number string] | Username or user ID | Yes
</details>
<details>
<summary>get_user_stats</summary>

**Description**:

```
Get a user's AniList statistics
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| user | [number string] | Username or user ID | Yes
</details>
<details>
<summary>update_user</summary>

**Description**:

```
[Requires Login] Update user settings
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| options | object | User options to update | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_list_entry | description | bee27d9670b8efed6061d9c21427b80864adb334ec9de9f7814db2b46b0f84db |
| tools | add_list_entry | id | 32b5327ea19475aed51110f4c6227d887523900d8b850b0f2b6441f7365d772f |
| tools | add_list_entry | options | 03603e2b3e3a692d2e225e2afddd31d0ff4f325b504a90502f6047a10077b8a3 |
| tools | delete_activity | description | 631269a0c704d52f32965272087730b4e57990b896e9a77849b7d2d86a26d219 |
| tools | delete_activity | id | f50253c3fc047fce20ff991ace60e2ed4a72e300d82902e15a299d652563b798 |
| tools | delete_thread | description | e626f45893a2683465040d7aab912e95a1826a21c2cb6b4b1f746b0da2e2c8f1 |
| tools | delete_thread | id | 9219c650ea0b5e49c4e6e3d61854ffff56e60b0ee2ee4c2764efc2458fd39bcd |
| tools | favourite_anime | description | 0eca9d1110b65304603a25203ed90f72e09e404ec0a49ecbffe67fb5ab6d261a |
| tools | favourite_anime | id | f4d93b25225bd03751f33dd43c5134a036b72e5759dc1c3b908e31102d1bf27d |
| tools | favourite_character | description | 145dd227c1087426e5b0c560a38a696dc0abf4040ef699cf35c9f25d6c81515c |
| tools | favourite_character | id | 1255b36c8834583bf3d70deb9db8312d87470aa898bc8c7139d77402dabb58da |
| tools | favourite_manga | description | 1fa1d64e2a87d7e0e3665bb82efc7bc9a7c81a5d7084a633e9e4f717b5ecb855 |
| tools | favourite_manga | id | f993415b6ac81ce9f580ecf8cca54f1ea063350a6bfa0c9e63f8296fbe17c538 |
| tools | favourite_staff | description | 20d3909a6e003cbe21ae5df88f12022ccd1023e97965a727a5656ea3b2cd152f |
| tools | favourite_staff | id | 78d227992de2a3308d8b2c12d41ce9f8fbec8bf715d366ff569b089549d59c18 |
| tools | favourite_studio | description | 99e7d201e6706025e2f6a337a1f8f1c0fac3ebb4aa6821cd724e0336947feffa |
| tools | favourite_studio | id | 779c76ebe852f380bec80ce5f8b09ddab8b04773b8ba5142d7995de27b486360 |
| tools | follow_user | description | 909d0d0ff52cae9ba82c5aee6a3147d5eb40c288ba50ed6217ed1a41f687cae8 |
| tools | follow_user | userID | 2bfe283776ae4b0fe78380fef5f015ea80ec03dcdf4ba2a1bf9b66a058f5ef06 |
| tools | get_activity | description | eac43d52c06f518dd5012cf5c9b57cc80419b6a367df510413531e9065b84e0a |
| tools | get_activity | activityID | 29b20be9e6cb1e270f8db6a282d82e6a7f7f23e44d2ac16dc0ed3e99104df00c |
| tools | get_anime | description | 01427fe8bff6f28b326483a960e9f8a703eb65a3b9f6ab6496e2739c4e6eb323 |
| tools | get_anime | id | e84f610046dfa29979b874dd94eedd62985185c1f8725b4cb96ace70df1b68ef |
| tools | get_authorized_user | description | 60fce3f7a98fbd45363251bca9e6f2d00b8e911c37a5fa99b20dee654012cfaf |
| tools | get_character | description | 25c66963c5ccc75b949c507944d7e1ba8b5113a57b4ae11b538b5c7b2910c5d9 |
| tools | get_character | id | 6d3ea78f44c9e999651a8ba595a02cdc17b20e304310edee1852b43d4662b8d3 |
| tools | get_full_user_info | description | 8eeed3e8325b958b40680cbe0a4b70e1f23612a7c2f64c8b3b044403e3fe24c3 |
| tools | get_full_user_info | user | 43033534e7ab2d124e138f11c785c53358569b48de583e133cbee4c90f177d36 |
| tools | get_genres | description | 3119d941576771602937edba90e01bcf1570033840e1d18db43551400ac709b1 |
| tools | get_manga | description | ff745d329e1ded5519ec851464b84991bac3477ba666eb00ebf364c3cdc58f58 |
| tools | get_manga | id | 50a243b88b74c604f24eedfc156eed1edac57b0f5a75e686ccc8c502b4363d32 |
| tools | get_media_tags | description | 39e9b1d5a8d8d23ce84b0ec13ff1b196999b6abff7ebf1be30603cce8ba774c3 |
| tools | get_recommendation | description | 04bf2c96e92b110f870dde57c5c2950dfa48ad4df02cf3a09fc143bf21d02b23 |
| tools | get_recommendation | recommendID | 6fdbc613824fda9d851f7720da13beb6c4c2a83282a699df53c74c51d6c534a9 |
| tools | get_recommendations_for_media | description | 0f669753486b55c2745c715349c23de8ec798979031ea1299dcfb89570a58909 |
| tools | get_recommendations_for_media | mediaID | caae22e3a6291aed0aec414007f99d03745239aad999ef886002e1491c877d13 |
| tools | get_recommendations_for_media | page | 6455dfbaa427a76661906350f3152bc2445171d5ab7587db8fd0714de8e7168e |
| tools | get_recommendations_for_media | perPage | f49c259f2bc996a97fb32268bb81898ffecba585f2bd6acd54921b5417b42240 |
| tools | get_site_statistics | description | 66e307e81457b3393b280768bf76012b3a2d27319240d182473e8a0f823f9c63 |
| tools | get_staff | description | 63a72128dbfd0832c5ec0816560100d2c4aa9ed88dda8d1097089cf37efb80ed |
| tools | get_staff | id | 8db9c77a6485331ca7daf753539abc62c08e029dc6dad688f1787197d5a5f4c0 |
| tools | get_studio | description | 3ab74d230b41b7d3dde787e4bb3cb0fd1f96d2bd8940fb4297626c35e23f37dd |
| tools | get_studio | studio | 3770ef402e84d503c19198c5768fc562fbabe1b4638add9d4cfd525139efa59b |
| tools | get_thread | description | b271d46247da1831713b4d7e83a22dbd04af0199597cc26554ec4db24c9b7257 |
| tools | get_thread | id | dfff86b1cdb6148691863e2700b29f70592b0bc88d57edc1511e8e69c6cd4ff6 |
| tools | get_thread_comments | description | 174ede3feb05cb25bb7fcc8db1f49dae33a6d9797b8e52fd4e5bd59e9ee02b52 |
| tools | get_thread_comments | id | e1b76f5e401ec313f6357e8f3f0e9adc1a052c0d9aee06c48fc210472584063c |
| tools | get_thread_comments | page | e583a34822e645f2f7ca8b876cc4367f3f486dcf70a85334bbdcb37d1aa4c50d |
| tools | get_thread_comments | perPage | 69187aa7046e5b81e1303bb306f8522d982580877cdd74b56b84a1f6efddc816 |
| tools | get_todays_birthday_characters | description | 715a5328579cd0ed37ab5a1f1c5ab838f4fd1e8d15318afa07982430f5f14238 |
| tools | get_todays_birthday_characters | page | dc1dab940cd36eaae54fb05b0c364a4ce8eacccbe9cfd4bf31f507383b916689 |
| tools | get_todays_birthday_staff | description | 5dfd65b8889b8884a94cbd898490cf92cf7eed7a24bf30a65666f4681f644092 |
| tools | get_todays_birthday_staff | page | dc1dab940cd36eaae54fb05b0c364a4ce8eacccbe9cfd4bf31f507383b916689 |
| tools | get_user_activity | description | 7f63e9582979d0187dbd940a090b22fc43c280805c8c80f6166e72b4c16d8ba7 |
| tools | get_user_activity | page | 0222c1b7b6559fe5dff2abe84c8a16abf5b27382f536c9664ce17d18fa8c7aab |
| tools | get_user_activity | perPage | 83665689364127ce83c8fd69e25f7cecd380d9a57290582340ef08858edded47 |
| tools | get_user_activity | user | a12818c6516eca35297f44fceda22594b127b8cef52533743b3e1c4cec292f92 |
| tools | get_user_anime_list | description | 3707303269504ea0edc4877d215cca18649117ec32c138dabe0333a09abb62b9 |
| tools | get_user_anime_list | user | 43033534e7ab2d124e138f11c785c53358569b48de583e133cbee4c90f177d36 |
| tools | get_user_manga_list | description | ed86001c9b4d854db3bbb0e5f5186d6ea7218e6850a7855e477fbc6e5ead3617 |
| tools | get_user_manga_list | user | 43033534e7ab2d124e138f11c785c53358569b48de583e133cbee4c90f177d36 |
| tools | get_user_profile | description | 867bf9e3df013f4055da23343b384c26b6f4eaed45ffa9e9282d5c354adf240c |
| tools | get_user_profile | user | 43033534e7ab2d124e138f11c785c53358569b48de583e133cbee4c90f177d36 |
| tools | get_user_recent_activity | description | 220d3882ae7a7260abe8532307c95045bd126de6cf08f7673a737db25735b15a |
| tools | get_user_recent_activity | user | 35511f07417cafaf74095c94567cc95d0b6995a68ac96d667fbe829be1ea2ae2 |
| tools | get_user_stats | description | cf0d584101a27d138246dc6583a6125d1121cb9047c423b6443e3fe61baf4b7e |
| tools | get_user_stats | user | 43033534e7ab2d124e138f11c785c53358569b48de583e133cbee4c90f177d36 |
| tools | post_message_activity | description | 55aeb3f9a919df996cddfb4aba05f6f12d13d8aea5b5e56d8362737a63858c21 |
| tools | post_message_activity | id | 8b8734c711b4af5168d78eaf297fd1a8d6c719ac50dc9e7b19ca37fa91aa0fcc |
| tools | post_message_activity | isPrivate | 6bd128ecedc86b2a671d5b141b4e2ff3995ec790cddc80f11ef92fd45974fd2d |
| tools | post_message_activity | recipientId | 0cd4254e191fb3025421afd222283cfa31ea5420a7f7bed4c27076a483653c30 |
| tools | post_message_activity | text | 6ad0a9a77ea01d9ae2fc3b441307320d0a429b230b46215a3068834a5b9bb066 |
| tools | post_text_activity | description | 138def6f1acb82fcc6b9fcb981e62b7b3948d56456392f945da2d88b106bc152 |
| tools | post_text_activity | id | 8b8734c711b4af5168d78eaf297fd1a8d6c719ac50dc9e7b19ca37fa91aa0fcc |
| tools | post_text_activity | text | 0b0baa548217ba49a9b769695c1dad0bea7762fd45f2e58c5ccccb2d0b0ab101 |
| tools | remove_list_entry | description | d7c8f3df8c1b92756e6766fe0c0ab02b4dab4c167c9dc8443bcfb77df5a9c879 |
| tools | remove_list_entry | id | 2a1730238100e84bb7349ab6fdfb97f205415df4d697dc34ec746a04fddfa1de |
| tools | search_activity | description | da28e761d186b39f0f8825e0b5350ce267f29e9bdf61f1b81e067479826b2f3a |
| tools | search_activity | activityID | ff8a578c5bc795861244c09834e31abd18d65f7d8f283810254f7c79a557f28c |
| tools | search_activity | filter | d4c02df9ce285dd4b24942e220271e78192e897d5e8661f735709e1fe632ea3c |
| tools | search_activity | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_activity | perPage | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_anime | description | 30d33276950da75d2c59893ca0512136de3ac4824c4112a94fe84fdf27054ff2 |
| tools | search_anime | amount | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_anime | filter | 7ea94e80fb92a9790152ead80a725befac13e3dbfaca8f8f3af045d9613bf514 |
| tools | search_anime | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_anime | term | 6b0adde6925b98b707d33b4ed1eee851914120bf4c4ea9819ee91b3f92f58194 |
| tools | search_character | description | 895648a9ecb585e3a8669cdc06f2e1c70a392aca5bebcdf801a43e89b2819824 |
| tools | search_character | amount | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_character | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_character | term | e81d2033587b90aeffff40f077fcf8a5bf879237b90b965cde6c861110784b3f |
| tools | search_manga | description | 625bc19214c8d8e964ce6c16359cceeddb9273778812c3d9471bfceb43bd50fb |
| tools | search_manga | amount | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_manga | filter | dc9449e93ab03147e11e4bfddaa044261e4e1e9daa5d903de4e84157cfeabe36 |
| tools | search_manga | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_manga | term | c027e49fb27eed94eab51e2f538a9d604e5da863ea6bc463251eb8bb4e997efe |
| tools | search_staff | description | c17135fe9313def830661391a5d2fdce743ac45e68e7092281319307460dc278 |
| tools | search_staff | amount | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_staff | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_staff | term | 5172d58e00b5d1b3ff27000d9004345232286e9ecddc1e873ce4c4fe66110eee |
| tools | search_studio | description | 269bd7055237ca621a27ae2bc551a8bac7b834d17a2fbfefff360bda541f8a81 |
| tools | search_studio | amount | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_studio | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_studio | term | 019c4f84eaf8442977bedc6e2f51480c969c8dba76b73d1941b9be26f7c145f3 |
| tools | search_user | description | 3b86c3374c917c5e831b4d0548b1e7309e19f8d05e76b150f9f8943bbf04aba0 |
| tools | search_user | amount | 97c44f113abc9400ee9dc01556628e652257cd9e0d19e5749b05fa14e0ac8419 |
| tools | search_user | page | e9c046b9e5397d63a6112bf628f03e2e5177673e80c21ddef8cc80baa4cda479 |
| tools | search_user | term | ecf5f8bdcd897ee6f2410844d6cc8482f33354b67c404677d1e119514684f9d7 |
| tools | update_list_entry | description | 956f0071c81d4f34921ad16b07c4113e07bbb75c7df99c1c1b1ede3da959989c |
| tools | update_list_entry | id | ccf996980d4e6b70ec1583f5d255c19276255ba5ef4a020b958e7b0f28c352ac |
| tools | update_list_entry | options | 03603e2b3e3a692d2e225e2afddd31d0ff4f325b504a90502f6047a10077b8a3 |
| tools | update_user | description | 5fd4dc93e55d9906968cc239b15efca05372ff78127c504527a36a0571cf1403 |
| tools | update_user | options | c8c24f5214a96cf9d8245c01d143dd57be0cf065c5b0583e65a806ec33e628a5 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
