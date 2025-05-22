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


# What is mcp-server-fibery?

[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-fibery/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fibery/0.1.3?logo=docker&logoColor=fff&label=0.1.3)](https://hub.docker.com/r/acuvity/mcp-server-fibery)
[![PyPI](https://img.shields.io/badge/0.1.3-3775A9?logo=pypi&logoColor=fff&label=fibery-mcp-server)](https://github.com/Fibery-inc/fibery-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fibery/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-fibery&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22FIBERY_API_TOKEN%22%2C%22-e%22%2C%22FIBERY_HOST%22%2C%22docker.io%2Facuvity%2Fmcp-server-fibery%3A0.1.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates Fibery workspace with LLMs using natural language queries.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from fibery-mcp-server original [sources](https://github.com/Fibery-inc/fibery-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-fibery/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/charts/mcp-server-fibery/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure fibery-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/Fibery-inc/fibery-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ fibery-mcp-server ](https://github.com/Fibery-inc/fibery-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ fibery-mcp-server ](https://github.com/Fibery-inc/fibery-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/charts/mcp-server-fibery)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-fibery/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.3`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-fibery:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-fibery:1.0.0-0.1.3`

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
  - `FIBERY_API_TOKEN` secret to be set as secrets.FIBERY_API_TOKEN either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `FIBERY_HOST` environment variable to be set by env.FIBERY_HOST

# How to install


Install will helm

```console
helm install mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-fibery
```

From there your MCP server mcp-server-fibery will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-fibery` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-fibery
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-fibery` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-fibery oci://docker.io/acuvity/mcp-server-fibery --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>current_date</summary>

**Description**:

```
Get today's date in ISO 8601 format (YYYY-mm-dd.HH:MM:SS.000Z)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>list_databases</summary>

**Description**:

```
Get list of all databases (their names) in user's Fibery workspace (schema)
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>describe_database</summary>

**Description**:

```
Get list of all fields (in format of 'Title [name]: type') in the selected Fibery database and for all related databases.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database_name | string | Database name as defined in Fibery schema | Yes
</details>
<details>
<summary>query_database</summary>

**Description**:

```
Run any Fibery API command. This gives tremendous flexibility, but requires a bit of experience with the low-level Fibery API. In case query succeeded, return value contains a list of records with fields you specified in select. If request failed, will return detailed error message.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: What newly created Features do we have for the past 2 months?
Tool use:
{
    "q_from": "Dev/Feature",
    "q_select": {
        "Name": ["Dev/Name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"]
    },
    "q_where": [">", ["fibery/creation-date"], "$twoMonthsAgo"],
    "q_order_by": {"fibery/creation-date": "q/desc"},
    "q_limit": 100,
    "q_offset": 0,
    "q_params": {
        $twoMonthsAgo: "2025-01-16T00:00:00.000Z"
    }
}

Query: What Admin Tasks for the past week are Approval or Done?
Tool use:
{
    "q_from": "Administrative/Admin Task",
    "q_select": {
        "Name": ["Administrative/Name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"],
        "State": ["workflow/state", "enum/name"]
    },
    "q_where": [
        "q/and", # satisfy time AND states condition
            [">", ["fibery/creation-date"], "$oneWeekAgo"],
            [
                "q/or", # nested or, since entity can be in either of these states
                    ["=", ["workflow/state", "enum/name"], "$state1"],
                    ["=", ["workflow/state", "enum/name"], "$state2"]
            ]
    ],
    "q_order_by": {"fibery/creation-date": "q/desc"},
    "q_limit": 100,
    "q_offset": 0,
    "q_params": { # notice that parameters used in "where" are always passed in params!
        $oneWeekAgo: "2025-03-07T00:00:00.000Z",
        $state1: "Approval",
        $state2: "Done"
    }
}

Query: What Admin Tasks for the past week are Approval or Done?
Tool use:
{
    "q_from": "Administrative/Admin Task",
    "q_select": {
        "State": ["workflow/state", "enum/name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"],
        "Modification Date": ["fibery/modification-date"],
        "Deadline": ["Administrative/Deadline"],
        "Group": ["Administrative/Group", "Administrative/name"],
        "Name": ["Administrative/Name"],
        "Priority": ["Administrative/Priority_Administrative/Admin Task", "enum/name"]
    },
    "q_where": ["!=", ["workflow/state", "workflow/Final"], "$stateType"], # Administrative/Admin Task is not "Finished" yet
    "q_order_by": {"fibery/creation-date": "q/desc"},
    "q_limit": 100,
    "q_offset": 0,
    "q_params: {
        "$stateType": true
    }
}

Query: Summarize acc contacts with public id 1.
Tool use:
{
    "q_from": "Accounting/Acc Contacts",
    "q_select": {
        "Name": ["Accounting/Name"],
        "Public Id": ["fibery/public-id"],
        "Creation Date": ["fibery/creation-date"],
        "Description": ["Accounting/Description"]
    },
    "q_where": ["=", ["fibery/public-id"], "$publicId"],
    "q_limit": 1,
    "q_params": {
        $publicId: "1",
    }
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| q_from | string | Specifies the entity type in "Space/Type" format (e.g., "Product Management/feature", "Product Management/Insight") | Yes
| q_limit | integer | Number of results per page (defaults to 50). Maximum allowed value is 1000 | No
| q_offset | integer | Number of results to skip. Mainly used in combination with limit and orderBy for pagination. | No
| q_order_by | object | List of sorting criteria in format {"field1": "q/asc", "field2": "q/desc"} | No
| q_params | object | Dictionary of parameter values referenced in where using "$param" syntax. For example, {$fromDate: "2025-01-01"} | No
| q_select | object | Defines what fields to retrieve. Can include:
  - Primitive fields using format {"AliasName": "FieldName"} (i.e. {"Name": "Product Management/Name"})
  - Related entity fields using format {"AliasName": ["Related entity", "related entity field"]} (i.e. {"Secret": ["Product Management/Description", "Collaboration~Documents/secret"]}). Careful, does not work with 1-* connection!
To work with 1-* relationships, you can use sub-querying: {"AliasName": {"q/from": "Related type", "q/select": {"AliasName 2": "fibery/id"}, "q/limit": 50}}
AliasName can be of any arbitrary value. | Yes
| q_where | object | Filter conditions in format [operator, [field_path], value] or ["q/and"|"q/or", ...conditions]. Common usages:
- Simple comparison: ["=", ["field", "path"], "$param"]. You cannot pass value of $param directly in where clause. Use params object instead. Pay really close attention to it as it is not common practice, but that's how it works in our case!
- Logical combinations: ["q/and", ["<", ["field1"], "$param1"], ["=", ["field2"], "$param2"]]
- Available operators: =, !=, <, <=, >, >=, q/contains, q/not-contains, q/in, q/not-in | No
</details>
<details>
<summary>create_entity</summary>

**Description**:

```
Create Fibery entity with specified fields.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: Create a feature
Tool use:
{
    "database": "Product Management/Feature",
    "entity": {
        "Product Management/Name": "New Feature",
        "Product Management/Description": "Description of the new feature",
        "workflow/state": "To Do" # notice how we use string literal for workflow field here
    }
}
In case of successful execution, you will get a link to created entity. Make sure to give that link to the user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Fibery Database where to create an entity. | Yes
| entity | object | Dictionary that defines what fields to set in format {"FieldName": value} (i.e. {"Product Management/Name": "My new entity"}). | Yes
</details>
<details>
<summary>create_entities_batch</summary>

**Description**:

```
Create multiple Fibery entities at once with specified fields.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: Create some features
Tool use:
{
    "database": "Product Management/Feature",
    "entities": [
        {
            "Product Management/Name": "New Feature 1",
            "Product Management/Description": "Description of the new feature 1",
            "workflow/state": "To Do" # notice how we use string literal for workflow field here
        },
        {
            "Product Management/Name": "New Feature 2",
            "Product Management/Description": "Description of the new feature 2",
            "workflow/state": "In Progress" # notice how we use string literal for workflow field here
        }
    ]
}
In case of successful execution, you will get links to created entities. Make sure to give the links to the user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Fibery Database where entities will be created. | Yes
| entities | object | List of dictionaries that define what fields to set in format [{"FieldName": value}] (i.e. [{"Product Management/Name": "My new entity"}]). | Yes
</details>
<details>
<summary>update_entity</summary>

**Description**:

```
Update Fibery entity with specified fields.
Examples (note, that these databases are non-existent, use databases only from user's schema!):
Query: Update a feature we talked about
Tool use:
{
    "database": "Product Management/Feature",
    "entity": {
        "fibery/id": "12345678-1234-5678-1234-567812345678",
        "Product Management/Name": "New Feature 2",
        "Product Management/Description": {"append": true, "content": "Notes: some notes"},
        "workflow/state": "In Progress"
    }
}
In case of successful execution, you will get a link to updated entity. Make sure to give that link to the user.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| database | string | Fibery Database where to update an entity. | Yes
| entity | object | Dictionary that defines what fields to set in format {"FieldName": value} (i.e. {"Product Management/Name": "My new entity"}).
Exception are document fields. For them you must specify append (boolean, whether to append to current content) and content itself: {"Product Management/Description": {"append": true, "content": "Additional info"}} | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_entities_batch | description | c6f857d3c26c430f3384b261e07c2ce8a40461d69c87ad70f68e2f1ce412400e |
| tools | create_entities_batch | database | 39755006c2083326d7be886a44b1b500f3d940d19045308865d79778927aa850 |
| tools | create_entities_batch | entities | aec365d872c358a769b5ab1ff9296903a439acb867a79146472276537fb3f47c |
| tools | create_entity | description | 4f0d98b2969f712d23cfb26ea25a3cc57d5a469193d44ca549ec25ac88ddf258 |
| tools | create_entity | database | 1c63dc9e3bd2f976b1bfda7c3717f502630a6350e4aba4f50fc5dab2dde0de2a |
| tools | create_entity | entity | fcabe74fe31032d7633f2dd334a10c65d58306c1dd4e180379c5deb42cc57781 |
| tools | current_date | description | 9317cd62334b10a1e0fbd0c93e08392dfee2c80efeb713d9ae35f2f4acaabda4 |
| tools | describe_database | description | dc90cb89fb73651dd904c01892c987de818b462e502d9bd7285a262b3e4bf47c |
| tools | describe_database | database_name | da77a6362dc6213860767ae59face55d4bb3a5daa170e1035c98a933c7c40597 |
| tools | list_databases | description | 8651205b8fe64666d30925db3bd8b0cc41647b106c220aaa3de1dc7b7a893d20 |
| tools | query_database | description | a5d75f5125a10f03de4ee4e8c275c2c5f451563ff21c0f2ef5d57404a390fe66 |
| tools | query_database | q_from | 53a846dbac5b74f897204f60d0150e698c320b33651518eecf90a6bc2c36b8ef |
| tools | query_database | q_limit | 1c9265f863e3f607bc79971e65107a114165dcfd66299a7b675d29b5c454d145 |
| tools | query_database | q_offset | 469a88dc989a485be5cb148dc492667da857259280084542915660d60fec02b3 |
| tools | query_database | q_order_by | 4076133f1c17635f9e2562f63d15eed0f67f437d6e73bb661aac31ea21497948 |
| tools | query_database | q_params | eefc09ae29d168d8e72ce3d4b28178b0f57192caa17b86c4321bd781d0927290 |
| tools | query_database | q_select | 47ef35a67e17868154e6268c8c53f604ab594c1a63b646881cb8a0bce8d81ce7 |
| tools | query_database | q_where | cc7a22d2d86cab4962b1dc336eaee161bf148749ad450e6137e53ce393c36146 |
| tools | update_entity | description | de2dbdcda08f5527eaa3226a59c7da409138d3c0dacee9e7907b5f1334f36f39 |
| tools | update_entity | database | 5f77c9ecd12602e71c8f30d3cf7c8ec3ec94cb6c107d08532b53e4b40ae5fe41 |
| tools | update_entity | entity | b7809c3e6e79f633abc36f03f943063c5390b870b0426b21795445aa9eea5d49 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
