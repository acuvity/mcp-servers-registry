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


# What is mcp-server-cartesia?
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-cartesia/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-cartesia/0.1.6?logo=docker&logoColor=fff&label=0.1.6)](https://hub.docker.com/r/acuvity/mcp-server-cartesia)
[![PyPI](https://img.shields.io/badge/0.1.6-3775A9?logo=pypi&logoColor=fff&label=cartesia-mcp)](https://github.com/cartesia-ai/cartesia-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-cartesia/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-cartesia&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22output%3A%2Foutput%22%2C%22-e%22%2C%22CARTESIA_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-cartesia%3A0.1.6%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connect to Cartesia voice platform for text-to-speech and voice cloning

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from cartesia-mcp original [sources](https://github.com/cartesia-ai/cartesia-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-cartesia/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/charts/mcp-server-cartesia/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure cartesia-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
  - [ Author ](https://github.com/cartesia-ai/cartesia-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ cartesia-mcp ](https://github.com/cartesia-ai/cartesia-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ cartesia-mcp ](https://github.com/cartesia-ai/cartesia-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/charts/mcp-server-cartesia)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.6`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-cartesia:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-cartesia:1.0.0-0.1.6`

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
  - `CARTESIA_API_KEY` secret to be set as secrets.CARTESIA_API_KEY either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `OUTPUT_DIRECTORY="/output"` environment variable can be changed with `env.OUTPUT_DIRECTORY="/output"`

# How to install


Install will helm

```console
helm install mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-cartesia
```

From there your MCP server mcp-server-cartesia will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-cartesia` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-cartesia
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-cartesia` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>text_to_speech</summary>

**Description**:

```

        Parameters
        ----------
        transcript : str

        voice : TtsRequestVoiceSpecifierParams

        output_format : OutputFormatParams

        model_id : str
            The ID of the model to use for the generation. See [Models](/build-with-cartesia/models) for available models.

        language : typing.Optional[SupportedLanguage]

        duration : typing.Optional[float]
            The maximum duration of the audio in seconds. You do not usually need to specify this.
            If the duration is not appropriate for the length of the transcript, the output audio may be truncated.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration. You can pass in configuration such as `chunk_size`, and more to customize the request and response.

          
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration | any | not set | No
| language | any | not set | No
| model_id | any | not set | No
| output_format | any | not set | Yes
| request_options | any | not set | No
| transcript | string | not set | Yes
| voice | any | not set | Yes
</details>
<details>
<summary>infill</summary>

**Description**:

```

        Generate audio that smoothly connects two existing audio segments. This is useful for inserting new speech between existing speech segments while maintaining natural transitions.

        **The cost is 1 credit per character of the infill text plus a fixed cost of 300 credits.**

        Infilling is only available on `sonic-2` at this time.

        At least one of `left_audio` or `right_audio` must be provided.

        As with all generative models, there's some inherent variability, but here's some tips we recommend to get the best results from infill:
        - Use longer infill transcripts
          - This gives the model more flexibility to adapt to the rest of the audio
        - Target natural pauses in the audio when deciding where to clip
          - This means you don't need word-level timestamps to be as precise
        - Clip right up to the start and end of the audio segment you want infilled, keeping as much silence in the left/right audio segments as possible
          - This helps the model generate more natural transitions

        Parameters
        ----------
        language : str
            The language of the transcript

        transcript : str
            The infill text to generate

        voice_id : str
            The ID of the voice to use for generating audio

        output_format_container : OutputFormatContainer
            The format of the output audio

        output_format_sample_rate : int
            The sample rate of the output audio

        output_format_encoding : typing.Optional[RawEncoding]
            Required for `raw` and `wav` containers.

        output_format_bit_rate : typing.Optional[int]
            Required for `mp3` containers.

        left_file_path : typing.Optional[str]
            The absolute path to the left audio file to infill.

        right_file_path : typing.Optional[str]
            The absolute path to the right audio file to infill.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration. You can pass in configuration such as `chunk_size`, and more to customize the request and response.
          
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| language | any | not set | Yes
| left_audio_file_path | any | not set | No
| output_format_bit_rate | any | not set | No
| output_format_container | any | not set | Yes
| output_format_encoding | any | not set | No
| output_format_sample_rate | integer | not set | Yes
| request_options | any | not set | No
| right_audio_file_path | any | not set | No
| transcript | string | not set | Yes
| voice_id | string | not set | Yes
</details>
<details>
<summary>voice_change</summary>

**Description**:

```

        Takes an audio file of speech, and returns an audio file of speech spoken with the same intonation, but with a different voice.

        Parameters
        ----------
        file_path : str
            The absolute path to the audio file to change.

        voice_id : str

        output_format_container : OutputFormatContainer

        output_format_sample_rate : int

        output_format_encoding : typing.Optional[RawEncoding]
            Required for `raw` and `wav` containers.

        output_format_bit_rate : typing.Optional[int]
            Required for `mp3` containers.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration. You can pass in configuration such as `chunk_size`, and more to customize the request and response.
          
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | not set | Yes
| output_format_bit_rate | any | not set | No
| output_format_container | any | not set | Yes
| output_format_encoding | any | not set | No
| output_format_sample_rate | integer | not set | Yes
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>localize_voice</summary>

**Description**:

```

        Create a new voice from an existing voice localized to a new language and dialect.

        Parameters
        ----------
        voice_id : str
            The ID of the voice to localize.

        name : str
            The name of the new localized voice.

        description : str
            The description of the new localized voice.

        language : SupportedLanguage

        original_speaker_gender : Gender

        dialect : typing.Optional[LocalizeDialectParams]

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | Yes
| dialect | any | not set | No
| language | any | not set | Yes
| name | string | not set | Yes
| original_speaker_gender | any | not set | Yes
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>delete_voice</summary>

**Description**:

```

        Parameters
        ----------
        voice_id : str
            The ID of the voice to delete.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>get_voice</summary>

**Description**:

```

        Parameters
        ----------
        voice_id : str
            The ID of the voice to get.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>update_voice</summary>

**Description**:

```

        Parameters
        ----------
        id : VoiceId

        name : str
            The name of the voice.

        description : str
            The description of the voice.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | Yes
| name | string | not set | Yes
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>clone_voice</summary>

**Description**:

```

        Clone a voice from an audio clip. This endpoint has two modes, stability and similarity.

        Similarity mode clones are more similar to the source clip, but may reproduce background noise. For these, use an audio clip about 5 seconds long.

        Stability mode clones are more stable, but may not sound as similar to the source clip. For these, use an audio clip 10-20 seconds long.

        Parameters
        ----------
        file_path : str
            The absolute path to the audio file to clone.

        name : str
            The name of the voice.

        language : SupportedLanguage
            The language of the voice.

        mode : CloneMode
            Tradeoff between similarity and stability. Similarity clones sound more like the source clip, but may reproduce background noise. Stability clones always sound like a studio recording, but may not sound as similar to the source clip.

        description : typing.Optional[str]
            A description for the voice.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| file_path | string | not set | Yes
| language | any | not set | Yes
| mode | any | not set | Yes
| name | string | not set | Yes
| request_options | any | not set | No
</details>
<details>
<summary>list_voices</summary>

**Description**:

```

        Parameters
        ----------
        limit : typing.Optional[int]
            The number of Voices to return per page, ranging between 1 and 100.

        starting_after : typing.Optional[str]
            A cursor to use in pagination. `starting_after` is a Voice ID that defines your
            place in the list. For example, if you make a /voices request and receive 100
            objects, ending with `voice_abc123`, your subsequent call can include
            `starting_after=voice_abc123` to fetch the next page of the list.

        ending_before : typing.Optional[str]
            A cursor to use in pagination. `ending_before` is a Voice ID that defines your
            place in the list. For example, if you make a /voices request and receive 100
            objects, starting with `voice_abc123`, your subsequent call can include
            `ending_before=voice_abc123` to fetch the previous page of the list.

        is_owner : typing.Optional[bool]
            Whether to only return voices owned by the current user.

        is_starred : typing.Optional[bool]
            Whether to only return starred voices.

        gender : typing.Optional[GenderPresentation]
            The gender presentation of the voices to return.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ending_before | any | not set | No
| gender | any | not set | No
| is_owner | any | not set | No
| is_starred | any | not set | No
| limit | any | not set | No
| request_options | any | not set | No
| starting_after | any | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | clone_voice | description | d000d5874fa1f3b8525a42b7e66ab7e38560e8ced5361814b7fdc3904ae3e7ed |
| tools | delete_voice | description | a0ddee9cbee01aa10047230f4d6944514cfad67ad4d11d3aadac25320ca6fd90 |
| tools | get_voice | description | 94488dca63e5587cd286beea05f0be145d141300c655b1b58f9d239951b0984b |
| tools | infill | description | 6db8e92e803cc4c1a4ffda8329225ad8be2ec02b64997a5353985245eeac1974 |
| tools | list_voices | description | 89485b7982e58bca0d0f9bd7a4049d676ac8c96ca769c4ca7a5c059740793e76 |
| tools | localize_voice | description | 89aba570ca1e43fc663065e5f595e55c8050e9e18ea5606f65d2b224c9fbf1c1 |
| tools | text_to_speech | description | dbe87dd215d9e19724d4fc94a30b872aed0251a7968c4585c82a9ed3be9393f6 |
| tools | update_voice | description | e31c18bb843c2924b82319aec98f631aca027d7c16d29ca311d65f034d6b6d2f |
| tools | voice_change | description | 81dada3df7b8aa51eb3ba974ebed8fc71d329f22158bb27346963c8333036d33 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
