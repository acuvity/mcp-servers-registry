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


# What is mcp-server-elevenlabs?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-elevenlabs/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-elevenlabs/0.3.0?logo=docker&logoColor=fff&label=0.3.0)](https://hub.docker.com/r/acuvity/mcp-server-elevenlabs)
[![PyPI](https://img.shields.io/badge/0.3.0-3775A9?logo=pypi&logoColor=fff&label=elevenlabs-mcp)](https://github.com/elevenlabs/elevenlabs-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-elevenlabs&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ELEVENLABS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-elevenlabs%3A0.3.0%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Enables voice synthesis and audio processing via APIs.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from elevenlabs-mcp original [sources](https://github.com/elevenlabs/elevenlabs-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-elevenlabs/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/charts/mcp-server-elevenlabs/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure elevenlabs-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/charts/mcp-server-elevenlabs#minibridge) for Helm charts).

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active.


# Quick reference

**Maintained by**:
  - [the Acuvity team](support@acuvity.ai) for packaging
  - [ Jacek Duszenko <jacek@elevenlabs.io>, Paul Asjes <paul.asjes@elevenlabs.io>, Louis Jordan <louis@elevenlabs.io>, Luke Harries <luke@elevenlabs.io> ](https://github.com/elevenlabs/elevenlabs-mcp) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ elevenlabs-mcp ](https://github.com/elevenlabs/elevenlabs-mcp)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ elevenlabs-mcp ](https://github.com/elevenlabs/elevenlabs-mcp)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/charts/mcp-server-elevenlabs)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-elevenlabs/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.3.0`

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
  - `ELEVENLABS_API_KEY` secret to be set as secrets.ELEVENLABS_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install mcp-server-elevenlabs oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-elevenlabs oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-elevenlabs
```

From there your MCP server mcp-server-elevenlabs will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-elevenlabs` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-elevenlabs
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-elevenlabs` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-elevenlabs oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-elevenlabs oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-elevenlabs oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-elevenlabs oci://docker.io/acuvity/mcp-server-elevenlabs --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (19)
<details>
<summary>text_to_speech</summary>

**Description**:

```
Convert text to speech with a given voice and save the output audio file to a given directory.
    Directory is optional, if not provided, the output file will be saved to $HOME/Desktop.
    Only one of voice_id or voice_name can be provided. If none are provided, the default voice will be used.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.

     Args:
        text (str): The text to convert to speech.
        voice_name (str, optional): The name of the voice to use.
        stability (float, optional): Stability of the generated audio. Determines how stable the voice is and the randomness between each generation. Lower values introduce broader emotional range for the voice. Higher values can result in a monotonous voice with limited emotion. Range is 0 to 1.
        similarity_boost (float, optional): Similarity boost of the generated audio. Determines how closely the AI should adhere to the original voice when attempting to replicate it. Range is 0 to 1.
        style (float, optional): Style of the generated audio. Determines the style exaggeration of the voice. This setting attempts to amplify the style of the original speaker. It does consume additional computational resources and might increase latency if set to anything other than 0. Range is 0 to 1.
        use_speaker_boost (bool, optional): Use speaker boost of the generated audio. This setting boosts the similarity to the original speaker. Using this setting requires a slightly higher computational load, which in turn increases latency.
        speed (float, optional): Speed of the generated audio. Controls the speed of the generated speech. Values range from 0.7 to 1.2, with 1.0 being the default speed. Lower values create slower, more deliberate speech while higher values produce faster-paced speech. Extreme values can impact the quality of the generated speech. Range is 0.7 to 1.2.
        output_directory (str, optional): Directory where files should be saved.
            Defaults to $HOME/Desktop if not provided.
        language: ISO 639-1 language code for the voice.
        output_format (str, optional): Output format of the generated audio. Formatted as codec_sample_rate_bitrate. So an mp3 with 22.05kHz sample rate at 32kbs is represented as mp3_22050_32. MP3 with 192kbps bitrate requires you to be subscribed to Creator tier or above. PCM with 44.1kHz sample rate requires you to be subscribed to Pro tier or above. Note that the μ-law format (sometimes written mu-law, often approximated as u-law) is commonly used for Twilio audio inputs.
            Defaults to "mp3_44100_128". Must be one of:
            mp3_22050_32
            mp3_44100_32
            mp3_44100_64
            mp3_44100_96
            mp3_44100_128
            mp3_44100_192
            pcm_8000
            pcm_16000
            pcm_22050
            pcm_24000
            pcm_44100
            ulaw_8000
            alaw_8000
            opus_48000_32
            opus_48000_64
            opus_48000_96
            opus_48000_128
            opus_48000_192

    Returns:
        Text content with the path to the output file and name of the voice used.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| language | string | not set | No
| output_directory | any | not set | No
| output_format | string | not set | No
| similarity_boost | number | not set | No
| speed | number | not set | No
| stability | number | not set | No
| style | number | not set | No
| text | string | not set | Yes
| use_speaker_boost | boolean | not set | No
| voice_id | any | not set | No
| voice_name | any | not set | No
</details>
<details>
<summary>speech_to_text</summary>

**Description**:

```
Transcribe speech from an audio file and either save the output text file to a given directory or return the text to the client directly.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.

    Args:
        file_path: Path to the audio file to transcribe
        language_code: ISO 639-3 language code for transcription (default: "eng" for English)
        diarize: Whether to diarize the audio file. If True, which speaker is currently speaking will be annotated in the transcription.
        save_transcript_to_file: Whether to save the transcript to a file.
        return_transcript_to_client_directly: Whether to return the transcript to the client directly.
        output_directory: Directory where files should be saved.
            Defaults to $HOME/Desktop if not provided.

    Returns:
        TextContent containing the transcription. If save_transcript_to_file is True, the transcription will be saved to a file in the output directory.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| diarize | boolean | not set | No
| input_file_path | string | not set | Yes
| language_code | string | not set | No
| output_directory | any | not set | No
| return_transcript_to_client_directly | boolean | not set | No
| save_transcript_to_file | boolean | not set | No
</details>
<details>
<summary>text_to_sound_effects</summary>

**Description**:

```
Convert text description of a sound effect to sound effect with a given duration and save the output audio file to a given directory.
    Directory is optional, if not provided, the output file will be saved to $HOME/Desktop.
    Duration must be between 0.5 and 5 seconds.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.

    Args:
        text: Text description of the sound effect
        duration_seconds: Duration of the sound effect in seconds
        output_directory: Directory where files should be saved.
            Defaults to $HOME/Desktop if not provided.
        output_format (str, optional): Output format of the generated audio. Formatted as codec_sample_rate_bitrate. So an mp3 with 22.05kHz sample rate at 32kbs is represented as mp3_22050_32. MP3 with 192kbps bitrate requires you to be subscribed to Creator tier or above. PCM with 44.1kHz sample rate requires you to be subscribed to Pro tier or above. Note that the μ-law format (sometimes written mu-law, often approximated as u-law) is commonly used for Twilio audio inputs.
            Defaults to "mp3_44100_128". Must be one of:
            mp3_22050_32
            mp3_44100_32
            mp3_44100_64
            mp3_44100_96
            mp3_44100_128
            mp3_44100_192
            pcm_8000
            pcm_16000
            pcm_22050
            pcm_24000
            pcm_44100
            ulaw_8000
            alaw_8000
            opus_48000_32
            opus_48000_64
            opus_48000_96
            opus_48000_128
            opus_48000_192
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration_seconds | number | not set | No
| output_directory | any | not set | No
| output_format | string | not set | No
| text | string | not set | Yes
</details>
<details>
<summary>search_voices</summary>

**Description**:

```

    Search for existing voices, a voice that has already been added to the user's ElevenLabs voice library.
    Searches in name, description, labels and category.

    Args:
        search: Search term to filter voices by. Searches in name, description, labels and category.
        sort: Which field to sort by. `created_at_unix` might not be available for older voices.
        sort_direction: Sort order, either ascending or descending.

    Returns:
        List of voices that match the search criteria.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| search | any | not set | No
| sort | string | not set | No
| sort_direction | string | not set | No
</details>
<details>
<summary>get_voice</summary>

**Description**:

```
Get details of a specific voice
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| voice_id | string | not set | Yes
</details>
<details>
<summary>voice_clone</summary>

**Description**:

```
Clone a voice using provided audio files.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| files | array | not set | Yes
| name | string | not set | Yes
</details>
<details>
<summary>isolate_audio</summary>

**Description**:

```
Isolate audio from a file and save the output audio file to a given directory.
    Directory is optional, if not provided, the output file will be saved to $HOME/Desktop.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| input_file_path | string | not set | Yes
| output_directory | any | not set | No
</details>
<details>
<summary>check_subscription</summary>

**Description**:

```
Check the current subscription status. Could be used to measure the usage of the API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_agent</summary>

**Description**:

```
Create a conversational AI agent with custom configuration.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.

    Args:
        name: Name of the agent
        first_message: First message the agent will say i.e. "Hi, how can I help you today?"
        system_prompt: System prompt for the agent
        voice_id: ID of the voice to use for the agent
        language: ISO 639-1 language code for the agent
        llm: LLM to use for the agent
        temperature: Temperature for the agent. The lower the temperature, the more deterministic the agent's responses will be. Range is 0 to 1.
        max_tokens: Maximum number of tokens to generate.
        asr_quality: Quality of the ASR. `high` or `low`.
        model_id: ID of the ElevenLabsmodel to use for the agent.
        optimize_streaming_latency: Optimize streaming latency. Range is 0 to 4.
        stability: Stability for the agent. Range is 0 to 1.
        similarity_boost: Similarity boost for the agent. Range is 0 to 1.
        turn_timeout: Timeout for the agent to respond in seconds. Defaults to 7 seconds.
        max_duration_seconds: Maximum duration of a conversation in seconds. Defaults to 600 seconds (10 minutes).
        record_voice: Whether to record the agent's voice.
        retention_days: Number of days to retain the agent's data.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| asr_quality | string | not set | No
| first_message | string | not set | Yes
| language | string | not set | No
| llm | string | not set | No
| max_duration_seconds | integer | not set | No
| max_tokens | any | not set | No
| model_id | string | not set | No
| name | string | not set | Yes
| optimize_streaming_latency | integer | not set | No
| record_voice | boolean | not set | No
| retention_days | integer | not set | No
| similarity_boost | number | not set | No
| stability | number | not set | No
| system_prompt | string | not set | Yes
| temperature | number | not set | No
| turn_timeout | integer | not set | No
| voice_id | any | not set | No
</details>
<details>
<summary>add_knowledge_base_to_agent</summary>

**Description**:

```
Add a knowledge base to ElevenLabs workspace. Allowed types are epub, pdf, docx, txt, html.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.

    Args:
        agent_id: ID of the agent to add the knowledge base to.
        knowledge_base_name: Name of the knowledge base.
        url: URL of the knowledge base.
        input_file_path: Path to the file to add to the knowledge base.
        text: Text to add to the knowledge base.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| agent_id | string | not set | Yes
| input_file_path | any | not set | No
| knowledge_base_name | string | not set | Yes
| text | any | not set | No
| url | any | not set | No
</details>
<details>
<summary>list_agents</summary>

**Description**:

```
List all available conversational AI agents
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_agent</summary>

**Description**:

```
Get details about a specific conversational AI agent
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| agent_id | string | not set | Yes
</details>
<details>
<summary>speech_to_speech</summary>

**Description**:

```
Transform audio from one voice to another using provided audio files.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| input_file_path | string | not set | Yes
| output_directory | any | not set | No
| voice_name | string | not set | No
</details>
<details>
<summary>text_to_voice</summary>

**Description**:

```
Create voice previews from a text prompt. Creates three previews with slight variations. Saves the previews to a given directory. If no text is provided, the tool will auto-generate text.

    Voice preview files are saved as: voice_design_(generated_voice_id)_(timestamp).mp3

    Example file name: voice_design_Ya2J5uIa5Pq14DNPsbC1_20250403_164949.mp3

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| output_directory | any | not set | No
| text | any | not set | No
| voice_description | string | not set | Yes
</details>
<details>
<summary>create_voice_from_preview</summary>

**Description**:

```
Add a generated voice to the voice library. Uses the voice ID from the `text_to_voice` tool.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| generated_voice_id | string | not set | Yes
| voice_description | string | not set | Yes
| voice_name | string | not set | Yes
</details>
<details>
<summary>make_outbound_call</summary>

**Description**:

```
Make an outbound call via Twilio using an ElevenLabs agent.

    ⚠️ COST WARNING: This tool makes an API call to ElevenLabs which may incur costs. Only use when explicitly requested by the user.

    Args:
        agent_id: The ID of the agent that will handle the call
        agent_phone_number_id: The ID of the phone number to use for the call
        to_number: The phone number to call (E.164 format: +1xxxxxxxxxx)

    Returns:
        TextContent containing information about the call
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| agent_id | string | not set | Yes
| agent_phone_number_id | string | not set | Yes
| to_number | string | not set | Yes
</details>
<details>
<summary>search_voice_library</summary>

**Description**:

```
Search for a voice across the entire ElevenLabs voice library.

    Args:
        page: Page number to return (0-indexed)
        page_size: Number of voices to return per page (1-100)
        search: Search term to filter voices by

    Returns:
        TextContent containing information about the shared voices
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | integer | not set | No
| page_size | integer | not set | No
| search | any | not set | No
</details>
<details>
<summary>list_phone_numbers</summary>

**Description**:

```
List all phone numbers associated with the ElevenLabs account
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>play_audio</summary>

**Description**:

```
Play an audio file. Supports WAV and MP3 formats.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| input_file_path | string | not set | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_knowledge_base_to_agent | description | 91f9e1324f9247ab9d29e6fd2ae071e9178f243ecb15b906249414fc19bdc059 |
| tools | check_subscription | description | 944f896d7183752af29b2030d36de77589e7bd1e624042bc1d30de11cc7bea8b |
| tools | create_agent | description | c3b330160492f76db976c1ef738c49fc62da33968bf1df068b3eb71129138bcc |
| tools | create_voice_from_preview | description | ba761d6a2b112b520cf8463bedd5da0b841720a48149e4ab0ec93fa2cd5afefa |
| tools | get_agent | description | 4607c36f84519b2172276551d4c64b55a326d4cd53cbff83d59f427a7c550c4c |
| tools | get_voice | description | 511ba8e3f9550db8dadc8561cab48730d25684f72069faf2461596a29c60ed79 |
| tools | isolate_audio | description | ecfd2b1b452ffd4492e23ff4680350ebe5ebed530e774ee25f9b8b5f20e71d04 |
| tools | list_agents | description | c86fa37dac2e1f0c6d6ba4784faed7c330e907453c299a60992c8af4bef9b665 |
| tools | list_phone_numbers | description | cced243ecf3b23b4b992847064779c30f844e6cb3f64618a53c72ce1f0ca1622 |
| tools | make_outbound_call | description | d8e7480101ea19cfa95141215d12f5cdc5f87d75fc20c0869a18b3fb02f09cc8 |
| tools | play_audio | description | ead1307454561355d22fb5546a6124de7899e129b244b565faac3072021fb3fa |
| tools | search_voice_library | description | 4a3cfacd422e0dd663ef421e72ccc80afcec75279c13422e884d7c79114a2a6d |
| tools | search_voices | description | 9546f9a40cc3db7af9115a8edb8afeda0fb34152df1be35b7906137627dc3af4 |
| tools | speech_to_speech | description | 2d83a2662e59f363cd80d7d75803c8c5a2eef9a91356afccb16db9b963bae4eb |
| tools | speech_to_text | description | aa8e90a21934f14abfc93728f02d72430eb266fe00889ad75a4ba4e989eb720d |
| tools | text_to_sound_effects | description | 9fe63c424ebbf0133561c9bdb0ff941157b9b84b34680ce15764e4dccc45f931 |
| tools | text_to_speech | description | e35a9e71722f2a738bba2d0db9d3d111de584a979157de39da236df40f47a1dd |
| tools | text_to_voice | description | 5a7eb20b8fce7560f39b99ab64bfea14a409f8ed0c1afe9529eb11d903cab523 |
| tools | voice_clone | description | 7fe2970dc4ad4f9494d42122253c53f17114f8a0ee1015422892d785552cb48a |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
