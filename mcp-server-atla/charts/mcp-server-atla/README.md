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


# What is mcp-server-atla?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-atla/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-atla/0.1.2?logo=docker&logoColor=fff&label=0.1.2)](https://hub.docker.com/r/acuvity/mcp-server-atla)
[![PyPI](https://img.shields.io/badge/0.1.2-3775A9?logo=pypi&logoColor=fff&label=atla-mcp-server)](https://github.com/atla-ai/atla-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-atla&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ATLA_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-atla%3A0.1.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** An MCP server implementation providing a standardized interface for LLMs to interact with the Atla API.

> [!NOTE]
> `atla-mcp-server` has been repackaged by Acuvity from Atla <team@atla-ai.com> original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure atla-mcp-server run reliably and safely.

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
  - [ Atla <team@atla-ai.com> ](https://github.com/atla-ai/atla-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ atla-mcp-server ](https://github.com/atla-ai/atla-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ atla-mcp-server ](https://github.com/atla-ai/atla-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atla/charts/mcp-server-atla)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atla/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.1.2`

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
  - `ATLA_API_KEY` secret to be set as secrets.ATLA_API_KEY either by `.value` or from existing with `.valueFrom`

# How to install


Install will helm

```console
helm install helm install mcp-server-atla oci://docker.io/acuvity/mcp-server-atla --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-atla --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-atla --version 1.0.0
````
From there your MCP server mcp-server-atla will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-atla` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-atla
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-atla` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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

## 🧰 Tools (2)
<details>
<summary>evaluate_llm_response</summary>

**Description**:

```
Evaluate an LLM's response to a prompt using a given evaluation criteria.

    This function uses an Atla evaluation model under the hood to return a dictionary
    containing a score for the model's response and a textual critique containing
    feedback on the model's response.

    Returns:
        dict[str, str]: A dictionary containing the evaluation score and critique, in
            the format `{"score": <score>, "critique": <critique>}`.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| evaluation_criteria | any | The specific criteria or instructions on which to evaluate the                 model output. A good evaluation criteria should provide the model                 with: (1) a description of the evaluation task, (2) a rubric of                 possible scores and their corresponding criteria, and (3) a                 final sentence clarifying expected score format. A good evaluation                 criteria should also be specific and focus on a single aspect of                 the model output. To evaluate a model's response on multiple                 criteria, use the `evaluate_llm_response_on_multiple_criteria`                 function and create individual criteria for each relevant evaluation                 task. Typical rubrics score responses either on a Likert scale from                 1 to 5 or binary scale with scores of 'Yes' or 'No', depending on                 the specific evaluation task. | Yes
| expected_llm_output | any | A reference or ideal answer to compare against the `llm_response`.                 This is useful in cases where a specific output is expected from                 the model. Defaults to None. | No
| llm_context | any | Additional context or information provided to the model during                 generation. This is useful in cases where the model was provided                 with additional information that is not part of the `llm_prompt`                 or `expected_llm_output` (e.g., a RAG retrieval context).                 Defaults to None. | No
| llm_prompt | any | The prompt given to an LLM to generate the `llm_response` to be                 evaluated. | Yes
| llm_response | any | The output generated by the model in response to the `llm_prompt`,                 which needs to be evaluated. | Yes
| model_id | any | The Atla model ID to use for evaluation. `atla-selene` is the                 flagship Atla model, optimized for the highest all-round performance.                 `atla-selene-mini` is a compact model that is generally faster and                 cheaper to run. Defaults to `atla-selene`. | No
</details>
<details>
<summary>evaluate_llm_response_on_multiple_criteria</summary>

**Description**:

```
Evaluate an LLM's response to a prompt across *multiple* evaluation criteria.

    This function uses an Atla evaluation model under the hood to return a list of
    dictionaries, each containing an evaluation score and critique for a given
    criteria.

    Returns:
        list[dict[str, str]]: A list of dictionaries containing the evaluation score
            and critique, in the format `{"score": <score>, "critique": <critique>}`.
            The order of the dictionaries in the list will match the order of the
            criteria in the `evaluation_criteria_list` argument.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| evaluation_criteria_list | array | <no value> | Yes
| expected_llm_output | any | A reference or ideal answer to compare against the `llm_response`.                 This is useful in cases where a specific output is expected from                 the model. Defaults to None. | No
| llm_context | any | Additional context or information provided to the model during                 generation. This is useful in cases where the model was provided                 with additional information that is not part of the `llm_prompt`                 or `expected_llm_output` (e.g., a RAG retrieval context).                 Defaults to None. | No
| llm_prompt | any | The prompt given to an LLM to generate the `llm_response` to be                 evaluated. | Yes
| llm_response | any | The output generated by the model in response to the `llm_prompt`,                 which needs to be evaluated. | Yes
| model_id | any | The Atla model ID to use for evaluation. `atla-selene` is the                 flagship Atla model, optimized for the highest all-round performance.                 `atla-selene-mini` is a compact model that is generally faster and                 cheaper to run. Defaults to `atla-selene`. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | evaluate_llm_response | description | 3c696082ec32123f441e9d65fb8424707fe1c25178251ec7b19eaa464c0ad131 |
| tools | evaluate_llm_response | evaluation_criteria | 9e00b1e73b41ba53b7422c388ea050d524021bcf039bc99d07091343b7d834bd |
| tools | evaluate_llm_response | expected_llm_output | da44033efb68e905ea4a9064fa4feab414b1d5bd3e838787f656c9d3a5421f19 |
| tools | evaluate_llm_response | llm_context | 1b20afab6e02510b84ef9f8d9443ec70a8a5f8ad4501dcd9f79a7868239255bb |
| tools | evaluate_llm_response | llm_prompt | 820330fc7a42cac6a378ed50e72bf4b9870ad864503a67ffc00606c3fb9e8a90 |
| tools | evaluate_llm_response | llm_response | 9f6d07917c26559a94cc16bc6f753bac39cd278e28996b0171bf90cdb5f9431e |
| tools | evaluate_llm_response | model_id | 7e14bd599507bd7a9ccafadef2fd719d0d54728ea2e9b3408be1a0444385d964 |
| tools | evaluate_llm_response_on_multiple_criteria | description | dadff2f7353d13543ee7c401bda85af71d552980219d46f201a2f48649581ce9 |
| tools | evaluate_llm_response_on_multiple_criteria | expected_llm_output | da44033efb68e905ea4a9064fa4feab414b1d5bd3e838787f656c9d3a5421f19 |
| tools | evaluate_llm_response_on_multiple_criteria | llm_context | 1b20afab6e02510b84ef9f8d9443ec70a8a5f8ad4501dcd9f79a7868239255bb |
| tools | evaluate_llm_response_on_multiple_criteria | llm_prompt | 820330fc7a42cac6a378ed50e72bf4b9870ad864503a67ffc00606c3fb9e8a90 |
| tools | evaluate_llm_response_on_multiple_criteria | llm_response | 9f6d07917c26559a94cc16bc6f753bac39cd278e28996b0171bf90cdb5f9431e |
| tools | evaluate_llm_response_on_multiple_criteria | model_id | 7e14bd599507bd7a9ccafadef2fd719d0d54728ea2e9b3408be1a0444385d964 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
