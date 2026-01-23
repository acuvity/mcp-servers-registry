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


# What is mcp-server-aws-git-search?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-git-search/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-git-search/1.0.12?logo=docker&logoColor=fff&label=1.0.12)](https://hub.docker.com/r/acuvity/mcp-server-aws-git-search)
[![PyPI](https://img.shields.io/badge/1.0.12-3775A9?logo=pypi&logoColor=fff&label=awslabs.git-repo-research-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/git-repo-research-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-git-search/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-git-search&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22--tmpfs%22%2C%22%2Ftmp%3Arw%2Cnosuid%2Cnodev%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-git-search%3A1.0.12%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Semantic search and analysis of Git repositories using Amazon Bedrock and FAISS

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.git-repo-research-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/git-repo-research-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-git-search/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-git-search/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-git-search/charts/mcp-server-aws-git-search/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.git-repo-research-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-git-search/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-git-search#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ AWSLabs MCP <203918161+awslabs-mcp@users.noreply.github.com> ](https://github.com/awslabs/mcp/tree/HEAD/src/git-repo-research-mcp-server) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ awslabs.git-repo-research-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/git-repo-research-mcp-server)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ awslabs.git-repo-research-mcp-server ](https://github.com/awslabs/mcp/tree/HEAD/src/git-repo-research-mcp-server)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-git-search/charts/mcp-server-aws-git-search)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-git-search/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-1.0.12`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-git-search:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-aws-git-search:1.0.0-1.0.12`

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
  - `GITHUB_TOKEN` secret to be set as secrets.GITHUB_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `AWS_PROFILE=""` environment variable can be changed with `env.AWS_PROFILE=""`
  - `AWS_REGION=""` environment variable can be changed with `env.AWS_REGION=""`

# How to install


Install will helm

```console
helm install mcp-server-aws-git-search oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-aws-git-search oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-aws-git-search
```

From there your MCP server mcp-server-aws-git-search will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-git-search` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-aws-git-search
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-aws-git-search` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-aws-git-search oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-aws-git-search oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-aws-git-search oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-aws-git-search oci://docker.io/acuvity/mcp-server-aws-git-search --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (5)
<details>
<summary>create_research_repository</summary>

**Description**:

```
Build a FAISS index for a Git repository.

    This tool indexes a Git repository (local or remote) using FAISS and Amazon Bedrock embeddings.
    The index can then be used for semantic search within the repository.

    Args:
        ctx: MCP context object used for progress tracking and error reporting
        repository_path: Path to local repository or URL to remote repository
        output_path: Where to store the index (optional, uses default if not provided)
        embedding_model: Which AWS embedding model to use
        include_patterns: Glob patterns for files to include (optional)
        exclude_patterns: Glob patterns for files to exclude (optional)
        chunk_size: Maximum size of each chunk in characters
        chunk_overlap: Overlap between chunks in characters

    Returns:
        Information about the created index
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| chunk_overlap | integer | Overlap between chunks in characters | No
| chunk_size | integer | Maximum size of each chunk in characters | No
| embedding_model | string | Which AWS embedding model to use | No
| exclude_patterns | any | Glob patterns for files to exclude (optional). Defaults to common binary files, build artifacts, and VCS directories. | No
| include_patterns | any | Glob patterns for files to include (optional). Defaults to common source code and documentation files. | No
| output_path | any | Where to store the index (optional, uses default if not provided) | No
| repository_path | string | Path to local repository or URL to remote repository | Yes
</details>
<details>
<summary>search_research_repository</summary>

**Description**:

```
Perform semantic search within an indexed repository.

    This tool searches an indexed repository using semantic search with Amazon Bedrock embeddings.
    It returns results ranked by relevance to the query.

    Args:
        ctx: MCP context object used for error reporting
        index_path: Name of the repository or path to the index to search
        query: The search query to use for semantic search
        limit: Maximum number of results to return
        threshold: Minimum similarity score threshold (0.0 to 1.0)

    Returns:
        Search results ranked by relevance to the query
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index_path | string | Name of the repository or path to the index to search | Yes
| limit | integer | Maximum number of results to return | No
| query | string | The search query to use for semantic search | Yes
| threshold | number | Minimum similarity score threshold (0.0 to 1.0) | No
</details>
<details>
<summary>search_repos_on_github</summary>

**Description**:

```
Search for GitHub repositories based on keywords, scoped to specific organizations.

    This tool searches for GitHub repositories using the GitHub REST/GraphQL APIs, scoped to specific GitHub
    organizations (aws-samples, aws-solutions-library-samples, and awslabs).

    Results are filtered to only include repositories with specific licenses (Apache License 2.0,
    MIT, and MIT No Attribution) and are sorted by stars (descending) and then by updated date.

    For higher rate limits, you can set the GITHUB_TOKEN environment variable with a GitHub
    personal access token. Without a token, the API is limited to 60 requests per hour, and requests are
    made with the REST API. With a token, this increases to 5,000 requests per hour, and requests are made
    with the GraphQL API.

    Args:
        ctx: MCP context object used for error reporting
        keywords: List of keywords to search for
        num_results: Number of results to return

    Returns:
        List of GitHub repositories matching the search criteria
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| keywords | array | List of keywords to search for GitHub repositories | Yes
| num_results | integer | Number of results to return | No
</details>
<details>
<summary>access_file</summary>

**Description**:

```
Access file or directory contents.

    This tool provides access to file or directory contents:
    - If the filepath references a text file, returns the content as a string
    - If the filepath references a directory, returns an array of files in the directory
    - If the filepath references a binary image (jpg, png), returns the image data

    For repository files, use the format: repository_name/repository/path/to/file
    Example: awslabs_mcp/repository/README.md

    For repositories with organization names, both formats are supported:
    - awslabs_mcp/repository/README.md (with underscore)
    - awslabs/mcp/repository/README.md (with slash)

    Args:
        ctx: MCP context object used for error reporting
        filepath: Path to the file or directory to access

    Returns:
        File content, directory listing, or image data
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| filepath | string | Path to the file or directory to access | Yes
</details>
<details>
<summary>delete_research_repository</summary>

**Description**:

```
Delete an indexed repository.

    This tool deletes an indexed repository and its associated files.
    It can be identified by repository name or the full path to the index.

    Args:
        ctx: MCP context object used for error reporting
        repository_name_or_path: Name of the repository or path to the index to delete
        index_directory: Directory to look for indices (optional, uses default if not provided)

    Returns:
        Status of the delete operation
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| index_directory | any | Directory to look for indices (optional, uses default if not provided) | No
| repository_name_or_path | string | Name of the repository or path to the index to delete | Yes
</details>

## 📚 Resources (1)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Indexed Repositories | application/json | repositories:// | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | access_file | description | 538ae8c2c6143e9c751c269bcda26bf75732ea8f6457735b4e162fd34ebbe56e |
| tools | access_file | filepath | 7e42f914e5e489b4037c9f6e16dff7ceceb935b6bd48b7319e0bd66f7c6a42d4 |
| tools | create_research_repository | description | c940a8dd4b9e4d9deb67a67f60bbcf4599e557b46e62bcc987af0d243d8c52f2 |
| tools | create_research_repository | chunk_overlap | 05c66ecb3debdcd434ddda278bd87023771034f434637bbbe5240a6ebd5cc2b3 |
| tools | create_research_repository | chunk_size | 70bde938031148dfe995e9846bbd3c795b0954f8f7a4669f1b6569aa22cff313 |
| tools | create_research_repository | embedding_model | 80bf3db2dca9c60281aad58727fdbb8cbc83af93eac41048dce3bb1d50a7c09c |
| tools | create_research_repository | exclude_patterns | f9eaffd2bf611b3f52a2c0c637d25ea82a4ead0ef674dbbbc26de0c5dc6182b1 |
| tools | create_research_repository | include_patterns | fb200038a763048571f840b9999411880fd51d656bbdf70546b9b5924f2fdfd9 |
| tools | create_research_repository | output_path | 42ba0e0affe9cf20145b919588e638250b0fb98db081dbce813a93e8f1039f12 |
| tools | create_research_repository | repository_path | 9e87b7491b858944f17c543f99ab2bcdf2af0c7e6bbac57c7622a84ed828d9f3 |
| tools | delete_research_repository | description | e477aea91e163d0b7171e032ee484d6d2c024ca6effbd6aa33ceeacc8145a456 |
| tools | delete_research_repository | index_directory | 091cb2afbc95074d36d2bc3b8b7aab33c7bc048371c92a747f4c26922f4d9d81 |
| tools | delete_research_repository | repository_name_or_path | 4b7176a7aab176477f93010539482d3b0f25a4f9c176998c221547f86dc34453 |
| tools | search_repos_on_github | description | afc2d618e7a37552c13bc7cfb4367b10bc34ed21e6d3779ffd879d9e4099cbdd |
| tools | search_repos_on_github | keywords | a56318459b3ada36d7065a7b45a0fd85763ff28ae8b0897d32ffe8a5ccab8988 |
| tools | search_repos_on_github | num_results | 6954eeae88250d596470c7aeb1f8f6b1350c408ae7182ea2db936a6fe2862bff |
| tools | search_research_repository | description | fbcdc6d4c04bba6202c0ac04c0711e1e09ba24a0db837b2d7bf4ac52a6f8eb1a |
| tools | search_research_repository | index_path | 85399129c160de5829951105ac839c04b1b40917fb516a51799d7201147fff6f |
| tools | search_research_repository | limit | b04468046d2f2a5692b75e7d703a30fd2787b8f80972a3b07b618e4ca4b3fa70 |
| tools | search_research_repository | query | 3fb13144244d3018c954845833da0792f2eced8241205b1535b7e98428b366e9 |
| tools | search_research_repository | threshold | 237e1bdf986ebe9c0aee3f1a3c4e51cb9b4c0b0eda7a2f591d4f97def9fdb890 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
