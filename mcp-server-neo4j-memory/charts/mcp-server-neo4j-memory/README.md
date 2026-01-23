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


# What is mcp-server-neo4j-memory?
[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-memory/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-neo4j-memory/0.4.4?logo=docker&logoColor=fff&label=0.4.4)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-memory)
[![PyPI](https://img.shields.io/badge/0.4.4-3775A9?logo=pypi&logoColor=fff&label=mcp-neo4j-memory)](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-neo4j-memory/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-neo4j-memory&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22NEO4J_PASSWORD%22%2C%22-e%22%2C%22NEO4J_URL%22%2C%22-e%22%2C%22NEO4J_USERNAME%22%2C%22docker.io%2Facuvity%2Fmcp-server-neo4j-memory%3A0.4.4%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides persistent memory capabilities through Neo4j graph database integration.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from mcp-neo4j-memory original [sources](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-neo4j-memory/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/charts/mcp-server-neo4j-memory/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure mcp-neo4j-memory run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/docker/policy.rego) that enables a set of runtime [guardrails](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory#%EF%B8%8F-guardrails) to help enforce security, privacy, and correct usage of your services. Below is list of each guardrail provided.


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
  - [ Author ](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [ mcp-neo4j-memory ](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ mcp-neo4j-memory ](https://github.com/neo4j-contrib/mcp-neo4j/tree/HEAD/servers/mcp-neo4j-memory)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Resources**:
  - [Charts](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/charts/mcp-server-neo4j-memory)
  - [Dockerfile](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-neo4j-memory/docker/Dockerfile)

**Current supported version:**
  - charts: `1.0.0`
  - container: `1.0.0-0.4.4`

**Verify signature with [cosign](https://github.com/sigstore/cosign):**
  - charts: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-neo4j-memory:1.0.0`
  - container: `cosign verify --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate-identity "https://github.com/acuvity/mcp-servers-registry/.github/workflows/release.yaml@refs/heads/main" docker.io/acuvity/mcp-server-neo4j-memory:1.0.0-0.4.4`

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
  - `NEO4J_PASSWORD` secret to be set as secrets.NEO4J_PASSWORD either by `.value` or from existing with `.valueFrom`

**Mandatory Environment variables**:
  - `NEO4J_URL` environment variable to be set by env.NEO4J_URL
  - `NEO4J_USERNAME` environment variable to be set by env.NEO4J_USERNAME

**Optional Environment variables**:
  - `NEO4J_DATABASE=""` environment variable can be changed with `env.NEO4J_DATABASE=""`

# How to install


Install will helm

```console
helm install mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
```

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
````

You can inpect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
````

Upgrade will helm

```console
helm upgrade mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0
```

Uninstall with helm

```console
helm uninstall mcp-server-neo4j-memory
```

From there your MCP server mcp-server-neo4j-memory will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-neo4j-memory` on port `8000` by default.


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
  repository: map[host:docker.io org:acuvity]/mcp-server-neo4j-memory
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
  - for persistent entries, creates a PersistentVolumeClaim named `mcp-server-neo4j-memory` with `storageClassName: <class>` and `resources.requests.storage: <size>`.

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
helm upgrade mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0 --set 'minibridge.guardrails={secrets-redaction}'
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
helm upgrade mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0 -f values.yaml
```

To enable basic auth:

```console
helm upgrade mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0 --set minibridge.basicAuth.value="supersecret"
```

or from a `values.yaml` file:

```yaml
minibridge:
  basicAuth:
    value: "supersecret"
```

Then upgrade with:

```console
helm upgrade mcp-server-neo4j-memory oci://docker.io/acuvity/mcp-server-neo4j-memory --version 1.0.0 -f values.yaml
```

Then you can connect through `http/sse` as usual given that you pass an `Authorization` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>read_graph</summary>

**Description**:

```
Read the entire knowledge graph with all entities and relationships.

Returns the complete memory graph including all stored entities and their relationships.
Use this to get a full overview of stored knowledge.

Returns:
    KnowledgeGraph: Complete graph with all entities and relations
    
Example response:
{
    "entities": [
        {"name": "John Smith", "type": "person", "observations": ["Works at Neo4j"]},
        {"name": "Neo4j Inc", "type": "company", "observations": ["Graph database company"]}
    ],
    "relations": [
        {"source": "John Smith", "target": "Neo4j Inc", "relationType": "WORKS_AT"}
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_entities</summary>

**Description**:

```
Create multiple new entities in the knowledge graph.

Creates new memory entities with their associated observations. If an entity with the same name
already exists, this operation will merge the observations with existing ones.

    
Returns:
    list[Entity]: The created entities with their final state
    
Example call:
{
    "entities": [
        {
            "name": "Alice Johnson",
            "type": "person",
            "observations": ["Software engineer", "Lives in Seattle", "Enjoys hiking"]
        },
        {
            "name": "Microsoft",
            "type": "company", 
            "observations": ["Technology company", "Headquartered in Redmond, WA"]
        }
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entities | array | List of entities to create with name, type, and observations | Yes
</details>
<details>
<summary>create_relations</summary>

**Description**:

```
Create multiple new relationships between existing entities in the knowledge graph.

Creates directed relationships between entities that already exist. Both source and target
entities must already be present in the graph. Use descriptive relationship types.

Returns:
    list[Relation]: The created relationships
    
Example call:
{
    "relations": [
        {
            "source": "Alice Johnson",
            "target": "Microsoft", 
            "relationType": "WORKS_AT"
        },
        {
            "source": "Alice Johnson",
            "target": "Seattle",
            "relationType": "LIVES_IN"
        }
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | List of relations to create between existing entities | Yes
</details>
<details>
<summary>add_observations</summary>

**Description**:

```
Add new observations/facts to existing entities in the knowledge graph.

Appends new observations to entities that already exist. The entity must be present
in the graph before adding observations. Each observation should be a distinct fact.

Returns:
    list[dict]: Details about the added observations including entity name and new facts
    
Example call:
{
    "observations": [
        {
            "entityName": "Alice Johnson",
            "observations": ["Promoted to Senior Engineer", "Completed AWS certification"]
        },
        {
            "entityName": "Microsoft",
            "observations": ["Launched new AI products", "Stock price increased 15%"]
        }
    ]
}
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| observations | array | List of observations to add to existing entities | Yes
</details>
<details>
<summary>delete_entities</summary>

**Description**:

```
Delete entities and all their associated relationships from the knowledge graph.

Permanently removes entities from the graph along with all relationships they participate in.
This is a destructive operation that cannot be undone. Entity names must match exactly.

Returns:
    str: Success confirmation message
    
Example call:
{
    "entityNames": ["Old Company", "Outdated Person"]
}

Warning: This will delete the entities and ALL relationships they're involved in.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entityNames | array | List of exact entity names to delete permanently | Yes
</details>
<details>
<summary>delete_observations</summary>

**Description**:

```
Delete specific observations from existing entities in the knowledge graph.

Removes specific observation texts from entities. The observation text must match exactly
what is stored. The entity will remain but the specified observations will be deleted.

Returns:
    str: Success confirmation message
    
Example call:
{
    "deletions": [
        {
            "entityName": "Alice Johnson",
            "observations": ["Old job title", "Outdated phone number"]
        },
        {
            "entityName": "Microsoft", 
            "observations": ["Former CEO information"]
        }
    ]
}

Note: Observation text must match exactly (case-sensitive) to be deleted.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| deletions | array | List of specific observations to remove from entities | Yes
</details>
<details>
<summary>delete_relations</summary>

**Description**:

```
Delete specific relationships between entities in the knowledge graph.

Removes relationships while keeping the entities themselves. The source, target, and 
relationship type must match exactly for deletion. This only affects the relationships,
not the entities they connect.

Returns:
    str: Success confirmation message
    
Example call:
{
    "relations": [
        {
            "source": "Alice Johnson",
            "target": "Old Company",
            "relationType": "WORKS_AT"
        },
        {
            "source": "John Smith", 
            "target": "Former City",
            "relationType": "LIVES_IN"
        }
    ]
}

Note: All fields (source, target, relationType) must match exactly for deletion.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| relations | array | List of specific relationships to delete from the graph | Yes
</details>
<details>
<summary>search_memories</summary>

**Description**:

```
Search for entities in the knowledge graph using fulltext search.

Searches across entity names, types, and observations using Neo4j's fulltext index.
Returns matching entities and their related connections. Supports partial matches
and multiple search terms.

Returns:
    KnowledgeGraph: Subgraph containing matching entities and their relationships
    
Example call:
{
    "query": "engineer software"
}

This searches for entities containing "engineer" or "software" in their name, type, or observations.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| query | string | Fulltext search query to find entities by name, type, or observations | Yes
</details>
<details>
<summary>find_memories_by_name</summary>

**Description**:

```
Find specific entities by their exact names.

Retrieves entities that exactly match the provided names, along with all their
relationships and connected entities. Use this when you know the exact entity names.

Returns:
    KnowledgeGraph: Subgraph containing the specified entities and their relationships
    
Example call:
{
    "names": ["Alice Johnson", "Microsoft", "Seattle"]
}

This retrieves the entities with exactly those names plus their connections.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| names | array | List of exact entity names to retrieve | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | add_observations | description | 74685109ad3cb4420a3f78ecd806c01d759803b525dc605879abbb7aac0332f9 |
| tools | add_observations | observations | 1dd71ddf6c37cd97309614815eb4678af3b8ec1fa7d869530c77820f295c640e |
| tools | create_entities | description | a029f2918d3008cf3fb59a0a5e56ef47911680558bde63e5f8de2fe94f5f9018 |
| tools | create_entities | entities | 81bf714250114c87d7635f4f37ec618a4919710bb558f06257409a3dfeb16202 |
| tools | create_relations | description | 867a4b2cc7e44b7e459b51e552fe4cb7228fe39b5ad2d81d34aaa49f3356c7e7 |
| tools | create_relations | relations | 6c7122f97e10ddbd5f84c7ddd9d9486b6d87f7e18c441f0d1cb0fb2049b4ae1d |
| tools | delete_entities | description | 4072c70aecf3e87e22273bf1964eeff7fa7d6baddd9b7af01b99dfeb5d50a844 |
| tools | delete_entities | entityNames | 07de112fc04997e4c54813a6f550234605df1b834c18f3719db8c264dbd196d6 |
| tools | delete_observations | description | 4c2fbb82d68f5fb10f0e051f676537cfc90ff7e470c9a9945a8708732ffc59e1 |
| tools | delete_observations | deletions | 15503546937d809c58c4c7e356abfd5adb13b37fda2af857cfa6c096042eb0f9 |
| tools | delete_relations | description | 9eb23da9b20cf68c38323bc5d32714bdc65a3b2c09f018069e2011744fbf4fb3 |
| tools | delete_relations | relations | 8b67ac0a7ec71340f17625aab674a7b807a98a1a06c883939aaf72c718ae0b11 |
| tools | find_memories_by_name | description | 0cf3fbcbe4d028e188890a4e440486759d35e55ebe22f9eff111d73084619e41 |
| tools | find_memories_by_name | names | 30dd21d889e064d390457c1c99e9d6eb58c49238c0691a8d558f5a2a986ffdc3 |
| tools | read_graph | description | 8eeeccee1fdb8b2a187ce791a2c923e2ee4e82b6480c11f26d515ba4e8a3f348 |
| tools | search_memories | description | 5b768f79973ccec75308c11a712ec3d5641124d594eb7b71358c2334352f3cf6 |
| tools | search_memories | query | 727e760e5c1432a057d24c0d97099961093e08eec261f5cdfcc3af703d851712 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
