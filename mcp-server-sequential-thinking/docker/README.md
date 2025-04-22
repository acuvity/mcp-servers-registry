
<p align="center">
  <a href="https://acuvity.ai">
    <picture>
      <img src="https://mma.prnewswire.com/media/2544052/Acuvity__Logo.jpg" height="90" alt="Acuvity logo"/>
    </picture>
  </a>
</p>
<p align="center">
  <a href="https://discord.gg/BkU7fBkrNk">
    <img src="https://img.shields.io/badge/Acuvity-Join-7289DA?logo=discord&logoColor=fff)](https://discord.gg/BkU7fBkrNk" alt="Join Acuvity community" /></a>
<a href="https://www.linkedin.com/company/acuvity/">
    <img src="https://img.shields.io/badge/LinkedIn-follow-0a66c2" alt="Follow us on LinkedIn" />
  </a>
</p>


# What is mcp-server-sequential-thinking?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-sequential-thinking?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-sequential-thinking/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-sequential-thinking/tags)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-sequential-thinking)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for sequential thinking and problem solving

> [!NOTE]
> `@modelcontextprotocol/server-sequential-thinking` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-sequential-thinking run reliably and safely.

## 🔐 Key Security Features

<details>
<summary>📦 Isolated Immutable Sandbox </summary>

- **Isolated Execution**: All tools run within secure, containerized sandboxes to enforce process isolation and prevent lateral movement.
- **Non-root by Default**: Enforces least-privilege principles, minimizing the impact of potential security breaches.
- **Read-only Filesystem**: Ensures runtime immutability, preventing unauthorized modification.
- **Version Pinning**: Guarantees consistency and reproducibility across deployments by locking tool and dependency versions.
- **CVE Scanning**: Continuously monitors for known vulnerabilities using [Docker Scout](https://docs.docker.com/scout/) to support proactive mitigation.
- **SBOM & Provenance**: Provides full supply chain transparency with embedded metadata and traceable build information.
</details>

<details>
<summary>🛡️ Runtime Security</summary>

**Minibridge Integration**: [Minibridge](https://github.com/acuvity/minibridge) establishes secure Agent-to-MCP connectivity, supports Rego/HTTP-based policy enforcement 🕵️, and simplifies orchestration.

Minibridge includes built-in guardrails to protect MCP server integrity and detect suspicious behavior:

- **Integrity via Hashing**: Verifies the authenticity and integrity of tool descriptors and runtime components.
- **Threat Detection**:
  - Detects hidden or covert instruction patterns.
  - Monitors for schema parameter misuse as potential exfiltration channels.
  - Flags unauthorized access to sensitive files or credentials.
  - Identifies tool shadowing and override attempts.
  - Enforces cross-origin and server-mismatch protection policies.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.
</details>


# Quick reference

**Maintained by**:
  - [Acuvity team](mailto:support@acuvity.ai) for packaging
  - [ Anthropic, PBC ](https://modelcontextprotocol.io) for application

**Where to get help**:
  - [The Acuvity MCP Forge repository](https://github.com/acuvity/mcp-servers-registry)
  - [The Acuvity community Discord](https://discord.gg/BkU7fBkrNk)
  - [ @modelcontextprotocol/server-sequential-thinking ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-sequential-thinking ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Base image**:
  - `node:23.11.0-alpine3.21`

**Dockerfile**:
  - `https://github.com/acuvity/mcp-servers-registry/mcp-server-sequential-thinking/docker/Dockerfile`

**Current supported tag:**
  - `latest` -> `0.6.2`

> [!TIP]
> See [Docker Hub Tags](https://hub.docker.com/r/acuvity/mcp-server-sequential-thinking/tags) section for older tags.

# 📦 How to Use


> [!NOTE]
> Given mcp-server-sequential-thinking scope of operation it can be hosted anywhere.
> But keep in mind that this keep a persistent state and that is not meant to be used by several client at the same time.

## 🐳 With Docker


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-sequential-thinking:0.6.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-sequential-thinking:0.6.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-sequential-thinking": {
      "url": "http://localhost:<localport>/sse",
    }
  }
}
```

You might have to use different ports for different tools.

</details>

<details>
<summary>Remotely with Websocket tunneling and MTLS </summary>

> This section assume you are familar with TLS and certificates and will require:
> - a server certificate with proper DNS/IP field matching your tool deployment.
> - a client-ca used to sign client certificates

1. Start the server in `backend` mode
 - add an environment variable like `-e MINIBRIDGE_MODE=backend`
 - add the TLS certificates (recommended) through a volume let's say `/certs` ex (`-v $PWD/certs:/certs`)
 - instruct minibridge to use those certs with
   - `-e MINIBRIDGE_TLS_SERVER_CERT=/certs/server-cert.pem`
   - `-e MINIBRIDGE_TLS_SERVER_KEY=/certs/server-key.pem`
   - `-e MINIBRIDGE_TLS_SERVER_KEY_PASS=optional`
   - `-e MINIBRIDGE_TLS_SERVER_CLIENT_CA=/certs/client-ca.pem`

2. Start `minibridge` locally in frontend mode:
  - Get [minibridge](https://github.com/acuvity/minibridge) binary for your OS.

In your client configuration, Minibridge works like any other STDIO command.

Example for Claude Desktop:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-sequential-thinking": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Of course there is plenty of other option that minibridge can provide.

Don't be shy to ask question either.

</details>

## ☁️ On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-sequential-thinking/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-sequential-thinking --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-sequential-thinking --version <version>
````

Install with helm

```console
helm install mcp-server-sequential-thinking oci://docker.io/acuvity/mcp-server-sequential-thinking --version <version>
```

From there your MCP server mcp-server-sequential-thinking will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-sequential-thinking` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.


</details>

# 🧰 Integrations

> [!NOTE]
> All the integrations below should work natively for all run mode.
> Only the `docker` local run is described to keep it concise.

<details>
<summary>Visual Studio Code</summary>

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-sequential-thinking": {
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sequential-thinking:0.6.2"]
      }
    }
  }
}
```

## Workspace scope

In your workspace createa file called `.vscode/mcp.json` and add the following section:

```json
{
  "servers": {
    "acuvity-mcp-server-sequential-thinking": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sequential-thinking:0.6.2"]
    }
  }
}
```

> To pass secrets you should use the `promptString` input type described in the [Visual Studio Code documentation](https://code.visualstudio.com/docs/copilot/chat/mcp-servers).

</details>

<details>
<summary>Windsurf IDE</summary>

In `~/.codeium/windsurf/mcp_config.json` add the following section:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-sequential-thinking": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sequential-thinking:0.6.2"]
    }
  }
}
```

See [Windsurf documentation](https://docs.windsurf.com/windsurf/mcp) for more info.

</details>

<details>
<summary>Cursor IDE</summary>

Add the following JSON block to your mcp configuration file:
- `~/.cursor/mcp.json` for global scope
- `.cursor/mcp.json` for project scope

```json
{
  "mcpServers": {
    "acuvity-mcp-server-sequential-thinking": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sequential-thinking:0.6.2"]
    }
  }
}
```

See [cursor documentation](https://docs.cursor.com/context/model-context-protocol) for more information.

</details>
<details>

<summary>Claude Desktop</summary>

In the `claude_desktop_config.json` configuration file add the following section:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-sequential-thinking": {
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sequential-thinking:0.6.2"]
    }
  }
}
```

See [Anthropic documentation](https://docs.anthropic.com/en/docs/agents-and-tools/mcp) for more information.
</details>

<details>
<summary>OpenAI python SDK</summary>

## Running locally

```python
async with MCPServerStdio(
    params={
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-sequential-thinking:0.6.2"]
    }
) as server:
    tools = await server.list_tools()
```

## Running remotely

```python
async with MCPServerSse(
    params={
        "url": "http://<ip>:<port>/sse",
    }
) as server:
    tools = await server.list_tools()
```

See [OpenAI Agents SDK docs](https://openai.github.io/openai-agents-python/mcp/) for more info.

</details>

# 🧠 Server features

## 🧰 Tools (1)
<details>
<summary>sequentialthinking</summary>

**Description**:

```
A detailed tool for dynamic and reflective problem-solving through thoughts.
This tool helps analyze problems through a flexible thinking process that can adapt and evolve.
Each thought can build on, question, or revise previous insights as understanding deepens.

When to use this tool:
- Breaking down complex problems into steps
- Planning and design with room for revision
- Analysis that might need course correction
- Problems where the full scope might not be clear initially
- Problems that require a multi-step solution
- Tasks that need to maintain context over multiple steps
- Situations where irrelevant information needs to be filtered out

Key features:
- You can adjust total_thoughts up or down as you progress
- You can question or revise previous thoughts
- You can add more thoughts even after reaching what seemed like the end
- You can express uncertainty and explore alternative approaches
- Not every thought needs to build linearly - you can branch or backtrack
- Generates a solution hypothesis
- Verifies the hypothesis based on the Chain of Thought steps
- Repeats the process until satisfied
- Provides a correct answer

Parameters explained:
- thought: Your current thinking step, which can include:
* Regular analytical steps
* Revisions of previous thoughts
* Questions about previous decisions
* Realizations about needing more analysis
* Changes in approach
* Hypothesis generation
* Hypothesis verification
- next_thought_needed: True if you need more thinking, even if at what seemed like the end
- thought_number: Current number in sequence (can go beyond initial total if needed)
- total_thoughts: Current estimate of thoughts needed (can be adjusted up/down)
- is_revision: A boolean indicating if this thought revises previous thinking
- revises_thought: If is_revision is true, which thought number is being reconsidered
- branch_from_thought: If branching, which thought number is the branching point
- branch_id: Identifier for the current branch (if any)
- needs_more_thoughts: If reaching end but realizing more thoughts needed

You should:
1. Start with an initial estimate of needed thoughts, but be ready to adjust
2. Feel free to question or revise previous thoughts
3. Don't hesitate to add more thoughts if needed, even at the "end"
4. Express uncertainty when present
5. Mark thoughts that revise previous thinking or branch into new paths
6. Ignore information that is irrelevant to the current step
7. Generate a solution hypothesis when appropriate
8. Verify the hypothesis based on the Chain of Thought steps
9. Repeat the process until satisfied with the solution
10. Provide a single, ideally correct answer as the final output
11. Only set next_thought_needed to false when truly done and a satisfactory answer is reached
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| branchFromThought | integer | Branching point thought number | No
| branchId | string | Branch identifier | No
| isRevision | boolean | Whether this revises previous thinking | No
| needsMoreThoughts | boolean | If more thoughts are needed | No
| nextThoughtNeeded | boolean | Whether another thought step is needed | Yes
| revisesThought | integer | Which thought is being reconsidered | No
| thought | string | Your current thinking step | Yes
| thoughtNumber | integer | Current thought number | Yes
| totalThoughts | integer | Estimated total thoughts needed | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | sequentialthinking | description | 638bac0560badec1e36742fbcf0ded31308fd3a06f05da4a432d43d473c52bed |
| tools | sequentialthinking | branchFromThought | 6d396d89d8aea6921f5ae4b93998dc6e4630cced82a7fef5aedc8be15ed268dd |
| tools | sequentialthinking | branchId | 3af8746d0b1d40ca8208d28cb2bdb116506456d937196ff8c3438f2321386536 |
| tools | sequentialthinking | isRevision | 48760e1f72ade2d06cd8ece8ce099e9385349771f163db3600f7e17d393ff1ad |
| tools | sequentialthinking | needsMoreThoughts | deb7824277425aea7785a98995eb0b43154ddb93ea2b0245b11e53d58e143e65 |
| tools | sequentialthinking | nextThoughtNeeded | cea36b8c3492ab029f329050cde7d604200f3afd54f1a638cb6dd6a15c88a1f9 |
| tools | sequentialthinking | revisesThought | 341da909d262df3e42dd0876feded500421f03c380778522c4ea840f566e3a3b |
| tools | sequentialthinking | thought | 663e7dc28e5e2e6fee16a0b560a8023b178f35ca3e2e24fbed1a0847232e5786 |
| tools | sequentialthinking | thoughtNumber | be1ad5c36f2e119ad95831a6e6855e3111fd3a9d4f00826ae27d02eb94fee0d7 |
| tools | sequentialthinking | totalThoughts | 9cb82eb4f2cd2c5836dfde2480f5538ecd30261801002a1487d2e3c88b2ff4ce |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
