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

**Description:** Enable AI agents to interact with the Atla API for state-of-the-art LLMJ evaluation.

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


# 📦 How to Use


> [!NOTE]
> Given mcp-server-atla scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-atla&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22ATLA_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-atla%3A0.1.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-atla": {
        "env": {
          "ATLA_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "ATLA_API_KEY",
          "docker.io/acuvity/mcp-server-atla:0.1.2"
        ]
      }
    }
  }
}
```

## Workspace scope

In your workspace create a file called `.vscode/mcp.json` and add the following section:

```json
{
  "servers": {
    "acuvity-mcp-server-atla": {
      "env": {
        "ATLA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLA_API_KEY",
        "docker.io/acuvity/mcp-server-atla:0.1.2"
      ]
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
    "acuvity-mcp-server-atla": {
      "env": {
        "ATLA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLA_API_KEY",
        "docker.io/acuvity/mcp-server-atla:0.1.2"
      ]
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
    "acuvity-mcp-server-atla": {
      "env": {
        "ATLA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLA_API_KEY",
        "docker.io/acuvity/mcp-server-atla:0.1.2"
      ]
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
    "acuvity-mcp-server-atla": {
      "env": {
        "ATLA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "ATLA_API_KEY",
        "docker.io/acuvity/mcp-server-atla:0.1.2"
      ]
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
        "env": {"ATLA_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","ATLA_API_KEY","docker.io/acuvity/mcp-server-atla:0.1.2"]
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

## 🐳 Run it with Docker
**Environment variables:**
  - `ATLA_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e ATLA_API_KEY docker.io/acuvity/mcp-server-atla:0.1.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e ATLA_API_KEY docker.io/acuvity/mcp-server-atla:0.1.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-atla": {
      "url": "http://localhost:<localport>/sse",
    }
  }
}
```

You might have to use different ports for different tools.

</details>

<details>
<summary>Remotely with Websocket tunneling and MTLS </summary>

> This section assume you are familiar with TLS and certificates and will require:
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
    "acuvity-mcp-server-atla": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Of course there are plenty of other options that minibridge can provide.

Don't be shy to ask question either.

</details>

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `ATLA_API_KEY` secret to be set as secrets.ATLA_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-atla --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-atla --version 1.0.0
````

Install with helm

```console
helm install mcp-server-atla oci://docker.io/acuvity/mcp-server-atla --version 1.0.0
```

From there your MCP server mcp-server-atla will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-atla` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-atla/charts/mcp-server-atla/README.md) for more details about settings.

</details>
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
| evaluation_criteria_list | array | not set | Yes
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
