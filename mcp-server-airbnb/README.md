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


# What is mcp-server-airbnb?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-airbnb/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-airbnb/0.1.1?logo=docker&logoColor=fff&label=0.1.1)](https://hub.docker.com/r/acuvity/mcp-server-airbnb)
[![PyPI](https://img.shields.io/badge/0.1.1-3775A9?logo=pypi&logoColor=fff&label=@openbnb/mcp-server-airbnb)](https://github.com/openbnb-org/mcp-server-airbnb)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-airbnb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-airbnb%3A0.1.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Provides tools to search Airbnb and get listing details.

> [!NOTE]
> `@openbnb/mcp-server-airbnb` has been repackaged by Acuvity from OpenBnB original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @openbnb/mcp-server-airbnb run reliably and safely.

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
> Given mcp-server-airbnb scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-airbnb&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-airbnb%3A0.1.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-airbnb": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-airbnb:0.1.1"
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
    "acuvity-mcp-server-airbnb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-airbnb:0.1.1"
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
    "acuvity-mcp-server-airbnb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-airbnb:0.1.1"
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
    "acuvity-mcp-server-airbnb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-airbnb:0.1.1"
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
    "acuvity-mcp-server-airbnb": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-airbnb:0.1.1"
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
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-airbnb:0.1.1"]
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


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-airbnb:0.1.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-airbnb:0.1.1
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-airbnb": {
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
    "acuvity-mcp-server-airbnb": {
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

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-airbnb --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-airbnb --version 1.0.0
````

Install with helm

```console
helm install mcp-server-airbnb oci://docker.io/acuvity/mcp-server-airbnb --version 1.0.0
```

From there your MCP server mcp-server-airbnb will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-airbnb` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-airbnb/charts/mcp-server-airbnb/README.md) for more details about settings.

</details>

# 🧠 Server features

## 🧰 Tools (2)
<details>
<summary>airbnb_search</summary>

**Description**:

```
Search for Airbnb listings with various filters and pagination. Provide direct links to the user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| adults | number | Number of adults | No
| checkin | string | Check-in date (YYYY-MM-DD) | No
| checkout | string | Check-out date (YYYY-MM-DD) | No
| children | number | Number of children | No
| cursor | string | Base64-encoded string used for Pagination | No
| ignoreRobotsText | boolean | Ignore robots.txt rules for this request | No
| infants | number | Number of infants | No
| location | string | Location to search for (city, state, etc.) | Yes
| maxPrice | number | Maximum price for the stay | No
| minPrice | number | Minimum price for the stay | No
| pets | number | Number of pets | No
| placeId | string | Google Maps Place ID (overrides the location parameter) | No
</details>
<details>
<summary>airbnb_listing_details</summary>

**Description**:

```
Get detailed information about a specific Airbnb listing. Provide direct links to the user
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| adults | number | Number of adults | No
| checkin | string | Check-in date (YYYY-MM-DD) | No
| checkout | string | Check-out date (YYYY-MM-DD) | No
| children | number | Number of children | No
| id | string | The Airbnb listing ID | Yes
| ignoreRobotsText | boolean | Ignore robots.txt rules for this request | No
| infants | number | Number of infants | No
| pets | number | Number of pets | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | airbnb_listing_details | description | 011db1da885610c9ac150e09ce15eaf2e1f466584906e8433b5a3497b79ef2c2 |
| tools | airbnb_listing_details | adults | e3da24f237679dc886393c4e256478b4ae4e2c695fd52c0f3239192031e3e8ed |
| tools | airbnb_listing_details | checkin | 54b67c841748044da6293c79ec45c182ba21377265d19842876136f470ecfaa5 |
| tools | airbnb_listing_details | checkout | 0d4cb2c5f7d2c47ed411d36986309799530a5ebfbf0ec2bc857c871365e0c980 |
| tools | airbnb_listing_details | children | 03678d5d4426e53c30eff8b3047d065f4e73e75226f40ba123024ea4ca197afb |
| tools | airbnb_listing_details | id | 655303f29b828171fd010ca1e56ee9a94cb55a38e05dfb4682dffe689223b54e |
| tools | airbnb_listing_details | ignoreRobotsText | 6cf8001889632ce9f32c02310db220717a5188c752a514d05ef3d0949bf1b62b |
| tools | airbnb_listing_details | infants | 17ab8ac5a1141ae2a690e32ea9b3df319a537a6171ad2f37685ddc6618e5616b |
| tools | airbnb_listing_details | pets | 6a6267a8ad8a5bbf9949d67eb93b31d73a81c4b2a287bbd3a889db2877b74b64 |
| tools | airbnb_search | description | c23c74d664b028a3c6c30a147149b343118e0570b4e8e8397e2899fb986e216b |
| tools | airbnb_search | adults | e3da24f237679dc886393c4e256478b4ae4e2c695fd52c0f3239192031e3e8ed |
| tools | airbnb_search | checkin | 54b67c841748044da6293c79ec45c182ba21377265d19842876136f470ecfaa5 |
| tools | airbnb_search | checkout | 0d4cb2c5f7d2c47ed411d36986309799530a5ebfbf0ec2bc857c871365e0c980 |
| tools | airbnb_search | children | 03678d5d4426e53c30eff8b3047d065f4e73e75226f40ba123024ea4ca197afb |
| tools | airbnb_search | cursor | 0f0bb366c5993fb1bad2c211fd27708aabbc88361489a19baae280df249cda9b |
| tools | airbnb_search | ignoreRobotsText | 6cf8001889632ce9f32c02310db220717a5188c752a514d05ef3d0949bf1b62b |
| tools | airbnb_search | infants | 17ab8ac5a1141ae2a690e32ea9b3df319a537a6171ad2f37685ddc6618e5616b |
| tools | airbnb_search | location | 5cd613963f0b0eefabeef72af5dc4f138831ab0801a7c3d0d6648c882f71a352 |
| tools | airbnb_search | maxPrice | a73a7d9b6103846a3985ada00a4093618e0418e2908bb0f045b010ca7464b9f7 |
| tools | airbnb_search | minPrice | a115d39d586b0d5e16d20fa7178f379b2b4a4ea085415bbf8ac218a2dcc1b2fb |
| tools | airbnb_search | pets | 6a6267a8ad8a5bbf9949d67eb93b31d73a81c4b2a287bbd3a889db2877b74b64 |
| tools | airbnb_search | placeId | ff40c86a746c7cdd4bfbc26b95818ec905cbc5a29361414f9d1b90cad97c8cf1 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
