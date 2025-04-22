
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


# What is mcp-server-google-maps?

[![Helm](https://img.shields.io/docker/v/acuvity/mcp-server-google-maps?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-fetch/latest?logo=docker&logoColor=fff&label=latest)](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags)
[![PyPI](https://img.shields.io/badge/0.6.2-3775A9?logo=pypi&logoColor=fff&label=@modelcontextprotocol/server-google-maps)](https://modelcontextprotocol.io)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)

**Description:** MCP server for using the Google Maps API

> [!NOTE]
> `@modelcontextprotocol/server-google-maps` has been repackaged by Acuvity from its original [sources](https://modelcontextprotocol.io).

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @modelcontextprotocol/server-google-maps run reliably and safely.

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
  - [ @modelcontextprotocol/server-google-maps ](https://modelcontextprotocol.io)

**Where to file issues**:
  - [Github issue tracker](https://github.com/acuvity/mcp-servers-registry/issues)
  - [ @modelcontextprotocol/server-google-maps ](https://modelcontextprotocol.io)

**Supported architectures**:
  - `amd64`
  - `arm64`

**Base image**:
  - `node:23.11.0-alpine3.21`

**Dockerfile**:
  - `https://github.com/acuvity/mcp-servers-registry/mcp-server-google-maps/docker/Dockerfile`

**Current supported tag:**
  - `latest` -> `0.6.2`

> [!TIP]
> See [Docker Hub Tags](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags) section for older tags.

# 📦 How to Use


> [!NOTE]
> Given mcp-server-google-maps scope of operation it can be hosted anywhere.
> But keep in mind that this keep a persistent state and that is not meant to be used by several client at the same time.

## 🐳 With Docker
**Environment variables:**
  - `GOOGLE_MAPS_API_KEY` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e GOOGLE_MAPS_API_KEY docker.io/acuvity/mcp-server-google-maps:0.6.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e GOOGLE_MAPS_API_KEY docker.io/acuvity/mcp-server-google-maps:0.6.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-google-maps": {
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
    "acuvity-mcp-server-google-maps": {
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

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `GOOGLE_MAPS_API_KEY` secret to be set as secrets.GOOGLE_MAPS_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

Pick a version from the [OCI registry](https://hub.docker.com/r/acuvity/mcp-server-google-maps/tags) looking for the type `helm`

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-google-maps --version <version>
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-google-maps --version <version>
````

Install with helm

```console
helm install mcp-server-google-maps oci://docker.io/acuvity/mcp-server-google-maps --version <version>
```

From there your MCP server mcp-server-google-maps will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-google-maps` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

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
      "acuvity-mcp-server-google-maps": {
        "env":
          {"GOOGLE_MAPS_API_KEY":"xxxxxx"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","GOOGLE_MAPS_API_KEY","docker.io/acuvity/mcp-server-google-maps:0.6.2"]
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
    "acuvity-mcp-server-google-maps": {
      "env":
        {"GOOGLE_MAPS_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","GOOGLE_MAPS_API_KEY","docker.io/acuvity/mcp-server-google-maps:0.6.2"]
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
    "acuvity-mcp-server-google-maps": {
      "env":
        {"GOOGLE_MAPS_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","GOOGLE_MAPS_API_KEY","docker.io/acuvity/mcp-server-google-maps:0.6.2"]
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
    "acuvity-mcp-server-google-maps": {
      "env":
        {"GOOGLE_MAPS_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","GOOGLE_MAPS_API_KEY","docker.io/acuvity/mcp-server-google-maps:0.6.2"]
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
    "acuvity-mcp-server-google-maps": {
      "env":
        {"GOOGLE_MAPS_API_KEY":"xxxxxx"},
      "command": "docker",
      "args": ["run","-i","--rm","--read-only","-e","GOOGLE_MAPS_API_KEY","docker.io/acuvity/mcp-server-google-maps:0.6.2"]
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
        "env": {"GOOGLE_MAPS_API_KEY":"xxxxxx"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","GOOGLE_MAPS_API_KEY","docker.io/acuvity/mcp-server-google-maps:0.6.2"]
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

## 🧰 Tools (7)
<details>
<summary>maps_geocode</summary>

**Description**:

```
Convert an address into geographic coordinates
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| address | string | The address to geocode | Yes
</details>
<details>
<summary>maps_reverse_geocode</summary>

**Description**:

```
Convert coordinates into an address
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| latitude | number | Latitude coordinate | Yes
| longitude | number | Longitude coordinate | Yes
</details>
<details>
<summary>maps_search_places</summary>

**Description**:

```
Search for places using Google Places API
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| location | object | Optional center point for the search | No
| query | string | Search query | Yes
| radius | number | Search radius in meters (max 50000) | No
</details>
<details>
<summary>maps_place_details</summary>

**Description**:

```
Get detailed information about a specific place
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| place_id | string | The place ID to get details for | Yes
</details>
<details>
<summary>maps_distance_matrix</summary>

**Description**:

```
Calculate travel distance and time for multiple origins and destinations
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destinations | array | Array of destination addresses or coordinates | Yes
| mode | string | Travel mode (driving, walking, bicycling, transit) | No
| origins | array | Array of origin addresses or coordinates | Yes
</details>
<details>
<summary>maps_elevation</summary>

**Description**:

```
Get elevation data for locations on the earth
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| locations | array | Array of locations to get elevation for | Yes
</details>
<details>
<summary>maps_directions</summary>

**Description**:

```
Get directions between two points
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination | string | Ending point address or coordinates | Yes
| mode | string | Travel mode (driving, walking, bicycling, transit) | No
| origin | string | Starting point address or coordinates | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | maps_directions | description | be6edc95fb62438faec05e86835dc456919392d8cf18526c951c7a08a4313958 |
| tools | maps_directions | destination | 2df250de879f7966a9a78785f234cd66b5e147e87cbe9235d5c7ecbef8114710 |
| tools | maps_directions | mode | fd11df1d8e93e808e44de93385fbb9ac0c42538e437d75eda08274e8f3656043 |
| tools | maps_directions | origin | 3b406abd35291a57c8bc98bfafc14dd5d385826e32a0b18d60e73e12c339867b |
| tools | maps_distance_matrix | description | e7862ed22fd55bcb4f38ff942ab0e152ed48f7586dd721e853a658560ce3f4e7 |
| tools | maps_distance_matrix | destinations | 603580b8ba0838fa89d01745f70e3ca800f38d37edfc34345e7d924027512541 |
| tools | maps_distance_matrix | mode | fd11df1d8e93e808e44de93385fbb9ac0c42538e437d75eda08274e8f3656043 |
| tools | maps_distance_matrix | origins | 6e86b75f528b3da9d842ea051020b59ca37b9cbdaa15159304c29211064f087f |
| tools | maps_elevation | description | 81010e93681dd9f4bb9bdd2b85b6f39f81d21e646380ddf4d590470a0ee2a2a5 |
| tools | maps_elevation | locations | 69af1eac3164bb92e5f241a90143aa9211a0b3993a465dd7f852aa0714d358da |
| tools | maps_geocode | description | a2385eab251b9571f1077b9635182b2de477beb3cdcc6e55984676e2f15b190a |
| tools | maps_geocode | address | 939c8b85e25ecceaeff4e531c5bc982d4be3d0d55ec91a2f17112bce002b1d57 |
| tools | maps_place_details | description | aa55b1ece847bf2602c7105930e3b77aeeff6001ab9b0228948124d493276746 |
| tools | maps_place_details | place_id | a31d452f480641a67d14ebb9211a132acae6e656a87dee7619a6ab95357140ef |
| tools | maps_reverse_geocode | description | 54a9f75c9bdf1a133afa572717edfe37c98fe7320d2a8cf716523347bd5fe84d |
| tools | maps_reverse_geocode | latitude | 104f84a6e60f6931e5dae557844d219c4399aac6977371a1fe478e03225ac37a |
| tools | maps_reverse_geocode | longitude | d1ee91527f594ffba2e15f4474146840c27810eb1b7b3637df3c35da6614fe88 |
| tools | maps_search_places | description | fe1f5391f114826110e251991e5b7cee4b0140d408eceb7601e6f70d3baf596b |
| tools | maps_search_places | location | 078c6550e737ec47a7b41ca7625466380af519f70e3b14f3f5ea97097a8e9bd6 |
| tools | maps_search_places | query | 9eef05233ecfc1fbcfe756aa79bd497fa20e58144012561b562b8856040f5100 |
| tools | maps_search_places | radius | b990286c4cbfb7fff848cf8a4a0588fd0ae823356374dada25f39106e8cee86e |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
