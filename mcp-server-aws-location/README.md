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


# What is mcp-server-aws-location?
[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-aws-location/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-aws-location/2.0.1?logo=docker&logoColor=fff&label=2.0.1)](https://hub.docker.com/r/acuvity/mcp-server-aws-location)
[![PyPI](https://img.shields.io/badge/2.0.1-3775A9?logo=pypi&logoColor=fff&label=awslabs.aws-location-mcp-server)](https://github.com/awslabs/mcp/tree/HEAD/src/aws-location-mcp-server)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-aws-location/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-location&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-location%3A2.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** AWS Location Service MCP server for place search, geocoding, and route calculation

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from awslabs.aws-location-mcp-server original [sources](https://github.com/awslabs/mcp/tree/HEAD/src/aws-location-mcp-server).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-aws-location/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-location/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-location/charts/mcp-server-aws-location/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure awslabs.aws-location-mcp-server run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-location/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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


# 📦 How to Install


> [!TIP]
> Given mcp-server-aws-location scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `AWS_REGION` optional (not set)
  - `AWS_PROFILE` optional (not set)
  - `AWS_ACCESS_KEY_ID` optional (not set)
  - `AWS_SECRET_ACCESS_KEY` optional (not set)
  - `AWS_SESSION_TOKEN` optional (not set)

For more information and extra configuration you can consult the [package](https://github.com/awslabs/mcp/tree/HEAD/src/aws-location-mcp-server) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-aws-location&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-aws-location%3A2.0.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-aws-location": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-aws-location:2.0.1"
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
    "acuvity-mcp-server-aws-location": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-location:2.0.1"
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
    "acuvity-mcp-server-aws-location": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-location:2.0.1"
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
    "acuvity-mcp-server-aws-location": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-location:2.0.1"
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
    "acuvity-mcp-server-aws-location": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-aws-location:2.0.1"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-aws-location:2.0.1"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-aws-location:2.0.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only docker.io/acuvity/mcp-server-aws-location:2.0.1
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-aws-location": {
      "url": "http://localhost:8000/sse"
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
    "acuvity-mcp-server-aws-location": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Minibridge offers a host of additional features. For step-by-step guidance, please visit the wiki. And if anything’s unclear, don’t hesitate to reach out!

</details>

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Optional Secrets**:
  - `AWS_ACCESS_KEY_ID` secret to be set as secrets.AWS_ACCESS_KEY_ID either by `.value` or from existing with `.valueFrom`
  - `AWS_SECRET_ACCESS_KEY` secret to be set as secrets.AWS_SECRET_ACCESS_KEY either by `.value` or from existing with `.valueFrom`
  - `AWS_SESSION_TOKEN` secret to be set as secrets.AWS_SESSION_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `AWS_REGION=""` environment variable can be changed with env.AWS_REGION=""
  - `AWS_PROFILE=""` environment variable can be changed with env.AWS_PROFILE=""

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-aws-location --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-aws-location --version 1.0.0
````

Install with helm

```console
helm install mcp-server-aws-location oci://docker.io/acuvity/mcp-server-aws-location --version 1.0.0
```

From there your MCP server mcp-server-aws-location will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-aws-location` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-aws-location/charts/mcp-server-aws-location/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (7)
<details>
<summary>search_places</summary>

**Description**:

```
Search for places using Amazon Location Service geo-places search_text API. Geocode the query using the geocode API to get BiasPosition. If no results, try a bounding box filter. Includes contact info and opening hours if present. Output is standardized and includes all fields, even if empty or not available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| max_results | integer | Maximum number of results to return | No
| mode | string | Output mode: 'summary' (default) or 'raw' for all AWS fields | No
| query | string | Search query (address, place name, etc.) | Yes
</details>
<details>
<summary>get_place</summary>

**Description**:

```
Get details for a place using Amazon Location Service geo-places get_place API. Output is standardized and includes all fields, even if empty or not available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| mode | string | Output mode: 'summary' (default) or 'raw' for all AWS fields | No
| place_id | string | The unique PlaceId for the place | Yes
</details>
<details>
<summary>reverse_geocode</summary>

**Description**:

```
Reverse geocode coordinates to an address using Amazon Location Service geo-places reverse_geocode API.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| latitude | number | Latitude of the location | Yes
| longitude | number | Longitude of the location | Yes
</details>
<details>
<summary>search_nearby</summary>

**Description**:

```
Search for places near a location using Amazon Location Service geo-places search_nearby API. If no results, expand the radius up to max_radius. Output is standardized and includes all fields, even if empty or not available.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| latitude | number | Latitude of the center point | Yes
| longitude | number | Longitude of the center point | Yes
| max_results | integer | Maximum number of results to return | No
| query | any | Optional search query | No
| radius | integer | Search radius in meters | No
</details>
<details>
<summary>search_places_open_now</summary>

**Description**:

```
Search for places that are open now using Amazon Location Service geo-places search_text API and filter by opening hours. If no open places, expand the search radius up to max_radius. Uses BiasPosition from geocode.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| initial_radius | integer | Initial search radius in meters for expansion | No
| query | string | Search query (address, place name, etc.) | Yes
</details>
<details>
<summary>calculate_route</summary>

**Description**:

```
Calculate a route and return summary info and turn-by-turn directions.

    Parameters:
        departure_position: [lon, lat]
        destination_position: [lon, lat]
        travel_mode: 'Car', 'Truck', 'Walking', or 'Bicycle' (default: 'Car')
        optimize_for: 'FastestRoute' or 'ShortestRoute' (default: 'FastestRoute')

    Returns:
        dict with distance, duration, and turn_by_turn directions (list of step summaries).
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| departure_position | array | Departure position as [longitude, latitude] | Yes
| destination_position | array | Destination position as [longitude, latitude] | Yes
| optimize_for | string | Optimize route for 'FastestRoute' or 'ShortestRoute' (default: 'FastestRoute') | No
| travel_mode | string | Travel mode: 'Car', 'Truck', 'Walking', or 'Bicycle' (default: 'Car') | No
</details>
<details>
<summary>optimize_waypoints</summary>

**Description**:

```
Optimize the order of waypoints using Amazon Location Service geo-routes optimize_waypoints API (V2).

    Returns summary (optimized order, total distance, duration, etc.) or full response if mode='raw'.
    
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| destination_position | array | Destination position as [longitude, latitude] | Yes
| mode | string | Output mode: 'summary' (default) or 'raw' for all AWS fields | No
| origin_position | array | Origin position as [longitude, latitude] | Yes
| travel_mode | string | Travel mode: 'Car', 'Truck', 'Walking', or 'Bicycle' (default: 'Car') | No
| waypoints | array | List of intermediate waypoints, each as a dict with at least Position [longitude, latitude], optionally Id | Yes
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | calculate_route | description | 6aa07c891095443e82a2ded61040e0f3ab77191fe4b71cecfbbcd6255dc8d1d6 |
| tools | calculate_route | departure_position | 02d3c3e194d934d0b0518863597ceb75523c8ea623861bd053a5e8b44d031a51 |
| tools | calculate_route | destination_position | 1692a571ac9e29bc0a11f1e16f6c1b1ed42f988b539df04d64b76056b75fb92d |
| tools | calculate_route | optimize_for | 5d1bc0ca69b9ae39c3b279950e65373a82795958d9aca5d46712c647383d6d1d |
| tools | calculate_route | travel_mode | e70c6762ede4716c33f0882fddf60e4164858a3d1d8cecbf1d0054d26a533caa |
| tools | get_place | description | fa018740b159a255a8fe8c69d299dc9f719a718c5fa95ce4634a3b57ecfa0012 |
| tools | get_place | mode | 6b85486d21f4ca331a47387a47bf7ab1214bb4fec0f8c706254fd8e888a09254 |
| tools | get_place | place_id | d065778edb9c66f96c79fa8ce71eb92bfb7a158e8e920200e79b5afe0a3df157 |
| tools | optimize_waypoints | description | ed7253d2ac6c813927ff96a951286a5385e06ade518105767565281367f2b1f3 |
| tools | optimize_waypoints | destination_position | 1692a571ac9e29bc0a11f1e16f6c1b1ed42f988b539df04d64b76056b75fb92d |
| tools | optimize_waypoints | mode | 6b85486d21f4ca331a47387a47bf7ab1214bb4fec0f8c706254fd8e888a09254 |
| tools | optimize_waypoints | origin_position | 1ed360dce1b9da752d5f9a96acf98bd89434668abb62dac5d4345e860aa813d9 |
| tools | optimize_waypoints | travel_mode | e70c6762ede4716c33f0882fddf60e4164858a3d1d8cecbf1d0054d26a533caa |
| tools | optimize_waypoints | waypoints | e86d10cb3b4a0451beb3fbb62704a1a758a30f9f755f3f4845a42f1b29f60aa6 |
| tools | reverse_geocode | description | 1256dba252fa448f207a15a7ac3a199b288a1e65811dfcb7b9c1b464f50f2fa9 |
| tools | reverse_geocode | latitude | 29f9df79b499e307fda27c69f976f89e328f88b5efa54679324a44c9c17b1e22 |
| tools | reverse_geocode | longitude | b6fbdac19067f2a638aaff2aa2f778ff9ece63ecf5ad15b833cd652ad5bd22bf |
| tools | search_nearby | description | 1a439190ee8f266dddce69961802f5f270ad14ff81fc872e095c3eb3875a0059 |
| tools | search_nearby | latitude | db286667a8763ab81c4ef01f76d473415856f74b8f07a61408aea669febf0e56 |
| tools | search_nearby | longitude | f9961110c3ed862dbdc8f016bb7746bf45eb78eafd01c1ac2b8d1d4e0fa78526 |
| tools | search_nearby | max_results | b04468046d2f2a5692b75e7d703a30fd2787b8f80972a3b07b618e4ca4b3fa70 |
| tools | search_nearby | query | 1db0ca55a8b4c6d39f157b5a149e63d3362ccbd4f9a1471ca2d39df3932d1eba |
| tools | search_nearby | radius | 6cb997bc2ace62eb134ca415b9201307e7bab593925550bdcdc9fca22f0a9d90 |
| tools | search_places | description | b6f879fe76c07430684eacd548492fe5241f79d72e8d862cb3db2baad3b512cd |
| tools | search_places | max_results | b04468046d2f2a5692b75e7d703a30fd2787b8f80972a3b07b618e4ca4b3fa70 |
| tools | search_places | mode | 6b85486d21f4ca331a47387a47bf7ab1214bb4fec0f8c706254fd8e888a09254 |
| tools | search_places | query | f9bb417383fa30c0469210f6828d12dea88ed17b3084d2eac8ab27dac20c6742 |
| tools | search_places_open_now | description | c0f32b1b0a7bda367e8957fa4672fe35933ec44aaab364c9728581a1eda07919 |
| tools | search_places_open_now | initial_radius | 04b08399046e0b2b0e5496385e48cd7ccae7e3513c21782c097d0053d278754d |
| tools | search_places_open_now | query | f9bb417383fa30c0469210f6828d12dea88ed17b3084d2eac8ab27dac20c6742 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
