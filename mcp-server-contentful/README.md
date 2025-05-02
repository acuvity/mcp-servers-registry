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


# What is mcp-server-contentful?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-contentful/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-contentful/1.13.1?logo=docker&logoColor=fff&label=1.13.1)](https://hub.docker.com/r/acuvity/mcp-server-contentful)
[![PyPI](https://img.shields.io/badge/1.13.1-3775A9?logo=pypi&logoColor=fff&label=@ivotoby/contentful-management-mcp-server)](https://github.com/ivo-toby/contentful-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-contentful&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CONTENTFUL_MANAGEMENT_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-contentful%3A1.13.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Update, create, delete content, content-models and assets in your Contentful Space.

> [!NOTE]
> `@ivotoby/contentful-management-mcp-server` has been repackaged by Acuvity from Author original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @ivotoby/contentful-management-mcp-server run reliably and safely.

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
> Given mcp-server-contentful scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-contentful&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CONTENTFUL_MANAGEMENT_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-contentful%3A1.13.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-contentful": {
        "env": {
          "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN",
          "docker.io/acuvity/mcp-server-contentful:1.13.1"
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
    "acuvity-mcp-server-contentful": {
      "env": {
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-contentful:1.13.1"
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
    "acuvity-mcp-server-contentful": {
      "env": {
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-contentful:1.13.1"
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
    "acuvity-mcp-server-contentful": {
      "env": {
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-contentful:1.13.1"
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
    "acuvity-mcp-server-contentful": {
      "env": {
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CONTENTFUL_MANAGEMENT_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-contentful:1.13.1"
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
        "env": {"CONTENTFUL_MANAGEMENT_ACCESS_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","CONTENTFUL_MANAGEMENT_ACCESS_TOKEN","docker.io/acuvity/mcp-server-contentful:1.13.1"]
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
  - `CONTENTFUL_MANAGEMENT_ACCESS_TOKEN` required to be set


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e CONTENTFUL_MANAGEMENT_ACCESS_TOKEN docker.io/acuvity/mcp-server-contentful:1.13.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e CONTENTFUL_MANAGEMENT_ACCESS_TOKEN docker.io/acuvity/mcp-server-contentful:1.13.1
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-contentful": {
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
    "acuvity-mcp-server-contentful": {
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
  - `CONTENTFUL_MANAGEMENT_ACCESS_TOKEN` secret to be set as secrets.CONTENTFUL_MANAGEMENT_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart:

```console
helm show chart oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0
````

Install with helm

```console
helm install mcp-server-contentful oci://docker.io/acuvity/mcp-server-contentful --version 1.0.0
```

From there your MCP server mcp-server-contentful will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-contentful` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-contentful/charts/mcp-server-contentful/README.md) for more details about settings.

</details>

# 🧠 Server features

## 🧰 Tools (35)
<details>
<summary>search_entries</summary>

**Description**:

```
Search for entries using query parameters. Returns a maximum of 3 items per request. Use skip parameter to paginate through results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| query | object | Query parameters for searching entries | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>create_entry</summary>

**Description**:

```
Create a new entry in Contentful, before executing this function, you need to know the contentTypeId (not the content type NAME) and the fields of that contentType, you can get the fields definition by using the GET_CONTENT_TYPE tool. 
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | The ID of the content type for the new entry | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | object | The fields of the entry | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>get_entry</summary>

**Description**:

```
Retrieve an existing entry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>update_entry</summary>

**Description**:

```
Update an existing entry, very important: always send all field values and all values related to locales, also the fields values that have not been updated
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | object | not set | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>delete_entry</summary>

**Description**:

```
Delete an entry
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_entry</summary>

**Description**:

```
Publish an entry or multiple entries. Accepts either a single entryId (string) or an array of entryIds (up to 100 entries). For a single entry, it uses the standard publish operation. For multiple entries, it automatically uses bulk publishing.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | any | ID of the entry to publish, or an array of entry IDs (max: 100) | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>unpublish_entry</summary>

**Description**:

```
Unpublish an entry or multiple entries. Accepts either a single entryId (string) or an array of entryIds (up to 100 entries). For a single entry, it uses the standard unpublish operation. For multiple entries, it automatically uses bulk unpublishing.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryId | any | ID of the entry to unpublish, or an array of entry IDs (max: 100) | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_assets</summary>

**Description**:

```
List assets in a space. Returns a maximum of 3 items per request. Use skip parameter to paginate through results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| limit | number | Maximum number of items to return (max: 3) | Yes
| skip | number | Number of items to skip for pagination | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>upload_asset</summary>

**Description**:

```
Upload a new asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| file | object | not set | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| title | string | not set | Yes
</details>
<details>
<summary>get_asset</summary>

**Description**:

```
Retrieve an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>update_asset</summary>

**Description**:

```
Update an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| description | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| file | object | not set | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| title | string | not set | No
</details>
<details>
<summary>delete_asset</summary>

**Description**:

```
Delete an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_asset</summary>

**Description**:

```
Publish an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>unpublish_asset</summary>

**Description**:

```
Unpublish an asset
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| assetId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_content_types</summary>

**Description**:

```
List content types in a space. Returns a maximum of 10 items per request. Use skip parameter to paginate through results.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| limit | number | Maximum number of items to return (max: 3) | Yes
| skip | number | Number of items to skip for pagination | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>get_content_type</summary>

**Description**:

```
Get details of a specific content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>create_content_type</summary>

**Description**:

```
Create a new content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | No
| displayField | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | array | Array of field definitions for the content type | Yes
| name | string | not set | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>update_content_type</summary>

**Description**:

```
Update an existing content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| description | string | not set | No
| displayField | string | not set | No
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| fields | array | not set | Yes
| name | string | not set | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>delete_content_type</summary>

**Description**:

```
Delete a content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_content_type</summary>

**Description**:

```
Publish a content type
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| contentTypeId | string | not set | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_spaces</summary>

**Description**:

```
List all available spaces
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>get_space</summary>

**Description**:

```
Get details of a space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| spaceId | string | not set | Yes
</details>
<details>
<summary>list_environments</summary>

**Description**:

```
List all environments in a space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| spaceId | string | not set | Yes
</details>
<details>
<summary>create_environment</summary>

**Description**:

```
Create a new environment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | not set | Yes
| name | string | not set | Yes
| spaceId | string | not set | Yes
</details>
<details>
<summary>delete_environment</summary>

**Description**:

```
Delete an environment
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | not set | Yes
| spaceId | string | not set | Yes
</details>
<details>
<summary>bulk_validate</summary>

**Description**:

```
Validate multiple entries at once
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| entryIds | array | Array of entry IDs to validate | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>list_ai_actions</summary>

**Description**:

```
List all AI Actions in a space
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| limit | number | Maximum number of AI Actions to return | No
| skip | number | Number of AI Actions to skip for pagination | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| status | string | Filter AI Actions by status | No
</details>
<details>
<summary>get_ai_action</summary>

**Description**:

```
Get a specific AI Action by ID
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to retrieve | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>create_ai_action</summary>

**Description**:

```
Create a new AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| configuration | object | The model configuration | Yes
| description | string | The description of the AI Action | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| instruction | object | The instruction object containing the template and variables | Yes
| name | string | The name of the AI Action | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| testCases | array | Optional array of test cases for the AI Action | No
</details>
<details>
<summary>update_ai_action</summary>

**Description**:

```
Update an existing AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to update | Yes
| configuration | object | The model configuration | Yes
| description | string | The description of the AI Action | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| instruction | object | The instruction object containing the template and variables | Yes
| name | string | The name of the AI Action | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| testCases | array | Optional array of test cases for the AI Action | No
</details>
<details>
<summary>delete_ai_action</summary>

**Description**:

```
Delete an AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to delete | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>publish_ai_action</summary>

**Description**:

```
Publish an AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to publish | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>unpublish_ai_action</summary>

**Description**:

```
Unpublish an AI Action
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to unpublish | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>
<details>
<summary>invoke_ai_action</summary>

**Description**:

```
Invoke an AI Action with variables
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action to invoke | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| outputFormat | string | The format of the output content | No
| rawVariables | array | Array of raw variable objects (for complex variable types like references) | No
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
| variables | object | Key-value pairs of variable IDs and their values | No
| waitForCompletion | boolean | Whether to wait for the AI Action to complete before returning | No
</details>
<details>
<summary>get_ai_action_invocation</summary>

**Description**:

```
Get the result of a previous AI Action invocation
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| aiActionId | string | The ID of the AI Action | Yes
| environmentId | string | The ID of the environment within the space, by default this will be called Master | Yes
| invocationId | string | The ID of the specific invocation to retrieve | Yes
| spaceId | string | The ID of the Contentful space. This must be the space's ID, not its name, ask for this ID if it's unclear. | Yes
</details>

## 📝 Prompts (14)
<details>
<summary>explain-api-concepts</summary>

**Description**:

```
Explain Contentful API concepts and relationships
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| concept | Contentful concept (Space/Environment/ContentType/Entry/Asset) |Yes |
<details>
<summary>space-identification</summary>

**Description**:

```
Guide for identifying the correct Contentful space for operations
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| operation | Operation you want to perform |Yes |
<details>
<summary>content-modeling-guide</summary>

**Description**:

```
Guide through content modeling decisions and best practices
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| useCase | Description of the content modeling scenario |Yes |
<details>
<summary>api-operation-help</summary>

**Description**:

```
Get detailed help for specific Contentful API operations
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| operation | API operation (CRUD, publish, archive, etc) |Yes |
| resourceType | Type of resource (Entry/Asset/ContentType) |Yes |
<details>
<summary>entry-management</summary>

**Description**:

```
Help with CRUD operations and publishing workflows for content entries
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (create/read/update/delete/publish/unpublish/bulk) |No |
| details | Additional context or requirements |No |
<details>
<summary>asset-management</summary>

**Description**:

```
Guidance on managing digital assets like images, videos, and documents
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (upload/process/update/delete/publish) |No |
| details | Additional context about asset types or requirements |No |
<details>
<summary>content-type-operations</summary>

**Description**:

```
Help with defining and managing content types and their fields
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (create/update/delete/publish/field configuration) |No |
| details | Additional context about field types or validations |No |
<details>
<summary>ai-actions-overview</summary>

**Description**:

```
Comprehensive overview of AI Actions in Contentful
```
<details>
<summary>ai-actions-create</summary>

**Description**:

```
Guide for creating and configuring AI Actions in Contentful
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| useCase | Purpose of the AI Action you want to create |Yes |
| modelType | AI model type (e.g., gpt-4, claude-3-opus) |No |
<details>
<summary>ai-actions-variables</summary>

**Description**:

```
Explanation of variable types and configuration for AI Actions
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| variableType | Type of variable (Text, Reference, StandardInput, etc) |No |
<details>
<summary>ai-actions-invoke</summary>

**Description**:

```
Help with invoking AI Actions and processing results
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| actionId | ID of the AI Action (if known) |No |
| details | Additional context about your invocation requirements |No |
<details>
<summary>bulk-operations</summary>

**Description**:

```
Guidance on performing actions on multiple entities simultaneously
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| operation | Bulk operation type (publish/unpublish/validate) |No |
| entityType | Type of entities to process (entries/assets) |No |
| details | Additional context about operation requirements |No |
<details>
<summary>space-environment-management</summary>

**Description**:

```
Help with managing spaces, environments, and deployment workflows
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| task | Specific task (create/list/manage environments/aliases) |No |
| entity | Entity type (space/environment) |No |
| details | Additional context about workflow requirements |No |
<details>
<summary>mcp-tool-usage</summary>

**Description**:

```
Instructions for using Contentful MCP tools effectively
```

**Parameter**:

| Argument | Description | Required |
|-----------|------|-------------|
| toolName | Specific tool name (e.g., invoke_ai_action, create_entry) |No |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| prompts | ai-actions-create | description | 04499ec6931bdbbaf3c31efc46867ff4d15a3265dcbc2ace61a162a708ce819b |
| prompts | ai-actions-create | modelType | 9dfcc5d7d4f46417567cad6cc2763e3c4fd846616150775df8aead5a21cf03e2 |
| prompts | ai-actions-create | useCase | b3fadad4cca866ea6a0af5ea9f4e039b1ecedb39b6fd519a394a453edd5beff0 |
| prompts | ai-actions-invoke | description | 52e8446af97f14b421401959ee22a6497b899ded39970eb21d61fe01620e230b |
| prompts | ai-actions-invoke | actionId | aceaef2f47d6f48f42b1475e35da3981185bf460497724f1f03868b88de6552d |
| prompts | ai-actions-invoke | details | 1320cdcf05919ff23e26d3345cee4d12473d6425d6a2fc853dc7e8830fa8ae14 |
| prompts | ai-actions-overview | description | ac01a2f621066d33ba866fd4bda29b67e2cbf17ea248f26187633e2b40997c4d |
| prompts | ai-actions-variables | description | cb29b5346bcf53c1b45c4c47086c199aaeb552bee81c941df59a42ad57606ce8 |
| prompts | ai-actions-variables | variableType | 61d7be4997f2965220a27b0683d008f7bf3f102990cdef003191ef2fc7d45d89 |
| prompts | api-operation-help | description | bec79ef2f1d7f1f7d5da6179c8c6aae4417101063122fa088e039c511b5f088b |
| prompts | api-operation-help | operation | 8d7c851d9342f2fc7885d6e383ef1f0371fa2414debe46eedeabd9811b19e5d7 |
| prompts | api-operation-help | resourceType | 97420bb6f450e7863a261b3f4ee1e1def0fed7c4b3e38e4d432bfc4e943b1a47 |
| prompts | asset-management | description | d6d4f3f6128ce73f7c892b137ac8a4ec32fee70c0d9532101608880649a3981c |
| prompts | asset-management | details | 481aaa4af76433ba1e711959678bf714a886318487669b2b8bb7c4c7e6085f4a |
| prompts | asset-management | task | 4c47ac467e18ba528dec44f37bda1b82a32c1597f2e348158366f981fdef2961 |
| prompts | bulk-operations | description | 6094c65ce88cdee99c15f72b80e3988d431bc0a7d49c125bccbb361881d2843b |
| prompts | bulk-operations | details | 267da141093b89c8df57b5711c0b1f0564ffe6e24ff4293e5a1ca1df5b5d76f7 |
| prompts | bulk-operations | entityType | e9e86161585d8773b014cbedeb41952e5cb4bd148ca30acebff21db3cc315636 |
| prompts | bulk-operations | operation | e953f9c8d0f275f816fb0832707d0476df143a79722e3cbb5fc750560ecad32d |
| prompts | content-modeling-guide | description | cacbd0d028478ddeac81a48491d6b4865699c726bebf0fea8f9d58b86e0ecb4f |
| prompts | content-modeling-guide | useCase | 742e58a5952e3ecf1e44aede7f946f6e5300e43d8d97feafcb2dbfbdfe4d1dce |
| prompts | content-type-operations | description | 6e109a3fd416c150e4d0cd71aa4b4124ac83779fd06443215c9b41666f8bb017 |
| prompts | content-type-operations | details | 6bc1ca6d233efa0bafb86453a95c6e9939697c65ea221fba183a894ef4d8f032 |
| prompts | content-type-operations | task | 469f4a49e5ef2ba9d69a61976cde0a8645d85e71f2f568894c4b4f5160f48b5a |
| prompts | entry-management | description | 3da363eb43fc113125caf7656cecc0b5a4305c30c31994613bd13dcee546a58f |
| prompts | entry-management | details | 25b4017796283cde87c655584d3c99a3867a801cab5c95c4e15e8eae93ae292c |
| prompts | entry-management | task | 4d6866bc18a8ea46246fc6c4db0d2cfe581d641649edab1be01e814de82ff3ab |
| prompts | explain-api-concepts | description | 4952c00f37238d1ca7e245fa82e5497248ab4c5bb2244497cf302fa9d8830b24 |
| prompts | explain-api-concepts | concept | 507f981d9d92b55ac0a3f3bd412615d9223b77fcabdc030d052b6debaa5f15e6 |
| prompts | mcp-tool-usage | description | 2c173ee0b55f51f1b348693bc9cdccc412eb68ee4b7375fa7437fd7bf81d0f11 |
| prompts | mcp-tool-usage | toolName | 8de2b1ca936682136c1723d1d4bca5cc33bea7752a326a73cc75b4c68b86be89 |
| prompts | space-environment-management | description | 8314ebadb16bbe2ad74f77957b124ba68de098562ea1d5b8fd0bb288d00a5195 |
| prompts | space-environment-management | details | 5a4d5eaea58b0e5423e15a6fce9c4af71b266a56e1c2fb2ef3cc4a6ac3dbf888 |
| prompts | space-environment-management | entity | 5184fcd64e7af348a207b4ad8954f3fe43c50a95573958a8855bf4a057c82b19 |
| prompts | space-environment-management | task | 1be912127cba1e2e9a58addade2092215288b45fd136baecb896d2d33cf40460 |
| prompts | space-identification | description | 3d70262daa49e68385713c991f479d978aaa0d60f374035dea1fef1cfb9cb8d4 |
| prompts | space-identification | operation | f86180ad94a556cc138da9712ae9c0fa612b890f28968b511b71980f303594f9 |
| tools | bulk_validate | description | 8ecb4456ace22c28b31473a59a7f7e2aafd9ad306660dfb7f5aa863f2b0339e1 |
| tools | bulk_validate | entryIds | cfb850350044490d46c9983a9681deb2b9cdbf744fffbfedd1bef58721f785fe |
| tools | bulk_validate | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | bulk_validate | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_ai_action | description | 37a11ccdfa19933c2800b850d290e68d97b066cd943c4dd8f5be8e1dde59527d |
| tools | create_ai_action | configuration | f9a3b300f3826bdb97e5ae6b377e653524cbe4cc7804ae95eb171c724a5573ef |
| tools | create_ai_action | description | 738b104b409f46bd943a50c5499f7027bf6544187b26626dc571fb29ca569253 |
| tools | create_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | create_ai_action | instruction | ebef280526abae1f91c3bbda5ec014e2406c624336fbd84e3c1b2fdb09e31e60 |
| tools | create_ai_action | name | c44e12cb538c2b6005353bdaa62fff36e89f40a1e3f98ac0c4807bbebb58fb6e |
| tools | create_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_ai_action | testCases | 195eaaf33aaf9a64981d3ae293b34297dd65614fd38592b2e4e9a8391bc056a6 |
| tools | create_content_type | description | d9744dc50d28fd896e176539b86c4d516298734c6c660c2a91a49b670b262a20 |
| tools | create_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | create_content_type | fields | 7e77d1884050a7aa4e0929815065ae045983a263c6ead31e28a0b28f1f1b7eaa |
| tools | create_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_entry | description | c1aae970359d9d305f7c2406cf750ab0a2ab8e175ed5f8b96c1e24eaff2c437d |
| tools | create_entry | contentTypeId | 957e01d15b8b4bb3a68264cc2127b3cbcfd6da3ed8cb2d7a82a9d86834d2e592 |
| tools | create_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | create_entry | fields | 992f0a1f879b5f76a0f218fc9c008340914f9d07ef29d35968ed952250d22338 |
| tools | create_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | create_environment | description | 82054b8ea3438535752e8a25bd56d0d23d304f8922bbcf9cd1905c0b5cd8cb12 |
| tools | delete_ai_action | description | acecc366a1002d97e05ae5a4223a9cdff1fc5ca008c5b99df0deeb9ef15c403c |
| tools | delete_ai_action | aiActionId | 9dd183dbe320721e68e17a97af3ebbdf738588d07f9c405d336f055c9b573eb1 |
| tools | delete_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_asset | description | 6c7c32568e6a7561f8f0415ea51e55a393f63285fe479a88c5d67a0361632b3c |
| tools | delete_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_content_type | description | dd3069640d149019bf7e31d4d2dec205214fdd3254c1b965df50548f33f3775a |
| tools | delete_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_entry | description | e035171af6f9f50e51b2a950ad298dbd11db9a3453f09c25d86e37f37657820c |
| tools | delete_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | delete_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | delete_environment | description | d71ccc7a648f021ca5e93376a7ec68e806947a2fe212f2e482e35805348e34e7 |
| tools | get_ai_action | description | 2a129b4f3e58dbb177e1ca6687be39186ff714ab86efde968e9cc5ff1c6b45b0 |
| tools | get_ai_action | aiActionId | ec6acb40764c4080207248094c332989c847a2cdfe1aa58eb46e9d3744d5c003 |
| tools | get_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_ai_action_invocation | description | 8b842c74c84b7761946264e11e6caafdf485a4fe6deed98c8c3583174bfc82be |
| tools | get_ai_action_invocation | aiActionId | 88d16fb7ad95f1013ba5b9ef34cea54f6f41ac20c380109ef0ed475fc9a6d3cb |
| tools | get_ai_action_invocation | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_ai_action_invocation | invocationId | a973285ca3b19dcf75a3df5f0475c00c0aec8d49ab0c8e97f2faa95f79a9025d |
| tools | get_ai_action_invocation | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_asset | description | f8353610a7c481ca975a62389184e981f7b3a6414a50160fa0c8cba366e254af |
| tools | get_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_content_type | description | 2a5357bc685b1b5843c2868b1124211676da3cc45550fe3c688f6a060903ec2f |
| tools | get_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_entry | description | 1de1c52a44e35412db5b7ad38ca92ae9881a2655bb5dfe1ad1d5d0aad2aaefb2 |
| tools | get_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | get_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | get_space | description | da364db7e6f099c12704b9793a65be4732231c51cd272e87040a287adac3dd88 |
| tools | invoke_ai_action | description | 094d76f15f911a0b16205342cab4282094fcf8ce22b465bb24ffa1745dbfcae7 |
| tools | invoke_ai_action | aiActionId | d0be2c8158fd0e42df3ebd5949fc36f009c871ac5e83a84bb39b55f58fb5b3d9 |
| tools | invoke_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | invoke_ai_action | outputFormat | 9d2301676daaafc442127528bc01d39e9695787f8ac78fd49ca42b4dedacfd03 |
| tools | invoke_ai_action | rawVariables | dca5ee1b3ec4ae493f18822b37027480ba5d1ac7c42cc06e6584350b9d735749 |
| tools | invoke_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | invoke_ai_action | variables | fd104b359a3b6aaa7245bebdfe1d6d46f79783d9488c81404bda970c2d129323 |
| tools | invoke_ai_action | waitForCompletion | a4df206ef1cb6fdc68bdcd500ac68e68c9584fb2e239a6119f12909ff37efaaf |
| tools | list_ai_actions | description | bb0323f41ba668092677e1063b6414c814301be0ce0c5e3d1cdec22677997c3d |
| tools | list_ai_actions | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | list_ai_actions | limit | daf6a199ced3432a0669924c3a8a5cb68a294de7ca010084c63acf1b933a3f81 |
| tools | list_ai_actions | skip | f4522f1436198fca9e16ad4925e9823ff67be7621a7cfbf4fb9423c8a37ec0af |
| tools | list_ai_actions | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | list_ai_actions | status | 922717d3f4a75218be2ec6a0431f85aa1cddc723e78d2b3a3ac606bdb4a964f3 |
| tools | list_assets | description | 9f9580698576ca34e3b75be7d8d08b87ec3508c743edecd8f9fb89846ce77fb1 |
| tools | list_assets | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | list_assets | limit | 50ba5c893a7c24657d068bc5f09c36af857de3ab7ef725d930ba24e60864224e |
| tools | list_assets | skip | c5afb15fad11afbacdefce188b50323f10c5399af9c5c73570f8f87e1a5e46f5 |
| tools | list_assets | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | list_content_types | description | a755d641298d1d07ce423a0be43cfa56f6676ef77a426a527bbe865941c02ad4 |
| tools | list_content_types | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | list_content_types | limit | 50ba5c893a7c24657d068bc5f09c36af857de3ab7ef725d930ba24e60864224e |
| tools | list_content_types | skip | c5afb15fad11afbacdefce188b50323f10c5399af9c5c73570f8f87e1a5e46f5 |
| tools | list_content_types | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | list_environments | description | f3e98be6e8fd140fbdd5ca858ca874c62ff2b2f70ae6661441f2ab8b451475ae |
| tools | list_spaces | description | d21f58227d879eb9c8ac5eb9c628aaf68b8d54d12086acfbe51f93ee2789f384 |
| tools | publish_ai_action | description | ac8dbb10e199ad3a414b039c6bb0aac6a2606823d048f6997da8e287e9992ef5 |
| tools | publish_ai_action | aiActionId | 548dd0d2a0fb5464800ac6df64dca7504e9a544770eed634d6dc5c61f06ad939 |
| tools | publish_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | publish_asset | description | 3e158ff99829e5cee1a52c1306c6dfc57a6dfeaf9830ddfca6ced197ff2edfe3 |
| tools | publish_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | publish_content_type | description | 9f875bfafa8380b3ca6c560343365319bb3a85525c3a6586c61bf7e041b58fdb |
| tools | publish_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | publish_entry | description | ddfe4d54604e17e0a3832f982ff339d4951017bd9e2082d4725efcb7fe614bfa |
| tools | publish_entry | entryId | 30d966f244cd5d2bef94794c9032fd33a7f81fb767b2f8aefea6fa353eda4a7d |
| tools | publish_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | publish_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | search_entries | description | e169395ebfba855657162ec96336a9f2c0dffafd85f38471334f01a983adcbe4 |
| tools | search_entries | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | search_entries | query | 9c4707942dced800fc119a3c9c4fcacc9522d43e656e9cb3c638ee6cb36e5c86 |
| tools | search_entries | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | unpublish_ai_action | description | 556acf65db8245d8e9143d0cf4defdb8ab84db37bc35a7d039a1aa64d5423bd3 |
| tools | unpublish_ai_action | aiActionId | 3a850af2b4a9c08bc3123e13f376170f9a027ef07f954167d75933a6ebcffe44 |
| tools | unpublish_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | unpublish_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | unpublish_asset | description | ce18725d3b8294723b1017d325aa92c3c0edeb3f7ff51d4751478b00345bc966 |
| tools | unpublish_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | unpublish_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | unpublish_entry | description | a46a000388faf53148196363c067f30509cdc0906328bf7c3a99876e0d769ab4 |
| tools | unpublish_entry | entryId | 6af7f8142280aaad6c9b01b479a71f8cb8611c78387dd8d58aa4931d3c7d5a53 |
| tools | unpublish_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | unpublish_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_ai_action | description | 90d6a01c4004be0ed99acfd9aed6083bfc44fb958f7c3c2c1284090c5339db51 |
| tools | update_ai_action | aiActionId | ba1b82ad534e5a3b7a2ee31231ec2121b809394dd12430f9d87aa0ac51b22fa9 |
| tools | update_ai_action | configuration | f9a3b300f3826bdb97e5ae6b377e653524cbe4cc7804ae95eb171c724a5573ef |
| tools | update_ai_action | description | 738b104b409f46bd943a50c5499f7027bf6544187b26626dc571fb29ca569253 |
| tools | update_ai_action | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_ai_action | instruction | ebef280526abae1f91c3bbda5ec014e2406c624336fbd84e3c1b2fdb09e31e60 |
| tools | update_ai_action | name | c44e12cb538c2b6005353bdaa62fff36e89f40a1e3f98ac0c4807bbebb58fb6e |
| tools | update_ai_action | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_ai_action | testCases | 195eaaf33aaf9a64981d3ae293b34297dd65614fd38592b2e4e9a8391bc056a6 |
| tools | update_asset | description | 6e3aa72f38e0036da9795b34fb5fca4838d8fac910dbee7cb4560eddd1262825 |
| tools | update_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_content_type | description | dddc16016803deac06cd0b00cfb46199ec5bb4838e3a57dbdc317e367d801667 |
| tools | update_content_type | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_content_type | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | update_entry | description | c37726ed20c49012efeeeb182da909b70f80b1ec7dbf99d637988c55f8a4f1af |
| tools | update_entry | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | update_entry | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |
| tools | upload_asset | description | d74192920518f1dd41465b2fded572980e31c111e90879ceb5ec5d4453e617fe |
| tools | upload_asset | environmentId | 96da3c6e665898f36612669e041a2c4a4c566a8d8f96d2f2b15ea75addddae96 |
| tools | upload_asset | spaceId | b2b25781b62ebfe08437eea6849c06eba6f634a9cd4f203c7031a88f1ed22c47 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
