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


# What is mcp-server-chart?

[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chart/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chart/0.2.2?logo=docker&logoColor=fff&label=0.2.2)](https://hub.docker.com/r/acuvity/mcp-server-chart)
[![PyPI](https://img.shields.io/badge/0.2.2-3775A9?logo=pypi&logoColor=fff&label=@antv/mcp-server-chart)](https://github.com/antvis/mcp-server-chart)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chart&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-chart%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** A Model Context Protocol server for generating charts using AntV, This is a TypeScript-based MCP server that provides chart generation capabilities. It allows you to create various types of charts through MCP tools.

> [!NOTE]
> `@antv/mcp-server-chart` has been repackaged by Acuvity from AntV original sources.

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @antv/mcp-server-chart run reliably and safely.

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
> Given mcp-server-chart scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chart&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22docker.io%2Facuvity%2Fmcp-server-chart%3A0.2.2%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-chart": {
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "docker.io/acuvity/mcp-server-chart:0.2.2"
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
    "acuvity-mcp-server-chart": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-chart:0.2.2"
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
    "acuvity-mcp-server-chart": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-chart:0.2.2"
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
    "acuvity-mcp-server-chart": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-chart:0.2.2"
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
    "acuvity-mcp-server-chart": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "docker.io/acuvity/mcp-server-chart:0.2.2"
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
        "args": ["run","-i","--rm","--read-only","docker.io/acuvity/mcp-server-chart:0.2.2"]
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
- arguments: `run -i --rm --read-only docker.io/acuvity/mcp-server-chart:0.2.2`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only docker.io/acuvity/mcp-server-chart:0.2.2
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-chart": {
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
    "acuvity-mcp-server-chart": {
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
helm show chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0-
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-chart --version 1.0.0
````

Install with helm

```console
helm install mcp-server-chart oci://docker.io/acuvity/mcp-server-chart --version 1.0.0
```

From there your MCP server mcp-server-chart will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-chart` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chart/charts/mcp-server-chart/README.md) for more details about settings.

</details>
# 🧠 Server features

## 🧰 Tools (15)
<details>
<summary>generate_line_chart</summary>

**Description**:

```
Generate a line chart to show trends over time, such as, the ratio of Apple computer sales to Apple's profits changed from 2000 to 2016.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for line chart, such as, [{ time: '2015', value: 23 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, line charts require a 'group' field in the data. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_column_chart</summary>

**Description**:

```
Generate a column chart, which are best for comparing categorical data, such as, when values are close, column charts are preferable because our eyes are better at judging height than other visual elements like area or angles.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for column chart, such as, [{ category: '北京' value: 825; group: '油车' }]. | Yes
| group | boolean | Whether grouping is enabled. When enabled, column charts require a 'group' field in the data. | No
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, column charts require a 'group' field in the data. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_pie_chart</summary>

**Description**:

```
Generate a pie chart to show the proportion of parts, such as, market share and budget allocation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for pie chart, (such as, [{ category: '分类一', value: 27 }]) | Yes
| height | number | Set the height of chart, default is 400. | No
| innerRadius | number | Set the pie chart as a donut chart. Set the value to 0.6 to enable it. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_area_chart</summary>

**Description**:

```
Generate a area chart to show data trends under continuous independent variables and observe the overall data trend, such as, displacement = velocity (average or instantaneous) × time: s = v × t. If the x-axis is time (t) and the y-axis is velocity (v) at each moment, an area chart allows you to observe the trend of velocity over time and infer the distance traveled by the area's size.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for pie chart, such as, [{ time: '2018', value: 99.9 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, area charts require a 'group' field in the data. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_bar_chart</summary>

**Description**:

```
Generate a bar chart to show data for numerical comparisons among different categories, such as, comparing categorical data and for horizontal comparisons.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for bar chart, such as, [{ category: '分类一', value: 10 }]. | Yes
| group | boolean | Whether grouping is enabled. When enabled, bar charts require a 'group' field in the data. | No
| height | number | Set the height of chart, default is 400. | No
| stack | boolean | Whether stacking is enabled. When enabled, bar charts require a 'group' field in the data. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_histogram_chart</summary>

**Description**:

```
Generate a histogram chart to show the frequency of data points within a certain range. It can observe data distribution, such as, normal and skewed distributions, and identify data concentration areas and extreme points.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| binNumber | number | Number of intervals to define the number of intervals in a histogram. | No
| data | array | Data for bar chart, such as, [ 78, 88, 60, 100, 95 ]. | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_scatter_chart</summary>

**Description**:

```
Generate a scatter chart to show the relationship between two variables, helps discover their relationship or trends, such as, the strength of correlation, data distribution patterns.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for scatter chart, such as, [{ x: 10, y: 15 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_word_cloud_chart</summary>

**Description**:

```
Generate a word cloud chart to show word frequency or weight through text size variation, such as, analyzing common words in social media, reviews, or feedback.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for word cloud chart, such as, [{ value: '4.272', text: '形成' }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_radar_chart</summary>

**Description**:

```
Generate a radar chart to display multidimensional data (four dimensions or more), such as, evaluate Huawei and Apple phones in terms of five dimensions: ease of use, functionality, camera, benchmark scores, and battery life.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for radar chart, such as, [{ name: 'Design', value: 70 }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_treemap_chart</summary>

**Description**:

```
Generate a treemap chart to display hierarchical data and can intuitively show comparisons between items at the same level, such as, show disk space usage with treemap.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | array | Data for treemap chart, such as, [{ name: 'Design', value: 70, children: [{ name: 'Tech', value: 20 }] }]. | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_dual_axes_chart</summary>

**Description**:

```
Generate a dual axes chart which is a combination chart that integrates two different chart types, typically combining a bar chart with a line chart to display both the trend and comparison of data, such as, the trend of sales and profit over time.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| categories | array | Categories for dual axes chart, such as, ['2015', '2016', '2017']. | No
| height | number | Set the height of chart, default is 400. | No
| series | array | <no value> | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_mind_map</summary>

**Description**:

```
Generate a mind map chart to organizes and presents information in a hierarchical structure with branches radiating from a central topic, such as, a diagram showing the relationship between a main topic and its subtopics.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | object | Data for mind map chart, such as, { name: 'main topic', children: [{ name: 'topic 1', children: [{ name:'subtopic 1-1' }] } | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_network_graph</summary>

**Description**:

```
Generate a network graph chart to show relationships (edges) between entities (nodes), such as, relationships between people in social networks.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | object | Data for network graph chart, such as, { nodes: [{ name: 'node1' }, { name: 'node2' }], edges: [{ source: 'node1', target: 'node2', name: 'edge1' }] } | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_flow_diagram</summary>

**Description**:

```
Generate a flow diagram chart to show the steps and decision points of a process or system, such as, scenarios requiring linear process presentation.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | object | Data for flow diagram chart, such as, { nodes: [{ name: 'node1' }, { name: 'node2' }], edges: [{ source: 'node1', target: 'node2', name: 'edge1' }] } | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>
<details>
<summary>generate_fishbone_diagram</summary>

**Description**:

```
Generate a fishbone diagram chart to uses a fish skeleton, like structure to display the causes or effects of a core problem, with the problem as the fish head and the causes/effects as the fish bones. It suits problems that can be split into multiple related factors.
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| axisXTitle | string | Set the x-axis title of chart. | No
| axisYTitle | string | Set the y-axis title of chart. | No
| data | object | Data for fishbone diagram chart , such as, { name: 'main topic', children: [{ name: 'topic 1', children: [{ name: 'subtopic 1-1' }] } | Yes
| height | number | Set the height of chart, default is 400. | No
| title | string | Set the title of chart. | No
| width | number | Set the width of chart, default is 600. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | generate_area_chart | description | f96bc61c1cd1f2516048ff2311911a27ad3c51ee90e35535248a31ed719dc626 |
| tools | generate_area_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_area_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_area_chart | data | c78e91fc932ad5633c950a406c8490a3d93fdfbc22add00a04f83474886e38e2 |
| tools | generate_area_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_area_chart | stack | da57ecb43f91bd7f5d6eec67c321b2e0ae8a8714c3e0719902b2adedfb56e6d4 |
| tools | generate_area_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_area_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_bar_chart | description | 54908b15980cd5eedf85551873c79cfb332ae31ec5e34e8348676a74b815f856 |
| tools | generate_bar_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_bar_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_bar_chart | data | b6f1bfd3a0b5ef1f273fef685cc47d125fe3cdab2ab989407eca2065e336408f |
| tools | generate_bar_chart | group | 13c8f482326e26caf8e24a5109ac29dc9d86306b3cf024e1098cdef08da29075 |
| tools | generate_bar_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_bar_chart | stack | bdc8f95dd42a52fadbd07bc7720cbfa1e39107d93d9ff28df423bd8085beff5d |
| tools | generate_bar_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_bar_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_column_chart | description | cb9505024eff95786bd632bbca3f11f798bd7826f25cdb56a52145ac52899d7f |
| tools | generate_column_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_column_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_column_chart | data | 6f35d87a83f01fa3193fc7aed5de24020fb5bf10c2d6c8f2abbab553775ff6ce |
| tools | generate_column_chart | group | 3a8cab0ad6f017d5082ac4a41658f8f1bec9c5496777ce4c477f48c22e9f9462 |
| tools | generate_column_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_column_chart | stack | 0d8e951b5339f93e9fcbdb4cd268790b5ab210bbfc67bd1d7e2f90bea3b7fac2 |
| tools | generate_column_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_column_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_dual_axes_chart | description | ebb7a6509b51f64850dc552ca3e3f6f8e1f62dce81eb77f86b5d71f9f2f27706 |
| tools | generate_dual_axes_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_dual_axes_chart | categories | 9a3a8ed51be4fe1fbb4bd4a0c55d31489fe24aad87972ad88902a46b0e1198fe |
| tools | generate_dual_axes_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_dual_axes_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_dual_axes_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_fishbone_diagram | description | b4c25d22c4d78e4617ac92578a8979d41fa401ff31eee777bd54ae6c4bff38bb |
| tools | generate_fishbone_diagram | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_fishbone_diagram | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_fishbone_diagram | data | 50fffcc2d6b4cd6dbb797703bc866d056a6d65944739bfa848b35ab11bc30d1b |
| tools | generate_fishbone_diagram | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_fishbone_diagram | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_fishbone_diagram | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_flow_diagram | description | be9973fdcd389ee607dfd0dbd8472b1e343a83d126c1614ce35f686aa40cf40c |
| tools | generate_flow_diagram | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_flow_diagram | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_flow_diagram | data | 0400dd85ec0609b1a2fe1b3e51edca6a495ca0d2975651f52c7f4e7b3b8ec3d1 |
| tools | generate_flow_diagram | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_flow_diagram | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_flow_diagram | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_histogram_chart | description | 912a3265e2729b0a7c984e7604e4676200b6b37fd72d338ba939b79584cdeb9e |
| tools | generate_histogram_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_histogram_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_histogram_chart | binNumber | aed7fd9c76b22c81f123e8354e8a1fab5474cf785057e597c82846271da1ed68 |
| tools | generate_histogram_chart | data | 110f1e7cd89de037b2f1d5ae52a12e8b9c729f8ff0d7ffdf500301be3be1911e |
| tools | generate_histogram_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_histogram_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_histogram_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_line_chart | description | 9d6966e9e2e13f6da7e4a741a1da19c396cc3fcefddfe7783508e34eece6ea19 |
| tools | generate_line_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_line_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_line_chart | data | 336d1ef1d3875e1bde3df2f0314264aaa6ec864c307cdbfe853b1c2b905861b2 |
| tools | generate_line_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_line_chart | stack | 94ebe7342735fc11d93fead5b58d420f17706a780cfd3774c1d7169a9c1361af |
| tools | generate_line_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_line_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_mind_map | description | 69bf6897ec2bef7cc910002af1f7cf7d92502920473bae8ab6f9adefbc94a628 |
| tools | generate_mind_map | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_mind_map | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_mind_map | data | dca09503b5c4788ff4f0747c4af9ad77dbfd0d46ba87f68a39ceef8e9977ecc9 |
| tools | generate_mind_map | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_mind_map | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_mind_map | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_network_graph | description | e9aa42fc72e3246243577e7be1f5c47ee4a10d74bcac5a0a140ff33719e18f44 |
| tools | generate_network_graph | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_network_graph | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_network_graph | data | c79e86bb596a8000143c5580d53b59f9a9d3a751b78db2429740b39e610ee359 |
| tools | generate_network_graph | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_network_graph | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_network_graph | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_pie_chart | description | 2dc22593f3f742f01a0862cca0c664c9021840501d3f83b27f73f40690a742c6 |
| tools | generate_pie_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_pie_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_pie_chart | data | d56461d0cbeab155f94cc71c0f356cf961428327c26f8feeca8197d46191f701 |
| tools | generate_pie_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_pie_chart | innerRadius | 2392b8b38214109309b04f3ece0b5d6883201cb67ab45c39e918d7be2341d561 |
| tools | generate_pie_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_pie_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_radar_chart | description | eadcd1d7352898155e8664e2c4ab360f4030c7c2f4f68eff86bbd984c4a891ab |
| tools | generate_radar_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_radar_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_radar_chart | data | 56d2c3632be9ccd0c97126c9fde5ca4869a3de8368178a7f8832d213ac259f26 |
| tools | generate_radar_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_radar_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_radar_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_scatter_chart | description | d75c8ea04f633bdc1f2c1b7a74d9bc24ea7ca1d14138ed75a3b6096321e529cf |
| tools | generate_scatter_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_scatter_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_scatter_chart | data | fb0e6070681773230652c9023313d6abe8653f710c54ddea6db7d4af7408eab1 |
| tools | generate_scatter_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_scatter_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_scatter_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_treemap_chart | description | 83973c4e02a8d3109dbd82dc491127008f3cf58a550bcc15bff98a583972ad40 |
| tools | generate_treemap_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_treemap_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_treemap_chart | data | 46418098a4acbdde40f7809faae1b5c912d4834c99f098f8d6fa57eb1876a0d1 |
| tools | generate_treemap_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_treemap_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_treemap_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |
| tools | generate_word_cloud_chart | description | e1661a55c9801f53cd0c3683458fc3dd1b78b0f8bc3e331550603262e2e02a8a |
| tools | generate_word_cloud_chart | axisXTitle | 29da00b2ca33e5c509c776bee355032ab6e3591cb838264f0cec76ba77ff938a |
| tools | generate_word_cloud_chart | axisYTitle | 66928c97bde9f9332a0dcda7c37eda3658f3a3f3949095ca4a0887dec2cbbf77 |
| tools | generate_word_cloud_chart | data | 2aeb67a1626ca271b2f9343fe7070a2023f722a7dd486e729d73ee92ffaaca14 |
| tools | generate_word_cloud_chart | height | 8bfd1882554fd2adddbd6a5b5cedde14eaacddcf97464db773fe7c5d38d8d338 |
| tools | generate_word_cloud_chart | title | dd3eec43d8ec9882fc9dd2273819b46df6a92f014b2f991512c340f48ce9632a |
| tools | generate_word_cloud_chart | width | 7db2100bcdfa22714c5e28eecc0b03a4c809e3e69a5ca3ed77bde0a5d8190d59 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
