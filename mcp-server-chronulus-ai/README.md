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


# What is mcp-server-chronulus-ai?
[![Rating](https://img.shields.io/badge/A-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-chronulus-ai/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-chronulus-ai/0.0.3?logo=docker&logoColor=fff&label=0.0.3)](https://hub.docker.com/r/acuvity/mcp-server-chronulus-ai)
[![PyPI](https://img.shields.io/badge/0.0.3-3775A9?logo=pypi&logoColor=fff&label=chronulus-mcp)](https://github.com/ChronulusAI/chronulus-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-chronulus-ai/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chronulus-ai&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHRONULUS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-chronulus-ai%3A0.0.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Predict anything with Chronulus AI forecasting and prediction agents.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from chronulus-mcp original [sources](https://github.com/ChronulusAI/chronulus-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-chronulus-ai/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chronulus-ai/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chronulus-ai/charts/mcp-server-chronulus-ai/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure chronulus-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chronulus-ai/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-chronulus-ai scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `CHRONULUS_API_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/ChronulusAI/chronulus-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-chronulus-ai&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22CHRONULUS_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-chronulus-ai%3A0.0.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-chronulus-ai": {
        "env": {
          "CHRONULUS_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "CHRONULUS_API_KEY",
          "docker.io/acuvity/mcp-server-chronulus-ai:0.0.3"
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
    "acuvity-mcp-server-chronulus-ai": {
      "env": {
        "CHRONULUS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHRONULUS_API_KEY",
        "docker.io/acuvity/mcp-server-chronulus-ai:0.0.3"
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
    "acuvity-mcp-server-chronulus-ai": {
      "env": {
        "CHRONULUS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHRONULUS_API_KEY",
        "docker.io/acuvity/mcp-server-chronulus-ai:0.0.3"
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
    "acuvity-mcp-server-chronulus-ai": {
      "env": {
        "CHRONULUS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHRONULUS_API_KEY",
        "docker.io/acuvity/mcp-server-chronulus-ai:0.0.3"
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
    "acuvity-mcp-server-chronulus-ai": {
      "env": {
        "CHRONULUS_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "CHRONULUS_API_KEY",
        "docker.io/acuvity/mcp-server-chronulus-ai:0.0.3"
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
        "env": {"CHRONULUS_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","CHRONULUS_API_KEY","docker.io/acuvity/mcp-server-chronulus-ai:0.0.3"]
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
- arguments: `run -i --rm --read-only -e CHRONULUS_API_KEY docker.io/acuvity/mcp-server-chronulus-ai:0.0.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e CHRONULUS_API_KEY docker.io/acuvity/mcp-server-chronulus-ai:0.0.3
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-chronulus-ai": {
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
    "acuvity-mcp-server-chronulus-ai": {
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

**Mandatory Secrets**:
  - `CHRONULUS_API_KEY` secret to be set as secrets.CHRONULUS_API_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-chronulus-ai --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-chronulus-ai --version 1.0.0
````

Install with helm

```console
helm install mcp-server-chronulus-ai oci://docker.io/acuvity/mcp-server-chronulus-ai --version 1.0.0
```

From there your MCP server mcp-server-chronulus-ai will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-chronulus-ai` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-chronulus-ai/charts/mcp-server-chronulus-ai/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>create_chronulus_session</summary>

**Description**:

```

A tool that creates a new Chronulus Session and returns a session_id

When to use this tool:
- Use this tool when a user has requested a forecast or prediction for a new use case
- Before calling this tool make sure you have enough information to write a well-defined situation and task. You might
need to ask clarifying questions in order to get this from the user.
- The same session_id can be reused as long as the situation and task remain the same
- If user wants to forecast a different use case, create a new session and then use that

How to use this tool:
- To create a session, you need to provide a situation and task that describe the forecasting use case 
- If the user has not provided enough detail for you to decompose the use case into a 
    situation (broad or background context) and task (specific requirements for the forecast), 
    ask them to elaborate since more detail will result in a better / more accurate forecast.
- Once created, this will generate a unique session_id that can be used to when calling other tools about this use case.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| name | string | A short descriptive name for the use case defined in the session. | Yes
| situation | string | The broader context for the use case | Yes
| task | string | Specific details on the forecasting or prediction task. | Yes
</details>
<details>
<summary>create_forecasting_agent_and_get_forecast</summary>

**Description**:

```

This tool creates a NormalizedForecaster agent with your session and input data model and then provides a forecast input 
data to the agent and returns the prediction data and text explanation from the agent.

When to use this tool:
- Use this tool to request a forecast from Chronulus
- This tool is specifically made to forecast values between 0 and 1 and does not require historical data
- The prediction can be thought of as seasonal weights, probabilities, or shares of something as in the decimal representation of a percent

How to use this tool:
- First, make sure you have a session_id for the forecasting or prediction use case.
- Next, think about the features / characteristics most suitable for producing the requested forecast and then 
create an input_data_model that corresponds to the input_data you will provide for the thing being forecasted.
- Remember to pass all relevant information to Chronulus including text and images provided by the user. 
- If a user gives you files about a thing you are forecasting or predicting, you should pass these as inputs to the 
agent using one of the following types: 
    - ImageFromFile
    - List[ImageFromFile]
    - TextFromFile
    - List[TextFromFile]
    - PdfFromFile
    - List[PdfFromFile]
- If you have a large amount of text (over 500 words) to pass to the agent, you should use the Text or List[Text] field types
- Finally, add information about the forecasting horizon and time scale requested by the user
- Assume the dates and datetimes in the prediction results are already converted to the appropriate local timezone if location is a factor in the use case. So do not try to convert from UTC to local time when plotting.
- When plotting the predictions, use a Rechart time series with the appropriate axes labeled and with the prediction explanation displayed as a caption below the plot

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| forecast_start_dt_str | string | The datetime str in '%Y-%m-%d %H:%M:%S' format of the first value in the forecast horizon. | Yes
| horizon_len | integer | The integer length of the forecast horizon. Eg., 60 if a 60 day forecast was requested. | No
| input_data | object | The forecast inputs that you will pass to the chronulus agent to make the prediction. The keys of the dict should correspond to the InputField name you provided in input_fields. | Yes
| input_data_model | array | Metadata on the fields you will include in the input_data. | Yes
| session_id | string | The session_id for the forecasting or prediction use case | Yes
| time_scale | string | The times scale of the forecast horizon. Valid time scales are 'hours', 'days', and 'weeks'. | No
</details>
<details>
<summary>reuse_forecasting_agent_and_get_forecast</summary>

**Description**:

```

This tool creates a NormalizedForecaster agent with your session and input data model and then provides a forecast input 
data to the agent and returns the prediction data and text explanation from the agent.

When to use this tool:
- Use this tool to request a forecast from Chronulus
- This tool is specifically made to forecast values between 0 and 1 and does not require historical data
- The prediction can be thought of as seasonal weights, probabilities, or shares of something as in the decimal representation of a percent

How to use this tool:
- First, make sure you have a session_id for the forecasting or prediction use case.
- Next, think about the features / characteristics most suitable for producing the requested forecast and then 
create an input_data_model that corresponds to the input_data you will provide for the thing being forecasted.
- Remember to pass all relevant information to Chronulus including text and images provided by the user. 
- If a user gives you files about a thing you are forecasting or predicting, you should pass these as inputs to the 
agent using one of the following types: 
    - ImageFromFile
    - List[ImageFromFile]
    - TextFromFile
    - List[TextFromFile]
    - PdfFromFile
    - List[PdfFromFile]
- If you have a large amount of text (over 500 words) to pass to the agent, you should use the Text or List[Text] field types
- Finally, add information about the forecasting horizon and time scale requested by the user
- Assume the dates and datetimes in the prediction results are already converted to the appropriate local timezone if location is a factor in the use case. So do not try to convert from UTC to local time when plotting.
- When plotting the predictions, use a Rechart time series with the appropriate axes labeled and with the prediction explanation displayed as a caption below the plot

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| agent_id | string | The agent_id for the forecasting or prediction use case and previously defined input_data_model | Yes
| forecast_start_dt_str | string | The datetime str in '%Y-%m-%d %H:%M:%S' format of the first value in the forecast horizon. | Yes
| horizon_len | integer | The integer length of the forecast horizon. Eg., 60 if a 60 day forecast was requested. | No
| input_data | object | The forecast inputs that you will pass to the chronulus agent to make the prediction. The keys of the dict should correspond to the InputField name you provided in input_fields. | Yes
| time_scale | string | The times scale of the forecast horizon. Valid time scales are 'hours', 'days', and 'weeks'. | No
</details>
<details>
<summary>rescale_forecast</summary>

**Description**:

```

A tool that rescales the prediction data (values between 0 and 1) from the NormalizedForecaster agent to scale required for a use case

When to use this tool:
- Use this tool when there is enough information from the user or use cases to determine a reasonable min and max for the forecast predictions
- Do not attempt to rescale or denormalize the predictions on your own without using this tool.
- Also, if the best min and max for the use case is 0 and 1, then no rescaling is needed since that is already the scale of the predictions.
- If a user requests to convert from probabilities to a unit in levels, be sure to caveat your use of this tool by noting that
    probabilities do not always scale uniformly to levels. Rescaling can be used as a rough first-pass estimate. But for best results, 
    it would be better to start a new Chronulus forecasting use case predicting in levels from the start.
    
How to use this tool:
- To use this tool present prediction_id from the normalized prediction and the min and max as floats
- If the user is also changing units, consider if the units will be inverted and set the inverse scale to True if needed.
- When plotting the rescaled predictions, use a Rechart time series plot with the appropriate axes labeled and include the chronulus 
    prediction explanation as a caption below the plot. 
- If you would like to add additional notes about the scaled series, put these below the original prediction explanation. 

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| invert_scale | boolean | Set this flag to true if the scale of the new units will run in the opposite direction from the inputs. | No
| prediction_id | string | The prediction_id from a prediction result | Yes
| y_max | number | The expected largest value for the use case. E.g., for product sales, 0 would be the largest possible value would be given by the user or determined from this history of sales for the product in question or a similar product. | Yes
| y_min | number | The expected smallest value for the use case. E.g., for product sales, 0 would be the least possible value for sales. | Yes
</details>
<details>
<summary>save_forecast</summary>

**Description**:

```

A tool that saves a Chronulus forecast from NormalizedForecaster to separate CSV and TXT files

When to use this tool:
- Use this tool when you need to save both the forecast data and its explanation to files
- The forecast data will be saved as a CSV file for data analysis
- The forecast explanation will be saved as a TXT file for reference
- Both files will be saved in the same directory specified by output_path
- This tool can also be used to directly save rescaled predictions without first calling the rescaling tool

How to use this tool:
- Provide the prediction_id from a previous forecast
- Specify the output_path where both files should be saved
- Provide csv_name for the forecast data file (must end in .csv)
- Provide txt_name for the explanation file (must end in .txt)
- Optionally provide y_min and y_max to rescale the predictions (defaults to 0)
- Set invert_scale to True if the target units run in the opposite direction
- The tool will provide status updates through the MCP context

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| csv_name | string | The path where the CSV file should be saved. Should end in .csv | Yes
| invert_scale | boolean | Set this flag to true if the scale of the new units will run in the opposite direction from the inputs. | No
| output_path | string | The path where the CSV file should be saved. Should end in .csv | Yes
| prediction_id | string | The prediction_id from a prediction result | Yes
| txt_name | string | The name of the TXT file to be saved. Should end in .txt | Yes
| y_max | number | The expected largest value for the use case. E.g., for product sales, 0 would be the largest possible value would be given by the user or determined from this history of sales for the product in question or a similar product. | No
| y_min | number | The expected smallest value for the use case. E.g., for product sales, 0 would be the least possible value for sales. | No
</details>
<details>
<summary>create_prediction_agent_and_get_predictions</summary>

**Description**:

```

This tool creates a BinaryPredictor agent with your session and input data model and then provides prediction input 
data to the agent and returns the consensus a prediction from a panel of experts along with their individual estimates
and text explanations. The agent also returns the alpha and beta parameters for a Beta distribution that allows you to
estimate the confidence interval of its consensus probability estimate.

When to use this tool:
- Use this tool to request a probability estimate from Chronulus in situation when there is a binary outcome
- This tool is specifically made to estimate the probability of an event occurring and not occurring and does not 
require historical data

How to use this tool:
- First, make sure you have a session_id for the prediction use case.
- Next, think about the features / characteristics most suitable for producing the requested prediction and then 
create an input_data_model that corresponds to the input_data you will provide for the thing or event being predicted.
- Remember to pass all relevant information to Chronulus including text and images provided by the user. 
- If a user gives you files about a thing you are forecasting or predicting, you should pass these as inputs to the 
agent using one of the following types: 
    - ImageFromFile
    - List[ImageFromFile]
    - TextFromFile
    - List[TextFromFile]
    - PdfFromFile
    - List[PdfFromFile]
- If you have a large amount of text (over 500 words) to pass to the agent, you should use the Text or List[Text] field types
- Finally, provide the number of experts to consult. The minimum and default number is 2, but users may request up to 30
30 opinions in situations where reproducibility and risk sensitively is of the utmost importance. In most cases, 2 to 5 
experts is sufficient. 

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| input_data | object | The forecast inputs that you will pass to the chronulus agent to make the prediction. The keys of the dict should correspond to the InputField name you provided in input_fields. | Yes
| input_data_model | array | Metadata on the fields you will include in the input_data. | Yes
| num_experts | integer | The number of experts to consult when forming consensus | Yes
| session_id | string | The session_id for the forecasting or prediction use case | Yes
</details>
<details>
<summary>reuse_prediction_agent_and_get_prediction</summary>

**Description**:

```

This tool provides prediction input data to a previously created Chronulus BinaryPredictor agent and returns the 
consensus a prediction from a panel of experts along with their individual estimates and text explanations. The agent 
also returns the alpha and beta parameters for a Beta distribution that allows you to estimate the confidence interval 
of its consensus probability estimate.

When to use this tool:
- Use this tool to request a prediction from a Chronulus prediction agent that you have already created and when your 
input data model is unchanged
- Use this tool to request a probability estimate from an existing prediction agent in a situation when there is a binary outcome
- This tool is specifically made to estimate the probability of an event occurring and not occurring and does not 
require historical data

How to use this tool:
- First, make sure you have a session_id for the prediction use case.
- Next, think about the features / characteristics most suitable for producing the requested prediction and then 
create an input_data_model that corresponds to the input_data you will provide for the thing or event being predicted.
- Remember to pass all relevant information to Chronulus including text and images provided by the user. 
- If a user gives you files about a thing you are forecasting or predicting, you should pass these as inputs to the 
agent using one of the following types: 
    - ImageFromFile
    - List[ImageFromFile]
    - TextFromFile
    - List[TextFromFile]
    - PdfFromFile
    - List[PdfFromFile]
- If you have a large amount of text (over 500 words) to pass to the agent, you should use the Text or List[Text] field types
- Finally, provide the number of experts to consult. The minimum and default number is 2, but users may request up to 30
30 opinions in situations where reproducibility and risk sensitively is of the utmost importance. In most cases, 2 to 5 
experts is sufficient. 

How to use this tool:
- First, make sure you have an agent_id for the prediction agent. The agent is already attached to the correct session. 
So you do not need to provide a session_id.
- Next, reference the input data model that you previously used with the agent and create new input data for the item 
being predicted that aligns with the previously specified input data model
- Remember to pass all relevant information to Chronulus including text and images provided by the user. 
- If a user gives you files about a thing you are forecasting or predicting, you should pass these as inputs to the 
agent using one of the following types: 
    - ImageFromFile
    - List[ImageFromFile]
    - TextFromFile
    - List[TextFromFile]
    - PdfFromFile
    - List[PdfFromFile]
- If you have a large amount of text (over 500 words) to pass to the agent, you should use the Text or List[Text] field types
- Finally, provide the number of experts to consult. The minimum and default number is 2, but users may request up to 30
30 opinions in situations where reproducibility and risk sensitively is of the utmost importance. In most cases, 2 to 5 
experts is sufficient. 

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| agent_id | string | The agent_id for the forecasting or prediction use case and previously defined input_data_model | Yes
| input_data | object | The forecast inputs that you will pass to the chronulus agent to make the prediction. The keys of the dict should correspond to the InputField name you provided in input_fields. | Yes
| num_experts | integer | The number of experts to consult when forming consensus | Yes
</details>
<details>
<summary>save_prediction_analysis_html</summary>

**Description**:

```

A tool that saves an analysis of a BinaryPredictor prediction to HTML. 

The analysis includes a plot of the theoretical and empirical beta distribution estimated by Chronulus and also
list the opinions provided by each expert.

When to use this tool:
- Use this tool when you need to save the BinaryPredictor estimates to for the user

How to use this tool:
- Provide the request_id from a previous prediction response
- Specify the output_path where the html should be saved
- Provide html_name for the file (must end in .html)
- The tool will provide status updates through the MCP context

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| chronulus_prediction_summary | string | A summary paragraph distilling prediction results and expert opinions provided by Chronulus | Yes
| dist_shape | string | A one line description of the shape of the distribution of predictions | Yes
| dist_shape_interpretation | string | 2-3 sentences interpreting the shape of the distribution of predictions in layman's terms | Yes
| html_name | string | The path where the HTML file should be saved. | Yes
| output_path | string | The path where the HTML file should be saved. | Yes
| plot_label | string | Label for the Beta plot | Yes
| request_id | string | The request_id from the BinaryPredictor result | Yes
| title | string | Title of analysis | Yes
</details>
<details>
<summary>get_risk_assessment_scorecard</summary>

**Description**:

```

A tool that retrieves the risk assessment scorecard for the Chronulus Session in Markdown format

When to use this tool:
- Use this tool when the use asks about the risk level or safety concerns of a forecasting use case
- You may also use this tool to provide justification to a user if you would like to warn them of the implications of 
    what they are asking you to forecasting or predict.

How to use this tool:
- Make sure you have a session_id for the forecasting or prediction use case
- When displaying the scorecard markdown for the user, you should use an MDX-style React component

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| as_json | boolean | If true, returns the scorecard in JSON format, otherwise returns a markdown formatted scorecard | Yes
| session_id | string | The session_id for the forecasting or prediction use case | Yes
</details>

## 📚 Resources (2)

<details>
<summary>Resources</summary>

| Name | Mime type | URI| Content |
|-----------|------|-------------|-----------|
| Scorecard React Template | text/javascript | chronulus-react://Scorecard.jsx | - |
| Beta Plot | text/javascript | chronulus-react://BetaPlot.jsx | - |

</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | create_chronulus_session | description | 023375f41c31f4db4d39c0181e002a778ba5863efb4b0f98e629adcd76ebf27d |
| tools | create_chronulus_session | name | df096f2e7ba978c73e165c9dc4761cdd91b8ef6094a1c1cf64c4f912052c603f |
| tools | create_chronulus_session | situation | 5cae7eb1ae7a0e28f19e084610745e4b667d888e30cf28bd8bcf25ebdce41bda |
| tools | create_chronulus_session | task | 782c060de9cf260b5151ad75ceb801ab37a65bce324158fed0facfc0ad54f3f6 |
| tools | create_forecasting_agent_and_get_forecast | description | 0a79b1dcace98bae5f5a36d73c75315b821ca993ce26ef7a2512eecd61115207 |
| tools | create_forecasting_agent_and_get_forecast | forecast_start_dt_str | d032b5667a5958a0899585a9a7629d7294cb2bfa4e8f9582383ec5d2255a1bd7 |
| tools | create_forecasting_agent_and_get_forecast | horizon_len | 319627c012de4f34775626da1fe8f3517e0f201c0c672aaa77ca2dc23eeea758 |
| tools | create_forecasting_agent_and_get_forecast | input_data | baa6368ab0bd640437f256f6a0390596742a56c6cf75ef8e5e7861565d847ce5 |
| tools | create_forecasting_agent_and_get_forecast | input_data_model | d2a1bef961bc02a591723fe9ae16d4a37737970ebf0791a17caff05077073292 |
| tools | create_forecasting_agent_and_get_forecast | session_id | 92caca648373b9bee4610361e107d03144091bcca5b4c1f5bcd9400711d0739e |
| tools | create_forecasting_agent_and_get_forecast | time_scale | 87229787d5f558d81f3ab245d6792d11f4146a2fb9cc99e23a2704bc3e7e70d0 |
| tools | create_prediction_agent_and_get_predictions | description | 1103d7b6acac7686d7aa29d73f94252c8204ca3dcb7978e829f7133db34e9d29 |
| tools | create_prediction_agent_and_get_predictions | input_data | baa6368ab0bd640437f256f6a0390596742a56c6cf75ef8e5e7861565d847ce5 |
| tools | create_prediction_agent_and_get_predictions | input_data_model | d2a1bef961bc02a591723fe9ae16d4a37737970ebf0791a17caff05077073292 |
| tools | create_prediction_agent_and_get_predictions | num_experts | 97268e8871eaf94999cffa368b028a4827ef197c50a7987873440d13b8b8db8a |
| tools | create_prediction_agent_and_get_predictions | session_id | 92caca648373b9bee4610361e107d03144091bcca5b4c1f5bcd9400711d0739e |
| tools | get_risk_assessment_scorecard | description | 2fc7b82383275ea8fe0733e72092339d630826b39cfafb477265e205478d8790 |
| tools | get_risk_assessment_scorecard | as_json | 248db44ccb2be41a4477162fddf4f844ae1da13ce853399a1e99a92bdff2e6d9 |
| tools | get_risk_assessment_scorecard | session_id | 92caca648373b9bee4610361e107d03144091bcca5b4c1f5bcd9400711d0739e |
| tools | rescale_forecast | description | 4e85694cc6af5e2d125701ac116bf0175ac661787c4014e58ef21e6efbb92395 |
| tools | rescale_forecast | invert_scale | ef385c94a69b89c791934f0602dcbd5d02ae00d7707112dfd34c3b0033e901d4 |
| tools | rescale_forecast | prediction_id | 1d4a55640700e36dadc1bafdaf36a7118b146c4ed602948cc45f848f90ab98c1 |
| tools | rescale_forecast | y_max | 7e002cd3ac9eae9f9dae47483b492117e97a491d2517eabc77c5437eebd9d715 |
| tools | rescale_forecast | y_min | 1e0c4c0c4af3c0108fd13db2760fa7f426971812c5332026533ff805c76cfaed |
| tools | reuse_forecasting_agent_and_get_forecast | description | 0a79b1dcace98bae5f5a36d73c75315b821ca993ce26ef7a2512eecd61115207 |
| tools | reuse_forecasting_agent_and_get_forecast | agent_id | 9a0bcd98efef7cacb6162ef182b4f4bdb2646caf40fce47120e8bd3caefec1c8 |
| tools | reuse_forecasting_agent_and_get_forecast | forecast_start_dt_str | d032b5667a5958a0899585a9a7629d7294cb2bfa4e8f9582383ec5d2255a1bd7 |
| tools | reuse_forecasting_agent_and_get_forecast | horizon_len | 319627c012de4f34775626da1fe8f3517e0f201c0c672aaa77ca2dc23eeea758 |
| tools | reuse_forecasting_agent_and_get_forecast | input_data | baa6368ab0bd640437f256f6a0390596742a56c6cf75ef8e5e7861565d847ce5 |
| tools | reuse_forecasting_agent_and_get_forecast | time_scale | 87229787d5f558d81f3ab245d6792d11f4146a2fb9cc99e23a2704bc3e7e70d0 |
| tools | reuse_prediction_agent_and_get_prediction | description | 7d418a64924d5babe924f743280763dff97eaa956d0c11801c575d8fe13547a9 |
| tools | reuse_prediction_agent_and_get_prediction | agent_id | 9a0bcd98efef7cacb6162ef182b4f4bdb2646caf40fce47120e8bd3caefec1c8 |
| tools | reuse_prediction_agent_and_get_prediction | input_data | baa6368ab0bd640437f256f6a0390596742a56c6cf75ef8e5e7861565d847ce5 |
| tools | reuse_prediction_agent_and_get_prediction | num_experts | 97268e8871eaf94999cffa368b028a4827ef197c50a7987873440d13b8b8db8a |
| tools | save_forecast | description | 2b63af460eb2b4b93aa1a2f2b4acba861f3ee0d2a9e5a2d52a3d3eb61f535961 |
| tools | save_forecast | csv_name | 599711e78254f5f76278742637ac5747b21f3c4d3a3b7dbc00d5cc26153b6417 |
| tools | save_forecast | invert_scale | ef385c94a69b89c791934f0602dcbd5d02ae00d7707112dfd34c3b0033e901d4 |
| tools | save_forecast | output_path | 599711e78254f5f76278742637ac5747b21f3c4d3a3b7dbc00d5cc26153b6417 |
| tools | save_forecast | prediction_id | 1d4a55640700e36dadc1bafdaf36a7118b146c4ed602948cc45f848f90ab98c1 |
| tools | save_forecast | txt_name | f61b6aeb6e1045bdb189db3a71ebf37383fcc6fc533679fa3c77a94b5673ddfd |
| tools | save_forecast | y_max | 7e002cd3ac9eae9f9dae47483b492117e97a491d2517eabc77c5437eebd9d715 |
| tools | save_forecast | y_min | 1e0c4c0c4af3c0108fd13db2760fa7f426971812c5332026533ff805c76cfaed |
| tools | save_prediction_analysis_html | description | 7cdb388bb9f699ad8b8a21afa76490254bdcf82f1814e707f9b520c91947f6cd |
| tools | save_prediction_analysis_html | chronulus_prediction_summary | 5d5f640c08878201187f658edacf5c67956bfef487c7369d1e14b3615ccf95d5 |
| tools | save_prediction_analysis_html | dist_shape | 6089ad4f42b83192534f751fd2dda6c1faa2a60943ad7369a4433cb2c2c88fef |
| tools | save_prediction_analysis_html | dist_shape_interpretation | 7e75db3ae524382cd56ecfedae5af93e05bbf754eafb9ef48e70f04a2fe3f6d2 |
| tools | save_prediction_analysis_html | html_name | df908c018bdbf282f5b8529500b6743bc9085b6e68360f9196da527fcabd4447 |
| tools | save_prediction_analysis_html | output_path | df908c018bdbf282f5b8529500b6743bc9085b6e68360f9196da527fcabd4447 |
| tools | save_prediction_analysis_html | plot_label | aa67b58870e4cc6212d3cc39994f9065b8258386da6518313658fff6a0bfa4d6 |
| tools | save_prediction_analysis_html | request_id | d7c3b3ab8b4b26b391c6191ef17c715cd9fc30170c5e6a70bf2f2f7526575c9c |
| tools | save_prediction_analysis_html | title | 53e2f8aa694041368b8ab8d38465fee64cd28ec85fb0745fb102ad849bd0bb03 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
