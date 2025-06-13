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


# What is mcp-server-cartesia?
[![Rating](https://img.shields.io/badge/D-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-cartesia/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-cartesia/0.1.6?logo=docker&logoColor=fff&label=0.1.6)](https://hub.docker.com/r/acuvity/mcp-server-cartesia)
[![PyPI](https://img.shields.io/badge/0.1.6-3775A9?logo=pypi&logoColor=fff&label=cartesia-mcp)](https://github.com/cartesia-ai/cartesia-mcp)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-cartesia/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-cartesia&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22output%3A%2Foutput%22%2C%22-e%22%2C%22CARTESIA_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-cartesia%3A0.1.6%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Connect to Cartesia voice platform for text-to-speech and voice cloning

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from cartesia-mcp original [sources](https://github.com/cartesia-ai/cartesia-mcp).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-cartesia/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/charts/mcp-server-cartesia/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure cartesia-mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-cartesia scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `CARTESIA_API_KEY` required to be set
  - `OUTPUT_DIRECTORY` optional (/output)
**Required volumes or mountPaths:**
  - data to be mounted on `/output`

For more information and extra configuration you can consult the [package](https://github.com/cartesia-ai/cartesia-mcp) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-cartesia&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-v%22%2C%22output%3A%2Foutput%22%2C%22-e%22%2C%22CARTESIA_API_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-cartesia%3A0.1.6%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-cartesia": {
        "env": {
          "CARTESIA_API_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-v",
          "output:/output",
          "-e",
          "CARTESIA_API_KEY",
          "docker.io/acuvity/mcp-server-cartesia:0.1.6"
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
    "acuvity-mcp-server-cartesia": {
      "env": {
        "CARTESIA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "output:/output",
        "-e",
        "CARTESIA_API_KEY",
        "docker.io/acuvity/mcp-server-cartesia:0.1.6"
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
    "acuvity-mcp-server-cartesia": {
      "env": {
        "CARTESIA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "output:/output",
        "-e",
        "CARTESIA_API_KEY",
        "docker.io/acuvity/mcp-server-cartesia:0.1.6"
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
    "acuvity-mcp-server-cartesia": {
      "env": {
        "CARTESIA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "output:/output",
        "-e",
        "CARTESIA_API_KEY",
        "docker.io/acuvity/mcp-server-cartesia:0.1.6"
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
    "acuvity-mcp-server-cartesia": {
      "env": {
        "CARTESIA_API_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-v",
        "output:/output",
        "-e",
        "CARTESIA_API_KEY",
        "docker.io/acuvity/mcp-server-cartesia:0.1.6"
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
        "env": {"CARTESIA_API_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-v","output:/output","-e","CARTESIA_API_KEY","docker.io/acuvity/mcp-server-cartesia:0.1.6"]
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
- arguments: `run -i --rm --read-only -v output:/output -e CARTESIA_API_KEY docker.io/acuvity/mcp-server-cartesia:0.1.6`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -v output:/output -e CARTESIA_API_KEY docker.io/acuvity/mcp-server-cartesia:0.1.6
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-cartesia": {
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
    "acuvity-mcp-server-cartesia": {
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
  - `CARTESIA_API_KEY` secret to be set as secrets.CARTESIA_API_KEY either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `OUTPUT_DIRECTORY="/output"` environment variable can be changed with env.OUTPUT_DIRECTORY="/output"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
````

Install with helm

```console
helm install mcp-server-cartesia oci://docker.io/acuvity/mcp-server-cartesia --version 1.0.0
```

From there your MCP server mcp-server-cartesia will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-cartesia` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-cartesia/charts/mcp-server-cartesia/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (9)
<details>
<summary>text_to_speech</summary>

**Description**:

```

        Parameters
        ----------
        transcript : str

        voice : TtsRequestVoiceSpecifierParams

        output_format : OutputFormatParams

        model_id : str
            The ID of the model to use for the generation. See [Models](/build-with-cartesia/models) for available models.

        language : typing.Optional[SupportedLanguage]

        duration : typing.Optional[float]
            The maximum duration of the audio in seconds. You do not usually need to specify this.
            If the duration is not appropriate for the length of the transcript, the output audio may be truncated.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration. You can pass in configuration such as `chunk_size`, and more to customize the request and response.

          
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| duration | any | not set | No
| language | any | not set | No
| model_id | any | not set | No
| output_format | any | not set | Yes
| request_options | any | not set | No
| transcript | string | not set | Yes
| voice | any | not set | Yes
</details>
<details>
<summary>infill</summary>

**Description**:

```

        Generate audio that smoothly connects two existing audio segments. This is useful for inserting new speech between existing speech segments while maintaining natural transitions.

        **The cost is 1 credit per character of the infill text plus a fixed cost of 300 credits.**

        Infilling is only available on `sonic-2` at this time.

        At least one of `left_audio` or `right_audio` must be provided.

        As with all generative models, there's some inherent variability, but here's some tips we recommend to get the best results from infill:
        - Use longer infill transcripts
          - This gives the model more flexibility to adapt to the rest of the audio
        - Target natural pauses in the audio when deciding where to clip
          - This means you don't need word-level timestamps to be as precise
        - Clip right up to the start and end of the audio segment you want infilled, keeping as much silence in the left/right audio segments as possible
          - This helps the model generate more natural transitions

        Parameters
        ----------
        language : str
            The language of the transcript

        transcript : str
            The infill text to generate

        voice_id : str
            The ID of the voice to use for generating audio

        output_format_container : OutputFormatContainer
            The format of the output audio

        output_format_sample_rate : int
            The sample rate of the output audio

        output_format_encoding : typing.Optional[RawEncoding]
            Required for `raw` and `wav` containers.

        output_format_bit_rate : typing.Optional[int]
            Required for `mp3` containers.

        left_file_path : typing.Optional[str]
            The absolute path to the left audio file to infill.

        right_file_path : typing.Optional[str]
            The absolute path to the right audio file to infill.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration. You can pass in configuration such as `chunk_size`, and more to customize the request and response.
          
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| language | any | not set | Yes
| left_audio_file_path | any | not set | No
| output_format_bit_rate | any | not set | No
| output_format_container | any | not set | Yes
| output_format_encoding | any | not set | No
| output_format_sample_rate | integer | not set | Yes
| request_options | any | not set | No
| right_audio_file_path | any | not set | No
| transcript | string | not set | Yes
| voice_id | string | not set | Yes
</details>
<details>
<summary>voice_change</summary>

**Description**:

```

        Takes an audio file of speech, and returns an audio file of speech spoken with the same intonation, but with a different voice.

        Parameters
        ----------
        file_path : str
            The absolute path to the audio file to change.

        voice_id : str

        output_format_container : OutputFormatContainer

        output_format_sample_rate : int

        output_format_encoding : typing.Optional[RawEncoding]
            Required for `raw` and `wav` containers.

        output_format_bit_rate : typing.Optional[int]
            Required for `mp3` containers.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration. You can pass in configuration such as `chunk_size`, and more to customize the request and response.
          
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| file_path | string | not set | Yes
| output_format_bit_rate | any | not set | No
| output_format_container | any | not set | Yes
| output_format_encoding | any | not set | No
| output_format_sample_rate | integer | not set | Yes
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>localize_voice</summary>

**Description**:

```

        Create a new voice from an existing voice localized to a new language and dialect.

        Parameters
        ----------
        voice_id : str
            The ID of the voice to localize.

        name : str
            The name of the new localized voice.

        description : str
            The description of the new localized voice.

        language : SupportedLanguage

        original_speaker_gender : Gender

        dialect : typing.Optional[LocalizeDialectParams]

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | Yes
| dialect | any | not set | No
| language | any | not set | Yes
| name | string | not set | Yes
| original_speaker_gender | any | not set | Yes
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>delete_voice</summary>

**Description**:

```

        Parameters
        ----------
        voice_id : str
            The ID of the voice to delete.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>get_voice</summary>

**Description**:

```

        Parameters
        ----------
        voice_id : str
            The ID of the voice to get.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>update_voice</summary>

**Description**:

```

        Parameters
        ----------
        id : VoiceId

        name : str
            The name of the voice.

        description : str
            The description of the voice.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | not set | Yes
| name | string | not set | Yes
| request_options | any | not set | No
| voice_id | string | not set | Yes
</details>
<details>
<summary>clone_voice</summary>

**Description**:

```

        Clone a voice from an audio clip. This endpoint has two modes, stability and similarity.

        Similarity mode clones are more similar to the source clip, but may reproduce background noise. For these, use an audio clip about 5 seconds long.

        Stability mode clones are more stable, but may not sound as similar to the source clip. For these, use an audio clip 10-20 seconds long.

        Parameters
        ----------
        file_path : str
            The absolute path to the audio file to clone.

        name : str
            The name of the voice.

        language : SupportedLanguage
            The language of the voice.

        mode : CloneMode
            Tradeoff between similarity and stability. Similarity clones sound more like the source clip, but may reproduce background noise. Stability clones always sound like a studio recording, but may not sound as similar to the source clip.

        description : typing.Optional[str]
            A description for the voice.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | any | not set | No
| file_path | string | not set | Yes
| language | any | not set | Yes
| mode | any | not set | Yes
| name | string | not set | Yes
| request_options | any | not set | No
</details>
<details>
<summary>list_voices</summary>

**Description**:

```

        Parameters
        ----------
        limit : typing.Optional[int]
            The number of Voices to return per page, ranging between 1 and 100.

        starting_after : typing.Optional[str]
            A cursor to use in pagination. `starting_after` is a Voice ID that defines your
            place in the list. For example, if you make a /voices request and receive 100
            objects, ending with `voice_abc123`, your subsequent call can include
            `starting_after=voice_abc123` to fetch the next page of the list.

        ending_before : typing.Optional[str]
            A cursor to use in pagination. `ending_before` is a Voice ID that defines your
            place in the list. For example, if you make a /voices request and receive 100
            objects, starting with `voice_abc123`, your subsequent call can include
            `ending_before=voice_abc123` to fetch the previous page of the list.

        is_owner : typing.Optional[bool]
            Whether to only return voices owned by the current user.

        is_starred : typing.Optional[bool]
            Whether to only return starred voices.

        gender : typing.Optional[GenderPresentation]
            The gender presentation of the voices to return.

        request_options : typing.Optional[RequestOptions]
            Request-specific configuration.
        
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| ending_before | any | not set | No
| gender | any | not set | No
| is_owner | any | not set | No
| is_starred | any | not set | No
| limit | any | not set | No
| request_options | any | not set | No
| starting_after | any | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | clone_voice | description | d000d5874fa1f3b8525a42b7e66ab7e38560e8ced5361814b7fdc3904ae3e7ed |
| tools | delete_voice | description | a0ddee9cbee01aa10047230f4d6944514cfad67ad4d11d3aadac25320ca6fd90 |
| tools | get_voice | description | 94488dca63e5587cd286beea05f0be145d141300c655b1b58f9d239951b0984b |
| tools | infill | description | 6db8e92e803cc4c1a4ffda8329225ad8be2ec02b64997a5353985245eeac1974 |
| tools | list_voices | description | 89485b7982e58bca0d0f9bd7a4049d676ac8c96ca769c4ca7a5c059740793e76 |
| tools | localize_voice | description | 89aba570ca1e43fc663065e5f595e55c8050e9e18ea5606f65d2b224c9fbf1c1 |
| tools | text_to_speech | description | dbe87dd215d9e19724d4fc94a30b872aed0251a7968c4585c82a9ed3be9393f6 |
| tools | update_voice | description | e31c18bb843c2924b82319aec98f631aca027d7c16d29ca311d65f034d6b6d2f |
| tools | voice_change | description | 81dada3df7b8aa51eb3ba974ebed8fc71d329f22158bb27346963c8333036d33 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
