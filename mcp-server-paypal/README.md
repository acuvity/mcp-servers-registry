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


# What is mcp-server-paypal?

[![Rating](https://img.shields.io/badge/B-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-paypal/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-paypal/0.3.1?logo=docker&logoColor=fff&label=0.3.1)](https://hub.docker.com/r/acuvity/mcp-server-paypal)
[![PyPI](https://img.shields.io/badge/0.3.1-3775A9?logo=pypi&logoColor=fff&label=@paypal/mcp)](https://github.com/paypal/agent-toolkit)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-fetch/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-paypal&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22PAYPAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-paypal%3A0.3.1%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** A Model Context Protocol (MCP) server that enables AI models to interact with PayPal Apis.

Packaged by Acuvity from @paypal/mcp original [sources](https://github.com/paypal/agent-toolkit).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-paypal/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/charts/mcp-server-paypal/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @paypal/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

### 🔒 Resource Integrity

**Mitigates MCP Rug Pull Attacks**

* **Goal:** Protect users from malicious tool description changes after initial approval, preventing post-installation manipulation or deception.
* **Mechanism:** Locks tool descriptions upon client approval and verifies their integrity before execution. Any modification to the description triggers a security violation, blocking unauthorized changes from server-side updates.

### 🛡️ Gardrails

### Covert Instruction Detection

Monitors incoming requests for hidden or obfuscated directives that could alter policy behavior.

* **Goal:** Stop attackers from slipping unnoticed commands or payloads into otherwise harmless data.
* **Mechanism:** Applies a library of regex patterns and binary‐encoding checks to the full request body. If any pattern matches a known covert channel (e.g., steganographic markers, hidden HTML tags, escape-sequence tricks), the request is rejected.

### Sensitive Pattern Detection

Block user-defined sensitive data patterns (credential paths, filesystem references).

* **Goal:** Block accidental or malicious inclusion of sensitive information that violates data-handling rules.
* **Mechanism:** Runs a curated set of regexes against all payloads and tool descriptions—matching patterns such as `.env` files, RSA key paths, directory traversal sequences.

### Shadowing Pattern Detection

Detects and blocks "shadowing" attacks, where a malicious MCP server sneaks hidden directives into its own tool descriptions to hijack or override the behavior of other, trusted tools.

* **Goal:** Stop a rogue server from poisoning the agent’s logic by embedding instructions that alter how a different server’s tools operate (e.g., forcing all emails to go to an attacker’s address even when the user calls a separate `send_email` tool).
* **Mechanism:** During policy load, each tool description is scanned for cross‐tool override patterns—such as `<IMPORTANT>` sections referencing other tool names, hidden side‐effects, or directives that apply to a different server’s API. Any description that attempts to shadow or extend instructions for a tool outside its own namespace triggers a policy violation and is rejected.

### Schema Misuse Prevention

Enforces strict adherence to MCP input schemas.

* **Goal:** Prevent malformed or unexpected fields from bypassing validations, causing runtime errors, or enabling injections.
* **Mechanism:** Compares each incoming JSON object against the declared schema (required properties, allowed keys, types). Any extra, missing, or mistyped field triggers an immediate policy violation.

### Cross-Origin Tool Access

Controls whether tools may invoke tools or services from external origins.

* **Goal:** Prevent untrusted or out-of-scope services from being called.
* **Mechanism:** Examines tool invocation requests and outgoing calls, verifying each target against an allowlist of approved domains or service names. Calls to any non-approved origin are blocked.

### Secrets Redaction

Automatically masks sensitive values so they never appear in logs or responses.

* **Goal:** Ensure that API keys, tokens, passwords, and other credentials cannot leak in plaintext.
* **Mechanism:** Scans every text output for known secret formats (e.g., AWS keys, GitHub PATs, JWTs). Matches are replaced with `[REDACTED]` before the response is sent or recorded.

## Basic Authentication via Shared Secret

Provides a lightweight auth layer using a single shared token.

* **Mechanism:** Expects clients to send an `Authorization` header with the predefined secret.
* **Use Case:** Quickly lock down your endpoint in development or simple internal deployments—no complex OAuth/OIDC setup required.

These controls ensure robust runtime integrity, prevent unauthorized behavior, and provide a foundation for secure-by-design system operations.

</details>

> [!NOTE]
> By default, all guardrails are turned off. You can enable or disable each one individually, ensuring that only the protections your environment needs are active. To review the full policy, see it [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/docker/policy.rego). Alternatively, you can override the default policy or supply your own policy file to use (see [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/docker/entrypoint.sh) for Docker, [here](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/charts/mcp-server-paypal#minibridge) for Helm charts).


# 📦 How to Install


> [!TIP]
> Given mcp-server-paypal scope of operation it can be hosted anywhere.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-paypal&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22PAYPAL_ACCESS_TOKEN%22%2C%22docker.io%2Facuvity%2Fmcp-server-paypal%3A0.3.1%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-paypal": {
        "env": {
          "PAYPAL_ACCESS_TOKEN": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "PAYPAL_ACCESS_TOKEN",
          "docker.io/acuvity/mcp-server-paypal:0.3.1"
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
    "acuvity-mcp-server-paypal": {
      "env": {
        "PAYPAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "PAYPAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-paypal:0.3.1"
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
    "acuvity-mcp-server-paypal": {
      "env": {
        "PAYPAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "PAYPAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-paypal:0.3.1"
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
    "acuvity-mcp-server-paypal": {
      "env": {
        "PAYPAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "PAYPAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-paypal:0.3.1"
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
    "acuvity-mcp-server-paypal": {
      "env": {
        "PAYPAL_ACCESS_TOKEN": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "PAYPAL_ACCESS_TOKEN",
        "docker.io/acuvity/mcp-server-paypal:0.3.1"
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
        "env": {"PAYPAL_ACCESS_TOKEN":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","PAYPAL_ACCESS_TOKEN","docker.io/acuvity/mcp-server-paypal:0.3.1"]
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

**Environment variables and secrets:**
  - `PAYPAL_ACCESS_TOKEN` required to be set
  - `PAYPAL_ENVIRONMENT` optional (SANDBOX)


<details>
<summary>Locally with STDIO</summary>

In your client configuration set:

- command: `docker`
- arguments: `run -i --rm --read-only -e PAYPAL_ACCESS_TOKEN docker.io/acuvity/mcp-server-paypal:0.3.1`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -i --rm --read-only -e PAYPAL_ACCESS_TOKEN docker.io/acuvity/mcp-server-paypal:0.3.1
```

Add `-p <localport>:8000` to expose the port.

Then on your application/client, you can configure to use something like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-paypal": {
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
    "acuvity-mcp-server-paypal": {
      "command": "minibridge",
      "args": ["frontend", "--backend", "wss://<remote-url>:8000/ws", "--tls-client-backend-ca", "/path/to/ca/that/signed/the/server-cert.pem/ca.pem", "--tls-client-cert", "/path/to/client-cert.pem", "--tls-client-key", "/path/to/client-key.pem"]
    }
  }
}
```

That's it.

Minibridge offers a host of additional features. For step-by-step guidance, please visit the wiki. And if anything’s unclear, don’t hesitate to reach out!

</details>

## 🛡️ Runtime security

To activate guardrails in your Docker containers, define the `GUARDRAILS` environment variable with the protections you need. Available options:
- covert-instruction-detection
- sensitive-pattern-detection
- shadowing-pattern-detection
- schema-misuse-prevention
- cross-origin-tool-access
- secrets-redaction

for example, `-e GUARDRAILS="secrets-redaction covert-instruction-detection"` will enable the `secrets-redaction` and `covert-instruction-detection` guardrails.


To turn on Basic Authentication, set BASIC_AUTH_SECRET like `- e BASIC_AUTH_SECRET="supersecret`

Then you can connect through `http/sse` as usual given that you pass an `Authorization: Bearer supersecret` header with your secret as Bearer token.

> [!CAUTION]
> While basic auth will protect against unauthorized access, you should use it only in controlled environment,
> rotate credentials frequently and **always** use TLS.

## ☁️ Deploy On Kubernetes

<details>
<summary>Deploy using Helm Charts</summary>

### Chart settings requirements

This chart requires some mandatory information to be installed.

**Mandatory Secrets**:
  - `PAYPAL_ACCESS_TOKEN` secret to be set as secrets.PAYPAL_ACCESS_TOKEN either by `.value` or from existing with `.valueFrom`

**Optional Environment variables**:
  - `PAYPAL_ENVIRONMENT="SANDBOX"` environment variable can be changed with env.PAYPAL_ENVIRONMENT="SANDBOX"

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-paypal --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-paypal --version 1.0.0
````

Install with helm

```console
helm install mcp-server-paypal oci://docker.io/acuvity/mcp-server-paypal --version 1.0.0
```

From there your MCP server mcp-server-paypal will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-paypal` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-paypal/charts/mcp-server-paypal/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (26)
<details>
<summary>create_invoice</summary>

**Description**:

```

Create Invoices on PayPal.

This function is used to create an invoice in the PayPal system. It allows you to generate a new invoice, specifying details such as customer information, items, quantities, pricing, and tax information. Once created, an invoice can be sent to the customer for payment.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| detail | object | The invoice detail | Yes
| invoicer | object | The invoicer business information that appears on the invoice. | No
| items | array | Array of invoice line items | No
| primary_recipients | array | array of recipients | No
</details>
<details>
<summary>list_invoices</summary>

**Description**:

```

List invoices from PayPal.

This function retrieves a list of invoices with optional pagination parameters.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | The page number of the result set to fetch. | No
| page_size | number | The number of records to return per page (maximum 100). | No
| total_required | boolean | Indicates whether the response should include the total count of items. | No
</details>
<details>
<summary>get_invoice</summary>

**Description**:

```

Get an invoice from PayPal.

This function retrieves details of a specific invoice using its ID.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| invoice_id | string | The ID of the invoice to retrieve. | Yes
</details>
<details>
<summary>send_invoice</summary>

**Description**:

```

Send an invoice to the recipient(s).

This function sends a previously created invoice to its intended recipients.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additional_recipients | array | Additional email addresses to which to send the invoice. | No
| invoice_id | string | The ID of the invoice to send. | Yes
| note | string | A note to the recipient. | No
| send_to_recipient | boolean | Indicates whether to send the invoice to the recipient. | No
</details>
<details>
<summary>send_invoice_reminder</summary>

**Description**:

```

Send a reminder for an invoice.

This function sends a reminder for an invoice that has already been sent but hasn't been paid yet.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additional_recipients | array | Additional email addresses to which to send the reminder. | No
| invoice_id | string | The ID of the invoice for which to send a reminder. | Yes
| note | string | A note to the recipient. | No
| subject | string | The subject of the reminder email. | No
</details>
<details>
<summary>cancel_sent_invoice</summary>

**Description**:

```

Cancel a sent invoice.

This function cancels an invoice that has already been sent to the recipient(s).

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| additional_recipients | array | Additional email addresses to which to send the cancellation. | No
| invoice_id | string | The ID of the invoice to cancel. | Yes
| note | string | A cancellation note to the recipient. | No
| send_to_recipient | boolean | Indicates whether to send the cancellation to the recipient. | No
</details>
<details>
<summary>generate_invoice_qr_code</summary>

**Description**:

```

Generate a QR code for an invoice.

This function generates a QR code for an invoice, which can be used to pay the invoice using a mobile device or scanning app.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| height | number | The QR code height | No
| invoice_id | string | The invoice id to generate QR code for | Yes
| width | number | The QR code width | No
</details>
<details>
<summary>create_product</summary>

**Description**:

```

Create a product in PayPal using product catalog - create products API.
This function creates a new product that will be used in subscription plans, subscriptions.
Required parameters are: name (product name), type (product type).
High level: 
    - id: (auto-generated or specify SKU of the product) The ID of the product
    - name: {product_name} (required) 
    - description: {product_description} (optional)
    - type {DIGITAL | PHYSICAL | SERVICE} (required)
    - category: {product_category} (optional) 
    - image_url: {image_url} (optional)
    - home_url: {home_url} (optional)

Below is the payload request structure:
{
    "id": "#PROD-XYAB12ABSB7868434",
    "name": "Video Streaming Service",
    "description": "Service for streaming latest series, movies etc.",
    "type": "SERVICE",
    "category": "SOFTWARE",
    "image_url": "https://example.com/streaming.jpg",
    "home_url": "https://example.com/home"
}


```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| category | string | The product category. | No
| description | string | The product description. | No
| home_url | string | The home page URL for the product. | No
| image_url | string | The image URL for the product. | No
| name | string | The product name. | Yes
| type | string | The product type. Value is PHYSICAL, DIGITAL, or SERVICE. | Yes
</details>
<details>
<summary>list_products</summary>

**Description**:

```

List products from PayPal.

This function retrieves a list of products with optional pagination parameters.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | The page number of the result set to fetch. | No
| page_size | number | The number of records to return per page (maximum 100). | No
| total_required | boolean | Indicates whether the response should include the total count of products. | No
</details>
<details>
<summary>update_product</summary>

**Description**:

```

Update a product in PayPal.

This function updates an existing product using JSON Patch operations.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| operations | array | The PATCH operations to perform on the product. | Yes
| product_id | string | The ID of the product to update. | Yes
</details>
<details>
<summary>show_product_details</summary>

**Description**:

```

List products from PayPal.

This function retrieves a list of products with optional pagination parameters.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| product_id | string | The ID of the product to update. | Yes
</details>
<details>
<summary>create_subscription_plan</summary>

**Description**:

```

Create a subsctiption plan in PayPal using subscription - create plan API.
This function creates a new subscription plan that defines pricing and billing cycle details for subscriptions.
Required parameters are: product_id (the ID of the product for which to create the plan), name (subscription plan name), billing_cycles (billing cycle details).
High level: product_id, name, description, taxes, status: {CREATED|INACTIVE|ACTIVE}, billing_cycles, payment_preferences are required in json object.
While creating billing_cycles object, trial(second) billing cycle should precede regular billing cycle.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| billing_cycles | array | The billing cycles of the plan. | Yes
| description | string | The subscription plan description. | No
| name | string | The subscription plan name. | Yes
| payment_preferences | object | The payment preferences for the subscription plan. | No
| product_id | string | The ID of the product for which to create the plan. | Yes
| taxes | object | The tax details. | No
</details>
<details>
<summary>list_subscription_plans</summary>

**Description**:

```

List subscription plans from PayPal.

This function retrieves a list of subscription plans with optional product filtering and pagination parameters.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| page | number | The page number of the result set to fetch. | No
| page_size | number | The number of records to return per page (maximum 100). | No
| product_id | string | The ID of the product for which to get subscription plans. | No
| total_required | boolean | Indicates whether the response should include the total count of plans. | No
</details>
<details>
<summary>show_subscription_plan_details</summary>

**Description**:

```

Show subscription plan details from PayPal.
This function retrieves the details of a specific subscription plan using its ID.
Required parameters are: plan_id (the ID of the subscription plan).

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| plan_id | string | The ID of the subscription plan to show. | Yes
</details>
<details>
<summary>create_subscription</summary>

**Description**:

```

Create a subscription in PayPal using the subscription - create subscription API.
This function allows you to create a new subscription for a specific plan, enabling the management of recurring payments.
The only required parameter is plan_id (the ID of the subscription plan). All other fields are optional and can be omitted if not provided.
The subscriber field is optional. If no subscriber information is provided, omit the subscriber field in the request payload.
The shipping address is optional. If no shipping address is provided, set the shipping_preference to GET_FROM_FILE in the application context.
The application context is also optional. If no application context information is provided, omit the application context field in the request payload.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| application_context | object | The application context for the subscription. | No
| plan_id | string | The ID of the subscription plan to create. | Yes
| quantity | number | The quantity of the product in the subscription. | No
| shipping_amount | object | The shipping amount for the subscription. | No
| subscriber | object | The subscriber details. | No
</details>
<details>
<summary>show_subscription_details</summary>

**Description**:

```

Show subscription details from PayPal.
This function retrieves the details of a specific subscription using its ID.
Required parameters are: subscription_id (the ID of the subscription).

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| subscription_id | string | The ID of the subscription to show details. | Yes
</details>
<details>
<summary>cancel_subscription</summary>

**Description**:

```

Cancel a customer subscription in PayPal.

This function cancels an active subscription for a customer. It requires the subscription ID and an optional reason for cancellation.
Required parameters are: subscription_id (the ID of the subscription to be canceled).
Below is the payload request structure:
{
    "reason": "Customer requested cancellation"
}
You MUST ask the user for: 
 - subscription_id
 - reason for cancellation.

Return all of the above as structured JSON in your response.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| payload | object | Payload for subscription cancellation. | Yes
| subscription_id | string | The ID of the subscription to show details. | Yes
</details>
<details>
<summary>create_shipment_tracking</summary>

**Description**:

```

Create a shipment for a transaction in PayPal.
This function creates a shipment record for a specific transaction, allowing you to track the shipment status and details.
The transaction_id can fetch from the captured payment details in the order information.
Required parameters are: tracking_number (the tracking number for the shipment), transaction_id (the transaction ID associated with the shipment). 
High level: tracking_number, transaction_id, status (optional), carrier (optional) are required json objects.
Below is the payload request structure:
{
    "tracking_number": "1234567890",
    "transaction_id": "9XJ12345ABC67890",
    "status": "SHIPPED", // Required: ON_HOLD, SHIPPED, DELIVERED, CANCELLED
    "carrier": "UPS" // Required: The carrier handling the shipment. Link to supported carriers: http://developer.paypal.com/docs/tracking/reference/carriers/
}

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| carrier | string | The carrier handling the shipment. | No
| order_id | string | The ID of the order for which to create a shipment | No
| status | string | The status of the shipment. It can be "ON_HOLD", "SHIPPED", "DELIVERED", or "CANCELLED". | No
| tracking_number | string | The tracking number for the shipment. Id is provided by the shipper. This is required to create a shipment. | Yes
| transaction_id | string | The transaction ID associated with the shipment. Transaction id available after the order is paid or captured. This is required to create a shipment. | Yes
</details>
<details>
<summary>get_shipment_tracking</summary>

**Description**:

```

Get tracking information for a shipment by ID.
This function retrieves tracking information for a specific shipment using the transaction ID and tracking number.
The transaction_id can fetch from the captured payment details in the order information.
Below is the payload request structure:

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| order_id | string | The ID of the order for which to create a shipment. | No
| transaction_id | string | The transaction ID associated with the shipment tracking to retrieve. | No
</details>
<details>
<summary>create_order</summary>

**Description**:

```

Create an order in PayPal.

This tool is used to create a new order in PayPal. This is typically the first step in initiating a payment flow. It sets up an order with specified details such as item(s) to be purchased, quantity, amount, currency, and other details.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| cancelUrl | string | not set | No
| currencyCode | string | Currency code of the amount. | Yes
| discount | number | The discount amount for the order. | No
| items | array | not set | Yes
| notes | any | not set | No
| returnUrl | string | not set | No
| shippingAddress | any | The shipping address for the order. | No
| shippingCost | number | The cost of shipping for the order. | No
</details>
<details>
<summary>get_order</summary>

**Description**:

```

Retrieves the order details from PayPal for a given order ID.

This tool is used to retrieve details of an existing order in PayPal. It provides information about the order, including items, amounts, status, and other relevant details.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The order id generated during create call | Yes
</details>
<details>
<summary>pay_order</summary>

**Description**:

```

Capture a payment for an order.

This tool is used to capture a payment for an order. It allows you to capture funds that have been authorized for a specific order but not yet captured.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| id | string | The order id generated during create call | Yes
</details>
<details>
<summary>list_disputes</summary>

**Description**:

```

List disputes from PayPal.

This function retrieves a list of disputes with optional pagination and filtering parameters.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dispute_state | string | OPEN_INQUIRIES | No
| disputed_transaction_id | [string null] | not set | No
| page | number | not set | No
| page_size | number | not set | No
</details>
<details>
<summary>get_dispute</summary>

**Description**:

```

Get details for a specific dispute from PayPal.

This tool is used to lists disputes with a summary set of details, which shows the dispute_id, reason, status, dispute_state, dispute_life_cycle_stage, dispute_channel, dispute_amount, create_time and update_time fields.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dispute_id | string | The order id generated during create call | Yes
</details>
<details>
<summary>accept_dispute_claim</summary>

**Description**:

```

Accept liability for a dispute claim.

This tool is used to accept liability for a dispute claim. When you accept liability for a dispute claim, the dispute closes in the customer's favor and PayPal automatically refunds money to the customer from the merchant's account.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dispute_id | string | not set | Yes
| note | string | A note about why the seller is accepting the claim | Yes
</details>
<details>
<summary>list_transactions</summary>

**Description**:

```

List transactions from PayPal.

This tool is used to list transactions with optional filtering parameters within a date range of 31 days. This tool can also be used to list details of a transaction given the transaction ID.

- The start_date and end_date should be specified in ISO8601 date and time format. Example dates: 1996-12-19T16:39:57-08:00, 1985-04-12T23:20:50.52Z, 1990-12-31T23:59:60Z
- The transaction_status accepts the following 4 values:
    1. "D" - represents denied transactions.
    2. "P" - represents pending transactions.
    3. "S" - represents successful transactions.
    4. "V" - represents transactions that were reversed.
- The transaction_id is the unique identifier for the transaction.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| end_date | string | Filters the transactions in the response by an end date and time, in ISO8601 date and time format. Seconds are required. Fractional seconds are optional. The maximum supported range is 31 days. | No
| page | number | not set | No
| page_size | number | not set | No
| search_months | number | Number of months to search back for a transaction by ID. Default is 12 months. | No
| start_date | string | Filters the transactions in the response by a start date and time, in ISO8601 date and time format. Seconds are required. Fractional seconds are optional. | No
| transaction_id | any | The ID of the transaction to retrieve. | No
| transaction_status | string | not set | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | accept_dispute_claim | description | b1933f793ac185703a018262c8eea7b242ce13368620775f70d86580b60aefbc |
| tools | accept_dispute_claim | note | fbaace9a801dc8badcc50faaeef1be1b616eafd80cb77762f07e40c8dbaae6be |
| tools | cancel_sent_invoice | description | b1c87854743acd5a5011a5cd11e1aff26651993737c584f50147488b47a957d7 |
| tools | cancel_sent_invoice | additional_recipients | 1e93299d0c00e68588a51c38ee4f9fa31229b46957f5d50ebf36c29664dfa3dc |
| tools | cancel_sent_invoice | invoice_id | c171c78257b409d1a5e731b433c645c057d0b170aa1c4bffe0e57a030482f28e |
| tools | cancel_sent_invoice | note | 88ead3387ee035399286823b66ae6c45d1cd98c01769aff4ebfa951684503559 |
| tools | cancel_sent_invoice | send_to_recipient | 3b43201223c68fa60d9454bb9a3b986893a81685d3567eaa68d579fc83363a0b |
| tools | cancel_subscription | description | 7d6833fff2db3c711f6c643cc5b1fe3ab29c572d020e652bf8cc6cc4c27e9127 |
| tools | cancel_subscription | payload | 37507667522e15e74568ab3d34e5c40fc2fdb455ee338cc19a2fc8d2b059c242 |
| tools | cancel_subscription | subscription_id | 22de63bd2395e148b9cb8fe8cf3a9880fa934e91645fcaaaed95a94a1ee9d534 |
| tools | create_invoice | description | d162fa6c1cb170d6c52eb9f0be58820afa8798ca4170316349c22b024e86a310 |
| tools | create_invoice | detail | f5003d577951c22781b31f27d515b809dfaf31b07fab88127d510f86a79dfbef |
| tools | create_invoice | invoicer | 929a43ba9bac8fb64de66777566e95d4cef378798a5e95b822b1c45298364382 |
| tools | create_invoice | items | 840ca004ed6cd1373249816219d1fdfb4d5766b9b27f284d29778074a5dd5ffb |
| tools | create_invoice | primary_recipients | d794d96c1205cb90c187c01955c84540d5f4b0f8a39d753901a3fa848695175e |
| tools | create_order | description | f1f1a9fd8fef15927596f4df87f7105870c577d4ab45066cf28e37d376a291f9 |
| tools | create_order | currencyCode | 4ec2c4acfdac276c0ca2981c6f4ec2398114843be5e1e1ea55b86117209430a2 |
| tools | create_order | discount | c9f902f56c6385a4cfef62d0ea8d5f9976ea6733c3af17aab2e1409e3a2ce519 |
| tools | create_order | shippingAddress | 6c62130b8faf6a5755de2ff664aa003037335339f7c68ff11b60679622a97ebb |
| tools | create_order | shippingCost | 8a1ca2ba2a8038618cc366c6abd1214e281b03b4e3a853e2a844c3c8a7d21243 |
| tools | create_product | description | 00a8879bf150980c2946297ca4a48449278ce048f7a94a711b7a1095f915db20 |
| tools | create_product | category | cce781630b6f2ab5df45cd04beeb606e3410c4760a4d9c7674afe67a9da80a1f |
| tools | create_product | description | 1ef017a834c7a3f5be33bcca42ff18895b821c81d398fe62ced1f4a6233ff23c |
| tools | create_product | home_url | b0f864deb5eb0308220c2402d9b8d7fdc1b60d6a253acacdd5197074e8983fae |
| tools | create_product | image_url | 608ba1af8b48ae826cee6810dc5cb5a124084808ab74a62f016c20ce4af2c915 |
| tools | create_product | name | 49f35cafedd1db605bc9d090593eb8a4489980fd332c801affe05ee55be2a248 |
| tools | create_product | type | f97abc519a2e60f2ac24f444eee89eee9a3cbac4a63fc25d79ce72c210cda5d5 |
| tools | create_shipment_tracking | description | 027bd7dc3b6b68f7c75083374afaeb9347cbca835dd6ff2b0f5b0a2b491769b3 |
| tools | create_shipment_tracking | carrier | 5b72ad316fd7e749dfb5eae97f148c7c4ff256894f9cdbed89c9e7b5ea4771fe |
| tools | create_shipment_tracking | order_id | 718a5cd2bb51958ee35d8d799e50e81ed4c69eeb7a0cc082a3a144a74bfb742d |
| tools | create_shipment_tracking | status | 87ad2fd33fab223266c2579f9534188ac039fad6eaa1bd4e0b7271e442bc0268 |
| tools | create_shipment_tracking | tracking_number | 2d2ce33ff462e68396265e657b341d5c851860ac2e2067707fd20c95284e37c6 |
| tools | create_shipment_tracking | transaction_id | eb1a93902db683c03cb4d88e4bc2f0f9fc3e434dd7e85573f8bac1ff204068e1 |
| tools | create_subscription | description | c7115b9f7e75abdd40899779d1bb63ae34a45f455465733eeb7828cfa3bf41a1 |
| tools | create_subscription | application_context | 7fdbf2f23f7d1a64aee383e30c15460653be03226411ec58c4d43644f1ab3dde |
| tools | create_subscription | plan_id | 2e105f8ba2f060c72dfd1a7a0d4fcd34b2e3e682e63044cdd4c27afd49ebd030 |
| tools | create_subscription | quantity | f8cdd79509b2554ade987538a8a2202d3bd3d27bc8602c28f0b86f5d46455d45 |
| tools | create_subscription | shipping_amount | e0f51047c99500811e0848ada4d01f37faa11306292bc82de8c563732a004ba9 |
| tools | create_subscription | subscriber | a68df6aeddc9706470fb0af7938d6e948d82ddf268986bf69f18a42346671810 |
| tools | create_subscription_plan | description | 5380689297757e84689409bab34c57bf4b29e2aea5dea15d233c141709038ba6 |
| tools | create_subscription_plan | billing_cycles | 80ea251c46e5faa9f523852d04b26b03abdd215b49f8f20e25e7142014e2150b |
| tools | create_subscription_plan | description | 7417b5d0e29cb78bf7dcf6ed411cf99ad6759637f9c1b9639e63d3c6648e1407 |
| tools | create_subscription_plan | name | 4cc188e571be729c505e8998fc2f160544fb0de68ee1de709e5c1f6c4c569cc7 |
| tools | create_subscription_plan | payment_preferences | 56e78fd87d40160dafb3958dd8a7b4a16fc06cbe5a01ff9581319b80db20a16e |
| tools | create_subscription_plan | product_id | 42f79d5bb0fda81c73f491ee10cec5dd0f64c0f03e2b618d2dd69cc022cbdcc1 |
| tools | create_subscription_plan | taxes | f975a3119b09add36459f117267a43943619acae1c04e1a6c65f8026edaacec6 |
| tools | generate_invoice_qr_code | description | 6920ac4c77a111f86b43449c4fa663cfc5a441facfc0f5ccc2d7f3ac93de9aa0 |
| tools | generate_invoice_qr_code | height | 9c3a03bfdd3bbe8020fd1c3a9b4481cd927c0281eba33b7d663c4c28c2bdd32f |
| tools | generate_invoice_qr_code | invoice_id | d1f3892050828dee8308368c48b0dedf2d89bc906f306a16826aac19972e9aea |
| tools | generate_invoice_qr_code | width | 6ff0e38b8c4e4191c38a1d9a4faa9473894be6f868f9051aa2b50e38276750ef |
| tools | get_dispute | description | 602385abe77c1d93ae06f5bfe29d4608ff88d2a56aa0ccd2a3f19370a38e0d01 |
| tools | get_dispute | dispute_id | 0d4b68361bc934c4f57f9c06dc86425396ecfaed39b650659dcba40d3462c9cf |
| tools | get_invoice | description | 00c6ebf42b3af8f9e7bc129f8026f4c437871d6a7e66f31aaa86c6f1266a2f47 |
| tools | get_invoice | invoice_id | d1619687a9b7811554b2b52a162c5db0636d6c1a69c1afa7159728979f6c0dc6 |
| tools | get_order | description | 5a776b6ca17bbf0f8bcf4d15e092aca1af56647b164073fdcf80b634e4c89aac |
| tools | get_order | id | 0d4b68361bc934c4f57f9c06dc86425396ecfaed39b650659dcba40d3462c9cf |
| tools | get_shipment_tracking | description | 4ee15334126f6265f48a944b47fd6ae1ca2fe868efc935d023f5e50c2d9be1d8 |
| tools | get_shipment_tracking | order_id | 1ea99bceeb25186893d9db55005f766b609de07a99e200ce98aff2a1a876e92f |
| tools | get_shipment_tracking | transaction_id | cb85245c59d5f94cdfecb537375f1b05ac7644811ab5c6e473402ca64d8f1f30 |
| tools | list_disputes | description | bf2fe130acca4c7784cab0e8531f1457a68e1845beb92071bd87975ec0d13a24 |
| tools | list_disputes | dispute_state | 313b09997f112d2095263ed270e89d78651e4625a60418e7c738810f0fa8d06f |
| tools | list_invoices | description | b45fbd18a3a846b9dea55c171d8ac91abbe62e575d440f260c5e2e5bd2925ed0 |
| tools | list_invoices | page | b9f4e9526010a0ab5c203f8f2fe13e09c0f4180a0690f7e96537f4a5d95c24cb |
| tools | list_invoices | page_size | 2372bb791f66d97a21c1709ac8b7fd0c13264f27910afad4eda05f0aa53cbc78 |
| tools | list_invoices | total_required | 50ad09b19aca2013ca7134aa899a2098b7b4e117b6015df74b478c47cccab675 |
| tools | list_products | description | 58cd51a5e3673a1597f9b0097b7b45077ac3301355e516470f9646cb09462403 |
| tools | list_products | page | b9f4e9526010a0ab5c203f8f2fe13e09c0f4180a0690f7e96537f4a5d95c24cb |
| tools | list_products | page_size | 2372bb791f66d97a21c1709ac8b7fd0c13264f27910afad4eda05f0aa53cbc78 |
| tools | list_products | total_required | 23b8c7faeb92033b38b267e243c7e8e44a94146c71c63e7b4da7a0fd54900940 |
| tools | list_subscription_plans | description | 8bf6e1de20b39cf519744af1793f3f37963afb4311256dfc1f882e5d155d3f62 |
| tools | list_subscription_plans | page | b9f4e9526010a0ab5c203f8f2fe13e09c0f4180a0690f7e96537f4a5d95c24cb |
| tools | list_subscription_plans | page_size | 2372bb791f66d97a21c1709ac8b7fd0c13264f27910afad4eda05f0aa53cbc78 |
| tools | list_subscription_plans | product_id | 1d6807c288dc45573188adadc93b97f6ff193871d4e08d2609a9da3b9d2fe0b5 |
| tools | list_subscription_plans | total_required | c7143bd25ecb067e86617dce388ce5557a3ef9088b4d8579407b4882d73191e3 |
| tools | list_transactions | description | 855b0696ed4f2f523950575e9b3118d6c99f35325861e4628a73e274b84d2d4e |
| tools | list_transactions | end_date | 73ac8319649c90c2934d55253b75362898af59b824e02a7017ce56463ab1a28b |
| tools | list_transactions | search_months | d3bd0a8cad421f80f6f3c029bda430777985ae0873d92045a0e486edd3614495 |
| tools | list_transactions | start_date | 4c2bb3018345b77c1a883553c71e911d3d7dc72ccbb270ae416e0dfdbf4a01b0 |
| tools | list_transactions | transaction_id | 773bd133efa194b2c82d823fd23f098b69e3a6ce1a40339672af9bc7b41aa10c |
| tools | pay_order | description | 2e1e89b75937ef80ec0209d45a0dd4347c9026f9a87cf1356c206bd78f875d40 |
| tools | pay_order | id | 0d4b68361bc934c4f57f9c06dc86425396ecfaed39b650659dcba40d3462c9cf |
| tools | send_invoice | description | 8c88997ae12580e167c7f5db8fabf298204d072042ea3c1ea17445be5499ead1 |
| tools | send_invoice | additional_recipients | 331781094eabb90876ae8114384c7d219b2ed05ac3dd90869e59b273b87973b3 |
| tools | send_invoice | invoice_id | c1c751d3b8ec5e75c19f9c2446f9133180655c26c1dc6fb95b011bac54c29307 |
| tools | send_invoice | note | 3b93e49fa51e4c7c0e2bccb0f0c00009e224dfe2192a57aa060d9bb329abf7bb |
| tools | send_invoice | send_to_recipient | dee375deb00a4d66eed02dbfc77b3177848491f13008fb51591196ceb7ebd18c |
| tools | send_invoice_reminder | description | fb5fa1bc3a7add68c4a8595106e007b5eef1bdcf24d720e8839a9b9a3097c99f |
| tools | send_invoice_reminder | additional_recipients | bed2a24aa2fadfb1d0e7295d6c99b29448764759c07342f62b508cd5e1bdac4a |
| tools | send_invoice_reminder | invoice_id | 8d7cbfcbf26df64cfcb5e6ce8ace319462dd3bd87bf451a27129fee9b7c6563b |
| tools | send_invoice_reminder | note | 3b93e49fa51e4c7c0e2bccb0f0c00009e224dfe2192a57aa060d9bb329abf7bb |
| tools | send_invoice_reminder | subject | d2ed816dd4486a81f9ada7b131ec8768203ce933bd0c0fba5a4b895ef9a244a6 |
| tools | show_product_details | description | 58cd51a5e3673a1597f9b0097b7b45077ac3301355e516470f9646cb09462403 |
| tools | show_product_details | product_id | 6a82a49e8519288550e18431e0bd9de45cf82de94b5b147e90d0b0d463ed55f7 |
| tools | show_subscription_details | description | 3d1116fb3df592fb7445420439472ae55cb15a590988c2ca01d0af37467e14a6 |
| tools | show_subscription_details | subscription_id | 22de63bd2395e148b9cb8fe8cf3a9880fa934e91645fcaaaed95a94a1ee9d534 |
| tools | show_subscription_plan_details | description | 4481df90ef55fd0532176b86535f305d185da32500e1663fcc66287395f37724 |
| tools | show_subscription_plan_details | plan_id | a6f4adc6ec92e33cbb9be4bd5c4ffddbd5ad41e6edc75697c3fc5f3b25ed70fd |
| tools | update_product | description | ed6ac81a692e5a44d99be9075ea74748bee0c046bcc3dfd487854f7b1f0117ac |
| tools | update_product | operations | 0ac0cfd477c65cff9aa1d9ca99573c9afbf7245e69f2d33310d2ca85a05fc225 |
| tools | update_product | product_id | 6a82a49e8519288550e18431e0bd9de45cf82de94b5b147e90d0b0d463ed55f7 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
