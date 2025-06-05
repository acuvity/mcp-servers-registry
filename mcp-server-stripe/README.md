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


# What is mcp-server-stripe?
[![Rating](https://img.shields.io/badge/C-3775A9?label=Rating)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use/implement-tool-use#best-practices-for-tool-definitions)
[![Helm](https://img.shields.io/badge/1.0.0-3775A9?logo=helm&label=Charts&logoColor=fff)](https://hub.docker.com/r/acuvity/mcp-server-stripe/tags/)
[![Docker](https://img.shields.io/docker/image-size/acuvity/mcp-server-stripe/0.2.3?logo=docker&logoColor=fff&label=0.2.3)](https://hub.docker.com/r/acuvity/mcp-server-stripe)
[![PyPI](https://img.shields.io/badge/0.2.3-3775A9?logo=pypi&logoColor=fff&label=@stripe/mcp)](https://github.com/stripe/agent-toolkit)
[![Scout](https://img.shields.io/badge/Active-3775A9?logo=docker&logoColor=fff&label=Scout)](https://hub.docker.com/r/acuvity/mcp-server-stripe/)
[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-stripe&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22STRIPE_SECRET_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-stripe%3A0.2.3%22%5D%2C%22command%22%3A%22docker%22%7D)

**Description:** Integrates Stripe APIs with agent frameworks for payments and custom actions.

Packaged by Acuvity and published to our curated MCP server [registry](https://mcp.acuvity.ai) from @stripe/mcp original [sources](https://github.com/stripe/agent-toolkit).

**Quick links:**

- [Integrate with your IDE](https://github.com/acuvity/mcp-servers-registry/blob/main/mcp-server-stripe/docker/README.md#-clients-integrations)
- [Install with Docker](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-stripe/docker/README.md#-run-it-with-docker)
- [Install with Helm](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-stripe/charts/mcp-server-stripe/README.md#how-to-install)

# Why We Built This

At [Acuvity](https://acuvity.ai), security is central to our mission—especially for critical systems like MCP servers and integration in agentic systems.
To address this need, we've created a secure and robust Docker image designed to ensure @stripe/mcp run reliably and safely.

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

The [ARC](https://github.com/acuvity/mcp-servers-registry/tree/main) container includes a [built-in Rego policy](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-stripe/docker/policy.rego) that enables a set of runtime "guardrails"" to help enforce security, privacy, and correct usage of your services. Below is an overview of each guardrail provided.

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
> Given mcp-server-stripe scope of operation it can be hosted anywhere.

**Environment variables and secrets:**
  - `STRIPE_SECRET_KEY` required to be set

For more information and extra configuration you can consult the [package](https://github.com/stripe/agent-toolkit) documentation.

# 🧰 Clients Integrations

Below are the steps for configuring most clients that use MCP to elevate their Copilot experience.

> [!NOTE]
> These integrations function natively across all Minibridge modes.
> To keep things brief, only the docker local-run setup is covered here.

<details>
<summary>Visual Studio Code</summary>

To get started immediately, you can use the "one-click" link below:

[![Install in VS Code Docker](https://img.shields.io/badge/VS_Code-One_click_install-0078d7?logo=githubcopilot)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-server-stripe&config=%7B%22args%22%3A%5B%22run%22%2C%22-i%22%2C%22--rm%22%2C%22--read-only%22%2C%22-e%22%2C%22STRIPE_SECRET_KEY%22%2C%22docker.io%2Facuvity%2Fmcp-server-stripe%3A0.2.3%22%5D%2C%22command%22%3A%22docker%22%7D)

## Global scope

Press `ctrl + shift + p` and type `Preferences: Open User Settings JSON` to add the following section:

```json
{
  "mcp": {
    "servers": {
      "acuvity-mcp-server-stripe": {
        "env": {
          "STRIPE_SECRET_KEY": "TO_BE_SET"
        },
        "command": "docker",
        "args": [
          "run",
          "-i",
          "--rm",
          "--read-only",
          "-e",
          "STRIPE_SECRET_KEY",
          "docker.io/acuvity/mcp-server-stripe:0.2.3"
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
    "acuvity-mcp-server-stripe": {
      "env": {
        "STRIPE_SECRET_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "STRIPE_SECRET_KEY",
        "docker.io/acuvity/mcp-server-stripe:0.2.3"
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
    "acuvity-mcp-server-stripe": {
      "env": {
        "STRIPE_SECRET_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "STRIPE_SECRET_KEY",
        "docker.io/acuvity/mcp-server-stripe:0.2.3"
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
    "acuvity-mcp-server-stripe": {
      "env": {
        "STRIPE_SECRET_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "STRIPE_SECRET_KEY",
        "docker.io/acuvity/mcp-server-stripe:0.2.3"
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
    "acuvity-mcp-server-stripe": {
      "env": {
        "STRIPE_SECRET_KEY": "TO_BE_SET"
      },
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--read-only",
        "-e",
        "STRIPE_SECRET_KEY",
        "docker.io/acuvity/mcp-server-stripe:0.2.3"
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
        "env": {"STRIPE_SECRET_KEY":"TO_BE_SET"},
        "command": "docker",
        "args": ["run","-i","--rm","--read-only","-e","STRIPE_SECRET_KEY","docker.io/acuvity/mcp-server-stripe:0.2.3"]
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
- arguments: `run -i --rm --read-only -e STRIPE_SECRET_KEY docker.io/acuvity/mcp-server-stripe:0.2.3`

</details>

<details>
<summary>Locally with HTTP/sse</summary>

Simply run as:

```console
docker run -it -p 8000:8000 --rm --read-only -e STRIPE_SECRET_KEY docker.io/acuvity/mcp-server-stripe:0.2.3
```

Then on your application/client, you can configure to use it like:

```json
{
  "mcpServers": {
    "acuvity-mcp-server-stripe": {
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
    "acuvity-mcp-server-stripe": {
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
  - `STRIPE_SECRET_KEY` secret to be set as secrets.STRIPE_SECRET_KEY either by `.value` or from existing with `.valueFrom`

### How to install

You can inspect the chart `README`:

```console
helm show readme oci://docker.io/acuvity/mcp-server-stripe --version 1.0.0
````

You can inspect the values that you can configure:

```console
helm show values oci://docker.io/acuvity/mcp-server-stripe --version 1.0.0
````

Install with helm

```console
helm install mcp-server-stripe oci://docker.io/acuvity/mcp-server-stripe --version 1.0.0
```

From there your MCP server mcp-server-stripe will be reachable by default through `http/sse` from inside the cluster using the Kubernetes Service `mcp-server-stripe` on port `8000` by default. You can change that by looking at the `service` section of the `values.yaml` file.

### How to Monitor

The deployment will create a Kubernetes service with a `healthPort`, that is used for liveness probes and readiness probes. This health port can also be used by the monitoring stack of your choice and exposes metrics under the `/metrics` path.

See full charts [Readme](https://github.com/acuvity/mcp-servers-registry/tree/main/mcp-server-stripe/charts/mcp-server-stripe/README.md) for more details about settings and runtime security including guardrails activation.

</details>

# 🧠 Server features

## 🧰 Tools (21)
<details>
<summary>create_customer</summary>

**Description**:

```

This tool will create a customer in Stripe.

It takes two arguments:
- name (str): The name of the customer.
- email (str, optional): The email of the customer.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| email | string | The email of the customer | No
| name | string | The name of the customer | Yes
</details>
<details>
<summary>list_customers</summary>

**Description**:

```

This tool will fetch a list of Customers from Stripe.

It takes two arguments:
- limit (int, optional): The number of customers to return.
- email (str, optional): A case-sensitive filter on the list based on the customer's email field.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| email | string | A case-sensitive filter on the list based on the customer's email field. The value must be a string. | No
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100. | No
</details>
<details>
<summary>create_product</summary>

**Description**:

```

This tool will create a product in Stripe.

It takes two arguments:
- name (str): The name of the product.
- description (str, optional): The description of the product.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| description | string | The description of the product. | No
| name | string | The name of the product. | Yes
</details>
<details>
<summary>list_products</summary>

**Description**:

```

This tool will fetch a list of Products from Stripe.

It takes one optional argument:
- limit (int, optional): The number of products to return.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100, and the default is 10. | No
</details>
<details>
<summary>create_price</summary>

**Description**:

```

This tool will create a price in Stripe. If a product has not already been specified, a product should be created first.

It takes three arguments:
- product (str): The ID of the product to create the price for.
- unit_amount (int): The unit amount of the price in cents.
- currency (str): The currency of the price.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| currency | string | The currency of the price. | Yes
| product | string | The ID of the product to create the price for. | Yes
| unit_amount | integer | The unit amount of the price in cents. | Yes
</details>
<details>
<summary>list_prices</summary>

**Description**:

```

This tool will fetch a list of Prices from Stripe.

It takes two arguments.
- product (str, optional): The ID of the product to list prices for.
- limit (int, optional): The number of prices to return.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100, and the default is 10. | No
| product | string | The ID of the product to list prices for. | No
</details>
<details>
<summary>create_payment_link</summary>

**Description**:

```

This tool will create a payment link in Stripe.

It takes two arguments:
- price (str): The ID of the price to create the payment link for.
- quantity (int): The quantity of the product to include in the payment link.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| price | string | The ID of the price to create the payment link for. | Yes
| quantity | integer | The quantity of the product to include. | Yes
</details>
<details>
<summary>create_invoice</summary>

**Description**:

```

  This tool will create an invoice in Stripe.
  
  It takes two arguments:
  - customer (str): The ID of the customer to create the invoice for.

  - days_until_due (int, optional): The number of days until the invoice is due.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customer | string | The ID of the customer to create the invoice for. | Yes
| days_until_due | integer | The number of days until the invoice is due. | No
</details>
<details>
<summary>create_invoice_item</summary>

**Description**:

```

This tool will create an invoice item in Stripe.

It takes three arguments'}:
- customer (str): The ID of the customer to create the invoice item for.

- price (str): The ID of the price to create the invoice item for.
- invoice (str): The ID of the invoice to create the invoice item for.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customer | string | The ID of the customer to create the invoice item for. | Yes
| invoice | string | The ID of the invoice to create the item for. | Yes
| price | string | The ID of the price for the item. | Yes
</details>
<details>
<summary>finalize_invoice</summary>

**Description**:

```

This tool will finalize an invoice in Stripe.

It takes one argument:
- invoice (str): The ID of the invoice to finalize.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| invoice | string | The ID of the invoice to finalize. | Yes
</details>
<details>
<summary>retrieve_balance</summary>

**Description**:

```

This tool will retrieve the balance from Stripe. It takes no input.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
</details>
<details>
<summary>create_refund</summary>

**Description**:

```

This tool will refund a payment intent in Stripe.

It takes three arguments:
- payment_intent (str): The ID of the payment intent to refund.
- amount (int, optional): The amount to refund in cents.
- reason (str, optional): The reason for the refund.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount | integer | The amount to refund in cents. | No
| payment_intent | string | The ID of the PaymentIntent to refund. | Yes
</details>
<details>
<summary>list_payment_intents</summary>

**Description**:

```

This tool will list payment intents in Stripe.

It takes two arguments:
- customer (str, optional): The ID of the customer to list payment intents for.

- limit (int, optional): The number of payment intents to return.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customer | string | The ID of the customer to list payment intents for. | No
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100. | No
</details>
<details>
<summary>list_subscriptions</summary>

**Description**:

```

This tool will list all subscriptions in Stripe.

It takes four arguments:
- customer (str, optional): The ID of the customer to list subscriptions for.

- price (str, optional): The ID of the price to list subscriptions for.
- status (str, optional): The status of the subscriptions to list.
- limit (int, optional): The number of subscriptions to return.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| customer | string | The ID of the customer to list subscriptions for. | No
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100. | No
| price | string | The ID of the price to list subscriptions for. | No
| status | string | The status of the subscriptions to retrieve. | No
</details>
<details>
<summary>cancel_subscription</summary>

**Description**:

```

This tool will cancel a subscription in Stripe.

It takes the following arguments:
- subscription (str, required): The ID of the subscription to cancel.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| subscription | string | The ID of the subscription to cancel. | Yes
</details>
<details>
<summary>update_subscription</summary>

**Description**:

```
This tool will update an existing subscription in Stripe. If changing an existing subscription item, the existing subscription item has to be set to deleted and the new one has to be added.
  
  It takes the following arguments:
  - subscription (str, required): The ID of the subscription to update.
  - proration_behavior (str, optional): Determines how to handle prorations when the subscription items change. Options: 'create_prorations', 'none', 'always_invoice', 'none_implicit'.
  - items (array, optional): A list of subscription items to update, add, or remove. Each item can have the following properties:
    - id (str, optional): The ID of the subscription item to modify.
    - price (str, optional): The ID of the price to switch to.
    - quantity (int, optional): The quantity of the plan to subscribe to.
    - deleted (bool, optional): Whether to delete this item.
  
```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| items | array | A list of subscription items to update, add, or remove. | No
| proration_behavior | string | Determines how to handle prorations when the subscription items change. | No
| subscription | string | The ID of the subscription to update. | Yes
</details>
<details>
<summary>search_stripe_documentation</summary>

**Description**:

```

This tool will take in a user question about integrating with Stripe in their application, then search and retrieve relevant Stripe documentation to answer the question.

It takes two arguments:
- question (str): The user question to search an answer for in the Stripe documentation.
- language (str, optional): The programming language to search for in the the documentation.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| language | string | The programming language to search for in the the documentation. | No
| question | string | The user question about integrating with Stripe will be used to search the documentation. | Yes
</details>
<details>
<summary>list_coupons</summary>

**Description**:

```

This tool will fetch a list of Coupons from Stripe.

It takes one optional argument:
- limit (int, optional): The number of coupons to return.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100. | No
</details>
<details>
<summary>create_coupon</summary>

**Description**:

```

This tool will create a coupon in Stripe.


It takes several arguments:
- name (str): The name of the coupon.

Only use one of percent_off or amount_off, not both:
- percent_off (number, optional): The percentage discount to apply (between 0 and 100).
- amount_off (number, optional): The amount to subtract from an invoice (in cents).

Optional arguments for duration. Use if specific duration is desired, otherwise default to 'once'.
- duration (str, optional): How long the discount will last ('once', 'repeating', or 'forever'). Defaults to 'once'.
- duration_in_months (number, optional): The number of months the discount will last if duration is repeating.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| amount_off | number | A positive integer representing the amount to subtract from an invoice total (required if percent_off is not passed) | Yes
| currency | string | Three-letter ISO code for the currency of the amount_off parameter (required if amount_off is passed). Infer based on the amount_off. For example, if a coupon is $2 off, set currency to be USD. | No
| duration | string | How long the discount will last. Defaults to "once" | No
| duration_in_months | number | The number of months the discount will last if duration is repeating | No
| name | string | Name of the coupon displayed to customers on invoices or receipts | Yes
| percent_off | number | A positive float larger than 0, and smaller or equal to 100, that represents the discount the coupon will apply (required if amount_off is not passed) | No
</details>
<details>
<summary>update_dispute</summary>

**Description**:

```

When you receive a dispute, contacting your customer is always the best first step. If that doesn't work, you can submit evidence to help resolve the dispute in your favor. This tool helps.

It takes the following arguments:
- dispute (string): The ID of the dispute to update
- evidence (object, optional): Evidence to upload for the dispute.
    - cancellation_policy_disclosure (string)
    - cancellation_rebuttal (string)
    - duplicate_charge_explanation (string)
    - uncategorized_text (string, optional): Any additional evidence or statements.
- submit (boolean, optional): Whether to immediately submit evidence to the bank. If false, evidence is staged on the dispute.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| dispute | string | The ID of the dispute to update | Yes
| evidence | object | Evidence to upload, to respond to a dispute. Updating any field in the hash will submit all fields in the hash for review. | No
| submit | boolean | Whether to immediately submit evidence to the bank. If false, evidence is staged on the dispute. | No
</details>
<details>
<summary>list_disputes</summary>

**Description**:

```

This tool will fetch a list of disputes in Stripe.

It takes the following arguments:
- charge (string, optional): Only return disputes associated to the charge specified by this charge ID.
- payment_intent (string, optional): Only return disputes associated to the PaymentIntent specified by this PaymentIntent ID.

```

**Parameter**:

| Name | Type | Description | Required? |
|-----------|------|-------------|-----------|
| charge | string | Only return disputes associated to the charge specified by this charge ID. | No
| limit | integer | A limit on the number of objects to be returned. Limit can range between 1 and 100, and the default is 10. | No
| payment_intent | string | Only return disputes associated to the PaymentIntent specified by this PaymentIntent ID. | No
</details>


# 🔐 Resource SBOM

Minibridge will perform hash checks for the following resources. The hashes are given as references and are the sha256 sum of the description.

| Resource | Name | Parameter | Hash |
|-----------|------|------|------|
| tools | cancel_subscription | description | d5281016042105579ae2a20d2a396079fb439841ddc0f676ef3d27d83d17e958 |
| tools | cancel_subscription | subscription | 42e215a7b67f6ae499397aaf15101d76be4df0d9febbd882689a9d5a9e994a38 |
| tools | create_coupon | description | 5cf3de2f3f4ed527ed78b7856e96bca2f03cc3d0f50b7f779ea750613dd72f45 |
| tools | create_coupon | amount_off | 662ab3bae58b4f78aa70f94897a17cc8bb196446a28edacdbff267b1b675b261 |
| tools | create_coupon | currency | 67f3cfd155e356aabe08688e2fc99aa8fd91f0f02cbd5befeacb2dfd818f03ca |
| tools | create_coupon | duration | e133b98bdc5958fa7b51bd462154eea63d67f898fa19f999385e1c814f9fad55 |
| tools | create_coupon | duration_in_months | 116f8855af22567351c3020c82ff0800253774ac67649d07d3de09dc1a39ebd4 |
| tools | create_coupon | name | 1efa27a394677fdc5bcf3b4268fbcd5e3446866dd46f845d2f008a60c704bfaf |
| tools | create_coupon | percent_off | 1094c36561b031126d3ebeec5cad56b1c840567ace96bca2b62e9b32d8b31416 |
| tools | create_customer | description | cdb36e9003bdee45463ea4e037431b0d7eb7e9784393697088a7ff358439d07c |
| tools | create_customer | email | d99f7de004bba07590b37985b25aff5f5a6ba44c76e427eb2b438b5fb94aef33 |
| tools | create_customer | name | f7c1d74e50840e8c18f5bfe738a653242755b99893dfc118a9512391b0de33cb |
| tools | create_invoice | description | 58f4f1bf25184bdf480801b6207df7c4984df380982ee0a20bf694bc6f55b11c |
| tools | create_invoice | customer | b35601d4b64cca25830fbde3acdcc09ffe201aace7db5afc8f2389977afed147 |
| tools | create_invoice | days_until_due | 1058c8c29ee0af000a7e54b13a210264226eb817cc544a494baa1c2b64243286 |
| tools | create_invoice_item | description | e4d1897bd8f791a1d8da33cb6ddae62473eaa6a69f1b5c6e4a0ca71af54a95b0 |
| tools | create_invoice_item | customer | 3c3fef960529e8c6b2fa71f3a43740103fd6d9bf35ad5cbc4e16ef2b03d15c62 |
| tools | create_invoice_item | invoice | 51c8ed0665f17d3b8c7caab19ae24998426670bfba0fdc21aeec6c49bf1ef5e3 |
| tools | create_invoice_item | price | f8a3f965a97d74c6365019baede9a2ca2a3fecc3f355dbbed4ef4bce122056a0 |
| tools | create_payment_link | description | 7ee22eb6a60c86051230fc7b96a8576f8528b883bb17658116bb7f0066561db3 |
| tools | create_payment_link | price | 1834560e20fba0615c43ff984736a2e457f2a4c3bcd257d8162a24be4711e284 |
| tools | create_payment_link | quantity | 5ea512a9bfc715a014d96c1a5fa8373b16249bff70fe8e006c2abd7c8c947672 |
| tools | create_price | description | f34412f5f87a7c7f4b04b1e82c56b339f83ab88c2ad46a75ec07c8437bf5bc80 |
| tools | create_price | currency | 6bf70be312491aea25785e8c8493a8499385cb847d6c9c92ce940e1938b67bf8 |
| tools | create_price | product | 1e7e6adb4a5eed36d1a299a36256283e48384b5f3e60b5c690b657b0eb81a74b |
| tools | create_price | unit_amount | b5104071601a65030e2346b9b82159b4b8fff925e48c0b51c52825a9ae0c0679 |
| tools | create_product | description | 32b43c71827d6a88177c906bbd923c9d9eb8df042b851433e48d030fd8139c88 |
| tools | create_product | description | 9ad594726497edd8cccdaa3f9355391c55f82c14bf8d4b2a38d67d89c84d8e8d |
| tools | create_product | name | 10fb2d345d86f9a4ff66819a9c86da911e4279145cb8e38165344f25a6c8b885 |
| tools | create_refund | description | 00248c92f357edb5c95becbb4c48ad80fc856a9671834fe08649539b16e2fea8 |
| tools | create_refund | amount | 411696a67aa2648bf2402d25aa027449bff6751b7c5d17138f597119fe757873 |
| tools | create_refund | payment_intent | 2f4e95ca314084e590382769b935ee2967b889ae84ffe29bc02dc068a92f313e |
| tools | finalize_invoice | description | 3b1eb70ad88b54996fabe1eeb283b5de63f7c3f8784c045fba71dda5a9d022a7 |
| tools | finalize_invoice | invoice | 99c68e1680159b1243962eafac81b37e098a216bb5877d03620d781d9b96191b |
| tools | list_coupons | description | 079483185ee0afd882046dc6c6116dd3d5bf8ecb8996126d2c0cd0ca6b128c6b |
| tools | list_coupons | limit | 405dd1ae7ab6f799c9c9986bf207e8a70fb9c28e5cb2e7d2a156376110adcb4f |
| tools | list_customers | description | fc9b06c457fb3eb493b07ed356b206f5af23b639a7927fa1a825be345eb1acdd |
| tools | list_customers | email | f47c815e7de0eb1b22b8fbb8e45e361e740eef0f5424e493bfd008486157092a |
| tools | list_customers | limit | 405dd1ae7ab6f799c9c9986bf207e8a70fb9c28e5cb2e7d2a156376110adcb4f |
| tools | list_disputes | description | 428366597bd9e962d6d60137ace4f682d4d972ac26d535ef8fa1c2d4b2e0f028 |
| tools | list_disputes | charge | 21d5f5856187b91973b747cc0082b1d42acd460e1590eca04166a65f67c93e6f |
| tools | list_disputes | limit | 57d5fc0d10d76b72692dfbbdf55291b6b1cfbd91efcfaeb3cde0df383d144a27 |
| tools | list_disputes | payment_intent | 33646415f148b9d0d7d013a37e99e35d2b487b6dcfbd7baae8f884abdf7858b8 |
| tools | list_payment_intents | description | 6f7b553eea744d425b376635973d57cdc1f09238dadffe2323ede06adc574a95 |
| tools | list_payment_intents | customer | bc0374954b25a175943a5945850bc71d6f79fe33cab1ca1acdc4b11017663cae |
| tools | list_payment_intents | limit | 405dd1ae7ab6f799c9c9986bf207e8a70fb9c28e5cb2e7d2a156376110adcb4f |
| tools | list_prices | description | 7d812ea4358dd65dd48509fac27a63fa4300637bc38eb92d052dc8b66116e2ad |
| tools | list_prices | limit | 57d5fc0d10d76b72692dfbbdf55291b6b1cfbd91efcfaeb3cde0df383d144a27 |
| tools | list_prices | product | 4d665e81f834434730ae69a9775268b7c2a5244ff3fa8397367106b7a899819f |
| tools | list_products | description | a55ba3daa31fbe9326d9faedfc0786b5221bcb9d3ace27cf6a0c1c39454f6044 |
| tools | list_products | limit | 57d5fc0d10d76b72692dfbbdf55291b6b1cfbd91efcfaeb3cde0df383d144a27 |
| tools | list_subscriptions | description | 52ad23c43d5e73fe19317cb349a057bacdaa98d5a2c697fded27e8008d1ef1aa |
| tools | list_subscriptions | customer | db5ed475b5daffc615431940b1c2ad4591aeca70d3dd015d9bacbcaa1a5e7244 |
| tools | list_subscriptions | limit | 405dd1ae7ab6f799c9c9986bf207e8a70fb9c28e5cb2e7d2a156376110adcb4f |
| tools | list_subscriptions | price | 640fe399e6d2c5d5f403be7b9245aba035edd21b89efbe7c38221fc8666404b1 |
| tools | list_subscriptions | status | 667b14ff3117138d9a12328076e00a8299eeb1948278fee5c6779307cacd9db4 |
| tools | retrieve_balance | description | 9c8fb8707dc9e98c9757483f0aa2f977a038a71b68497f4c9ad53eaf645da603 |
| tools | search_stripe_documentation | description | 27d8ca92f9679af20a22917b22fdcc57592dea3a97ed2b93ea6d688d0c948f10 |
| tools | search_stripe_documentation | language | 070a252b9466e9ede7bcca9e61ddbebb9c52efab647e83adc0face1e09ab28b9 |
| tools | search_stripe_documentation | question | 2dc9d1dbb1ccc4224a7465970d83733c07b1210c4e280d6c04d853a10909eb2a |
| tools | update_dispute | description | 5e15c03bddac95ecc67e8cb9f7787892c2e01374cb503493c7cc37ee5ca26158 |
| tools | update_dispute | dispute | 74fea5510e0aebdfeccc806d56d217925570a3e345dd1839fd8e6354e00e3d70 |
| tools | update_dispute | evidence | 671c39f2f893875fcfc38a784238f34e3adf49a73d925cf20d7c142cc918b305 |
| tools | update_dispute | submit | cfb21f0558511ddd1a5dd845ff81906dccb4db0f8aa681d7433d6f0775267fe0 |
| tools | update_subscription | description | 72580163c4f1e439e52b4b9eba9e0a7d46162a6e77c4781e001ce60f44077727 |
| tools | update_subscription | items | 1ae3540c1a2f19b01acc532a404feb50b826328528ce72a340ff52b33f398e74 |
| tools | update_subscription | proration_behavior | 77e189a2197b1b43050008523be716c98970ff98b23c24c995b6d9896f5d1d8e |
| tools | update_subscription | subscription | 37b9bbf503f3ec160f9ba6c7f283bc0cb155a5c6cd9ca5abaa094194110ea9f2 |


💬 Questions? Open an issue or contact [ support@acuvity.ai ](mailto:support@acuvity.ai).
📦 Contributions welcome!
