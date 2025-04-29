# 🚀 Secure and Simplify Your MCP Server with ARC

At [Acuvity](https://acuvity.ai), security is essential—especially for MCP servers powering critical agentic systems. That's why we created **ARC (Acuvity Runtime Container)**: a secure, streamlined Docker runtime designed specifically for MCP servers.

**ARC** provides an isolated, robust environment, adding strong security measures, simplified deployment, and seamless remote access—letting you focus on your MCP server’s capabilities, not operational complexities.

## 🔧 Why ARC?

**ARC** securely hosts your MCP servers with built-in runtime protection, secure connectivity, and effortless deployment:

### 🔐 Built-in Security

- **Isolated Execution**: Run securely in isolated containers, preventing lateral movement.
- **Non-root by Default**: Minimize risks by enforcing least-privilege.
- **Immutable Runtime**: Read-only filesystem ensures tamper-proof operations.
- **Version Pinning & CVE Scanning**: Consistent and secure deployments with proactive vulnerability detection (via Docker Scout).
- **SBOM & Provenance**: Traceable builds for complete supply chain transparency.

### 🛡️ Runtime Protection with Minibridge

[Minibridge](https://github.com/acuvity/minibridge) integrates seamlessly with ARC to secure agent-to-MCP interactions, enforcing runtime integrity and policy compliance:

- **Integrity Checks**: Ensures authenticity with runtime component hashing.
- **Threat Detection & Prevention with built-in Rego Policy**:
  - Covert‐instruction screening: Blocks any tool description or call arguments that match a wide list of "hidden prompt" phrases (e.g., "do not tell", "ignore previous instructions", Unicode steganography).
  - Schema-key misuse guard: Rejects tools or call arguments that expose internal-reasoning fields such as note, debug, context, etc., preventing jailbreaks that try to surface private metadata.
  - Sensitive-resource exposure check: Denies tools whose descriptions—or call arguments—that reference paths, files, or patterns typically associated with secrets (e.g., .env, /etc/passwd, SSH keys).
  - Tool-shadowing detector: Flags wording like "instead of using" that might instruct an assistant to replace or override an existing tool with a different behavior.
  - Cross-tool ex-filtration filter: Scans responses and tool descriptions for instructions to invoke external tools not belonging to this server.
  - Credential / secret redaction mutator: Automatically replaces recognized tokens format with `[REDACTED]` in outbound content.

> **ARC** is the fortress. **Minibridge** is the guard.
> Together, they securely connect and protect your MCP servers.

## 📦 What ARC Offers

- **SBOM Validation**: Automatic verification to prevent compromised deployments.
- **Rego Policy Enforcement**: Fine-grained governance using Open Policy Agent (OPA).
- **Simplified Remote Connectivity**: Effortlessly bridge your MCP server without custom protocols—Minibridge handles HTTP/SSE, WebSockets, and more.
- **Kubernetes Integration**: Quickly deploy into Kubernetes with Helm charts and sensible defaults.

## Features comparisons

| 🚀 **Feature**                              | 🔹 **MCP**       | 🔸 **Minibridge Wrapper**  | 📦 **ARC (Acuvity Containers)** | 🌟 **ARC + Acuvity Platform** |
| ------------------------------------------- | ---------------- | -------------------------- | ------------------------------- | ----------------------------- |
| 🌐 **Remote Access**                        | ⚠️ HTTP/SSE Only | ✅ Built-in                | ✅ Built-in                     | ✅ Built-in                   |
| 🔒 **TLS Support**                          | ❌               | ✅ Built-in                | ✅ Built-in                     | ✅ Built-in                   |
| 📃 **Tool integrity check**                 | ❌               | 👤 Requires Implementation | ✅ Built-in                     | ✅ Built-in                   |
| 🔐 **Security Policy Management**           | ❌               | 👤 Requires Implementation | ⚠️ Basic                        | ✅ Built-in                   |
| 🕵️ **Secrets Redaction**                    | ❌               | 👤 Requires Implementation | ⚠️ Basic                        | ✅ Built-in                   |
| 🛡️ **Isolation**                            | ❌               | ❌                         | ✅ Built-in                     | ✅ Built-in                   |
| 📃 **Software Bill of Materials (SBOM)**    | ❌               | ❌                         | ✅ Built-in                     | ✅ Built-in                   |
| 📌 **Version Pinning**                      | ❌               | ❌                         | ✅ Built-in                     | ✅ Built-in                   |
| 📊 **Visualization and Tracing**            | ❌               | 👤 Requires Implementation | 👤 Requires Implementation      | ✅ Built-in                   |
| 🔑 **Authorization Controls**               | ❌               | 👤 Requires Implementation | 👤 Requires Implementation      | ✅ Built-in                   |
| 🧑‍💻 **PII Detection and Redaction**          | ❌               | 👤 Requires Implementation | 👤 Requires Implementation      | ✅ Built-in                   |
| 🔍 **Deep Multimodal Analysis & Redaction** | ❌               | ❌                         | ❌                              | ✅ Built-in                   |

✅ _Included_ | ⚠️ _Partial/Basic Support_ | 👤 _Requires User Implementation_ | ❌ _Not Supported_

## ✨ Contribute Your MCP Server to ARC!

Join our secure MCP ecosystem by adding your server to ARC:

1. **Open a GitHub Issue**: Use our simple [issue template](https://github.com/acuvity/mcp-servers-registry/issues/new?template=add-mcp-server.yaml).
2. Provide:
   - 🌐 **Source Link**: Your app's location (GitHub, npm, PyPI, etc.)
   - ⚙️ **Runtime Config**: Environment variables or CLI arguments.

We'll handle the rest—secure containerization, Minibridge integration, SBOM validation, and remote support.

### Why Contribute?

- **Enhanced Visibility**: Instantly usable in secure, enterprise-grade deployments.
- **Built-in Security**: Benefit from ARC’s robust protections.
- **Community Strength**: Boost the secure and plug-and-play MCP ecosystem.
