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
- **Threat Detection & Prevention**:
  - Identifies hidden instruction patterns.
  - Detects misuse of schema parameters.
  - Flags unauthorized access attempts.
  - Prevents tool shadowing and sensitive information leaks.

> **ARC** is the fortress. **Minibridge** is the guard.
> Together, they securely connect and protect your MCP servers.

## 📦 What ARC Offers

- **SBOM Validation**: Automatic verification to prevent compromised deployments.
- **Rego Policy Enforcement**: Fine-grained governance using Open Policy Agent (OPA).
- **Simplified Remote Connectivity**: Effortlessly bridge your MCP server without custom protocols—Minibridge handles HTTP/SSE, WebSockets, and more.
- **Kubernetes Integration**: Quickly deploy into Kubernetes with Helm charts and sensible defaults.

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
