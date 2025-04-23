# 🚀 You Built an Amazing MCP Server—Now Let’s Secure It and Simplify Deployment!

ARC takes your powerful MCP server and effortlessly adds robust security, transparent bridging, and streamlined deployment—without getting in your way.

Together with **ARC** (Acuvity Runtime Container), you now have a complete, hardened platform for trusted MCP server execution—whether running locally, inside Kubernetes, or remotely accessed by clients.

## 🔧 What Is ARC?

**ARC** stands for **Acuvity Runtime Container**—your secure, production-ready environment for running any MCP server with confidence:

- Immutable, non-root container images
- Read-only file system with CVE scanning
- Version-pinned dependencies
- Helm charts for easy deployment
- Leverage [Minibridge](https://github.com/acuvity/minibridge)’s live SBOM, policy enforcement and remote access

> **ARC** is the fortress. **Minibridge** is the guard.
> Together, they let you deploy, run, and connect your MCP servers—securely and at scale.

## What You Get with ARC

- **🔐 SBOM Integrity Checks**: Automatically verify your MCP server hasn’t been compromised or modified unexpectedly.
- **🛡️ Rego Policy Enforcement**: Define fine-grained governance rules with Open Policy Agent (OPA) and Rego.
- **📡 Remote Access Made Simple**: Stop struggling with custom protocols like `http/sse` or WebSockets—Minibridge handles it all. Securely bridge any MCP server remotely with zero changes.
- **📦 ARC (Acuvity Runtime Container)**: Immutable, non-root, CVE-scanned containers for running your MCP server securely and consistently.
- **🚀 Kubernetes-Ready with Helm**: Deploy your ARC-powered server into any cluster in minutes with built-in Helm charts and sane defaults.

## 🙌 Contribute with Your Own MCP Server to ARC!

Want to make your own MCP-compatible server part of the secure ARC ecosystem? It's easy, dev-friendly, and fast:

### ✨ How to Contribute:

1. **Open a GitHub Issue**: Use our quick, friendly [issue template](#).
   _(Replace `#` with the link to your GitHub issue template.)_

2. **Tell us just two things**:
   - 🌐 **Source Link**: Where your app lives (GitHub release, npm, PyPI, etc.)
   - ⚙️ **Runtime Configuration**: Any environment variables or CLI args needed to run it.

We’ll take it from there—containerizing it securely, wrapping it with Minibridge, and enabling SBOM validation, Rego enforcement, and remote support.

### ✨ Why Contribute?

- **Visibility**: Make your MCP server instantly usable in secure Kubernetes deployments.
- **Security**: Leverage ARC's hardened containers and Minibridge’s runtime protections.
- **Community Impact**: Help strengthen the MCP ecosystem by enabling more secure, plug-and-play servers.
