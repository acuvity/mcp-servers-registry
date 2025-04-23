# 🚀 Contribute with your MCP Server

Thanks for your interest in contributing to the **ARC + Minibridge** ecosystem!
Please fill out the details below to help us integrate your MCP-compatible tool securely and efficiently.

## 📦 MCP Tool Source

Where can we find your tool?

- [ ] GitHub Release: `<paste link here>`
- [ ] npm Package: `<paste link here>`
- [ ] PyPI Package: `<paste link here>`

> Select one and provide the corresponding URL.

## 🛠️ Run Command

How is your MCP tool launched?
Provide either the CLI command or a sample `mcpServers` JSON configuration block like below:

```json
{
  "mcpServers": {
    "your-tool": {
      "command": "your-binary",
      "args": ["--run", "mcp-mode"]
    }
  }
}
```

Or describe the CLI:

```
your-binary --run mcp-mode
```

## ⚙️ Configuration: Arguments and Environment Variables

List any arguments or environment variables your tool accepts.

| Name       | Type       | Default | Description                       |
| ---------- | ---------- | ------- | --------------------------------- |
| `MY_TOKEN` | env var    | (none)  | API token used for authentication |
| `--debug`  | CLI flag   | false   | Enable verbose output             |
| `--port`   | CLI option | 8080    | Port for local HTTP API           |
| ...        | ...        | ...     | ...                               |

## 🌐 Runtime Dependencies

What does your tool rely on at runtime?

- [ ] 🖥️ Native desktop tools (e.g., git, curl)
- [ ] 🌐 Remote APIs (e.g., cloud-based endpoints)
- [ ] 🧱 Fully self-contained / standalone

> Check all that apply and add notes if needed.

## 💾 Persistent Storage Required?

- [ ] ✅ Yes, needs a persistent volume
- [ ] 🚫 No, runs entirely in-memory

If **Yes**, briefly explain what’s stored and why:

> _e.g., stores a SQLite DB for caching results_

## 👥 Supports Concurrent Clients?

Can your tool handle requests from multiple clients at once?

- [ ] ✅ Yes
- [ ] ⚠️ No, single-client only
- [ ] 🤷 Not sure

> Let us know if it maintains session state or writes to shared temp directories.

Thank you for contributing!
Once submitted, we’ll review and help wrap your tool in an **ARC (Acuvity Runtime Container)** with SBOM checks, Rego policy support, and a Helm-based deployment for secure runtime.

Let’s make the MCP ecosystem even stronger—together! 🔐🛠️🚀
