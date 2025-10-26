# FMC MCP Server

A simple MCP server that gives Claude access to your Cisco Firepower Management Center (FMC) API.

## What It Does

Connects to your FMC, fetches its OpenAPI specification, and dynamically creates 665+ tools for every API endpoint. No manual coding required.

**Example use cases:**
- "List all network objects"
- "Show me the access policies"
- "Create a network object for 10.5.0.0/16"
- "What's the device status?"

## Installation

```bash
# From GitHub
pip install git+https://github.com/daxm/fmcmcp.git

# Or with Poetry
poetry add git+https://github.com/daxm/fmcmcp.git
```

## Configuration

Add to your MCP client config (e.g., `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fmc": {
      "command": "fmcmcp",
      "env": {
        "FMC_HOST": "your-fmc.example.com",
        "FMC_USERNAME": "admin",
        "FMC_PASSWORD": "YourPassword",
        "FMC_DOMAIN": "Global",
        "FMC_VERIFY_SSL": "false"
      }
    }
  }
}
```

**Defaults** (if not specified):
- `FMC_HOST`: 192.168.45.45
- `FMC_USERNAME`: admin
- `FMC_PASSWORD`: Admin123
- `FMC_DOMAIN`: Global
- `FMC_VERIFY_SSL`: false

Restart your MCP client after making changes.

## How It Works

1. Connects to FMC with provided credentials
2. Fetches OpenAPI spec from FMC (`/api/api-explorer/openapi.json`)
3. Starts `mcp-openapi-proxy` subprocess to generate tools
4. Proxies tool calls to FMC API with automatic token refresh

**Token Management:**
- Tokens last 30 minutes
- Auto-refreshes up to 3 times (90 minutes total)
- Re-authenticates automatically after max refreshes

## Requirements

- Python 3.11+
- FMC 6.4+ (first version with OpenAPI support)
- `uvx` command (install with: `pip install pipx && pipx ensurepath`)
- Network access to your FMC

## Troubleshooting

**Authentication fails:**
- Check credentials (case-sensitive)
- Verify user has API access in FMC
- Confirm FMC is reachable

**Domain not found:**
- Domain names are case-sensitive
- Check available domains: FMC UI → System → Configuration → REST API Preferences
- Default is `Global`

**Logged out of FMC GUI:**
- FMC doesn't allow same user in both API and GUI simultaneously
- Use a dedicated API user account for the MCP server

**Proxy fails to start:**
- Ensure `uvx` is installed: `pip install pipx && pipx ensurepath`
- Check FMC is accessible

## Development

```bash
git clone https://github.com/daxm/fmcmcp.git
cd fmcmcp
poetry install
poetry run fmcmcp
```

## License

MIT License - see [LICENSE](LICENSE) file.

Copyright (c) 2025 Dax Mickelson
