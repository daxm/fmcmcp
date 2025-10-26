# FMC MCP Server

A Model Context Protocol (MCP) server that provides Claude with **665+ dynamically-generated tools** for interacting with Cisco Firepower Management Center (FMC) via its REST API.

## What It Does

Connects Claude (or any MCP client) to your FMC and automatically creates tools for every API endpoint:
- List/create/update/delete network objects
- Manage access policies and rules
- Configure devices
- Deploy configurations
- Monitor system health
- And 660+ more operations

**No manual coding required** - tools are generated from your FMC's OpenAPI specification at runtime.

## Installation

### Option 1: PyPI (Recommended)

```bash
pip install fmcmcp
```

### Option 2: Docker

```bash
docker build -t fmcmcp .
```

### Option 3: From Source

```bash
git clone https://github.com/daxm/fmcmcp.git
cd fmcmcp
pip install -e .
```

## Quick Start

### If Installed via PyPI or Source

Edit your Claude Desktop configuration file:

**macOS/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add this server configuration:

```json
{
  "mcpServers": {
    "fmc-server": {
      "command": "fmc-mcp-server",
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

### If Installed via Docker

Edit your Claude Desktop configuration file (same paths as above) and add:

```json
{
  "mcpServers": {
    "fmc-server": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "fmcmcp"],
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

Replace the `env` values with your FMC credentials.

### Restart Claude Desktop

**Important:** Quit Claude Desktop completely (from system tray/menu bar), then relaunch.

### Test in Claude

Try these prompts:
```
"Test my FMC connection"
"List all available tools"
"Show me all network objects"
"What access policies are configured?"
```

## Credential Configuration

### Option 1: Claude Desktop Config (Recommended)

Set credentials directly in `claude_desktop_config.json` as shown above.

### Option 2: Environment File

Create `.env` file:
```env
FMC_HOST=192.168.1.10
FMC_USERNAME=admin
FMC_PASSWORD=MySecurePassword
FMC_DOMAIN=Global
FMC_VERIFY_SSL=false
```

Then run:
```bash
docker run --rm -i --env-file .env fmcmcp
```

### Option 3: Inline Environment Variables

```bash
docker run --rm -i \
  -e FMC_HOST=192.168.1.10 \
  -e FMC_USERNAME=admin \
  -e FMC_PASSWORD=MyPassword \
  -e FMC_DOMAIN=Global \
  fmcmcp
```

## How It Works

1. **Server starts** and connects to your FMC
2. **Fetches OpenAPI spec** from FMC (`/api/api-explorer/openapi.json`)
3. **Generates tools** dynamically using `mcp-openapi-proxy`
4. **Registers 665+ tools** with Claude
5. **Routes requests** from Claude → FMC API

The server acts as a proxy, translating Claude's natural language requests into FMC API calls.

## Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `FMC_HOST` | `192.168.45.45` | FMC hostname or IP address |
| `FMC_USERNAME` | `admin` | FMC username |
| `FMC_PASSWORD` | `Admin123` | FMC password |
| `FMC_DOMAIN` | `Global` | FMC domain name |
| `FMC_VERIFY_SSL` | `false` | Verify SSL certificates (true/false) |

## Requirements

- Docker
- FMC 6.4+ with OpenAPI support and API access enabled
- Claude Desktop (or another MCP client)
- Network access from Docker container to FMC

## Troubleshooting

### "Authentication failed: 401"
- Check credentials (case-sensitive)
- Verify user has API permissions in FMC
- Confirm FMC is reachable from Docker container

### "No tools loaded" or "Proxy failed to start"
- Check Docker logs: `docker run --rm -i --env-file .env fmcmcp 2>&1 | tee debug.log`
- Verify `uvx` is installed in container
- Ensure FMC OpenAPI endpoint is accessible

### "Domain 'X' not found"
- Domain name is case-sensitive
- Check available domains in FMC UI: System > Configuration > REST API Preferences
- Try `Global` (default domain)

### Claude Desktop doesn't see the server
- Verify `claude_desktop_config.json` is valid JSON
- Check Docker is running: `docker ps`
- Quit Claude Desktop from system tray (don't just close window)
- Check logs: `~/Library/Logs/Claude/mcp*.log` (macOS)

## Development

### Local Development Setup
```bash
# Clone repository
git clone https://github.com/daxm/fmcmcp.git
cd fmcmcp

# Install in editable mode
pip install -e .

# Run locally (requires FMC access)
fmc-mcp-server
```

### Building for Distribution
```bash
# Using Poetry
poetry build
poetry publish  # Publish to PyPI

# Using Docker
docker build -t fmcmcp .
```

## Documentation

- **[CLAUDE.md](CLAUDE.md)** - Comprehensive developer guide
- **[FMC API Reference Guides](https://www.cisco.com/c/en/us/support/security/defense-center/products-programming-reference-guides-list.html)** - Official Cisco FMC API documentation
- **[Cisco DevNet Firepower](https://developer.cisco.com/firepower/)** - Developer resources and examples
- **[MCP Protocol](https://modelcontextprotocol.io/)** - Model Context Protocol specification

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Dax Mickelson

## Support

For issues or questions:
- Check [CLAUDE.md](CLAUDE.md) for detailed troubleshooting
- Review FMC API documentation
- Verify network connectivity and credentials
