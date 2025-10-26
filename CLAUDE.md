# CLAUDE.md

Developer guide for the FMC MCP Server project.

## Project Purpose

This is a simple MCP server that provides AI assistants access to Cisco Firepower Management Center (FMC) REST API. Tools are dynamically generated from the FMC's OpenAPI specification at runtime.

**Goal:** Enable conversational access to FMC without manual tool coding.

**Requirements:** FMC 6.4+ (first version with OpenAPI support)

## Architecture

The server has three main components:

### 1. FMCConnection
- Manages authentication and token lifecycle
- Handles token refresh (max 3 refreshes, then re-auth)
- Fetches OpenAPI spec from FMC

**Token lifecycle:**
- Initial token: 30 minutes
- Refreshes: up to 3 times (90 minutes total)
- After 3 refreshes: full re-authentication

### 2. ProxyManager
- Spawns `mcp-openapi-proxy` subprocess
- Passes OpenAPI spec and FMC auth token to proxy
- Proxy generates 665+ tools from the spec
- Routes tool calls to proxy via HTTP (localhost:8000)

### 3. MCP Server Hooks
- `list_tools()`: Returns tools from proxy
- `call_tool()`: Executes tools via proxy

## Code Structure

```
fmcmcp.py                # Single file (~260 lines)
├── FMCConnection        # Auth and spec fetching
├── ProxyManager         # mcp-openapi-proxy management
└── main()               # Entry point
```

**Everything is in one file.** No package structure, no subdirectories. Just a single Python script.

## Flow

```
Startup:
1. Read credentials from environment (or use defaults)
2. Connect to FMC and authenticate
3. Fetch OpenAPI spec from /api/api-explorer/openapi.json
4. Write spec to temp file
5. Start mcp-openapi-proxy subprocess with spec
6. Proxy generates tools from spec
7. Start MCP stdio server

Runtime:
1. MCP client calls tool
2. Server routes to proxy via HTTP
3. Proxy makes FMC API call
4. Response flows back to client
```

## Credential Management

**Two-tier fallback:**
1. Environment variables (recommended)
2. Defaults (Cisco's documented defaults)

**Environment variables:**
- `FMC_HOST` (default: 192.168.45.45)
- `FMC_USERNAME` (default: admin)
- `FMC_PASSWORD` (default: Admin123)
- `FMC_DOMAIN` (default: Global)
- `FMC_VERIFY_SSL` (default: false)

**Example MCP client config:**
```json
{
  "mcpServers": {
    "fmc": {
      "command": "fmcmcp",
      "env": {
        "FMC_HOST": "10.1.1.100",
        "FMC_USERNAME": "admin",
        "FMC_PASSWORD": "YourPassword"
      }
    }
  }
}
```

## Development

**Setup:**
```bash
git clone https://github.com/daxm/fmcmcp.git
cd fmcmcp
poetry install
```

**Run:**
```bash
poetry run fmcmcp
```

**Build:**
```bash
poetry build
```

## Key Design Decisions

**Why fetch OpenAPI spec at runtime?**
- Always matches the target FMC version
- No version mismatch issues
- No need to update cached specs

**Why use mcp-openapi-proxy?**
- Auto-generates tools from OpenAPI spec
- Handles 665+ endpoints without manual coding
- Deals with OpenAPI complexities ($ref, allOf, etc.)

**Why no rate limiting?**
- Removed for simplicity
- FMC handles rate limiting naturally (120 req/min)
- Can add back if needed

**Why no custom tools?**
- Proxy handles everything
- Simpler codebase
- Less maintenance

## Dependencies

From `pyproject.toml`:
- `mcp` - Model Context Protocol SDK
- `aiohttp` - Async HTTP for FMC API calls
- `httpx` - Async HTTP for proxy communication
- `mcp-openapi-proxy` - Dynamic tool generation

## FMC API Notes

**Authentication:**
- Endpoint: `/api/fmc_platform/v1/auth/generatetoken`
- Returns: `X-auth-access-token` and `X-auth-refresh-token` headers
- Domain UUID extracted from `DOMAINS` header

**Token refresh:**
- Endpoint: `/api/fmc_platform/v1/auth/refreshtoken`
- Max 3 refreshes per token
- After 3 refreshes: must re-authenticate

**OpenAPI spec:**
- Endpoint: `/api/api-explorer/openapi.json`
- Contains all API operations
- 9,372+ `$ref` references

**Rate limits:**
- 120 requests per minute per IP
- 10 simultaneous connections per IP

## Common Issues

**"Authentication failed"**
- Check credentials (case-sensitive)
- Verify user has API access in FMC
- Test connectivity to FMC

**"Domain not found"**
- Domain names are case-sensitive
- Default domain is usually "Global"
- Check FMC UI: System → Configuration → REST API Preferences

**"Proxy failed to start"**
- Ensure `uvx` is installed
- Check network connectivity
- Verify FMC spec endpoint is accessible

**GUI logout when using API**
- FMC doesn't allow same user in both API and GUI
- Use dedicated API user for MCP server

## Publishing to GitHub MCP Registry

To publish this server to the GitHub MCP registry:

1. Ensure you have write access to the GitHub repository
2. Use the `mcp-publisher` CLI tool
3. Authenticate with GitHub OAuth
4. Follow namespace requirements (io.github.daxm/*)

**Schema requirements:**
- Server name, title, description
- Version string
- Package metadata

See: https://github.com/modelcontextprotocol/registry

## License

MIT License - Copyright (c) 2025 Dax Mickelson
