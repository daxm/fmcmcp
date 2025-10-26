# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# FMC MCP Server - Developer Guide

## Project Overview

This is a **dynamic MCP (Model Context Protocol) server** that provides AI assistants (like Claude) with tools to interact with Cisco Firepower Management Center (FMC) via its REST API.

**Purpose:** Enable conversational access to FMC operations without writing code manually. Tools are automatically generated from FMC's OpenAPI specification.

**Requirements:** FMC 6.4+ (first version with OpenAPI support)

**Example Usage:**
- "List all network objects on my FMC"
- "Create a network object for 10.5.0.0/16"
- "Show me device status"
- "Get access policies"

## Architecture

**Docker-based design with dynamic tool generation:**
- Docker container packages all dependencies
- Runtime fetches/loads FMC OpenAPI spec
- `mcp-openapi-proxy` generates 665+ tools automatically from spec
- Single `test_fmc_connection` custom tool for validation

### Core Components (in order of appearance in fmc_mcp_server.py)

1. **FMCConnection** - `class FMCConnection`
   - Async context manager for FMC API access
   - Manages authentication and token lifecycle (30-minute expiry, max 3 refreshes)
   - Provides `.get()` and `.post()` methods that auto-refresh tokens
   - Handles domain UUID resolution from domain name
   - Self-signed SSL cert support

2. **FMCSpecManager** - `class FMCSpecManager`
   - Fetches OpenAPI spec from FMC at runtime
   - Always uses live spec from `/api-explorer/openapi.json`
   - Ensures spec matches the actual FMC version being accessed

3. **FMCProxy** - `class FMCProxy`
   - Bridge to `mcp-openapi-proxy` subprocess
   - Spawns `uvx mcp-openapi-proxy` with FMC connection details
   - Health-check polling (15s timeout with 0.5s retries)
   - Fetches 665+ auto-generated tools from proxy
   - Proxies tool calls via HTTP to subprocess

4. **ToolRegistry** - `class ToolRegistry`
   - Unified tool management (custom + dynamic)
   - Decorator pattern for custom tools (`@registry.tool()`)
   - Dynamic tool registration from proxy
   - Unified `call_tool()` dispatch

5. **Credential Extraction** - `extract_fmc_credentials()`
   - Implements 3-tier credential fallback:
     1. Tool arguments (highest priority)
     2. Environment variables
     3. Cisco defaults (192.168.45.45/admin/Admin123)

6. **MCP Server Hooks** - `@app.list_tools()` and `@app.call_tool()`
   - Standard MCP stdio server hooks
   - Client-agnostic (works with Claude Desktop, Claude Code, etc.)
   - Registered via `async def main()` function

### Authentication Flow
```
User provides credentials (chat or env vars)
    ↓
extract_fmc_credentials() pulls from:
  1. Chat parameters (highest priority)
  2. Environment variables
  3. Cisco defaults (192.168.45.45/admin/Admin123)
    ↓
FMCConnection authenticates and gets tokens
    ↓
FMCSpecManager fetches/loads OpenAPI spec
    ↓
FMCProxy spawns mcp-openapi-proxy subprocess
    ↓
Proxy generates 665+ tools from OpenAPI spec
    ↓
Tools use connection to make API calls
```

### Dynamic Tool Generation Flow
```
Startup
    ↓
Connect to FMC → Authenticate
    ↓
Fetch OpenAPI spec from FMC (/api-explorer/openapi.json)
    ↓
Write spec to temp_spec.json
    ↓
Start mcp-openapi-proxy subprocess
    ├─> OPENAPI_SPEC_URL=file://temp_spec.json
    ├─> SERVER_URL_OVERRIDE=https://fmc.example.com/api
    └─> API_KEY=<FMC auth token>
    ↓
Poll proxy /tools/list (health check)
    ↓
Register 665+ tools (one per FMC API endpoint)
    ↓
Start MCP stdio server
    ↓
Handle tool calls → Proxy → FMC API
```

## Credential Management

**Hybrid approach** - supports three methods:

### 1. Environment Variables (Recommended for Docker)
Set in Claude Desktop config or Docker environment:

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "fmc-server": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "fmcmcp"],
      "env": {
        "FMC_HOST": "fmc.example.com",
        "FMC_USERNAME": "apiuser",
        "FMC_PASSWORD": "SecurePassword",
        "FMC_DOMAIN": "Global",
        "FMC_VERIFY_SSL": "false"
      }
    }
  }
}
```

**Docker `.env` file:**
```env
FMC_HOST=fmc.example.com
FMC_USERNAME=apiuser
FMC_PASSWORD=SecurePassword
FMC_DOMAIN=Global
FMC_VERIFY_SSL=false
```

### 2. Chat Parameters (Flexible Override)
User says: "Test my FMC at 10.1.1.100 with username admin and password Cisco123"

### 3. Defaults (Touchless Deployment)
Falls back to Cisco's documented defaults for fresh FMC deployments:
- Host: `192.168.45.45`
- Username: `admin`
- Password: `Admin123`
- Domain: `Global`

## Docker Workflow

### Build Process
```bash
# 1. Copy app/ directory to container
# 2. Install dependencies from app/requirements.txt
# 3. Configure pipx/uvx in PATH
# 4. Set up for stdio MCP server (ready to fetch specs at runtime)
```

### Runtime Process
```bash
# 1. Load credentials from environment
# 2. Connect to FMC and authenticate
# 3. Fetch OpenAPI spec from FMC (/api-explorer/openapi.json)
# 4. Write spec to temp file
# 5. Start mcp-openapi-proxy subprocess with spec
# 6. Proxy generates 665+ tools from spec
# 7. Start MCP stdio server
# 8. Handle tool calls from Claude → Proxy → FMC API
```

### Commands

**Build:**
```bash
docker build -t fmcmcp .
```

**Run (with .env file):**
```bash
docker run --rm -i --env-file .env fmcmcp
```

**Run (with inline env vars):**
```bash
docker run --rm -i \
  -e FMC_HOST=10.1.1.100 \
  -e FMC_USERNAME=admin \
  -e FMC_PASSWORD=Cisco123 \
  fmcmcp
```

**Test locally:**
```bash
# In project directory
python app/fmc_mcp_server.py
```

## OpenAPI Specification Management

The server **always fetches the OpenAPI spec from the target FMC at runtime**. This ensures:
- ✅ Spec matches the actual FMC version
- ✅ No version mismatches or stale specs
- ✅ No maintenance burden for spec updates
- ✅ Simpler codebase

**How it works:**
1. Server connects to FMC
2. Fetches spec from `https://<fmc-host>/api/api-explorer/openapi.json`
3. Writes to temporary file (`temp_spec.json`)
4. Passes to `mcp-openapi-proxy` for tool generation
5. Proxy generates 665+ tools from the spec

**Trade-off:** 1-2 second startup delay to fetch spec (acceptable for real-world use)

## Tool Development

### Custom Tools (Rare)

Most tools are auto-generated from OpenAPI spec. Only add custom tools for:
- Special authentication flows
- Multi-step workflows
- Custom data transformations

**Pattern:**
```python
@registry.tool(
    name="tool_name",
    description="What this tool does and when to use it",
    input_schema={
        "type": "object",
        "properties": {
            **FMC_CREDENTIALS_SCHEMA,  # Include FMC credentials
            "custom_param": {
                "type": "string",
                "description": "Description of custom parameter"
            }
        },
        "required": [],
    },
)
async def tool_name(arguments: dict) -> str:
    """Detailed docstring."""
    try:
        host, username, password, domain, verify_ssl = extract_fmc_credentials(arguments)
        async with FMCConnection(host, username, password, domain, verify_ssl) as fmc:
            result = await fmc.get("endpoint")
            return f"✓ Success: {result}"
    except Exception as e:
        return f"✗ Error: {str(e)}"
```

### Tool Development Checklist
- [ ] Includes `**FMC_CREDENTIALS_SCHEMA` in input_schema
- [ ] Uses `extract_fmc_credentials(arguments)` for credential extraction
- [ ] Uses `async with FMCConnection(...)` context manager
- [ ] Wraps logic in try/except with user-friendly error messages
- [ ] Returns formatted string output (not raw JSON)
- [ ] Prefixes errors with `✗` and success with `✓`

## Code Standards

### Style Guidelines
- Use type hints for function parameters and returns
- Async functions for all I/O operations
- Context managers (`async with`) for FMC connections
- Descriptive variable names (no single letters except in loops)
- Comprehensive docstrings for all functions

### Error Handling
- Always use try/except in tool functions
- Return user-friendly error messages (not raw stack traces)
- Prefix error messages with `✗` and success with `✓`
- Log to stderr for debugging (stdout is for MCP protocol)

## Testing

### Without FMC (Dry Run)
Since most tools are auto-generated, manual testing is limited to:
1. Docker build succeeds
2. Server starts without errors
3. Custom tools (like `test_fmc_connection`) work

```bash
# Test build
docker build -t fmcmcp .

# Test startup (will fail auth with defaults)
docker run --rm -i fmcmcp &
echo '{"method":"tools/list"}' | docker run --rm -i fmcmcp
```

### With Real FMC
1. Configure credentials in `.env` or Claude Desktop config
2. Start server via Claude Desktop/Code
3. In chat: "Test my FMC connection"
4. Try auto-generated tools: "List all network objects"

### Manual Testing with Claude Desktop

1. Build and configure:
   ```bash
   docker build -t fmcmcp .
   # Edit ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

2. Add to config:
   ```json
   {
     "mcpServers": {
       "fmc-server": {
         "command": "docker",
         "args": ["run", "--rm", "-i", "fmcmcp"],
         "env": {
           "FMC_HOST": "your-fmc.example.com",
           "FMC_USERNAME": "apiuser",
           "FMC_PASSWORD": "password",
           "FMC_DOMAIN": "Global"
         }
       }
     }
   }
   ```

3. Restart Claude Desktop (quit from system tray, not just close window)

4. Test in chat:
   - "Test my FMC connection"
   - "List all available tools" (should show 665+)
   - "Get network objects"

## Dependencies

From `app/requirements.txt`:
- `mcp` - Model Context Protocol SDK
- `mcp-openapi-proxy` - Dynamic tool generation from OpenAPI specs
- `aiohttp` - Async HTTP client for FMC API calls
- `httpx` - Async HTTP client for proxy communication
- `urllib3` - SSL warning suppression
- `packaging` - Version comparison for spec matching
- `pipx` - Provides `uvx` for running mcp-openapi-proxy

Install with:
```bash
pip install -r app/requirements.txt
```

## FMC API Reference

Key resources:
- **Official API Docs:** https://www.cisco.com/c/en/us/support/security/defense-center/products-programming-reference-guides-list.html
- **Cisco DevNet:** https://developer.cisco.com/firepower/
- **API Explorer:** `https://<fmc-host>/api/api-explorer` (on your FMC)
- **OpenAPI Spec:** `https://<fmc-host>/api/api-explorer/openapi.json` (on your FMC)

### Authentication Details
- **Token lifetime:** 30 minutes
- **Refresh limit:** 3 times per token
- **After 3 refreshes:** Must re-authenticate
- **Headers required:**
  - `X-auth-access-token`: For all API calls
  - `Content-Type: application/json`: For POST/PUT

### Rate Limiting
- **120 requests per minute** per IP address
- **10 simultaneous connections** per IP address
- **Payload limit:** 20,480 bytes

## Common Issues

### "Proxy failed to start after 15s"
- **Cause:** `uvx` not found or mcp-openapi-proxy installation failed
- **Fix:** Check Dockerfile installed pipx correctly
- **Debug:** `docker run --rm -it fmcmcp /bin/bash`, then `which uvx`

### "Authentication failed: 401"
- Check credentials (case-sensitive)
- Verify FMC is reachable from Docker container
- Confirm user has API permissions in FMC

### "Domain 'X' not found"
- Domain name is case-sensitive
- Check available domains in FMC UI (System > Configuration > REST API Preferences)
- Try "Global" (most common default)

### "No tools loaded" or "0 tools"
- Proxy failed to parse OpenAPI spec
- Check spec has valid JSON structure
- Look at proxy stderr output in error message

### Claude Desktop doesn't see the server
- Check `claude_desktop_config.json` syntax (must be valid JSON)
- Use `docker` command, not direct Python
- **Must quit Claude Desktop from system tray** (not just close window)
- Check Docker is running: `docker ps`

### "Connection refused" when calling tools
- FMC not reachable from Docker container
- Try `docker run --network host` for testing
- Check firewall rules

## Development Workflow

### Setup
```bash
# Clone repository
git clone <repo-url>
cd fmcmcp

# Create virtual environment (for local dev)
python -m venv .venv
source .venv/bin/activate  # Linux/WSL
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -r app/requirements.txt
```

### Build and Test
```bash
# Build Docker image
docker build -t fmcmcp .

# Test with env vars
docker run --rm -i \
  -e FMC_HOST=192.168.45.45 \
  -e FMC_USERNAME=admin \
  -e FMC_PASSWORD=Admin123 \
  fmcmcp
```

### Debugging
```bash
# Run with DEBUG output
docker run --rm -i --env-file .env fmcmcp 2>&1 | tee debug.log

# Interactive shell in container
docker run --rm -it fmcmcp /bin/bash

# Check proxy is accessible
docker run --rm -it fmcmcp /bin/bash
# Inside container:
python -c "import httpx; print(httpx.get('http://localhost:8000/health'))"
```

### Making Changes

1. **Edit code** in `app/fmc_mcp_server.py`
2. **Rebuild:** `docker build -t fmcmcp .`
3. **Test:** Via Claude Desktop or manual Docker run
4. **Commit:** Git commit with descriptive message

### Adding Features

**For custom tools:** Edit `fmc_mcp_server.py`, add `@registry.tool()` decorated function

**For core changes:** Update FMCConnection, FMCSpecManager, FMCProxy, or ToolRegistry classes

## Project Structure
```
fmcmcp/
├── app/
│   ├── fmc_mcp_server.py    # Main server (~415 lines)
│   └── requirements.txt     # Python dependencies
├── Dockerfile               # Container definition
├── .dockerignore            # Docker build exclusions
├── .gitignore               # Git exclusions
├── LICENSE                  # MIT License
├── CLAUDE.md                # This file
└── README.md                # User documentation
```

## Architecture Decisions

### Why Docker?
- Self-contained dependencies (pipx, uvx, mcp-openapi-proxy)
- Consistent runtime environment
- Easy deployment to Claude Desktop/Code
- Isolated from host Python environment

### Why mcp-openapi-proxy?
- Auto-generates 665+ tools from OpenAPI spec
- No manual tool coding for each endpoint
- Automatically updates when spec changes
- Handles OpenAPI complexities ($ref, allOf, oneOf)

### Why runtime spec fetching (no caching)?
- Ensures spec always matches the target FMC version
- No version mismatch issues
- No maintenance burden for updating cached specs
- Simpler codebase (no version matching, caching, compression logic)
- 1-2 second startup delay is acceptable for real-world use
- FMC spec has 9,372 `$ref` references - keeping it intact prevents breakage

## Future Enhancements

- Multi-FMC support (requires multiple proxy instances or credential-based routing)
- Connection pooling for custom tools
- Health check endpoint for proxy
- Unit tests with mocked FMC API
- Caching of common API responses
- Observability (metrics, structured logging)
- Support for FMC API v2+ features

## License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for full details.

Copyright (c) 2025 Dax Mickelson