# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# FMC MCP Server - Developer Guide

## Project Overview

This is an MCP (Model Context Protocol) server that provides AI assistants (like Claude) with tools to interact with Cisco Firepower Management Center (FMC) via its REST API.

**Purpose:** Enable conversational access to FMC operations without writing code manually.

**Example Usage:**
- "List all network objects on my FMC"
- "Create a network object for 10.5.0.0/16"
- "Show me device status"

## Architecture

**Single-file design:** All code lives in `fmc_mcp_server.py` (~434 lines). This makes the server easy to deploy, understand, and modify.

### Core Components (in order of appearance in file)

1. **FMCConnection** (lines 22-197)
   - Async context manager for FMC API access
   - Manages authentication and token lifecycle (30-minute expiry, max 3 refreshes)
   - Provides `.get()` and `.post()` methods that auto-refresh tokens
   - Handles domain UUID resolution from domain name

2. **FMCConnectionPool** (lines 204-248)
   - Singleton pattern via global `connection_pool` instance
   - Caches connections by (host, user, domain, verify_ssl) tuple
   - Enables multi-FMC support in a single server instance

3. **ToolRegistry** (lines 288-327)
   - Decorator pattern for registering MCP tools
   - Maps tool names to handler functions
   - Auto-generates MCP Tool objects from metadata

4. **Credential Extraction** (line 335-344)
   - `extract_fmc_credentials()` implements the 3-tier fallback:
     1. Tool arguments (highest priority)
     2. Environment variables
     3. Cisco defaults (192.168.45.45/admin/Admin123)

5. **MCP Server** (lines 405-434)
   - Standard MCP stdio server using `@app.list_tools()` and `@app.call_tool()` hooks
   - Client-agnostic (works with Claude Desktop, Claude Code, etc.)

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
Tools use connection to make API calls
```

## Credential Management

**Hybrid approach** - supports three methods:

### 1. Environment Variables (Secure Default)
Set in `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "fmc-server": {
      "command": "path/to/python.exe",
      "args": ["path/to/fmc_mcp_server.py"],
      "env": {
        "FMC_HOST": "fmc.example.com",
        "FMC_USERNAME": "apiuser",
        "FMC_PASSWORD": "SecurePassword",
        "FMC_DOMAIN": "Global"
      }
    }
  }
}
```

### 2. Chat Parameters (Flexible Override)
User says: "Test my FMC at 10.1.1.100 with username admin and password Cisco123"

### 3. Defaults (Touchless Deployment)
Falls back to Cisco's documented defaults for fresh FMC deployments:
- Host: `192.168.45.45`
- Username: `admin`
- Password: `Admin123`
- Domain: `Global`

## Adding New Tools

### Pattern to Follow

All tools follow this structure:
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
        "required": [],  # Usually empty - credentials are optional
    },
)
async def tool_name(arguments: dict) -> str:
    """Detailed docstring explaining what this tool does."""
    try:
        # Extract credentials
        host, username, password, domain, verify_ssl = extract_fmc_credentials(
            arguments
        )
        
        # Extract custom parameters
        custom_param = arguments.get("custom_param")
        
        # Create/get FMC connection
        async with FMCConnection(
            host, username, password, domain, verify_ssl
        ) as fmc:
            # Make API call
            result = await fmc.get("object/networks")  # or .post()
            
            # Process and format response
            items = result.get("items", [])
            output = "Formatted results here..."
            
            return output
    
    except Exception as e:
        return f"✗ Error: {str(e)}"
```

### FMC API Endpoint Patterns

From the API docs (`Firepower_Management_Center_REST_API_Quick_Start_Guide_620.pdf`):

**Base URL:** `/api/fmc_config/v1/domain/{domain_UUID}/`

**Common endpoints:**
- Objects: `object/networks`, `object/hosts`, `object/networkgroups`
- Devices: `devices/devicerecords`
- Policies: `policy/accesspolicies`, `policy/accesspolicies/{policy_id}/accessrules`
- Deployment: `deployment/deployabledevices`, `deployment/deploymentrequests`

**Query parameters:**
- `expanded=true` - Get full object details (not just references)
- `offset=N` - Pagination starting position
- `limit=N` - Number of results (default 25, max 1000)
- Filtering: varies by object type (see API docs)

### Example: List Network Objects
```python
@registry.tool(
    name="list_network_objects",
    description="List all network objects in FMC. Returns name, value, and type for each object.",
    input_schema={
        "type": "object",
        "properties": {
            **FMC_CREDENTIALS_SCHEMA,
            "limit": {
                "type": "integer",
                "description": "Maximum number of objects to return (default: 25, max: 1000)",
                "default": 25
            }
        },
        "required": [],
    },
)
async def list_network_objects(arguments: dict) -> str:
    """List all network objects from FMC."""
    try:
        host, username, password, domain, verify_ssl = extract_fmc_credentials(
            arguments
        )
        limit = arguments.get("limit", 25)
        
        async with FMCConnection(
            host, username, password, domain, verify_ssl
        ) as fmc:
            result = await fmc.get(
                "object/networks",
                params={"limit": limit, "expanded": "true"}
            )
            
            items = result.get("items", [])
            if not items:
                return "No network objects found."
            
            output = f"Found {len(items)} network objects:\n\n"
            for item in items:
                name = item.get("name", "Unknown")
                value = item.get("value", "Unknown")
                obj_type = item.get("type", "Unknown")
                output += f"• {name}: {value} ({obj_type})\n"
            
            return output
    
    except Exception as e:
        return f"✗ Failed to list network objects: {str(e)}"
```

## Code Standards

### Formatting
- **Black formatter** is required for all Python code
- Line length: 88 characters (Black default)
- Run `black fmc_mcp_server.py` before committing

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

## Testing

### Manual Testing with Claude Desktop

1. Ensure server is configured in `claude_desktop_config.json`
2. Restart Claude Desktop (quit from system tray)
3. In chat: "Test my FMC connection"
4. Try new tools conversationally

### With Real FMC
Provide actual credentials when testing tools.

### Without FMC (Mock Testing)
Currently not implemented - contributions welcome!

## Development Commands

### Setup
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Linux/WSL:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Code Formatting
```bash
# Format all Python files (required before commits)
black fmc_mcp_server.py

# Check formatting without making changes
black --check fmc_mcp_server.py
```

### Running the Server
```bash
# The server runs via MCP client (Claude Desktop/Code)
# For standalone testing:
python fmc_mcp_server.py
```

### Testing Tools
Since this is an MCP server, test tools through an MCP client (Claude Desktop or Claude Code):
1. Configure server in client's config file
2. Restart client completely
3. Invoke tools conversationally: "Test my FMC connection"

## Dependencies

From `requirements.txt`:
- `mcp` - Model Context Protocol SDK
- `aiohttp` - Async HTTP client for FMC API calls
- `urllib3` - SSL warning suppression

Install with:
```bash
pip install -r requirements.txt
```

## FMC API Reference

Key resources:
- **API Guide:** `Firepower_Management_Center_REST_API_Quick_Start_Guide_620.pdf`
- **Online Docs:** https://developer.cisco.com/firepower/
- **API Explorer:** `https://<fmc-host>/api/api-explorer`

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

### "Authentication failed: 401"
- Check credentials
- Verify FMC is reachable
- Confirm user has API permissions

### "Domain 'X' not found"
- Domain name is case-sensitive
- Check available domains in FMC UI
- Try "Global" (most common)

### "Module 'mcp' not found"
- Virtual environment not activated
- Run: `pip install -r requirements.txt`

### Claude Desktop doesn't see the server
- Check `claude_desktop_config.json` syntax
- Verify Python path points to venv Python
- **Must quit from system tray** (not just close window)

## Development Workflow for New Tools

1. **Research the FMC API endpoint** using the API Explorer (`https://<fmc-host>/api/api-explorer`)
2. **Add tool using `@registry.tool()` decorator** following the pattern in "Adding New Tools"
3. **Run Black formatter**: `black fmc_mcp_server.py`
4. **Test via MCP client:**
   - Restart Claude Desktop/Code completely
   - Invoke tool conversationally
   - Verify output format and error handling
5. **Update CLAUDE.md** only if introducing new architectural patterns

## Tool Development Checklist

When implementing a new tool:
- [ ] Includes `**FMC_CREDENTIALS_SCHEMA` in input_schema
- [ ] Uses `extract_fmc_credentials(arguments)` for credential extraction
- [ ] Uses `async with FMCConnection(...)` context manager
- [ ] Wraps logic in try/except with user-friendly error messages
- [ ] Returns formatted string output (not raw JSON)
- [ ] Prefixes errors with `✗` and success with `✓`
- [ ] Passes Black formatting check