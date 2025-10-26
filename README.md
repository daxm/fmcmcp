# FMC MCP Server

## Setup
1. Copy `.env_example` to `.env` and edit if needed.
2. Place raw specs in `app/specs/` (e.g., `fmc-7.6.0.json`).
3. Build: `docker build -t fmcmcp .`
4. Run: `docker run --rm -i fmcmcp`
5. Claude Desktop: Set command to `docker run --rm -i fmcmcp`, transport=stdio.

## Adding New Specs
1. Add `fmc-7.7.0.json` to `app/specs/`.
2. Update `KNOWN_API_VERSIONS` in `app/fmc_mcp_server.py`.
3. Rebuild: `docker build -t fmcmcp .`
