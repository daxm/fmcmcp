"""MCP server for Cisco Firepower Management Center API access."""
import asyncio
import aiohttp
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Suppress SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "0.20250126.0"

# FMC token configuration
TOKEN_LIFETIME_MINUTES = 30
MAX_TOKEN_REFRESHES = 3

app = Server("fmc-server")


class FMCConnection:
    """Manages connection and authentication to FMC."""

    def __init__(self, host: str, username: str, password: str,
                 domain: str = "Global", verify_ssl: bool = False):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.domain_name = domain
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.host}/api"

        self.auth_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.domain_uuid: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self.refresh_count = 0
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def authenticate(self):
        """Authenticate to FMC and get initial tokens."""
        url = f"{self.base_url}/fmc_platform/v1/auth/generatetoken"
        auth = aiohttp.BasicAuth(self.username, self.password)

        async with self.session.post(url, auth=auth, ssl=self.verify_ssl) as resp:
            if resp.status != 204:
                raise Exception(f"Authentication failed with status {resp.status}")

            self.auth_token = resp.headers.get("X-auth-access-token")
            self.refresh_token = resp.headers.get("X-auth-refresh-token")

            # Extract domain UUID
            domains = resp.headers.get("DOMAINS", "")
            for domain_entry in domains.split(";"):
                if "(" in domain_entry and ")" in domain_entry:
                    name = domain_entry[:domain_entry.find("(")].strip()
                    if name == self.domain_name:
                        self.domain_uuid = domain_entry[domain_entry.find("(") + 1:domain_entry.find(")")]
                        break

            if not self.domain_uuid:
                raise Exception(f"Domain '{self.domain_name}' not found")

            self.token_expiry = datetime.now() + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
            self.refresh_count = 0

    async def refresh_auth_token(self):
        """Refresh auth token or re-authenticate if max refreshes reached."""
        if self.refresh_count >= MAX_TOKEN_REFRESHES:
            await self.authenticate()
            return

        url = f"{self.base_url}/fmc_platform/v1/auth/refreshtoken"
        headers = {
            "X-auth-access-token": self.auth_token,
            "X-auth-refresh-token": self.refresh_token,
        }

        async with self.session.post(url, headers=headers, ssl=self.verify_ssl) as resp:
            if resp.status != 204:
                await self.authenticate()
                return

            self.auth_token = resp.headers.get("X-auth-access-token")
            self.refresh_token = resp.headers.get("X-auth-refresh-token")
            self.token_expiry = datetime.now() + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
            self.refresh_count += 1

    async def ensure_valid_token(self):
        """Ensure we have a valid auth token, refreshing if needed."""
        if not self.auth_token or not self.token_expiry:
            await self.authenticate()
            return

        # Refresh if within 5 minutes of expiry
        time_remaining = (self.token_expiry - datetime.now()).total_seconds()
        if time_remaining < 300:
            await self.refresh_auth_token()

    async def get_spec(self) -> dict:
        """Fetch OpenAPI specification from FMC."""
        await self.ensure_valid_token()
        url = f"{self.base_url}/api-explorer/openapi.json"
        headers = {"X-auth-access-token": self.auth_token}

        async with self.session.get(url, headers=headers, ssl=self.verify_ssl) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to fetch OpenAPI spec: {resp.status}")
            return await resp.json()


class ProxyManager:
    """Manages mcp-openapi-proxy subprocess."""

    def __init__(self, spec_path: Path, fmc_url: str, auth_token: str):
        self.spec_path = spec_path
        self.fmc_url = fmc_url
        self.auth_token = auth_token
        self.process: Optional[asyncio.subprocess.Process] = None
        self.tools: list[Tool] = []

    async def start(self):
        """Start proxy subprocess and load tools."""
        env = os.environ.copy()
        env.update({
            "OPENAPI_SPEC_URL": f"file://{self.spec_path}",
            "SERVER_URL_OVERRIDE": self.fmc_url,
            "API_KEY": self.auth_token,
        })

        self.process = await asyncio.create_subprocess_exec(
            "uvx", "mcp-openapi-proxy",
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Wait for proxy to be ready
        import httpx
        for _ in range(30):
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.post("http://localhost:8000/tools/list")
                    resp.raise_for_status()
                    self.tools = [Tool(**t) for t in resp.json()]
                    print(f"✓ Loaded {len(self.tools)} tools from FMC", file=sys.stderr)
                    return
            except Exception:
                await asyncio.sleep(0.5)

        raise Exception("Proxy failed to start")

    async def call_tool(self, name: str, arguments: dict) -> str:
        """Call a tool via the proxy."""
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "http://localhost:8000/call_tool",
                json={"name": name, "arguments": arguments}
            )
            result = resp.json()
            if isinstance(result, list) and result:
                return result[0].get("text", str(result))
            return str(result)

    async def stop(self):
        """Stop the proxy subprocess."""
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()


# Global proxy instance
proxy: Optional[ProxyManager] = None


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Return available tools from proxy."""
    return proxy.tools if proxy else []


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool via the proxy."""
    if not proxy:
        return [TextContent(type="text", text="Error: Proxy not initialized")]

    result = await proxy.call_tool(name, arguments)
    return [TextContent(type="text", text=result)]


def main():
    """Run the MCP server."""
    asyncio.run(async_main())


async def async_main():
    """Main async entry point."""
    global proxy

    # Get credentials from environment or use defaults
    host = os.getenv("FMC_HOST", "192.168.45.45")
    username = os.getenv("FMC_USERNAME", "admin")
    password = os.getenv("FMC_PASSWORD", "Admin123")
    domain = os.getenv("FMC_DOMAIN", "Global")
    verify_ssl = os.getenv("FMC_VERIFY_SSL", "false").lower() == "true"

    spec_file = Path(tempfile.gettempdir()) / "fmc_openapi.json"

    try:
        # Connect to FMC and fetch spec
        async with FMCConnection(host, username, password, domain, verify_ssl) as fmc:
            print(f"✓ Connected to FMC at {host}", file=sys.stderr)

            spec = await fmc.get_spec()
            spec_file.write_text(json.dumps(spec))
            print(f"✓ Fetched OpenAPI spec", file=sys.stderr)

            # Start proxy
            proxy = ProxyManager(spec_file, fmc.base_url, fmc.auth_token)
            await proxy.start()

            # Run MCP server
            async with stdio_server() as (read_stream, write_stream):
                await app.run(read_stream, write_stream, app.create_initialization_options())

    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        if proxy:
            await proxy.stop()
        if spec_file.exists():
            spec_file.unlink()


if __name__ == "__main__":
    main()
