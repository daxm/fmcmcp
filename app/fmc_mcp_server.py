from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import asyncio
import aiohttp
import os
import json
import gzip
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict
from packaging import version
import subprocess
import httpx
import urllib3

# Disable SSL warnings (FMC often uses self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Server("fmc-server")


# ============================================
# FMC CONNECTION MANAGER
# ============================================
class FMCConnection:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "Global",
        verify_ssl: bool = False,
    ):
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
        url = f"{self.base_url}/fmc_platform/v1/auth/generatetoken"
        auth = aiohttp.BasicAuth(self.username, self.password)
        async with self.session.post(url, auth=auth, ssl=self.verify_ssl) as response:
            if response.status != 204:
                raise Exception(f"Authentication failed: {response.status}")
            self.auth_token = response.headers.get("X-auth-access-token")
            self.refresh_token = response.headers.get("X-auth-refresh-token")
            domains = response.headers.get("DOMAINS", "")
            for domain_entry in domains.split(";"):
                domain_entry = domain_entry.strip()
                if self.domain_name in domain_entry:
                    start = domain_entry.find("(")
                    end = domain_entry.find(")")
                    if start != -1 and end != -1:
                        self.domain_uuid = domain_entry[start + 1 : end]
                        break
            if not self.domain_uuid:
                raise Exception(f"Domain '{self.domain_name}' not found")
            self.token_expiry = datetime.now() + timedelta(minutes=30)
            self.refresh_count = 0

    async def refresh_auth_token(self):
        if self.refresh_count >= 3:
            await self.authenticate()
            return
        url = f"{self.base_url}/fmc_platform/v1/auth/refreshtoken"
        headers = {
            "X-auth-access-token": self.auth_token,
            "X-auth-refresh-token": self.refresh_token,
        }
        async with self.session.post(
            url, headers=headers, ssl=self.verify_ssl
        ) as response:
            if response.status != 204:
                await self.authenticate()
                return
            self.auth_token = response.headers.get("X-auth-access-token")
            self.refresh_token = response.headers.get("X-auth-refresh-token")
            self.token_expiry = datetime.now() + timedelta(minutes=30)
            self.refresh_count += 1

    async def ensure_authenticated(self):
        if not self.auth_token or not self.token_expiry:
            await self.authenticate()
            return
        time_until_expiry = (self.token_expiry - datetime.now()).total_seconds()
        if time_until_expiry < 300:
            await self.refresh_auth_token()

    def get_headers(self) -> Dict[str, str]:
        return {
            "X-auth-access-token": self.auth_token,
            "Content-Type": "application/json",
        }

    async def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        await self.ensure_authenticated()
        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        async with self.session.get(
            url, headers=self.get_headers(), params=params, ssl=self.verify_ssl
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(
                    f"GET {endpoint} failed ({response.status}): {error_text}"
                )
            return await response.json()

    async def post(self, endpoint: str, data: Dict) -> Dict:
        await self.ensure_authenticated()
        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        async with self.session.post(
            url, headers=self.get_headers(), json=data, ssl=self.verify_ssl
        ) as response:
            if response.status not in [200, 201, 202]:
                error_text = await response.text()
                raise Exception(
                    f"POST {endpoint} failed ({response.status}): {error_text}"
                )
            return await response.json()


# ============================================
# CONNECTION POOL
# ============================================
class FMCConnectionPool:
    def __init__(self):
        self._connections: Dict[str, FMCConnection] = {}

    @staticmethod
    def _get_key(host: str, username: str, domain: str, verify_ssl: bool) -> str:
        return f"{host}|{username}|{domain}|{verify_ssl}"

    async def get_connection(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "Global",
        verify_ssl: bool = False,
    ) -> FMCConnection:
        key = self._get_key(host, username, domain, verify_ssl)
        if key not in self._connections:
            self._connections[key] = FMCConnection(
                host, username, password, domain, verify_ssl
            )
        return self._connections[key]

    async def cleanup(self):
        for conn in self._connections.values():
            if conn.session:
                await conn.session.close()
        self._connections.clear()


connection_pool = FMCConnectionPool()


# ============================================
# SPEC MANAGER
# ============================================
class FMCSpecManager:
    KNOWN_API_VERSIONS = ["7.4.0", "7.6.0", "7.7.0"]

    def __init__(self, spec_dir: str = "specs"):
        self.spec_dir = Path(spec_dir)
        self.spec_dir.mkdir(exist_ok=True)

    def _find_closest_version(self, target_version: str) -> Optional[str]:
        """Find the closest spec version <= the target FMC version."""
        try:
            target = version.parse(target_version)
            valid_versions = [
                v for v in self.KNOWN_API_VERSIONS if version.parse(v) <= target
            ]
            return max(valid_versions, key=lambda x: version.parse(x), default=None)
        except version.InvalidVersion:
            return None

    @staticmethod
    def _load_spec(spec_path: Path) -> Dict:
        """Load spec from compressed JSON."""
        with gzip.open(spec_path, "rt", encoding="utf-8") as f:
            return json.load(f)

    async def _fetch_and_slim_spec(self, fmc: FMCConnection, version: str) -> Dict:
        """Fetch full spec from FMC, slim it, and cache as .gz."""
        url = f"{fmc.base_url}/api-explorer/openapi.json"
        await fmc.ensure_authenticated()
        async with fmc.session.get(
            url, headers=fmc.get_headers(), ssl=fmc.verify_ssl
        ) as response:
            if response.status != 200:
                raise Exception(f"Failed to fetch spec: {response.status}")
            full_spec = await response.json()

        slim_spec = {
            "openapi": full_spec["openapi"],
            "info": full_spec.get("info", {}),
            "servers": full_spec.get("servers", []),
            "paths": full_spec["paths"],
            "components": {
                "securitySchemes": full_spec.get("components", {}).get(
                    "securitySchemes", {}
                )
            },
        }

        gzip_path = self.spec_dir / f"fmc-{version}_slim.json.gz"
        with gzip.open(gzip_path, "wt", encoding="utf-8") as f:
            json.dump(slim_spec, f, indent=2)
        return slim_spec

    async def get_spec(self, fmc: FMCConnection) -> Dict:
        """Get the appropriate spec for the FMC version."""
        result = await fmc.get("../info/serverversion")
        fmc_version = result.get("items", [{}])[0].get("serverVersion", "unknown")
        spec_version = self._find_closest_version(fmc_version) or fmc_version

        gzip_path = self.spec_dir / f"fmc-{spec_version}_slim.json.gz"
        if gzip_path.exists():
            return self._load_spec(gzip_path)

        return await self._fetch_and_slim_spec(fmc, spec_version)


# ============================================
# PROXY INTEGRATION
# ============================================
class FMCProxy:
    def __init__(
        self, spec_path: Path, fmc_url: str, auth_token: str, port: int = 8000
    ):
        self.spec_path = spec_path
        self.fmc_url = fmc_url
        self.auth_token = auth_token
        self.port = port
        self.process = None

    async def start(self) -> list[Tool]:
        """Start a proxy subprocess and fetch tools."""
        env = os.environ.copy()
        env.update(
            {
                "OPENAPI_SPEC_URL": f"file://{self.spec_path}",
                "OPENAPI_SPEC_FORMAT": "json",
                "SERVER_URL_OVERRIDE": self.fmc_url,
                "API_AUTH_TYPE": "Bearer",
                "API_KEY": self.auth_token,
                "DEBUG": "true",
            }
        )
        self.process = await asyncio.create_subprocess_exec(
            "uvx",
            "mcp-openapi-proxy",
            "--port",
            str(self.port),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(2)
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(f"http://localhost:{self.port}/tools/list")
                resp.raise_for_status()
                return [Tool(**t) for t in resp.json()]
            except Exception as e:
                print(f"Failed to fetch proxy tools: {e}")
                return []

    async def call_tool(self, name: str, arguments: dict) -> str:
        """Call a proxy tool via HTTP."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"http://localhost:{self.port}/call_tool",
                    json={"name": name, "arguments": arguments},
                )
                resp.raise_for_status()
                return resp.json()[0]["text"]
            except Exception as e:
                return f"Error calling tool {name}: {str(e)}"

    async def stop(self):
        """Stop the proxy subprocess."""
        if self.process:
            self.process.terminate()
            await self.process.wait()


# ============================================
# TOOL REGISTRY
# ============================================
class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, dict] = {}
        self.handlers: Dict[str, callable] = {}
        self.proxy: Optional[FMCProxy] = None

    def tool(self, name: str, description: str, input_schema: dict):
        def decorator(func):
            self.tools[name] = {
                "name": name,
                "description": description,
                "inputSchema": input_schema,
            }
            self.handlers[name] = func
            return func

        return decorator

    def add_proxy_tools(self, proxy_tools: list[Tool]):
        """Add dynamic tools from proxy."""
        for tool in proxy_tools:
            self.tools[tool.name] = {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.inputSchema,
            }

    def get_tools(self) -> list[Tool]:
        return [Tool(**tool_def) for tool_def in self.tools.values()]

    async def call_tool(self, name: str, arguments: dict) -> str:
        if name in self.handlers:
            return await self.handlers[name](arguments)
        if self.proxy:
            return await self.proxy.call_tool(name, arguments)
        raise ValueError(f"Unknown tool: {name}")


registry = ToolRegistry()

# ============================================
# FMC CREDENTIALS SCHEMA
# ============================================
FMC_CREDENTIALS_SCHEMA = {
    "fmc_host": {"type": "string", "description": "FMC hostname or IP address"},
    "fmc_username": {"type": "string", "description": "FMC username"},
    "fmc_password": {"type": "string", "description": "FMC password"},
    "fmc_domain": {
        "type": "string",
        "description": "FMC domain name",
        "default": "Global",
    },
    "verify_ssl": {
        "type": "boolean",
        "description": "Verify SSL certificates",
        "default": False,
    },
}


# ============================================
# TOOL: Test Connection
# ============================================
@registry.tool(
    name="test_fmc_connection",
    description="Test connection to Cisco FMC and verify authentication.",
    input_schema={
        "type": "object",
        "properties": FMC_CREDENTIALS_SCHEMA,
        "required": [],
    },
)
async def test_fmc_connection(arguments: dict) -> str:
    try:
        host, username, password, domain, verify_ssl = extract_fmc_credentials(
            arguments
        )
        async with FMCConnection(host, username, password, domain, verify_ssl) as fmc:
            result = await fmc.get("../info/serverversion")
            items = result.get("items", [])
            if items:
                server_info = items[0]
                version = server_info.get("serverVersion", "Unknown")
                build = server_info.get("buildNumber", "Unknown")
                return f"""✓ Successfully connected to Cisco FMC!
Host: {fmc.host}
Domain: {fmc.domain_name} ({fmc.domain_uuid})
Version: {version}
Build: {build}
SSL Verification: {'Enabled' if verify_ssl else 'Disabled'}
Authentication token is valid and ready for API calls."""
            else:
                return "✓ Connected to FMC but no version information available."
    except Exception as e:
        return f"✗ Failed to connect to FMC: {str(e)}"


def extract_fmc_credentials(arguments: dict) -> tuple:
    host = arguments.get("fmc_host") or os.getenv("FMC_HOST", "192.168.45.45")
    username = arguments.get("fmc_username") or os.getenv("FMC_USERNAME", "admin")
    password = arguments.get("fmc_password") or os.getenv("FMC_PASSWORD", "Admin123")
    domain = arguments.get("fmc_domain") or os.getenv("FMC_DOMAIN", "Global")
    verify_ssl = arguments.get("verify_ssl", False)
    return host, username, password, domain, verify_ssl


# ============================================
# MCP SERVER HOOKS
# ============================================
@app.list_tools()
async def list_tools() -> list[Tool]:
    return registry.get_tools()


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    result = await registry.call_tool(name, arguments)
    return [TextContent(type="text", text=result)]


# ============================================
# SERVER RUNNER
# ============================================
async def main():
    """Start the MCP server with dynamic spec-based tools."""
    host = os.getenv("FMC_HOST", "192.168.45.45")
    username = os.getenv("FMC_USERNAME", "admin")
    password = os.getenv("FMC_PASSWORD", "Admin123")
    domain = os.getenv("FMC_DOMAIN", "Global")
    verify_ssl = os.getenv("FMC_VERIFY_SSL", "False").lower() == "true"

    async with FMCConnection(host, username, password, domain, verify_ssl) as fmc:
        spec_manager = FMCSpecManager(spec_dir="specs")
        spec = await spec_manager.get_spec(fmc)
        temp_spec_path = Path("specs/temp_spec.json")
        with open(temp_spec_path, "w") as f:
            json.dump(spec, f)

        proxy = FMCProxy(temp_spec_path, fmc.base_url, fmc.auth_token)
        registry.proxy = proxy
        proxy_tools = await proxy.start()
        registry.add_proxy_tools(proxy_tools)

        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream, write_stream, app.create_initialization_options()
            )

        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
