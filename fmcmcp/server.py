from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import asyncio
import aiohttp
import os
import sys
import json
import signal
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Callable, Any
import httpx
import urllib3
from aiolimiter import AsyncLimiter

# Disable SSL warnings (FMC often uses self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
TOKEN_EXPIRY_MINUTES = 30
TOKEN_REFRESH_THRESHOLD_SECONDS = 300  # 5 minutes before expiry
TOKEN_MAX_REFRESHES = 3
TOKEN_REFRESH_INTERVAL_MINUTES = 25  # Refresh proxy token before expiry
PROXY_DEFAULT_PORT = 8000
PROXY_STARTUP_MAX_RETRIES = 30
PROXY_STARTUP_RETRY_DELAY = 0.5
PROXY_STOP_TIMEOUT = 5.0
FMC_RATE_LIMIT_REQUESTS = 120
FMC_RATE_LIMIT_PERIOD_SECONDS = 60

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
        # FMC allows 120 requests per minute - rate limit to stay within bounds
        self.rate_limiter = AsyncLimiter(max_rate=FMC_RATE_LIMIT_REQUESTS, time_period=FMC_RATE_LIMIT_PERIOD_SECONDS)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        try:
            await self.authenticate()
        except Exception:
            # If authentication fails, close the session before re-raising
            await self.session.close()
            raise
        return self

    async def __aexit__(
        self,
        exc_type,
        exc_val,
        exc_tb,
    ):
        if self.session:
            await self.session.close()

    async def authenticate(self):
        url = f"{self.base_url}/fmc_platform/v1/auth/generatetoken"
        auth = aiohttp.BasicAuth(
            self.username,
            self.password,
        )
        async with self.session.post(
            url,
            auth=auth,
            ssl=self.verify_ssl,
        ) as response:
            if response.status != 204:
                raise Exception(f"Authentication failed: {response.status}")
            self.auth_token = response.headers.get("X-auth-access-token")
            self.refresh_token = response.headers.get("X-auth-refresh-token")
            domains = response.headers.get("DOMAINS", "")
            for domain_entry in domains.split(";"):
                domain_entry = domain_entry.strip()
                # Extract domain name and UUID - format is "DomainName (uuid)"
                start = domain_entry.find("(")
                end = domain_entry.find(")")
                if start != -1 and end != -1:
                    domain_name_in_entry = domain_entry[:start].strip()
                    # Exact match to avoid matching substrings like "Global" in "GlobalTest"
                    if domain_name_in_entry == self.domain_name:
                        self.domain_uuid = domain_entry[start + 1 : end]
                        break
            if not self.domain_uuid:
                raise Exception(f"Domain '{self.domain_name}' not found")
            self.token_expiry = datetime.now() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
            self.refresh_count = 0

    async def refresh_auth_token(self):
        if self.refresh_count >= TOKEN_MAX_REFRESHES:
            await self.authenticate()
            return
        url = f"{self.base_url}/fmc_platform/v1/auth/refreshtoken"
        headers = {
            "X-auth-access-token": self.auth_token,
            "X-auth-refresh-token": self.refresh_token,
        }
        async with self.session.post(
            url,
            headers=headers,
            ssl=self.verify_ssl,
        ) as response:
            if response.status != 204:
                await self.authenticate()
                return
            self.auth_token = response.headers.get("X-auth-access-token")
            self.refresh_token = response.headers.get("X-auth-refresh-token")
            self.token_expiry = datetime.now() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
            self.refresh_count += 1

    async def ensure_authenticated(self):
        if not self.auth_token or not self.token_expiry:
            await self.authenticate()
            return
        time_until_expiry = (self.token_expiry - datetime.now()).total_seconds()
        if time_until_expiry < TOKEN_REFRESH_THRESHOLD_SECONDS:
            await self.refresh_auth_token()

    def get_headers(self) -> Dict[str, str]:
        return {
            "X-auth-access-token": self.auth_token,
            "Content-Type": "application/json",
        }

    async def get(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
    ) -> Dict:
        await self.ensure_authenticated()
        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        async with self.rate_limiter:
            async with self.session.get(
                url,
                headers=self.get_headers(),
                params=params,
                ssl=self.verify_ssl,
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(
                        f"GET {endpoint} failed ({response.status}): {error_text}"
                    )
                return await response.json()

    async def post(
        self,
        endpoint: str,
        data: Dict,
    ) -> Dict:
        await self.ensure_authenticated()
        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        async with self.rate_limiter:
            async with self.session.post(
                url,
                headers=self.get_headers(),
                json=data,
                ssl=self.verify_ssl,
            ) as response:
                if response.status not in [200, 201, 202]:
                    error_text = await response.text()
                    raise Exception(
                        f"POST {endpoint} failed ({response.status}): {error_text}"
                    )
                return await response.json()

    async def put(
        self,
        endpoint: str,
        data: Dict,
    ) -> Dict:
        await self.ensure_authenticated()
        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        async with self.rate_limiter:
            async with self.session.put(
                url,
                headers=self.get_headers(),
                json=data,
                ssl=self.verify_ssl,
            ) as response:
                if response.status not in [200, 201, 202]:
                    error_text = await response.text()
                    raise Exception(
                        f"PUT {endpoint} failed ({response.status}): {error_text}"
                    )
                return await response.json()

    async def delete(
        self,
        endpoint: str,
    ) -> Dict:
        await self.ensure_authenticated()
        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        async with self.rate_limiter:
            async with self.session.delete(
                url,
                headers=self.get_headers(),
                ssl=self.verify_ssl,
            ) as response:
                if response.status not in [200, 204]:
                    error_text = await response.text()
                    raise Exception(
                        f"DELETE {endpoint} failed ({response.status}): {error_text}"
                    )
                # DELETE may return 204 No Content
                if response.status == 204:
                    return {}
                return await response.json()


# ============================================
# SPEC MANAGER
# ============================================
class FMCSpecManager:
    """Fetches OpenAPI spec from FMC at runtime."""

    @staticmethod
    async def get_spec(fmc: FMCConnection) -> Dict:
        """Fetch the OpenAPI spec from the FMC."""
        url = f"{fmc.base_url}/api-explorer/openapi.json"
        await fmc.ensure_authenticated()
        async with fmc.rate_limiter:
            async with fmc.session.get(
                url,
                headers=fmc.get_headers(),
                ssl=fmc.verify_ssl,
            ) as response:
                if response.status != 200:
                    raise Exception(f"Failed to fetch spec: {response.status}")
                return await response.json()


# ============================================
# PROXY INTEGRATION
# ============================================
class FMCProxy:
    def __init__(
        self,
        spec_path: Path,
        fmc_url: str,
        fmc_connection: 'FMCConnection',
        port: int = PROXY_DEFAULT_PORT,
    ):
        self.spec_path = spec_path
        self.fmc_url = fmc_url
        self.fmc_connection = fmc_connection
        self.port = port
        self.process: Optional[asyncio.subprocess.Process] = None
        self._token_refresh_task: Optional[asyncio.Task] = None

    async def _update_proxy_token(self):
        """Background task to refresh proxy's auth token periodically."""
        try:
            while True:
                await asyncio.sleep(TOKEN_REFRESH_INTERVAL_MINUTES * 60)
                await self.fmc_connection.ensure_authenticated()
                # Note: mcp-openapi-proxy reads API_KEY from environment at startup
                # This approach ensures FMCConnection tokens stay fresh, but proxy
                # continues using its initial token. For long-running sessions,
                # the proxy would need to support dynamic token updates.
                print(f"✓ Refreshed FMC auth token", file=sys.stderr)
        except asyncio.CancelledError:
            pass

    async def start(self) -> list[Tool]:
        """Start a proxy subprocess and fetch tools."""
        env = os.environ.copy()
        env.update(
            {
                "OPENAPI_SPEC_URL": f"file://{self.spec_path}",
                "OPENAPI_SPEC_FORMAT": "json",
                "SERVER_URL_OVERRIDE": self.fmc_url,
                "API_AUTH_TYPE": "Bearer",
                "API_KEY": self.fmc_connection.auth_token,
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

        # Poll proxy until ready
        max_retries = PROXY_STARTUP_MAX_RETRIES
        retry_delay = PROXY_STARTUP_RETRY_DELAY
        last_error = None

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.post(f"http://localhost:{self.port}/tools/list")
                    resp.raise_for_status()
                    tools = [Tool(**t) for t in resp.json()]
                    print(
                        f"✓ Proxy ready after {(attempt + 1) * retry_delay:.1f}s, loaded {len(tools)} tools",
                        file=sys.stderr
                    )
                    # Start background token refresh task
                    self._token_refresh_task = asyncio.create_task(self._update_proxy_token())
                    return tools
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)

        # Failed to start
        stderr_output = ""
        if self.process and self.process.stderr:
            try:
                stderr_bytes = await asyncio.wait_for(
                    self.process.stderr.read(1000), timeout=1.0
                )
                stderr_output = stderr_bytes.decode(
                    "utf-8",
                    errors="ignore",
                )
            except Exception:
                pass

        error_msg = f"Proxy failed to start after {max_retries * retry_delay}s. Last error: {last_error}"
        if stderr_output:
            error_msg += f"\nProxy stderr: {stderr_output}"
        print(f"✗ {error_msg}", file=sys.stderr)
        return []

    async def call_tool(
        self,
        name: str,
        arguments: dict,
    ) -> str:
        """Call a proxy tool via HTTP."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(
                    f"http://localhost:{self.port}/call_tool",
                    json={"name": name, "arguments": arguments},
                )
                resp.raise_for_status()
                result = resp.json()
                if isinstance(result, list) and len(result) > 0:
                    return result[0].get(
                        "text",
                        str(result),
                    )
                return str(result)
            except httpx.TimeoutException:
                return f"✗ Tool '{name}' timed out after 30s"
            except httpx.HTTPStatusError as e:
                return f"✗ Tool '{name}' failed: HTTP {e.response.status_code}"
            except Exception as e:
                return f"✗ Error calling tool '{name}': {str(e)}"

    async def stop(self):
        """Stop the proxy subprocess."""
        # Cancel token refresh task
        if self._token_refresh_task:
            self._token_refresh_task.cancel()
            try:
                await self._token_refresh_task
            except asyncio.CancelledError:
                pass

        # Stop subprocess with timeout
        if self.process:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=PROXY_STOP_TIMEOUT)
            except asyncio.TimeoutError:
                print("⚠ Proxy didn't stop gracefully, force killing...", file=sys.stderr)
                self.process.kill()
                await self.process.wait()


# ============================================
# TOOL REGISTRY
# ============================================
class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, dict] = {}
        self.handlers: Dict[str, Callable[[dict], Any]] = {}
        self.proxy: Optional[FMCProxy] = None

    def tool(
        self,
        name: str,
        description: str,
        input_schema: dict,
    ) -> Callable:
        def decorator(func: Callable) -> Callable:
            self.tools[name] = {
                "name": name,
                "description": description,
                "inputSchema": input_schema,
            }
            self.handlers[name] = func
            return func

        return decorator

    def add_proxy_tools(
        self,
        proxy_tools: list[Tool],
    ):
        """Add dynamic tools from proxy."""
        for tool in proxy_tools:
            self.tools[tool.name] = {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.inputSchema,
            }

    def get_tools(self) -> list[Tool]:
        return [Tool(**tool_def) for tool_def in self.tools.values()]

    async def call_tool(
        self,
        name: str,
        arguments: dict,
    ) -> str:
        if name in self.handlers:
            return await self.handlers[name](arguments)
        if self.proxy:
            return await self.proxy.call_tool(
                name,
                arguments,
            )
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
        async with FMCConnection(
            host,
            username,
            password,
            domain,
            verify_ssl,
        ) as fmc:
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


def extract_fmc_credentials(arguments: dict) -> tuple[str, str, str, str, bool]:
    host = arguments.get("fmc_host") or os.getenv("FMC_HOST", "192.168.45.45")
    username = arguments.get("fmc_username") or os.getenv("FMC_USERNAME", "admin")
    password = arguments.get("fmc_password") or os.getenv("FMC_PASSWORD", "Admin123")
    domain = arguments.get("fmc_domain") or os.getenv("FMC_DOMAIN", "Global")
    verify_ssl = (
        arguments.get("verify_ssl")
        or os.getenv("FMC_VERIFY_SSL", "false").lower() == "true"
    )
    return host, username, password, domain, verify_ssl


# ============================================
# MCP SERVER HOOKS
# ============================================
@app.list_tools()
async def list_tools() -> list[Tool]:
    return registry.get_tools()


@app.call_tool()
async def call_tool(
    name: str,
    arguments: dict,
) -> list[TextContent]:
    result = await registry.call_tool(
        name,
        arguments,
    )
    return [TextContent(type="text", text=result)]


# ============================================
# SHUTDOWN HANDLING
# ============================================
def handle_shutdown(signum, frame):
    """Handle shutdown signals gracefully."""
    print(f"\n✓ Received shutdown signal ({signal.Signals(signum).name}), cleaning up...", file=sys.stderr)
    # Note: Cleanup happens in the finally block of main()
    # Signal handlers are registered to provide user feedback during shutdown


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

    temp_spec_path = Path(tempfile.gettempdir()) / "fmc_spec.json"
    proxy: Optional[FMCProxy] = None

    try:
        async with FMCConnection(
            host,
            username,
            password,
            domain,
            verify_ssl,
        ) as fmc:
            spec_manager = FMCSpecManager()
            spec = await spec_manager.get_spec(fmc)
            with open(temp_spec_path, "w") as f:
                json.dump(spec, f)

            proxy = FMCProxy(
                temp_spec_path,
                fmc.base_url,
                fmc,
            )
            registry.proxy = proxy
            proxy_tools = await proxy.start()
            registry.add_proxy_tools(proxy_tools)

            # Register signal handlers for graceful shutdown
            signal.signal(signal.SIGTERM, handle_shutdown)
            signal.signal(signal.SIGINT, handle_shutdown)

            async with stdio_server() as (read_stream, write_stream):
                await app.run(
                    read_stream,
                    write_stream,
                    app.create_initialization_options(),
                )

            if proxy:
                await proxy.stop()

    except aiohttp.client_exceptions.ClientConnectorError as e:
        print(f"\n✗ ERROR: Cannot connect to FMC at {host}", file=sys.stderr)
        print(f"  Connection details: {str(e)}", file=sys.stderr)
        print(f"\n  Troubleshooting steps:", file=sys.stderr)
        print(f"  - Verify FMC_HOST is correct (current: {host})", file=sys.stderr)
        print(f"  - Ensure FMC is running and accessible", file=sys.stderr)
        print(f"  - Check network connectivity from this container/host to FMC", file=sys.stderr)
        print(f"  - Verify firewall rules allow HTTPS (443) traffic\n", file=sys.stderr)
        sys.exit(1)

    except aiohttp.client_exceptions.ClientResponseError as e:
        if e.status == 401:
            print(f"\n✗ ERROR: Authentication failed for FMC at {host}", file=sys.stderr)
            print(f"  Status: {e.status} {e.message}", file=sys.stderr)
            print(f"\n  Troubleshooting steps:", file=sys.stderr)
            print(f"  - Verify FMC_USERNAME is correct (current: {username})", file=sys.stderr)
            print(f"  - Verify FMC_PASSWORD is correct", file=sys.stderr)
            print(f"  - Confirm user has API access permissions in FMC", file=sys.stderr)
            print(f"  - Check if user account is locked or expired\n", file=sys.stderr)
        else:
            print(f"\n✗ ERROR: FMC returned error {e.status}: {e.message}", file=sys.stderr)
            print(f"  URL: {e.request_info.url if e.request_info else 'unknown'}", file=sys.stderr)
            print(f"\n  Check FMC logs for more details\n", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"\n✗ ERROR: Unexpected error during startup", file=sys.stderr)
        print(f"  Error type: {type(e).__name__}", file=sys.stderr)
        print(f"  Details: {str(e)}", file=sys.stderr)
        print(f"\n  If this persists, please report at:", file=sys.stderr)
        print(f"  https://github.com/daxm/fmcmcp/issues\n", file=sys.stderr)
        sys.exit(1)

    finally:
        # Cleanup proxy subprocess if it exists
        if proxy:
            try:
                await proxy.stop()
            except Exception as e:
                print(f"Warning: Failed to stop proxy: {e}", file=sys.stderr)

        # Cleanup temporary spec file
        if temp_spec_path.exists():
            try:
                temp_spec_path.unlink()
            except Exception as e:
                print(f"Warning: Failed to remove temp spec file: {e}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
