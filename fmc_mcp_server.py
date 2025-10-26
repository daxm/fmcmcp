from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import asyncio
import aiohttp
import os
from datetime import datetime, timedelta
from typing import Optional, Dict
import urllib3

# Disable SSL warnings (FMC often uses self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Server("fmc-server")


# ============================================
# FMC CONNECTION MANAGER
# ============================================


class FMCConnection:
    """Manages authentication and API communication with Cisco FMC.

    This class handles the complete lifecycle of FMC API access including:
    - Initial authentication and token acquisition
    - Automatic token refresh (up to 3 times per token)
    - Re-authentication when tokens expire
    - HTTP session management with async context manager pattern

    FMC tokens expire after 30 minutes and can be refreshed up to 3 times
    before requiring re-authentication. This class automatically handles
    token lifecycle, refreshing preemptively when < 5 minutes remain.

    Designed to be used as an async context manager to ensure proper
    session cleanup.

    Attributes:
        host: FMC hostname or IP address (without protocol or trailing slash).
        username: FMC API username.
        password: FMC API password.
        domain_name: FMC domain name (typically "Global").
        verify_ssl: Whether to verify SSL certificates.
        base_url: Constructed base URL for API calls.
        auth_token: Current X-auth-access-token (None until authenticated).
        refresh_token: Current X-auth-refresh-token (None until authenticated).
        domain_uuid: UUID of the specified domain (resolved during auth).
        token_expiry: Datetime when current token expires.
        refresh_count: Number of times current token has been refreshed.
        session: aiohttp ClientSession for making requests.

    Example:
        async with FMCConnection("fmc.example.com", "admin", "password") as fmc:
            networks = await fmc.get("object/networks")
            for net in networks.get("items", []):
                print(net["name"])
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "Global",
        verify_ssl: bool = False,
    ):
        """Initialize FMC connection manager.

        Creates a connection manager instance but does not establish the
        connection. Actual authentication occurs when entering the async
        context manager (via __aenter__).

        Args:
            host: FMC hostname or IP address without protocol (e.g.,
                "fmc.example.com" or "192.168.1.100"). Trailing slashes
                are automatically stripped.
            username: FMC username with API access permissions.
            password: FMC password for authentication.
            domain: FMC domain name, case-sensitive (default: "Global").
                Must match exactly as shown in FMC UI.
            verify_ssl: Whether to verify SSL certificates (default: False).
                Set to False for self-signed certificates (common in FMC).

        Note:
            This constructor does not perform authentication. Use the instance
            as an async context manager to authenticate and create the session.
        """
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
        """Context manager entry - create session and authenticate.

        Called automatically when entering an 'async with' block. Creates
        the aiohttp ClientSession and authenticates to FMC to obtain tokens.

        Returns:
            Self, allowing the connection to be used in the with block.

        Raises:
            Exception: If authentication fails or domain is not found.
        """
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self

    async def __aexit__(
        self,
        exc_type,
        exc_val,
        exc_tb,
    ):
        """Context manager exit - close session and cleanup.

        Called automatically when exiting an 'async with' block. Ensures
        the aiohttp session is properly closed to prevent resource leaks.

        Args:
            exc_type: Exception type if an exception occurred, None otherwise.
            exc_val: Exception value if an exception occurred, None otherwise.
            exc_tb: Exception traceback if an exception occurred, None otherwise.

        Note:
            Does not suppress exceptions. Any exceptions from the context
            block will propagate after cleanup.
        """
        if self.session:
            await self.session.close()

    async def authenticate(self):
        """Authenticate to FMC and obtain initial access tokens.

        Makes a POST request to the /auth/generatetoken endpoint using HTTP
        Basic Authentication. Extracts access and refresh tokens from response
        headers, resolves the domain UUID from the DOMAINS header, and sets
        token expiry to 30 minutes from now.

        The FMC authentication response includes:
        - X-auth-access-token: Used for API requests
        - X-auth-refresh-token: Used to refresh the access token
        - DOMAINS: Semicolon-separated list of "DomainName (UUID)" pairs

        Raises:
            Exception: If authentication fails (non-204 status code) or if
                the specified domain name is not found in the DOMAINS header.

        Side Effects:
            Sets auth_token, refresh_token, domain_uuid, token_expiry and
            resets refresh_count to 0.
        """
        url = f"{self.base_url}/fmc_platform/v1/auth/generatetoken"

        auth = aiohttp.BasicAuth(self.username, self.password)

        async with self.session.post(
            url,
            auth=auth,
            ssl=self.verify_ssl,
        ) as response:
            if response.status != 204:
                raise Exception(f"Authentication failed: {response.status}")

            # Extract tokens and domain from headers
            self.auth_token = response.headers.get("X-auth-access-token")
            self.refresh_token = response.headers.get("X-auth-refresh-token")

            # Parse domain UUID from DOMAINS header
            domains = response.headers.get("DOMAINS", "")
            # Format: "Global (UUID1); DomainName (UUID2)"
            for domain_entry in domains.split(";"):
                domain_entry = domain_entry.strip()
                if self.domain_name in domain_entry:
                    # Extract UUID from parentheses
                    start = domain_entry.find("(")
                    end = domain_entry.find(")")
                    if start != -1 and end != -1:
                        self.domain_uuid = domain_entry[start + 1 : end]
                        break

            if not self.domain_uuid:
                raise Exception(f"Domain '{self.domain_name}' not found")

            # Token expires in 30 minutes
            self.token_expiry = datetime.now() + timedelta(minutes=30)
            self.refresh_count = 0

    async def refresh_auth_token(self):
        """Refresh the authentication token using the refresh token.

        FMC tokens can be refreshed up to 3 times before requiring full
        re-authentication. If the refresh count has reached 3 or if the
        refresh request fails, this method automatically falls back to
        full re-authentication.

        Raises:
            No exceptions raised directly. Falls back to authenticate() on failure.

        Side Effects:
            Updates auth_token, refresh_token, token_expiry and increments
            refresh_count. May reset all auth state if re-authentication occurs.
        """
        if self.refresh_count >= 3:
            # Can only refresh 3 times, need to re-authenticate
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
                # Refresh failed, re-authenticate
                await self.authenticate()
                return

            # Update tokens
            self.auth_token = response.headers.get("X-auth-access-token")
            self.refresh_token = response.headers.get("X-auth-refresh-token")
            self.token_expiry = datetime.now() + timedelta(minutes=30)
            self.refresh_count += 1

    async def ensure_authenticated(self):
        """Ensure we have a valid authentication token, refresh if needed.

        Checks if a valid token exists and if it will expire soon. If no
        token exists, authenticates. If token expires in less than 5 minutes,
        refreshes it preemptively to avoid mid-request expiration.

        This method is called automatically by get() and post() before each
        API request to ensure token validity.

        Side Effects:
            May call authenticate() or refresh_auth_token() to obtain/refresh tokens.
        """
        if not self.auth_token or not self.token_expiry:
            await self.authenticate()
            return

        # Refresh if the token expires in less than 5 minutes
        time_until_expiry = (self.token_expiry - datetime.now()).total_seconds()
        if time_until_expiry < 300:  # 5 minutes
            await self.refresh_auth_token()

    def get_headers(self) -> Dict[str, str]:
        """Get headers required for FMC API requests.

        Constructs a dictionary of HTTP headers including the authentication
        token and content type required by FMC API.

        Returns:
            Dictionary containing X-auth-access-token and Content-Type headers.

        Note:
            Should only be called after authentication. The auth_token must
            be set or requests will fail.
        """
        return {
            "X-auth-access-token": self.auth_token,
            "Content-Type": "application/json",
        }

    async def get(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
    ) -> Dict:
        """Make a GET request to the FMC API.

        Automatically ensures authentication token is valid before making the
        request. Constructs the full URL by combining base URL, domain UUID,
        and the provided endpoint path.

        Args:
            endpoint: API endpoint path relative to the domain (e.g.,
                "object/networks" or "devices/devicerecords"). Do not include
                leading slash or domain UUID. Use "../" to escape domain scope
                (e.g., "../info/serverversion").
            params: Optional dictionary of query parameters to append to the URL
                (e.g., {"limit": 100, "expanded": "true", "offset": 25}).

        Returns:
            Dictionary containing the JSON response from FMC API.

        Raises:
            Exception: If the request fails (non-200 status code), with error
                details from FMC API response.

        Example:
            # Get first 100 network objects with full details
            networks = await fmc.get(
                "object/networks",
                params={"limit": 100, "expanded": "true"}
            )
            for net in networks.get("items", []):
                print(f"{net['name']}: {net['value']}")
        """
        await self.ensure_authenticated()

        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"

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
        """Make a POST request to the FMC API.

        Automatically ensures authentication token is valid before making the
        request. Used for creating new objects or triggering actions in FMC.

        Args:
            endpoint: API endpoint path relative to the domain (e.g.,
                "object/networks" to create a network object or
                "deployment/deploymentrequests" to deploy changes).
            data: Dictionary containing the request body, will be serialized
                to JSON. Structure depends on the endpoint (refer to FMC API docs).

        Returns:
            Dictionary containing the JSON response from FMC API, typically
            including the created object with its assigned UUID.

        Raises:
            Exception: If the request fails (not 200/201/202 status code),
                with error details from FMC API response.

        Example:
            # Create a new network object
            new_network = await fmc.post(
                "object/networks",
                data={
                    "name": "Corporate-LAN",
                    "value": "10.0.0.0/8",
                    "type": "Network"
                }
            )
            print(f"Created network with ID: {new_network['id']}")
        """
        await self.ensure_authenticated()

        url = f"{self.base_url}/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"

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


# ============================================
# CONNECTION POOL (for reusing connections)
# ============================================


class FMCConnectionPool:
    """Manages multiple FMC connections with caching and reuse.

    Implements a connection pool to cache FMC connections by their unique
    combination of host, username, domain, and SSL verification settings.
    This allows tools to efficiently reuse connections when making multiple
    API calls to the same FMC instance.

    Connections are cached by a composite key of (host, username, domain,
    verify_ssl). Each unique combination gets its own connection instance
    that persists in the pool until cleanup() is called.

    This enables:
    - Efficient token reuse across multiple tool invocations
    - Support for multiple FMC instances in a single server
    - Reduced authentication overhead

    Attributes:
        _connections: Dictionary mapping cache keys to FMCConnection instances.

    Note:
        Password changes are not detected for cached connections. If
        credentials change, call cleanup() to force new connections.
    """

    def __init__(self):
        """Initialize an empty connection pool."""
        self._connections: Dict[str, FMCConnection] = {}

    @staticmethod
    def _get_key(
        host: str,
        username: str,
        domain: str,
        verify_ssl: bool,
    ) -> str:
        """Generate a unique cache key for a connection configuration.

        Creates a string key by joining connection parameters with pipe
        separators. This key uniquely identifies a connection configuration
        for caching purposes.

        Args:
            host: FMC hostname or IP address.
            username: FMC username.
            domain: FMC domain name.
            verify_ssl: SSL verification setting.

        Returns:
            String in format "host|username|domain|verify_ssl".

        Note:
            Password is intentionally excluded from the key to avoid
            storing sensitive data, but this means password changes
            won't trigger new connections.
        """
        return f"{host}|{username}|{domain}|{verify_ssl}"

    async def get_connection(
        self,
        host: str,
        username: str,
        password: str,
        domain: str = "Global",
        verify_ssl: bool = False,
    ) -> FMCConnection:
        """Get or create a connection to the specified FMC instance.

        Returns a cached connection if one exists for the given parameters,
        otherwise creates a new FMCConnection instance and caches it.

        Args:
            host: FMC hostname or IP address.
            username: FMC username.
            password: FMC password.
            domain: FMC domain name (default: "Global").
            verify_ssl: Whether to verify SSL certificates (default: False).

        Returns:
            FMCConnection instance, either from cache or newly created.

        Note:
            The returned connection is not yet authenticated. Use it as an
            async context manager to authenticate and make API calls.

        Example:
            pool = FMCConnectionPool()
            fmc = await pool.get_connection("fmc.example.com", "admin", "pass")
            async with fmc:
                networks = await fmc.get("object/networks")
        """
        key = self._get_key(host, username, domain, verify_ssl)

        if key not in self._connections:
            self._connections[key] = FMCConnection(
                host,
                username,
                password,
                domain,
                verify_ssl,
            )

        return self._connections[key]

    async def cleanup(self):
        """Close all cached connections and clear the pool.

        Iterates through all cached connections, closes their HTTP sessions,
        and clears the connection cache. Use this to force fresh connections
        on the next request, such as when credentials have changed.

        Side Effects:
            Closes all active HTTP sessions and empties the _connections dict.
        """
        for conn in self._connections.values():
            if conn.session:
                await conn.session.close()
        self._connections.clear()


# Global connection pool
connection_pool = FMCConnectionPool()

# ============================================
# COMMON INPUT SCHEMA FOR FMC CREDENTIALS
# ============================================

FMC_CREDENTIALS_SCHEMA = {
    "fmc_host": {
        "type": "string",
        "description": "FMC hostname or IP address (optional if FMC_HOST env var is set)",
    },
    "fmc_username": {
        "type": "string",
        "description": "FMC username (optional if FMC_USERNAME env var is set)",
    },
    "fmc_password": {
        "type": "string",
        "description": "FMC password (optional if FMC_PASSWORD env var is set)",
    },
    "fmc_domain": {
        "type": "string",
        "description": "FMC domain name (default: 'Global' or FMC_DOMAIN env var)",
        "default": "Global",
    },
    "verify_ssl": {
        "type": "boolean",
        "description": "Verify SSL certificates (default: false or FMC_VERIFY_SSL env var)",
        "default": False,
    },
}


# ============================================
# TOOL REGISTRY
# ============================================


class ToolRegistry:
    """Registry for MCP tools using decorator pattern.

    Provides a decorator-based system for registering Python functions as
    MCP tools. Each registered tool includes metadata (name, description,
    input schema) and a handler function that implements the tool's logic.

    The registry auto-discovers all decorated functions and exposes them
    to MCP clients via the list_tools() and call_tool() hooks.

    Attributes:
        tools: Dictionary mapping tool names to their metadata dicts.
        handlers: Dictionary mapping tool names to their handler functions.

    Example:
        registry = ToolRegistry()

        @registry.tool(
            name="example_tool",
            description="Does something useful",
            input_schema={"type": "object", "properties": {...}}
        )
        async def example_tool(arguments: dict) -> str:
            return "Result"
    """

    def __init__(self):
        """Initialize an empty tool registry."""
        self.tools: Dict[str, dict] = {}
        self.handlers: Dict[str, callable] = {}

    def tool(
        self,
        name: str,
        description: str,
        input_schema: dict,
    ):
        """Decorator to register a function as an MCP tool.

        Use this decorator to mark async functions as MCP tools. The decorated
        function will be automatically discovered and made available to MCP
        clients.

        Args:
            name: Unique identifier for the tool (e.g., "test_fmc_connection").
            description: Human-readable description of what the tool does.
                This is shown to the AI to help it decide when to use the tool.
            input_schema: JSON Schema dict defining the tool's input parameters.
                Must follow JSON Schema specification with "type", "properties",
                and optional "required" fields.

        Returns:
            Decorator function that registers the tool and returns the original
            function unchanged.

        Example:
            @registry.tool(
                name="greet_user",
                description="Greet a user by name",
                input_schema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "User's name"}
                    },
                    "required": ["name"]
                }
            )
            async def greet_user(arguments: dict) -> str:
                return f"Hello, {arguments['name']}!"
        """

        def decorator(func):
            self.tools[name] = {
                "name": name,
                "description": description,
                "inputSchema": input_schema,
            }
            self.handlers[name] = func
            return func

        return decorator

    def get_tools(self) -> list[Tool]:
        """Return all registered tools as MCP Tool objects.

        Converts the internal tool metadata dicts to MCP Tool objects that
        can be returned to MCP clients via the list_tools() hook.

        Returns:
            List of Tool objects containing name, description, and inputSchema
            for each registered tool.
        """
        return [Tool(**tool_def) for tool_def in self.tools.values()]

    async def call_tool(
        self,
        name: str,
        arguments: dict,
    ) -> str:
        """Call a registered tool by name with the provided arguments.

        Looks up the tool's handler function and invokes it with the
        provided arguments dictionary.

        Args:
            name: Name of the tool to call.
            arguments: Dictionary of arguments to pass to the tool handler.

        Returns:
            String result from the tool handler (typically formatted output
            for display to the user).

        Raises:
            ValueError: If the specified tool name is not registered.
        """
        if name not in self.handlers:
            raise ValueError(f"Unknown tool: {name}")
        return await self.handlers[name](arguments)


registry = ToolRegistry()


# ============================================
# HELPER: Extract FMC credentials from arguments
# ============================================


def extract_fmc_credentials(arguments: dict) -> tuple:
    """Extract FMC credentials using a 3-tier fallback strategy.

    Implements a hybrid credential management approach that supports both
    secure environment variables and flexible chat-based parameters while
    maintaining touchless deployment for lab environments.

    Credential priority order:
    1. Tool arguments (highest priority) - Passed explicitly in tool call
    2. Environment variables - Set in MCP server configuration
    3. Cisco documented defaults - For fresh FMC deployments (192.168.45.45)

    Args:
        arguments: Dictionary of tool arguments that may contain:
            - fmc_host: FMC hostname or IP
            - fmc_username: API username
            - fmc_password: API password
            - fmc_domain: Domain name (default: "Global")
            - verify_ssl: SSL verification flag (default: False)

    Returns:
        Tuple of (host, username, password, domain, verify_ssl) with all
        required credentials resolved from the 3-tier fallback.

    Note:
        Default credentials (192.168.45.45/admin/Admin123) should only be
        used in lab environments. Production deployments should always use
        environment variables to avoid exposing credentials.

    Example:
        # With environment variables set
        host, user, pwd, domain, ssl = extract_fmc_credentials({})

        # With explicit overrides
        host, user, pwd, domain, ssl = extract_fmc_credentials({
            "fmc_host": "10.1.1.100",
            "fmc_username": "apiuser"
        })
        # Falls back to env vars or defaults for missing values
    """
    # Try arguments first, then fall back to environment variables, then documented defaults
    host = arguments.get("fmc_host") or os.getenv("FMC_HOST", "192.168.45.45")
    username = arguments.get("fmc_username") or os.getenv("FMC_USERNAME", "admin")
    password = arguments.get("fmc_password") or os.getenv("FMC_PASSWORD", "Admin123")
    domain = arguments.get("fmc_domain") or os.getenv("FMC_DOMAIN", "Global")
    verify_ssl = arguments.get("verify_ssl", False)

    return host, username, password, domain, verify_ssl


# ============================================
# TOOL: Test Connection
# ============================================


@registry.tool(
    name="test_fmc_connection",
    description="Test connection to Cisco FMC and verify authentication. Uses environment variables by default, or provide credentials explicitly. Returns server version and domain information.",
    input_schema={
        "type": "object",
        "properties": FMC_CREDENTIALS_SCHEMA,
        "required": [],  # Nothing required - can use env vars
    },
)
async def test_fmc_connection(arguments: dict) -> str:
    """Test FMC connection and return server version info.

    Authenticates to FMC and retrieves server version information to verify
    connectivity, credentials, and domain configuration. This is typically
    the first tool to run when setting up FMC integration.

    Args:
        arguments: Dictionary of FMC connection parameters (see
            FMC_CREDENTIALS_SCHEMA). All parameters are optional if
            environment variables are configured.

    Returns:
        Formatted string containing connection status, FMC version, build
        number, and domain information. Returns error message prefixed with
        ✗ if connection fails.

    Example Output:
        ✓ Successfully connected to Cisco FMC!

        Host: fmc.example.com
        Domain: Global (uuid-here)
        Version: 7.2.0
        Build: 123
        SSL Verification: Disabled

        Authentication token is valid and ready for API calls.
    """
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
            # Get serverversion to confirm connection
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


# ============================================
# MCP SERVER HOOKS
# ============================================


@app.list_tools()
async def list_tools() -> list[Tool]:
    """MCP hook to list all available tools.

    Called by MCP clients to discover what tools this server provides.
    Returns the complete list of registered tools from the global registry.

    Returns:
        List of Tool objects describing each available tool with its name,
        description, and input schema.
    """
    return registry.get_tools()


@app.call_tool()
async def call_tool(
    name: str,
    arguments: dict,
) -> list[TextContent]:
    """MCP hook to invoke a tool by name.

    Called by MCP clients when they want to execute a tool. Delegates to
    the registry to find and call the appropriate handler function, then
    wraps the result in MCP TextContent format.

    Args:
        name: Name of the tool to invoke.
        arguments: Dictionary of arguments to pass to the tool.

    Returns:
        List containing a single TextContent object with the tool's result.

    Raises:
        ValueError: If the tool name is not registered (raised by registry).
    """
    result = await registry.call_tool(name, arguments)
    return [TextContent(type="text", text=result)]


# ============================================
# SERVER RUNNER
# ============================================


async def main():
    """Start the MCP server with stdio transport.

    Entry point for the FMC MCP server. Creates a stdio-based transport
    (reading from stdin, writing to stdout) and runs the MCP server event
    loop. This allows MCP clients to communicate with the server via
    standard input/output streams.

    The server runs indefinitely until the client disconnects or the process
    is terminated.
    """
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
