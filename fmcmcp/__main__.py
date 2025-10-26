"""Entry point for running fmcmcp as a module."""

import asyncio
from fmcmcp.server import main

if __name__ == "__main__":
    asyncio.run(main())
