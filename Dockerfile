FROM python:3.11.11-slim

WORKDIR /app

# Copy package files
COPY fmcmcp/ ./fmcmcp/
COPY pyproject.toml README.md LICENSE requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure pipx/uvx is in PATH
ENV PATH="/root/.local/bin:${PATH}"
RUN pipx ensurepath

# Health check - verify Python runtime and required packages are available
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python -c "import sys, mcp, aiohttp, httpx; sys.exit(0)" || exit 1

CMD ["python", "-m", "fmcmcp"]
