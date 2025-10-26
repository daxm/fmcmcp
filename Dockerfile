FROM python:3.11-slim

WORKDIR /app

# Copy application code
COPY app/ .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure pipx/uvx is in PATH
ENV PATH="/root/.local/bin:${PATH}"
RUN pipx ensurepath

# Health check - verify Python runtime is functional
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "fmc_mcp_server.py"]
