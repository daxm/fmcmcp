FROM python:3.11-slim

WORKDIR /app

# Copy application code
COPY app/ .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure pipx/uvx is in PATH
ENV PATH="/root/.local/bin:${PATH}"
RUN pipx ensurepath

# Load environment variables from .env (if provided)
COPY .env* ./
RUN if [ -f .env ]; then set -a; . .env; set +a; fi

CMD ["python", "fmc_mcp_server.py"]
