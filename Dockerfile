FROM python:3.9-slim

WORKDIR /app

COPY app/ .

RUN pip install --no-cache-dir mcp mcp-openapi-proxy httpx packaging aiohttp

# Slim and compress JSONs, keeping only .gz
RUN python slim_specs.py specs specs

# Load environment variables from .env (if provided)
COPY .env* ./
RUN if [ -f .env ]; then set -a; . .env; set +a; fi

EXPOSE 8000

CMD ["python", "fmc_mcp_server.py"]
