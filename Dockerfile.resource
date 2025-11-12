# Dockerfile for resource_server.py
FROM python:3.13-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application files
COPY resource_server.py ./

# Expose the resource server port
EXPOSE 9091

# Run the resource server
CMD ["uv", "run", "python", "resource_server.py"]
