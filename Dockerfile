# Dockerfile for main.py application
FROM python:3.13-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application files
COPY main.py ./
COPY config.json ./

# Expose the application port
EXPOSE 9090

# Run the application
CMD ["uv", "run", "python", "main.py"]
