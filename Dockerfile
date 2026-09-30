# Dockerfile for main.py application
FROM python:3.13-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.5.29 /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application files
COPY main.py ./
# The station screens. Without this the app boots and every /station/* route
# 500s on a missing template.
COPY templates ./templates
# The stylesheet. Flask serves /static/* from this directory, so without this
# copy /static/style.css 404s and every screen renders as raw unstyled HTML.
COPY static ./static

# Expose the application port
EXPOSE 9090

# Run the application
CMD ["uv", "run", "python", "main.py"]
