FROM python:3.10-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Create app directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-cache && rm -f .venv/.lock && chown -R 1000:1000 /app

# Copy source code
COPY src/ ./src/

# Create log directory and set permissions
RUN mkdir -p /var/log/trap && chown -R 1000:1000 /var/log/trap

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Run as non-root user
USER 1000

# Entry point
CMD ["python", "-m", "src.trap.main"]
