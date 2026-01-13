FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

# Set environment variables
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV PYTHONPATH=/home/agent/src

# Create user first to set up the home directory
RUN adduser --disabled-password --gecos "" agent

WORKDIR /home/agent

# Copy dependency files
COPY pyproject.toml uv.lock README.md ./

# Install dependencies using cache mount
# Note: we use /root/.cache/uv because uv sync runs as root initially or we can switch to agent
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

# Copy the source code
COPY src /home/agent/src/

# Ensure the agent user owns the files
RUN chown -R agent:agent /home/agent

# Switch to non-privileged user
USER agent

# Expose the API port
EXPOSE 9009

# Run the server
ENTRYPOINT ["uv", "run", "src/server.py"]
CMD ["--host", "0.0.0.0", "--port", "9009"]