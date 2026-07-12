FROM python:3.13-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gdb gcc && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY edb_debugger_mcp/ edb_debugger_mcp/
COPY binaryninja_mcp/ binaryninja_mcp/
COPY web_ui/ web_ui/
RUN pip install --no-cache-dir .

FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends gdb && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app
WORKDIR /app
EXPOSE 8000

# Default: MCP stdio mode.
# Override CMD to run web UI: python3 -m web_ui.server
CMD ["python3", "-c", "from edb_debugger_mcp import main; main()"]
