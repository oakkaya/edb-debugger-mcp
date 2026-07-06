FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends gdb gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY edb_debugger_mcp.py gdb_backend.py pwntools_mcp.py ./
COPY binaryninja_mcp/mcp_client.py binaryninja_mcp/

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["python3", "edb_debugger_mcp.py"]
