# RedAmon — AI surface recon guinea pig
#
# Single-image, all-Python target that binds to 18 ports on host loopback
# and emits every signal the lap-1 AI surface catalog tries to detect.
# No LLM, no model weights, no GPU.

FROM python:3.11-slim

WORKDIR /app

# Pinned aiohttp only — no torch, no numpy, no transitive AI deps.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Source last so a source-only edit doesn't bust the pip layer cache.
COPY ai_signals.py server.py ./

# Healthcheck pokes the Ollama-stub port (11434). If asyncio crashes or
# we fail to bind, this fires within ~15 s.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 11434)); s.close()" || exit 1

CMD ["python3", "-u", "server.py"]
