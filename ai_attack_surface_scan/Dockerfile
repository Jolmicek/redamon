# =============================================================================
# RedAmon AI Attack Surface Scanner - Python Container (Step 2: skeleton)
# =============================================================================
# Reads the AI surface recon annotated into the graph, runs a fixed catalog of
# attack tools against selected nodes, and writes normalized Vulnerability
# findings back. Step 2 ships the shared spine only (target loader, safety/bounds,
# normalizer) with a dummy finding. Per-tool adapters land in later steps.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="AI Attack Surface deterministic offensive scanner for RedAmon"

WORKDIR /app

# Spine deps (just the Neo4j driver for now).
COPY ai_attack_surface_scan/requirements.txt /tmp/ai_attack_requirements.txt
RUN pip install --no-cache-dir -r /tmp/ai_attack_requirements.txt

# Copy the scanner. graph_db is NOT baked in: the spine talks to Neo4j via the
# bare driver, and the orchestrator volume-mounts graph_db at spawn if a later
# adapter needs the mixin helpers.
COPY ai_attack_surface_scan/ ./ai_attack_surface_scan/

RUN mkdir -p ai_attack_surface_scan/output

ENV PYTHONPATH=/app/ai_attack_surface_scan
ENV PYTHONUNBUFFERED=1

CMD ["python", "ai_attack_surface_scan/main.py"]
