"""
Signal catalogue the guinea pig emits.

Must mirror what `recon/helpers/ai_signal_catalog.py` is built to detect.
When the recon catalog changes, this file must be updated in lockstep —
the e2e driver does a parity check between the two before running the
scan, so any drift fails fast.

Three tables:
  - PORT_LISTENERS: one entry per port the guinea pig binds. Each port
    serves an HTML page on `/` with a deterministic title + Server header
    that fires (or deliberately skips, for disambiguate ports) the
    matching detection.
  - HEADER_VARIANTS: one entry per AI_HEADER_PATTERNS pattern. Served
    from the header-showroom port on `/header/<framework>`.
  - TITLE_VARIANTS: one entry per AI_TITLE_PATTERNS pattern. Served
    from the title-showroom port on `/title/<product>`.

No regex on this side — we only emit bytes. The recon catalog does
the matching.
"""
from __future__ import annotations


HEADER_SHOWROOM_PORT = 9100
TITLE_SHOWROOM_PORT = 9101
# Lap-2 — resource_enum AI classifier showroom. Serves an HTML index with
# links to every catalogued AI path. Katana crawls, builds Endpoint nodes,
# and the resource_enum AI classifier tags each one.
ENDPOINT_AI_CLASSIFIER_PORT = 9103


# ---------------------------------------------------------------------------
# Per-port listeners — exercise port_scan catalog + nmap version regex
# ---------------------------------------------------------------------------

PORT_LISTENERS: list[dict] = [
    # ─── Unambiguous AI ports (11) — port_scan MUST emit Technology(ai-*) ─
    {
        "port": 11434, "name": "ollama",
        "html_title": "Ollama",
        "server_header": "Ollama/0.1.32",
        "expected_port_catalog": {"name": "ollama", "category": "ai-runtime"},
        "expected_nmap_runtime": "ollama",
    },
    {
        "port": 1234, "name": "lm-studio",
        "html_title": "LM Studio",
        "server_header": "lm-studio/0.2.10",
        "expected_port_catalog": {"name": "lm-studio", "category": "ai-runtime"},
        "expected_nmap_runtime": None,  # not in AI_NMAP_VERSION_PATTERNS
    },
    {
        "port": 4000, "name": "litellm",
        "html_title": "LiteLLM",
        "server_header": "LiteLLM/1.30",
        "expected_port_catalog": {"name": "litellm", "category": "ai-proxy"},
        "expected_nmap_runtime": "litellm",
    },
    {
        "port": 6333, "name": "qdrant",
        "html_title": "Qdrant",
        "server_header": "qdrant/1.7.0",
        "expected_port_catalog": {"name": "qdrant", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 6334, "name": "qdrant-grpc",
        "html_title": "Qdrant gRPC",
        "server_header": "qdrant/1.7.0",
        "expected_port_catalog": {"name": "qdrant-grpc", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 19530, "name": "milvus",
        "html_title": "Milvus",
        "server_header": "milvus/2.3.0",
        "expected_port_catalog": {"name": "milvus", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 9091, "name": "milvus-metrics",
        "html_title": "Milvus Metrics",
        "server_header": "milvus/2.3.0",
        "expected_port_catalog": {"name": "milvus-metrics", "category": "ai-vector-db"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 7860, "name": "gradio",
        "html_title": "Gradio Demo",
        "server_header": "gradio/4.0",
        "expected_port_catalog": {"name": "gradio", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 8188, "name": "comfyui",
        "html_title": "ComfyUI",
        "server_header": "ComfyUI/0.1.0",
        "expected_port_catalog": {"name": "comfyui", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 8501, "name": "streamlit",
        "html_title": "Streamlit App",
        "server_header": "Streamlit/1.30",
        "expected_port_catalog": {"name": "streamlit", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },
    {
        "port": 3001, "name": "anythingllm",
        "html_title": "AnythingLLM Workspace",
        "server_header": "AnythingLLM/0.2.0",
        "expected_port_catalog": {"name": "anythingllm", "category": "ai-frontend"},
        "expected_nmap_runtime": None,
    },

    # ─── Disambiguate ports (2) — port_scan MUST skip; one still fires
    #     via http_probe title regex for :8080 ────────────────────────────
    #
    # Three catalog disambiguate ports CANNOT be bound here because Redamon
    # services publish them on the host:
    #   - 8000: kali-sandbox MCP network-recon
    #   - 8002: kali-sandbox MCP nuclei
    #   - 3000: webapp (the UI itself)
    # The disambiguate behaviour is still validated by 8001 + 8080.
    # The vllm nmap-regex test is preserved by binding `vllm/0.4.1` on
    # off-catalog port 18000.
    {
        "port": 18000, "name": "vllm-banner-only",
        "html_title": "vLLM API",
        "server_header": "vllm/0.4.1",
        # Outside the AI port catalog → port_scan must NOT tag, nmap regex MUST tag
        "expected_port_catalog": None,
        "expected_nmap_runtime": "vllm",
    },
    {
        "port": 8001, "name": "triton-or-vllm",
        "html_title": "Triton API",
        "server_header": "triton-server/24.05",
        "expected_port_catalog": None,
        "expected_nmap_runtime": "triton",
    },
    {
        "port": 8080, "name": "open-webui-front",
        # IMPORTANT: title fires `http_probe` AI title regex → BaseURL gets
        # is_ai_framework_detected=true via httpx-ai-title path, even though
        # port_scan skipped 8080 because it's disambiguate=True. Proves the
        # plan's "disambiguate ports can still be promoted by http_probe" rule.
        "html_title": "Open WebUI",
        "server_header": "nginx/1.18",
        "expected_port_catalog": None,
        "expected_nmap_runtime": None,
        "expected_http_title": "open-webui",
    },
]


# ---------------------------------------------------------------------------
# Header showroom (port 9100) — exercise every AI_HEADER_PATTERNS entry
# ---------------------------------------------------------------------------

HEADER_VARIANTS: dict[str, dict] = {
    # Runtimes
    "vllm":       {"headers": {"x-vllm-cache-hit": "1"},
                   "expected_framework": "vllm", "expected_category": "ai-runtime"},
    "tgi":        {"headers": {"x-tgi-request-id": "stub"},
                   "expected_framework": "tgi", "expected_category": "ai-runtime"},
    "tei":        {"headers": {"x-tei-version": "1.2"},
                   "expected_framework": "text-embeddings-inference", "expected_category": "ai-runtime"},
    "bentoml":    {"headers": {"x-bentoml-version": "1.1.0"},
                   "expected_framework": "bentoml", "expected_category": "ai-runtime"},
    "baseten":    {"headers": {"x-baseten-deployment": "dep-abc"},
                   "expected_framework": "baseten", "expected_category": "ai-runtime"},
    "modal":      {"headers": {"x-modal-task-id": "task-xyz"},
                   "expected_framework": "modal", "expected_category": "ai-runtime"},
    "replicate":  {"headers": {"x-replicate-prediction": "pred-123"},
                   "expected_framework": "replicate", "expected_category": "ai-runtime"},
    "runpod":     {"headers": {"x-runpod-pod-id": "pod-456"},
                   "expected_framework": "runpod", "expected_category": "ai-runtime"},

    # Frameworks / orchestrators
    "langchain":  {"headers": {"x-langchain-run-id": "run-789"},
                   "expected_framework": "langchain", "expected_category": "ai-framework"},
    "llamaindex": {"headers": {"x-llamaindex-trace-id": "trace-abc"},
                   "expected_framework": "llamaindex", "expected_category": "ai-framework"},
    "langfuse":   {"headers": {"langfuse-trace-id": "lf-trace-1"},
                   "expected_framework": "langfuse", "expected_category": "ai-framework"},
    "mcp":        {"headers": {"x-mcp-server-name": "stub"},
                   "expected_framework": "mcp", "expected_category": "ai-framework"},

    # Proxies / gateways
    "litellm":    {"headers": {"x-litellm-model-id": "gpt-4"},
                   "expected_framework": "litellm", "expected_category": "ai-proxy"},
    "helicone":   {"headers": {"x-helicone-cache": "HIT"},
                   "expected_framework": "helicone", "expected_category": "ai-proxy"},
    "portkey":    {"headers": {"x-portkey-cache": "x"},
                   "expected_framework": "portkey", "expected_category": "ai-proxy"},
    "omniroute":  {"headers": {"x-omniroute-trace": "x"},
                   "expected_framework": "omniroute", "expected_category": "ai-proxy"},
    "cloudflare": {"headers": {"cf-aig-cache-status": "hit"},
                   "expected_framework": "cloudflare-ai-gateway", "expected_category": "ai-proxy"},
    "together":   {"headers": {"together-request-id": "req-1"},
                   "expected_framework": "together", "expected_category": "ai-proxy"},

    # SDK clients
    "openai":     {"headers": {"openai-organization": "org-abc"},
                   "expected_framework": "openai", "expected_category": "ai-sdk-client"},
    "anthropic":  {"headers": {"anthropic-version": "2023-06-01"},
                   "expected_framework": "anthropic", "expected_category": "ai-sdk-client"},
}


# ---------------------------------------------------------------------------
# Title showroom (port 9101) — exercise every AI_TITLE_PATTERNS entry
# ---------------------------------------------------------------------------

TITLE_VARIANTS: dict[str, dict] = {
    "open-webui":     {"title": "Open WebUI",
                       "expected_product": "open-webui"},
    "librechat":      {"title": "LibreChat",
                       "expected_product": "librechat"},
    "anythingllm":    {"title": "AnythingLLM Workspace",
                       "expected_product": "anythingllm"},
    "flowise":        {"title": "Flowise",
                       "expected_product": "flowise"},
    "langflow":       {"title": "Langflow",
                       "expected_product": "langflow"},
    "dify":           {"title": "Dify Dashboard",
                       "expected_product": "dify"},
    "comfyui":        {"title": "ComfyUI",
                       "expected_product": "comfyui"},
    "gradio":         {"title": "Gradio demo",
                       "expected_product": "gradio"},
    "streamlit":      {"title": "Streamlit App",
                       "expected_product": "streamlit"},
    "chatgpt-clone":  {"title": "ChatGPT for everyone",
                       "expected_product": "chatgpt-clone"},
    "hf-chat-ui":     {"title": "HuggingFace Chat UI",
                       "expected_product": "hf-chat-ui"},
    "lobechat":       {"title": "LobeChat workspace",
                       "expected_product": "lobechat"},
    "nextchat":       {"title": "NextChat",
                       "expected_product": "nextchat"},
    "sillytavern":    {"title": "SillyTavern",
                       "expected_product": "sillytavern"},
    "jan":            {"title": "Jan - Open Source AI",
                       "expected_product": "jan"},
    "h2ogpt":         {"title": "h2oGPT",
                       "expected_product": "h2ogpt"},
    "privategpt":     {"title": "PrivateGPT",
                       "expected_product": "privategpt"},
    "quivr":          {"title": "Quivr",
                       "expected_product": "quivr"},
}


def all_ports() -> list[int]:
    """Every TCP port the guinea pig binds. Pass this to naabuCustomPorts."""
    return (
        [d["port"] for d in PORT_LISTENERS]
        + [HEADER_SHOWROOM_PORT, TITLE_SHOWROOM_PORT, ENDPOINT_AI_CLASSIFIER_PORT]
    )


def header_paths() -> list[str]:
    """Every /header/* path the title-showroom serves. Pass this to httpxPaths."""
    return [f"/header/{f}" for f in HEADER_VARIANTS]


def title_paths() -> list[str]:
    """Every /title/* path the title-showroom serves. Pass this to httpxPaths."""
    return [f"/title/{p}" for p in TITLE_VARIANTS]


# ---------------------------------------------------------------------------
# Lap-2 — resource_enum AI classifier showroom (port 9103)
# ---------------------------------------------------------------------------
#
# One entry per ai_interface_type the resource_enum classifier can stamp.
# Each entry carries the path Katana should discover plus the enum value the
# classifier must produce.
#
# Each link on the index page also carries query-string params: one or two
# from AI_PARAM_NAMES (must get `is_ai_prompt_injectable=true`) and one
# control name like `model`/`temperature` (must NOT get tagged). This lets
# the e2e check both the positive AND negative paths of the param classifier.

RESOURCE_ENUM_AI_PATHS: list[dict] = [
    # ── llm-chat ────────────────────────────────────────────────────────
    {"path": "/v1/chat/completions", "enum": "llm-chat",
     "prompt_params": ["messages", "system"], "control_params": ["model", "temperature"]},
    {"path": "/v1/messages", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["model"]},
    {"path": "/api/chat", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["stream"]},
    {"path": "/v1beta/models/gemini-1.5-pro:generateContent", "enum": "llm-chat",
     "prompt_params": ["contents"], "control_params": ["model"]},
    {"path": "/v2/chat", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["model"]},
    {"path": "/v1/sonar", "enum": "llm-chat",
     "prompt_params": ["messages"], "control_params": ["model"]},

    # ── llm-completion ──────────────────────────────────────────────────
    {"path": "/v1/completions", "enum": "llm-completion",
     "prompt_params": ["prompt"], "control_params": ["max_tokens"]},
    {"path": "/v1/fim/completions", "enum": "llm-completion",
     "prompt_params": ["prompt", "suffix"], "control_params": ["model"]},
    {"path": "/api/generate", "enum": "llm-completion",
     "prompt_params": ["prompt", "system"], "control_params": ["model"]},

    # ── llm-embedding ───────────────────────────────────────────────────
    {"path": "/v1/embeddings", "enum": "llm-embedding",
     "prompt_params": ["input"], "control_params": ["model"]},
    {"path": "/api/embed", "enum": "llm-embedding",
     "prompt_params": ["input"], "control_params": ["model"]},
    {"path": "/v2/embed", "enum": "llm-embedding",
     "prompt_params": ["inputs"], "control_params": ["model"]},

    # ── llm-tool-call ───────────────────────────────────────────────────
    {"path": "/v1/threads/thread_demo/runs", "enum": "llm-tool-call",
     "prompt_params": ["instructions"], "control_params": ["assistant_id"]},
    {"path": "/v1/responses/resp_demo/input_items", "enum": "llm-tool-call",
     "prompt_params": ["input"], "control_params": ["order"]},

    # ── sse-stream ──────────────────────────────────────────────────────
    {"path": "/generate_stream", "enum": "sse-stream",
     "prompt_params": ["prompt"], "control_params": ["max_new_tokens"]},
    {"path": "/agents/demo/stream", "enum": "sse-stream",
     "prompt_params": ["input"], "control_params": ["config"]},

    # ── mcp ─────────────────────────────────────────────────────────────
    {"path": "/mcp", "enum": "mcp",
     "prompt_params": ["arguments"], "control_params": ["method"]},
    {"path": "/api/mcp", "enum": "mcp",
     "prompt_params": ["arguments"], "control_params": ["method"]},
    {"path": "/sse", "enum": "mcp",
     "prompt_params": [], "control_params": []},
    {"path": "/tools/list", "enum": "mcp",
     "prompt_params": [], "control_params": ["cursor"]},

    # ── llm-graphql (gated on parent-AI — fires here because the showroom
    #    BaseURL is parent-AI-tagged via the http_probe header showroom
    #    when the e2e driver runs both showrooms on the same host) ──────
    {"path": "/graphql", "enum": "llm-graphql",
     "prompt_params": ["query"], "control_params": ["operationName"]},
]


# Unambiguous RAG paths. Each must get is_ai_rag_ingest=true regardless of
# parent-AI status. Ambiguous RAG paths (/search, /upload, /query) are not
# included here — they need parent-AI corroboration and are exercised by the
# http_probe header showroom that tags this same host.
RESOURCE_ENUM_AI_RAG_PATHS: list[dict] = [
    {"path": "/v1/files",
     "prompt_params": [], "control_params": ["purpose"]},
    {"path": "/v1/uploads",
     "prompt_params": [], "control_params": ["filename"]},
    {"path": "/v1/vector_stores",
     "prompt_params": [], "control_params": ["name"]},
    {"path": "/v1/vector_stores/vs_demo/search",
     "prompt_params": ["query"], "control_params": ["max_num_results"]},
    {"path": "/v1/assistants",
     "prompt_params": ["instructions"], "control_params": ["model"]},
    {"path": "/vectors/upsert",
     "prompt_params": [], "control_params": ["namespace"]},
    {"path": "/v1/objects",
     "prompt_params": [], "control_params": ["class"]},
    {"path": "/collections/demo/points/search",
     "prompt_params": ["query"], "control_params": ["limit"]},
]


def resource_enum_paths() -> list[str]:
    """Every classifier-targeted path with its full query string. Pass to
    httpxPaths so httpx probes them when Katana follows the showroom links."""
    out: list[str] = []
    for entry in RESOURCE_ENUM_AI_PATHS + RESOURCE_ENUM_AI_RAG_PATHS:
        params = entry.get("prompt_params", []) + entry.get("control_params", [])
        if params:
            qs = "&".join(f"{p}=demo" for p in params)
            out.append(f"{entry['path']}?{qs}")
        else:
            out.append(entry["path"])
    return out
