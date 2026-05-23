"""Single source of truth for AI / LLM surface detection signals.

This module is the canonical catalogue consumed by every distributed AI-recon
hook (domain_recon, port_scan/masscan/nmap, http_probe, resource_enum, js_recon,
vuln_scan, subdomain_takeover, vhost_sni_enum, add_mitre, the OSINT enrichments,
and the future central ai_surface_recon module). Every hook imports the constants
it needs from this file and never duplicates the data inline.

Naming convention (see internal/ADVERSARIAL_AI/AI_SURFACE_RECON.md §7.0):

  - Properties prefixed ``ai_`` or ``is_ai_`` are AI surface annotations.
  - Values prefixed ``ai-``, ``llm-``, or ``AML.T`` are AI classifications on
    fields whose own name is generic (Technology.category, MitreData.id, etc.).

This file is forward-only: later integration laps fill the empty stubs at the
bottom. The import path stays stable from day one so distributed hooks land
cleanly across laps.
"""
from __future__ import annotations

import re
from typing import Pattern


# ---------------------------------------------------------------------------
# domain_recon  (AI_SURFACE_RECON.md §2.1 #1)
# ---------------------------------------------------------------------------

# AI provider substrings to look for inside TXT records (SPF, DKIM, DMARC,
# verification tokens). Order matters: the first match wins so that the
# strongest signal (a clear vendor domain) outranks generic CDN hints.
AI_TXT_PATTERNS: list[tuple[Pattern[str], str]] = [
    (re.compile(r"\banthropic\.com\b", re.IGNORECASE), "anthropic"),
    (re.compile(r"\bopenai\.com\b", re.IGNORECASE), "openai"),
    (re.compile(r"\bhuggingface\.co\b", re.IGNORECASE), "huggingface"),
    (re.compile(r"\bcohere\.com\b", re.IGNORECASE), "cohere"),
    (re.compile(r"\breplicate\.com\b", re.IGNORECASE), "replicate"),
    (re.compile(r"\blangchain\.com\b", re.IGNORECASE), "langchain"),
    (re.compile(r"\blangfuse\.com\b", re.IGNORECASE), "langfuse"),
    (re.compile(r"\blangsmith\.com\b", re.IGNORECASE), "langsmith"),
    (re.compile(r"\btogether\.ai\b", re.IGNORECASE), "together"),
    (re.compile(r"\bgroq\.com\b", re.IGNORECASE), "groq"),
    (re.compile(r"\bmistral\.ai\b", re.IGNORECASE), "mistral"),
]

# NS-record substrings that hint at AI-friendly hosting providers. Always a
# weak signal — these providers host plenty of non-AI sites — so the consumer
# must only set ``Subdomain.ai_service_hint = "ai-hosting-candidate"`` when no
# stronger TXT hint already exists.
AI_NS_HINT_PATTERNS: list[tuple[Pattern[str], str]] = [
    (re.compile(r"\bvercel-dns\b", re.IGNORECASE), "vercel"),
    (re.compile(r"\bnsone\.net\b", re.IGNORECASE), "netlify"),
    (re.compile(r"\breplit\b", re.IGNORECASE), "replit"),
    (re.compile(r"\bmodal-dns\b", re.IGNORECASE), "modal"),
    (re.compile(r"\bhuggingface\.co\b", re.IGNORECASE), "huggingface-spaces"),
]


# ---------------------------------------------------------------------------
# port_scan / masscan_scan  (AI_SURFACE_RECON.md §2.1 #2)
# ---------------------------------------------------------------------------

# Port → AI service descriptor.
#
# Each entry carries ``name`` (the Technology.name we MERGE in the graph),
# ``category`` (Technology.category value, always prefixed ``ai-``), and an
# optional ``disambiguate`` flag. When ``disambiguate`` is True the port is
# shared between AI and non-AI services (e.g. 8000 is also a generic dev
# server) and the lookup must be gated on a corroborating signal — a matching
# header or title from http_probe — before any AI annotation is written. The
# port_scan hook never sets an AI tag on a ``disambiguate=True`` port on its
# own; that promotion happens later in the central ai_surface_recon module
# once chat-shape probes confirm the surface.
AI_PORTS: dict[int, dict[str, str | bool]] = {
    # ─── Local model runtimes ─────────────────────────────────────────────
    11434: {"name": "ollama", "category": "ai-runtime"},
    1234:  {"name": "lm-studio", "category": "ai-runtime", "disambiguate": True},
    3000:  {"name": "bentoml-or-langflow-or-openllm", "category": "ai-runtime", "disambiguate": True},
    5000:  {"name": "mlflow-or-flask", "category": "ai-mlops", "disambiguate": True},
    5001:  {"name": "koboldcpp", "category": "ai-runtime", "disambiguate": True},
    8000:  {"name": "vllm-or-chroma-or-langserve-or-nim-or-mlc-or-faster-whisper", "category": "ai-runtime", "disambiguate": True},
    8001:  {"name": "triton-or-vllm-or-redis-insight", "category": "ai-runtime", "disambiguate": True},
    8002:  {"name": "triton-metrics", "category": "ai-runtime", "disambiguate": True},
    8080:  {"name": "open-webui-or-weaviate-or-localai-or-whisper-cpp", "category": "ai-frontend", "disambiguate": True},
    8880:  {"name": "kokoro-tts", "category": "ai-runtime"},
    30000: {"name": "sglang", "category": "ai-runtime"},

    # ─── Vector databases ─────────────────────────────────────────────────
    6333:  {"name": "qdrant", "category": "ai-vector-db"},
    6334:  {"name": "qdrant-grpc", "category": "ai-vector-db"},
    19530: {"name": "milvus", "category": "ai-vector-db"},
    9091:  {"name": "milvus-metrics-or-invokeai-or-prometheus", "category": "ai-vector-db", "disambiguate": True},
    50051: {"name": "weaviate-grpc", "category": "ai-vector-db", "disambiguate": True},

    # ─── Proxies / gateways ───────────────────────────────────────────────
    4000:  {"name": "litellm", "category": "ai-proxy", "disambiguate": True},

    # ─── Frontends / web UIs ──────────────────────────────────────────────
    7860:  {"name": "gradio-or-automatic1111-or-langflow", "category": "ai-frontend"},
    7865:  {"name": "fooocus", "category": "ai-frontend", "disambiguate": True},
    8188:  {"name": "comfyui", "category": "ai-frontend"},
    8501:  {"name": "streamlit", "category": "ai-frontend"},
    3001:  {"name": "anythingllm", "category": "ai-frontend", "disambiguate": True},
    9090:  {"name": "invokeai", "category": "ai-frontend", "disambiguate": True},

    # ─── MLOps / observability stacks ─────────────────────────────────────
    6006:  {"name": "phoenix-arize-or-tensorboard", "category": "ai-mlops", "disambiguate": True},
    6900:  {"name": "argilla", "category": "ai-mlops"},
    8081:  {"name": "autogen-studio", "category": "ai-mlops", "disambiguate": True},
    8123:  {"name": "langgraph-or-clickhouse", "category": "ai-framework", "disambiguate": True},
    8265:  {"name": "ray-dashboard", "category": "ai-mlops", "disambiguate": True},
    2024:  {"name": "langgraph-dev", "category": "ai-framework"},
}


# ---------------------------------------------------------------------------
# nmap_scan  (AI_SURFACE_RECON.md §2.1 #4)
# ---------------------------------------------------------------------------

# Regex applied to nmap's ``product`` / ``version`` fields. On match, set
# ``Service.ai_runtime_version`` to the matched substring so downstream CVE
# lookups can join against AI library CVE clusters in later laps.
AI_NMAP_VERSION_PATTERNS: list[tuple[Pattern[str], str]] = [
    (re.compile(r"\bOllama/", re.IGNORECASE), "ollama"),
    (re.compile(r"\bvllm/", re.IGNORECASE), "vllm"),
    (re.compile(r"\bLiteLLM/", re.IGNORECASE), "litellm"),
    (re.compile(r"\bTGI/|text-generation-inference/", re.IGNORECASE), "tgi"),
    (re.compile(r"\btriton-server/", re.IGNORECASE), "triton"),
    (re.compile(r"\bllama\.cpp/", re.IGNORECASE), "llama.cpp"),
]


# ---------------------------------------------------------------------------
# http_probe  (AI_SURFACE_RECON.md §2.1 #5)
# ---------------------------------------------------------------------------

# AI-stack header signature regex. Matched against captured response header
# *names* (case-insensitive). First match wins; ordering matters because some
# headers (``x-litellm-*``) hint at a proxy in front of a real runtime, so the
# runtime headers come first.
#
# Tuple shape: (header_name_pattern, framework_name, technology_category).
AI_HEADER_PATTERNS: list[tuple[Pattern[str], str, str]] = [
    # Runtimes — strongest signal
    (re.compile(r"^x-vllm-", re.IGNORECASE), "vllm", "ai-runtime"),
    (re.compile(r"^x-tgi-", re.IGNORECASE), "tgi", "ai-runtime"),
    (re.compile(r"^x-tei-", re.IGNORECASE), "text-embeddings-inference", "ai-runtime"),
    (re.compile(r"^x-bentoml-", re.IGNORECASE), "bentoml", "ai-runtime"),
    (re.compile(r"^x-baseten-", re.IGNORECASE), "baseten", "ai-runtime"),
    (re.compile(r"^x-modal-", re.IGNORECASE), "modal", "ai-runtime"),
    (re.compile(r"^x-replicate-", re.IGNORECASE), "replicate", "ai-runtime"),
    (re.compile(r"^x-runpod-", re.IGNORECASE), "runpod", "ai-runtime"),

    # Frameworks / orchestrators
    (re.compile(r"^x-langchain-", re.IGNORECASE), "langchain", "ai-framework"),
    (re.compile(r"^x-llamaindex-", re.IGNORECASE), "llamaindex", "ai-framework"),
    (re.compile(r"^langfuse-", re.IGNORECASE), "langfuse", "ai-framework"),

    # Proxies / gateways
    (re.compile(r"^x-litellm-", re.IGNORECASE), "litellm", "ai-proxy"),
    (re.compile(r"^x-helicone-", re.IGNORECASE), "helicone", "ai-proxy"),
    (re.compile(r"^x-portkey-", re.IGNORECASE), "portkey", "ai-proxy"),
    (re.compile(r"^x-omniroute-", re.IGNORECASE), "omniroute", "ai-proxy"),
    (re.compile(r"^cf-aig-", re.IGNORECASE), "cloudflare-ai-gateway", "ai-proxy"),
    (re.compile(r"^together-", re.IGNORECASE), "together", "ai-proxy"),

    # SDK clients (proxied vendor calls)
    (re.compile(r"^openai-(organization|version|processing-ms)", re.IGNORECASE), "openai", "ai-sdk-client"),
    (re.compile(r"^anthropic-(version|beta|ratelimit-)", re.IGNORECASE), "anthropic", "ai-sdk-client"),
    # Azure OpenAI: x-ms-region + azureml-model-session are unique to AOAI.
    # The combination is the strongest signal, but each alone is high-confidence
    # for an AOAI-fronted endpoint.
    (re.compile(r"^x-ms-region$|^azureml-model-session$", re.IGNORECASE), "azure-openai", "ai-sdk-client"),
    # Fireworks AI's unique ratelimit suffix and account header.
    (re.compile(r"^x-ratelimit-limit-tokens-cache-adjusted-prompt$|^x-fireworks-account-id$", re.IGNORECASE), "fireworks", "ai-sdk-client"),

    # MCP
    (re.compile(r"^x-mcp-", re.IGNORECASE), "mcp", "ai-framework"),
]

# Page-title regex catalogue for AI frontend products. Matched against the
# captured ``title`` from httpx. Each entry maps to a Technology(name) under
# Technology.category = "ai-frontend".
AI_TITLE_PATTERNS: list[tuple[Pattern[str], str]] = [
    # ─── Chat / generic LLM frontends ─────────────────────────────────────
    (re.compile(r"\bOpen WebUI\b", re.IGNORECASE), "open-webui"),
    (re.compile(r"\bLibreChat\b", re.IGNORECASE), "librechat"),
    (re.compile(r"\bAnythingLLM\b", re.IGNORECASE), "anythingllm"),
    (re.compile(r"\bFlowise\b", re.IGNORECASE), "flowise"),
    (re.compile(r"\bLangflow\b", re.IGNORECASE), "langflow"),
    (re.compile(r"\bDify\b", re.IGNORECASE), "dify"),
    (re.compile(r"\bComfyUI\b", re.IGNORECASE), "comfyui"),
    (re.compile(r"\bGradio\b", re.IGNORECASE), "gradio"),
    (re.compile(r"\bStreamlit\b", re.IGNORECASE), "streamlit"),
    # Specific clones first, then the generic ChatGPT-clone fallback.
    (re.compile(r"\bBetterChatGPT\b", re.IGNORECASE), "betterchatgpt"),
    (re.compile(r"\bOnyx\b|\bDanswer\b", re.IGNORECASE), "onyx"),
    (re.compile(r"\bChatGPT\b", re.IGNORECASE), "chatgpt-clone"),
    (re.compile(r"\bHuggingFace Chat UI\b", re.IGNORECASE), "hf-chat-ui"),
    (re.compile(r"\bLobeChat\b|\bLobeHub\b", re.IGNORECASE), "lobechat"),
    (re.compile(r"\bNextChat\b", re.IGNORECASE), "nextchat"),
    (re.compile(r"\bSillyTavern\b", re.IGNORECASE), "sillytavern"),
    (re.compile(r"\bJan\b\s*-\s*Open\s*Source", re.IGNORECASE), "jan"),
    (re.compile(r"\bh2oGPT\b", re.IGNORECASE), "h2ogpt"),
    (re.compile(r"\bPrivateGPT\b", re.IGNORECASE), "privategpt"),
    (re.compile(r"\bQuivr\b", re.IGNORECASE), "quivr"),

    # ─── Image-gen UIs (run on Gradio shell) ──────────────────────────────
    # InvokeAI: exact title "Invoke - Community Edition" set via index.html
    (re.compile(r"\bInvoke\s*-\s*Community Edition\b", re.IGNORECASE), "invokeai"),
    # A1111 / Forge: title is just "Stable Diffusion". This is broad — body
    # fingerprint (txt2img_textarea) is the high-confidence channel; title
    # here is a corroborating hint.
    (re.compile(r"^Stable Diffusion$", re.IGNORECASE), "automatic1111"),

    # ─── MLOps / observability frontends ──────────────────────────────────
    # Word-boundary patterns: title field from httpx is the bare text inside
    # <title>...</title>, not the markup itself. Anchored "^...$" patterns
    # require the title to be exactly the product name (no surrounding text).
    (re.compile(r"^MLflow$", re.IGNORECASE), "mlflow"),
    (re.compile(r"^Labelstudio$", re.IGNORECASE), "label-studio"),
    (re.compile(r"\bRay Dashboard\b", re.IGNORECASE), "ray-dashboard"),
    (re.compile(r"\bRedisInsight\b", re.IGNORECASE), "redis-insight"),
    (re.compile(r"\bAutoGen Studio\b", re.IGNORECASE), "autogen-studio"),
    (re.compile(r"\bLangfuse\b", re.IGNORECASE), "langfuse-ui"),
    (re.compile(r"\bArize Phoenix\b|^Phoenix$", re.IGNORECASE), "phoenix-arize"),
    (re.compile(r"\bArgilla\b", re.IGNORECASE), "argilla"),
    (re.compile(r"\bGPT Researcher\b", re.IGNORECASE), "gpt-researcher"),
]

# AI Wappalyzer-style fingerprints. Each entry matches against the HTTP
# response *body* (HTML / JS bundle text). Patterns are deliberately specific
# enough that a casual mention in documentation will NOT trip them — we want
# fingerprints of the deployed product, not blog posts about it.
#
# Tuple shape: (body_regex, framework_name, technology_category).
# First match wins. Iteration order: runtimes > frameworks > frontends > sdk.
AI_BODY_FINGERPRINTS: list[tuple[Pattern[str], str, str]] = [
    # --- Runtimes ---------------------------------------------------------
    # TGI: the streaming form action / API client path
    (re.compile(r"""(?:action|href|fetch\()\s*=?\s*["']/generate_stream["']""", re.IGNORECASE), "tgi", "ai-runtime"),
    # vLLM: session cookie literal often echoed in error pages or JS
    (re.compile(r"\bvllm_session\b", re.IGNORECASE), "vllm", "ai-runtime"),

    # --- Frameworks -------------------------------------------------------
    # LangChain JS globals injected into the page by langchain/langgraph apps
    (re.compile(r"window\.__LANGCHAIN__|window\.__LANGCHAIN_TRACING_V2__", re.IGNORECASE), "langchain", "ai-framework"),
    # LangChain JS package import string visible in unminified bundles
    (re.compile(r"""@langchain/(core|community|langgraph|openai|anthropic)["']""", re.IGNORECASE), "langchain", "ai-framework"),
    # LlamaIndex JS package + global
    (re.compile(r"""@llamaindex/(core|cloud|community)["']|window\.LlamaIndex\b""", re.IGNORECASE), "llamaindex", "ai-framework"),

    # --- Image-gen UIs (run on Gradio shell — these patterns disambiguate) ---
    # A1111 Stable Diffusion WebUI — high-confidence textarea IDs + JS hooks
    (re.compile(r"\btxt2img_textarea\b|\bimg2img_textarea\b|\bonAfterUiUpdate\b|\bgradioApp\(\)", re.IGNORECASE), "automatic1111", "ai-frontend"),
    # Fooocus — literal version tag in their script.js shipped to browser
    (re.compile(r"\bfooocus_v2\b", re.IGNORECASE), "fooocus", "ai-frontend"),
    # InvokeAI — branded favicon asset path is shipped in the HTML
    (re.compile(r"invoke-favicon\.svg|/src/main\.tsx['\"]", re.IGNORECASE), "invokeai", "ai-frontend"),
    # ComfyUI frontend (Vue rewrite) — distinctive splash + manifest pattern
    (re.compile(r'aria-label=["\']Loading ComfyUI["\']|\bcomfy-splash-bg\b', re.IGNORECASE), "comfyui", "ai-frontend"),

    # --- General frontends ------------------------------------------------
    # Gradio: custom element tag + the runtime config global it bootstraps
    (re.compile(r"<gradio-app\b|window\.gradio_config\s*=", re.IGNORECASE), "gradio", "ai-frontend"),
    # Streamlit: the React app's root testid (used in client-side selectors)
    (re.compile(r"""data-testid=["']stApp["']|stStreamlitApp""", re.IGNORECASE), "streamlit", "ai-frontend"),

    # --- MLOps / observability stacks -------------------------------------
    # MLflow — distinctive container class on the React root
    (re.compile(r"\bmlflow-ui-container\b|/ajax-api/2\.0/mlflow/", re.IGNORECASE), "mlflow", "ai-mlops"),
    # Langfuse / NextAuth + Langfuse-specific paths
    (re.compile(r"/api/public/(ingestion|projects)\b", re.IGNORECASE), "langfuse", "ai-mlops"),
    # Phoenix Arize: OTLP traces endpoint + its REST API shape
    (re.compile(r"/v1/traces\b.*phoenix|/v1/datasets\b.*phoenix", re.IGNORECASE), "phoenix-arize", "ai-mlops"),
    # Ray Dashboard backend API
    (re.compile(r"/api/cluster_status\b|/logs/job/[\w-]+", re.IGNORECASE), "ray-dashboard", "ai-mlops"),

    # --- Vector DB consoles -----------------------------------------------
    # Weaviate /v1/meta unique response shape
    (re.compile(r'"hostname"\s*:\s*"[^"]+"\s*,\s*"version"\s*:.+?"modules"', re.IGNORECASE | re.DOTALL), "weaviate", "ai-vector-db"),
    # Chroma /api/v1/heartbeat unique response key
    (re.compile(r'"nanosecond[\s_]?heartbeat"\s*:\s*\d+', re.IGNORECASE), "chroma", "ai-vector-db"),

    # --- Specialized runtimes ---------------------------------------------
    # SGLang /get_model_info distinctive JSON shape
    (re.compile(r'"is_generation"\s*:\s*(true|false)\s*,\s*"model_path"', re.IGNORECASE), "sglang", "ai-runtime"),
    # KoboldCpp /api/extra/version distinctive response
    (re.compile(r'"result"\s*:\s*"KoboldCpp"', re.IGNORECASE), "koboldcpp", "ai-runtime"),
    # LocalAI gallery installer endpoint
    (re.compile(r"/models/apply\b|/models/available\b", re.IGNORECASE), "localai", "ai-runtime"),
    # OpenLLM
    (re.compile(r"/v1/generate\b.*openllm|openllm\s+server", re.IGNORECASE), "openllm", "ai-runtime"),

    # --- SDK clients shipped to the browser (high-severity context) -------
    # @anthropic-ai/sdk import string in shipped JS bundle
    (re.compile(r"""@anthropic-ai/sdk["']""", re.IGNORECASE), "anthropic", "ai-sdk-client"),
    # OpenAI JS SDK import (only flag the deliberate browser-allowed pattern
    # to avoid matching every Node service that imports openai)
    (re.compile(r"\bdangerouslyAllowBrowser\s*:\s*true\b", re.IGNORECASE), "openai", "ai-sdk-client"),
]


# mmh3 favicon hash → product. The hash is the Shodan/FOFA standard:
# ``mmh3.hash(base64.encodebytes(favicon_bytes).decode())``. Httpx computes it
# during the probe; this dict is just a lookup.
#
# Hashes below were computed from each product's *upstream* favicon as of
# 2026-05-23. A deployed instance may serve a re-encoded favicon (asset bundler,
# CDN, version skew) whose hash differs — when that happens, add the new hash
# next to the existing one so both sources point at the same product name.
# Empty is acceptable; http_probe simply skips the lookup.
AI_FAVICON_HASHES: dict[int, str] = {
    # Source: open-webui/open-webui   main:/static/favicon.png       21666 bytes
    1470014414:  "open-webui",
    # Source: Mintplex-Labs/anything-llm  master:/frontend/public/favicon.png  3624 bytes
    -1279687529: "anythingllm",
    # Source: langflow-ai/langflow   main:/src/frontend/public/favicon.ico   5768 bytes
    1727196746:  "langflow",
    # Source: danny-avila/LibreChat  main:/client/public/assets/favicon-32x32.png  1712 bytes
    -1529607070: "librechat",
    # Source: danny-avila/LibreChat  main:/client/public/assets/favicon-16x16.png   709 bytes
    1920842013:  "librechat",
    # Source: lobehub/lobe-chat      main:/public/favicon.ico               5210 bytes
    840913910:   "lobechat",
    # Source: langgenius/dify        main:/web/public/favicon.ico          16958 bytes
    -1483370344: "dify",
    # Source: SillyTavern/SillyTavern  release:/public/favicon.ico         15086 bytes
    358928722:   "sillytavern",
    # Source: zylon-ai/private-gpt   main:/private_gpt/ui/avatar-bot.ico   15406 bytes
    1629655701:  "privategpt",
    # Source: onyx-dot-app/onyx      main:/web/public/onyx.ico              4286 bytes
    1782891946:  "onyx",
    # Source: ztjhz/BetterChatGPT    main:/public/favicon-32x32.png         8887 bytes
    500268275:   "betterchatgpt",
    # Source: FlowiseAI/Flowise      main:/packages/ui/public/favicon-32x32.png  1887 bytes
    -993118755:  "flowise",
    # Source: FlowiseAI/Flowise      main:/packages/ui/public/favicon-16x16.png   750 bytes
    1221895556:  "flowise",
    # Source: huggingface/chat-ui    main:/static/huggingchat/logo.svg      1506 bytes
    -492944552:  "hf-chat-ui",
    # Source: streamlit/streamlit    develop:/frontend/app/public/favicon.png  1019 bytes
    1080665471:  "streamlit",

    # --- MLOps / observability frontends -----------------------------------
    # Source: invoke-ai/InvokeAI  main:/invokeai/frontend/web/public/assets/images/invoke-favicon.svg   265 bytes
    -871048477:  "invokeai",
    # Source: mlflow/mlflow      master:/mlflow/server/js/public/favicon.ico                          5430 bytes
    -1507094812: "mlflow",
    # Source: langfuse/langfuse  main:/web/public/favicon.ico                                        15086 bytes
    -1554896788: "langfuse",
    # Source: langfuse/langfuse  main:/web/public/favicon-32x32.png                                   2911 bytes
    1945774221:  "langfuse",
    # Source: Arize-ai/phoenix   main:/app/static/favicon.ico                                       34494 bytes
    -1338105374: "phoenix-arize",
    # Source: ray-project/ray    master:/python/ray/dashboard/client/public/favicon.ico              4286 bytes
    463802404:   "ray-dashboard",
    # Source: argilla-io/argilla main:/argilla-frontend/static/favicon-32x32.png                     1139 bytes
    -758513505:  "argilla",
    # Source: assafelovic/gpt-researcher  master:/frontend/static/favicon.ico                       72140 bytes
    -1416193340: "gpt-researcher",

    # --- SaaS provider login pages (catches corporate proxies, embedded chat) ---
    # Source: chat.deepseek.com favicon       7662 bytes
    -1039044905: "deepseek",
    # Source: huggingface.co favicon         47890 bytes
    -13322702:   "huggingface",
    # Source: api.together.ai favicon        15086 bytes
    -1841877931: "together",
    # Source: cohere.com favicon             15406 bytes
    491503251:   "cohere",
    # Source: smith.langchain.com favicon    15406 bytes
    940038473:   "langsmith",
    # Source: groq.com favicon               15406 bytes
    -1893709737: "groq",
    # Source: openrouter.ai favicon          15406 bytes
    -1708031290: "openrouter",
    # Source: www.perplexity.ai favicon      15086 bytes
    -1432997490: "perplexity",
    # Source: helicone.ai logo.png         173630 bytes (their wordmark used as favicon)
    -87074294:   "helicone",
}


# ---------------------------------------------------------------------------
# resource_enum  (AI_SURFACE_RECON.md §2.1 #6)
# ---------------------------------------------------------------------------

# Path regex catalogue. Matched against the URL path of every Endpoint
# produced by Katana / Hakrawler / GAU / FFuf / ParamSpider / Arjun /
# Kiterunner / jsluice. First match wins.
#
# Tuple shape: (path_regex, ai_interface_type).
# ai_interface_type ∈ {llm-chat, llm-completion, llm-embedding, llm-tool-call,
#                      sse-stream, mcp, llm-graphql, non-llm}.
#
# Ordering matters: more-specific patterns first (vendor-specific routes
# outrank generic /generate / /stream which collide with image-gen and
# server-sent-event endpoints).
AI_PATH_PATTERNS: list[tuple[Pattern[str], str]] = [
    # ── llm-chat ──────────────────────────────────────────────────────────
    # OpenAI /v1/chat/completions — also Fireworks, Together, Mistral, TGI
    # Sources: developers.openai.com/api/reference/overview, docs.fireworks.ai,
    # docs.together.ai, docs.mistral.ai/api, huggingface.co/docs/text-generation-inference/messages_api
    (re.compile(r"^/v1/chat/completions/?$", re.IGNORECASE), "llm-chat"),
    # Groq prefixes OpenAI paths with /openai. Source: console.groq.com/docs/api-reference
    (re.compile(r"^/openai/v1/chat/completions/?$", re.IGNORECASE), "llm-chat"),
    # DeepSeek omits the /v1 prefix. Source: api-docs.deepseek.com/api/create-chat-completion
    (re.compile(r"^/chat/completions/?$", re.IGNORECASE), "llm-chat"),
    # Anthropic Messages. Source: platform.claude.com/docs/en/api/messages
    (re.compile(r"^/v1/messages/?$", re.IGNORECASE), "llm-chat"),
    # OpenAI Responses API. Source: developers.openai.com/api/reference/overview
    (re.compile(r"^/v1/responses/?$", re.IGNORECASE), "llm-chat"),
    # Ollama /api/chat (also Open WebUI proxy). Source: github.com/ollama/ollama/blob/main/docs/api.md
    (re.compile(r"^/api/chat/?$", re.IGNORECASE), "llm-chat"),
    # Gemini generateContent + streamGenerateContent. Source: ai.google.dev/api/generate-content
    (re.compile(r"^/v1beta/models/[^/]+:generateContent$", re.IGNORECASE), "llm-chat"),
    (re.compile(r"^/v1beta/models/[^/]+:streamGenerateContent$", re.IGNORECASE), "llm-chat"),
    # Cohere v2 chat. Source: docs.cohere.com/reference/chat
    (re.compile(r"^/v2/chat/?$", re.IGNORECASE), "llm-chat"),
    # Perplexity Sonar. Source: docs.perplexity.ai/api-reference/chat-completions-post
    (re.compile(r"^/v1/sonar/?$", re.IGNORECASE), "llm-chat"),

    # ── llm-completion ────────────────────────────────────────────────────
    # OpenAI legacy completions + TGI. Source: developers.openai.com,
    # github.com/huggingface/text-generation-inference/blob/main/docs/openapi.json
    (re.compile(r"^/v1/completions/?$", re.IGNORECASE), "llm-completion"),
    # Mistral fill-in-middle. Source: docs.mistral.ai/api/endpoint/fim
    (re.compile(r"^/v1/fim/completions/?$", re.IGNORECASE), "llm-completion"),
    # Ollama /api/generate. Source: github.com/ollama/ollama/blob/main/docs/api.md
    (re.compile(r"^/api/generate/?$", re.IGNORECASE), "llm-completion"),
    # TGI standalone /generate (the non-stream variant). Source: TGI openapi.json
    (re.compile(r"^/generate/?$", re.IGNORECASE), "llm-completion"),
    # TGI SageMaker invoke. Source: TGI openapi.json
    (re.compile(r"^/invocations/?$", re.IGNORECASE), "llm-completion"),

    # ── llm-embedding ─────────────────────────────────────────────────────
    # OpenAI /v1/embeddings (also Voyage, Mistral, Fireworks, Together).
    # Sources: developers.openai.com, docs.voyageai.com/reference/embeddings-api
    (re.compile(r"^/v1/embeddings/?$", re.IGNORECASE), "llm-embedding"),
    # Ollama legacy. Source: github.com/ollama/ollama/blob/main/docs/api.md
    (re.compile(r"^/api/embeddings/?$", re.IGNORECASE), "llm-embedding"),
    # Ollama current. Source: same
    (re.compile(r"^/api/embed/?$", re.IGNORECASE), "llm-embedding"),
    # Cohere v2 embed. Source: docs.cohere.com/reference
    (re.compile(r"^/v2/embed/?$", re.IGNORECASE), "llm-embedding"),
    # Gemini embed (single + batch). Source: ai.google.dev/api/generate-content
    (re.compile(r"^/v1beta/models/[^/]+:embedContent$", re.IGNORECASE), "llm-embedding"),
    (re.compile(r"^/v1beta/models/[^/]+:batchEmbedContents$", re.IGNORECASE), "llm-embedding"),

    # ── llm-tool-call ─────────────────────────────────────────────────────
    # OpenAI Assistants runs + steps. Source: developers.openai.com/api/reference/overview
    (re.compile(r"^/v1/threads/[^/]+/runs/?$", re.IGNORECASE), "llm-tool-call"),
    (re.compile(r"^/v1/threads/[^/]+/runs/[^/]+/steps/?$", re.IGNORECASE), "llm-tool-call"),
    # OpenAI Responses input_items. Source: same
    (re.compile(r"^/v1/responses/[^/]+/input_items/?$", re.IGNORECASE), "llm-tool-call"),
    # MCP JSON-RPC method name appearing as path on REST-style shims.
    # Source: modelcontextprotocol.io/docs/concepts/tools
    (re.compile(r"(?:^|/)tools/call/?$", re.IGNORECASE), "llm-tool-call"),

    # ── sse-stream (path-only hint; Content-Type confirms) ────────────────
    # TGI generate_stream. Source: TGI openapi.json
    (re.compile(r"^/generate_stream/?$", re.IGNORECASE), "sse-stream"),
    # LangServe runnable streaming surfaces. Source: github.com/langchain-ai/langserve README
    (re.compile(r"(?:^|/)stream/?$", re.IGNORECASE), "sse-stream"),
    (re.compile(r"(?:^|/)stream_log/?$", re.IGNORECASE), "sse-stream"),
    (re.compile(r"(?:^|/)astream_events/?$", re.IGNORECASE), "sse-stream"),
    (re.compile(r"(?:^|/)stream_events/?$", re.IGNORECASE), "sse-stream"),

    # ── mcp (paths are implementation-defined per spec; these are the
    # widely-used conventions). Source: modelcontextprotocol.io/specification/2025-03-26/basic/transports
    (re.compile(r"^/mcp(/.*)?$", re.IGNORECASE), "mcp"),
    (re.compile(r"^/api/mcp(/.*)?$", re.IGNORECASE), "mcp"),
    (re.compile(r"^/sse/?$", re.IGNORECASE), "mcp"),
    # MCP JSON-RPC method names appearing as path on REST-style shims.
    # Source: modelcontextprotocol.io/docs/concepts/tools
    (re.compile(r"(?:^|/)tools/list/?$", re.IGNORECASE), "mcp"),
    (re.compile(r"(?:^|/)resources/list/?$", re.IGNORECASE), "mcp"),
    (re.compile(r"(?:^|/)prompts/list/?$", re.IGNORECASE), "mcp"),

    # ── llm-graphql (gated on parent-AI in the caller — too generic alone).
    # Sources: apollographql.com docs, docs.weaviate.io/weaviate/api/rest
    (re.compile(r"^/(api/)?graphql/?$", re.IGNORECASE), "llm-graphql"),
    (re.compile(r"^/v1/graphql/?$", re.IGNORECASE), "llm-graphql"),
]

# RAG ingestion / retrieval path regex. Each entry is paired with a boolean
# `requires_parent_ai`: when True, the caller must only flag is_ai_rag_ingest
# if the parent BaseURL / Service is already AI-tagged (prevents tagging
# every e-commerce search bar as a RAG endpoint).
AI_RAG_PATH_PATTERNS: list[tuple[Pattern[str], bool]] = [
    # ── Unambiguous vendor-specific RAG paths ─────────────────────────────
    # OpenAI Files / Uploads / Vector Stores / Assistants.
    # Source: developers.openai.com/api/reference/overview
    (re.compile(r"^/v1/files/?$", re.IGNORECASE), False),
    (re.compile(r"^/v1/uploads/?$", re.IGNORECASE), False),
    (re.compile(r"^/v1/vector_stores(/[^/]+(/files|/search)?)?/?$", re.IGNORECASE), False),
    (re.compile(r"^/v1/assistants/?$", re.IGNORECASE), False),
    (re.compile(r"^/v1/threads/?$", re.IGNORECASE), False),
    (re.compile(r"^/v1/threads/[^/]+/messages/?$", re.IGNORECASE), False),

    # Pinecone upsert + query.
    # Source: docs.pinecone.io/reference/api/2024-10/data-plane/{upsert,query}
    (re.compile(r"^/vectors/upsert/?$", re.IGNORECASE), False),

    # Weaviate object writes.
    # Source: docs.weaviate.io/weaviate/api/rest
    (re.compile(r"^/v1/objects/?$", re.IGNORECASE), False),
    (re.compile(r"^/v1/batch/objects/?$", re.IGNORECASE), False),

    # Qdrant points (collection-scoped).
    # Source: qdrant.tech/documentation/concepts/points
    (re.compile(r"^/collections/[^/]+/points(/(search|query))?/?$", re.IGNORECASE), False),

    # ── Ambiguous paths — only flag when parent host is AI-tagged ─────────
    # Sources: generic — most webapps name an endpoint /search or /upload.
    # The parent_is_ai gate prevents tagging every e-commerce search bar.
    (re.compile(r"^/(upload|files?)/?$", re.IGNORECASE), True),
    (re.compile(r"^/(search|query|q)/?$", re.IGNORECASE), True),
    (re.compile(r"^/(index|embed|embeddings)/?$", re.IGNORECASE), True),
    (re.compile(r"^/(retrieve|lookup|knn|rag|vectorize|similarity[-_]?search)/?$", re.IGNORECASE), True),
    (re.compile(r"^/(documents?|docs?)/?$", re.IGNORECASE), True),
]

# Parameter names that, on an AI-classified endpoint, indicate user-controlled
# text flowing to an LLM. Matched case-insensitively against the parameter
# name. The caller must require the parent Endpoint to be AI-classified
# before tagging (otherwise a parameter named "text" on a contact form would
# be flagged as prompt-injectable, which is meaningless).
AI_PARAM_NAMES: set[str] = {
    # ── Confirmed cited names ─────────────────────────────────────────────
    # OpenAI / Anthropic / Ollama / Cohere / Mistral / TGI chat request body.
    # Sources per name: developers.openai.com, platform.claude.com/docs/en/api/messages,
    # github.com/ollama/ollama/blob/main/docs/api.md, docs.cohere.com/reference/chat,
    # docs.mistral.ai/api, huggingface.co/docs/text-generation-inference/messages_api
    "messages",
    "prompt",
    "system",
    "input",
    "instructions",

    # Gemini request body.
    # Source: ai.google.dev/api/generate-content (`contents`, `systemInstruction`)
    "contents",
    "systeminstruction",  # matched lowercase against incoming lowered name

    # HuggingFace Inference text-generation.
    # Source: huggingface.co/docs/inference-providers/tasks/text-generation
    "inputs",

    # Ollama /api/generate suffix; Mistral FIM suffix.
    # Sources: github.com/ollama/ollama/blob/main/docs/api.md, docs.mistral.ai/api/endpoint/fim
    "suffix",

    # Tool-array field on every modern chat API (OpenAI, Anthropic, Gemini,
    # Ollama, Cohere, Mistral, TGI — universal naming).
    "tools",

    # MCP tools/call params.arguments. Source: modelcontextprotocol.io/docs/concepts/tools
    "arguments",

    # ── Soft-match names (parent endpoint AI-classified guard already gates
    # these, so they only fire on a known chat / RAG endpoint). Used by
    # LangServe playground inputs and generic chat clones without a single
    # vendor cite.
    "message",
    "instruction",
    "query",
    "question",
    "text",
    "query_text",
    "search_query",
    "content",
    "q",
    # Tool argument carriers used by LangChain / generic tool-call wrappers.
    "tool_input",
    "tool_arguments",
    "function_args",
}

# Tool-schema dialects. JSON Pointer prefix where each tool's argument
# properties live. Used by the resolver below — the resolver itself is
# Phase-15-deferred (no-op until ai_surface_recon discovers an OpenAPI /
# ai-plugin.json / MCP tools-list spec), but the catalogue ships now so the
# resolver contract is stable across laps.
AI_TOOL_ARG_PATH_DIALECTS: list[tuple[str, str]] = [
    ("openai-functions",  "/parameters/properties"),
    ("anthropic-tools",   "/input_schema/properties"),
    ("gemini-functions",  "/parameters/properties"),
    ("mcp-tools-list",    "/inputSchema/properties"),
    ("langchain-tool",    "/properties"),
]


# ---------------------------------------------------------------------------
# Forward-declared stubs (filled by later integration laps)
# ---------------------------------------------------------------------------
# These constants are imported by their host modules as soon as the relevant
# lap lands. Leaving them present-but-empty keeps the import path stable so
# adding a new lap is a content-only change, never a structural one.

# js_recon — AI SDK import regex
AI_SDK_IMPORT_REGEX: list[tuple[Pattern[str], str, str]] = []

# subdomain_takeover — AI provider CNAMEs
AI_TAKEOVER_PROVIDERS: dict[str, str] = {}

# vhost_sni_enum — AI vhost wordlist additions
AI_VHOST_WORDLIST: list[str] = []

# vuln_scan / cve_helpers — AI library names for CVE lookup
AI_CVE_LIBRARIES: list[str] = []

# add_mitre — keyword → MITRE ATLAS technique IDs
AI_ATLAS_MAPPING: dict[str, list[str]] = {}

# OSINT enrichments — provider-specific query strings
AI_SHODAN_QUERIES: list[str] = []
AI_CENSYS_QUERIES: list[str] = []
AI_FOFA_QUERIES: list[str] = []
AI_ZOOMEYE_QUERIES: list[str] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def match_ai_txt_hint(record_value: str) -> str | None:
    """Return the provider name if the TXT record value matches a known AI vendor.

    Used by domain_recon's AI TXT hint hook. Returns the first match (patterns
    are ordered by strength) or None if no AI signal is present.
    """
    if not record_value:
        return None
    for pattern, hint in AI_TXT_PATTERNS:
        if pattern.search(record_value):
            return hint
    return None


def match_ai_ns_hint(record_value: str) -> str | None:
    """Return the provider hint if the NS record matches a known AI-hosting platform.

    Always the weakest signal. The caller must only apply this hint when no
    stronger TXT-derived hint has already been recorded for the host.
    """
    if not record_value:
        return None
    for pattern, hint in AI_NS_HINT_PATTERNS:
        if pattern.search(record_value):
            return hint
    return None


def lookup_ai_port(port: int) -> dict[str, str | bool] | None:
    """Return the AI service descriptor for a port, or None.

    The descriptor carries ``name``, ``category``, and optionally
    ``disambiguate``. When ``disambiguate`` is True, the port is shared between
    AI and non-AI services and the caller must require a corroborating signal
    (matching header / title from http_probe) before promoting the annotation
    to a Technology graph node.
    """
    return AI_PORTS.get(port)


def match_ai_header(header_name: str) -> tuple[str, str] | None:
    """Return (framework_name, technology_category) on first matching header pattern.

    Matched against the header *name* only. Header values are not inspected
    here — that responsibility belongs to the central ai_surface_recon module
    in phase 15.
    """
    if not header_name:
        return None
    for pattern, framework, category in AI_HEADER_PATTERNS:
        if pattern.search(header_name):
            return framework, category
    return None


def match_ai_title(title: str) -> str | None:
    """Return the AI frontend product name if the page title matches."""
    if not title:
        return None
    for pattern, product in AI_TITLE_PATTERNS:
        if pattern.search(title):
            return product
    return None


def match_ai_nmap_version(product_or_version: str) -> str | None:
    """Return the AI runtime name if the nmap product/version string matches."""
    if not product_or_version:
        return None
    for pattern, runtime in AI_NMAP_VERSION_PATTERNS:
        if pattern.search(product_or_version):
            return runtime
    return None


def match_ai_body_fingerprint(body: str) -> tuple[str, str] | None:
    """Return (framework_name, technology_category) on the first body match.

    Scans against `AI_BODY_FINGERPRINTS` — the Wappalyzer-style catalogue
    of regexes that match AI-product signatures embedded in the response
    body (HTML markup, shipped JS, form actions). Returns None if no entry
    matches. Bodies larger than a few hundred KB should be capped by the
    caller before invoking this helper.
    """
    if not body:
        return None
    for pattern, framework, category in AI_BODY_FINGERPRINTS:
        if pattern.search(body):
            return framework, category
    return None


# ---------------------------------------------------------------------------
# resource_enum helpers
# ---------------------------------------------------------------------------

def match_ai_path(path: str) -> str | None:
    """Return the ``ai_interface_type`` enum value if the URL path matches
    a known LLM-shape route, else ``None``.

    Iterates ``AI_PATH_PATTERNS`` in catalogue order (vendor-specific first,
    generic fallbacks last). Matches on the path component only — query string
    must be stripped by the caller. Case-insensitive.

    Uses ``re.search`` (not ``re.match``) so patterns anchored with
    ``(?:^|/)`` correctly fire on suffix positions (e.g. LangServe's
    ``/agents/foo/stream``). Most patterns are explicitly anchored with
    ``^``, so search-vs-match makes no behavioural difference there.

    The returned value is one of: ``llm-chat``, ``llm-completion``,
    ``llm-embedding``, ``llm-tool-call``, ``sse-stream``, ``mcp``,
    ``llm-graphql``. Callers that want the explicit ``non-llm`` sentinel
    must substitute it themselves when this helper returns ``None``.
    """
    if not path:
        return None
    for pattern, interface_type in AI_PATH_PATTERNS:
        if pattern.search(path):
            return interface_type
    return None


def is_ai_rag_path(path: str, parent_is_ai: bool = False) -> bool:
    """True if the URL path looks like a RAG ingestion or retrieval endpoint.

    Some patterns (``/upload``, ``/search``, ``/query``) are too generic to
    flag standalone — they collide with file-upload and search bars on every
    e-commerce site. Those patterns carry an ``ambiguous=True`` flag in the
    catalogue and only fire when ``parent_is_ai`` is True (i.e. the parent
    BaseURL or Service is already AI-tagged via another signal channel).

    Unambiguous patterns (``/v1/vector_stores``, ``/vectors/upsert``,
    ``/collections/<name>/points``) fire regardless of ``parent_is_ai``.
    """
    if not path:
        return False
    for pattern, requires_parent_ai in AI_RAG_PATH_PATTERNS:
        if pattern.search(path):
            if requires_parent_ai and not parent_is_ai:
                continue
            return True
    return False


def is_ai_prompt_param(name: str) -> bool:
    """True if a parameter name is a known prompt-injection vector.

    Matches case-insensitively against ``AI_PARAM_NAMES``. The caller is
    expected to gate this check on the parent Endpoint already being
    AI-classified (``ai_interface_type IS NOT NULL`` and != ``non-llm``);
    a parameter named ``text`` on a contact form is not prompt-injectable
    in any meaningful sense.
    """
    if not name:
        return False
    return name.strip().lower() in AI_PARAM_NAMES


def resolve_ai_tool_arg_path(spec: dict, dialect: str, param_name: str) -> str | None:
    """Return a JSON Pointer to ``param_name`` inside the tool-schema ``spec``.

    Walks the spec using the JSON Pointer prefix registered in
    ``AI_TOOL_ARG_PATH_DIALECTS`` for the named dialect. Returns the
    full pointer (e.g. ``/parameters/properties/query``) on success, or
    ``None`` if the dialect is unknown, the spec doesn't contain the
    expected shape, or the parameter is not in the schema.

    This is a placeholder for the Phase-15 ai_surface_recon module — the
    spec is only populated once that module discovers an OpenAPI /
    ai-plugin.json / MCP tools/list document. Until then the resolver is
    effectively a no-op (no spec, no resolution).
    """
    if not spec or not dialect or not param_name:
        return None
    prefix = next((p for d, p in AI_TOOL_ARG_PATH_DIALECTS if d == dialect), None)
    if prefix is None:
        return None
    # Walk the spec by the prefix components and verify the parameter is
    # in the resulting properties dict.
    cursor: dict | None = spec
    for segment in prefix.strip("/").split("/"):
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    if not isinstance(cursor, dict) or param_name not in cursor:
        return None
    return f"{prefix}/{param_name}"
