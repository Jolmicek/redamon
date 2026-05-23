"""
AI Surface Recon — Guinea Pig HTTP target.

Listens on every port + path the lap-1 catalog cares about, returns
deterministic responses that fire each detection. No LLM, no model
weights, no GPU — just a Python aiohttp process producing surface signals.

Layout:
    16 per-port listeners (one aiohttp app per AI product port)
    +  1 header showroom on port 9100 (20 framework variants)
    +  1 title  showroom on port 9101 (18 product variants)
    = 18 ports bound to 0.0.0.0

The recon container reaches this via `network_mode: host` → 127.0.0.1:*.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys

from aiohttp import web

from ai_signals import (
    HEADER_SHOWROOM_PORT,
    HEADER_VARIANTS,
    PORT_LISTENERS,
    TITLE_SHOWROOM_PORT,
    TITLE_VARIANTS,
)


# ---------------------------------------------------------------------------
# Logging — concise, single-line per request
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("guinea-pig")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _html(title: str, body: str = "") -> str:
    return (
        "<!DOCTYPE html><html><head>"
        f"<title>{title}</title>"
        "<meta charset='utf-8'></head><body>"
        f"<h1>{title}</h1><pre>{body}</pre>"
        "<p>RedAmon AI surface guinea pig — deterministic stub.</p>"
        "</body></html>"
    )


def _empty_favicon() -> web.Response:
    # Tiny PNG-style placeholder so httpx -favicon doesn't 404.
    # Hash is irrelevant for lap-1 (catalog is empty); Phase 15 will use a
    # known mmh3 hash here.
    return web.Response(body=b"\x00", content_type="image/x-icon")


# ---------------------------------------------------------------------------
# Per-product port handler factory
# ---------------------------------------------------------------------------

def make_port_app(descriptor: dict) -> web.Application:
    app = web.Application()
    app["descriptor"] = descriptor

    @web.middleware
    async def server_header_mw(request: web.Request, handler) -> web.Response:
        response = await handler(request)
        response.headers["Server"] = descriptor.get("server_header", "ai-test-target")
        return response

    app.middlewares.append(server_header_mw)

    async def root(request: web.Request) -> web.Response:
        body = (
            f"product       = {descriptor['name']}\n"
            f"port          = {descriptor['port']}\n"
            f"server_banner = {descriptor.get('server_header', '')}\n"
        )
        return web.Response(
            text=_html(descriptor.get("html_title", descriptor["name"]), body),
            content_type="text/html",
        )

    async def favicon(_request: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_request: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", root)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Header showroom (port 9100) — emit AI headers per /header/<framework>
# ---------------------------------------------------------------------------

def make_header_showroom_app() -> web.Application:
    app = web.Application()

    async def index(_request: web.Request) -> web.Response:
        links = "\n".join(
            f"  <li><a href='/header/{k}'>/header/{k}</a> &mdash; "
            f"{', '.join(v['headers'].keys())} → {v['expected_framework']}/{v['expected_category']}</li>"
            for k, v in HEADER_VARIANTS.items()
        )
        body = _html(
            "AI Header Showroom",
            f"GET /header/&lt;framework&gt; returns response carrying that AI header.\n\n<ul>\n{links}\n</ul>",
        )
        return web.Response(text=body, content_type="text/html")

    async def emit(request: web.Request) -> web.Response:
        framework = request.match_info["framework"]
        info = HEADER_VARIANTS.get(framework)
        if not info:
            return web.Response(
                text=f"unknown framework: {framework}",
                status=404,
                content_type="text/plain",
            )
        body = _html(
            f"AI Header: {framework}",
            "\n".join(f"{k}: {v}" for k, v in info["headers"].items()),
        )
        response = web.Response(text=body, content_type="text/html")
        for h_name, h_value in info["headers"].items():
            response.headers[h_name] = h_value
        response.headers["Server"] = "ai-test-target/header-showroom"
        return response

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/header/{framework}", emit)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Title showroom (port 9101) — emit AI titles per /title/<product>
# ---------------------------------------------------------------------------

def make_title_showroom_app() -> web.Application:
    app = web.Application()

    async def index(_request: web.Request) -> web.Response:
        links = "\n".join(
            f"  <li><a href='/title/{k}'>/title/{k}</a> &mdash; "
            f"&lt;title&gt;{v['title']}&lt;/title&gt; → {v['expected_product']}</li>"
            for k, v in TITLE_VARIANTS.items()
        )
        body = _html(
            "AI Title Showroom",
            f"GET /title/&lt;product&gt; returns HTML with the matching &lt;title&gt;.\n\n<ul>\n{links}\n</ul>",
        )
        return web.Response(text=body, content_type="text/html")

    async def emit(request: web.Request) -> web.Response:
        product = request.match_info["product"]
        info = TITLE_VARIANTS.get(product)
        if not info:
            return web.Response(
                text=f"unknown product: {product}",
                status=404,
                content_type="text/plain",
            )
        body = _html(info["title"], f"product = {product}")
        response = web.Response(text=body, content_type="text/html")
        response.headers["Server"] = "ai-test-target/title-showroom"
        return response

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/title/{product}", emit)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def _start_site(app: web.Application, port: int, label: str) -> web.AppRunner:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info(f"+ listening :{port:<5d}  {label}")
    return runner


async def main() -> None:
    runners: list[web.AppRunner] = []

    log.info("=" * 60)
    log.info("RedAmon AI surface guinea pig starting")
    log.info("=" * 60)

    # 1. Per-product ports
    for descriptor in PORT_LISTENERS:
        app = make_port_app(descriptor)
        runner = await _start_site(
            app,
            descriptor["port"],
            f"{descriptor['name']:<22s}  banner={descriptor.get('server_header', '')!r}",
        )
        runners.append(runner)

    # 2. Header showroom
    runners.append(
        await _start_site(
            make_header_showroom_app(),
            HEADER_SHOWROOM_PORT,
            f"header showroom — {len(HEADER_VARIANTS)} variants on /header/<framework>",
        )
    )

    # 3. Title showroom
    runners.append(
        await _start_site(
            make_title_showroom_app(),
            TITLE_SHOWROOM_PORT,
            f"title  showroom — {len(TITLE_VARIANTS)} variants on /title/<product>",
        )
    )

    log.info("=" * 60)
    log.info(f"Ready. {len(runners)} ports bound. Ctrl-C / SIGTERM to stop.")
    log.info("=" * 60)

    # Block until cancelled / signal
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            # No signal support (e.g. on Windows) — fall back to forever loop
            pass
    await stop.wait()

    log.info("Shutting down…")
    for runner in runners:
        await runner.cleanup()
    log.info("Bye.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
