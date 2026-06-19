"""Shared spine piece 1 — the target loader (§6.1).

Reads the AI surface that recon annotated and renders the §2 selectors. Each
tool declares its `applies_to` interface-type filter; the loader applies it. No
tool reimplements node selection.

The request shape comes from recon automatically (§2.3): each Endpoint already
carries ai_interface_type / ai_model_family_guess / ai_supports_* so the attack
tools are pre-configured from the graph.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger("ai-attack-surface")


# Attack-type -> applicable Endpoint.ai_interface_type values (§2.1).
INTERFACE_FILTERS: dict[str, list[str]] = {
    "llm-chat": ["llm-chat"],
    "llm-chat-completion": ["llm-chat", "llm-completion"],
    "llm-tool-call": ["llm-tool-call"],
    "mcp": ["mcp"],
}


@dataclass
class Target:
    """A selected attack target, enriched from recon annotations."""
    baseurl: str
    path: str
    method: str = "POST"
    ai_interface_type: str | None = None
    ai_model_family_guess: str | None = None
    ai_model_ids: list | None = None
    ai_supports_tools: bool | None = None
    ai_supports_streaming: bool | None = None

    @property
    def url(self) -> str:
        base = (self.baseurl or "").rstrip("/")
        path = self.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"


_RETURN = """
    e.baseurl AS baseurl, e.path AS path,
    coalesce(e.method, 'POST') AS method,
    e.ai_interface_type AS ai_interface_type,
    e.ai_model_family_guess AS ai_model_family_guess,
    e.ai_model_ids AS ai_model_ids,
    e.ai_supports_tools AS ai_supports_tools,
    e.ai_supports_streaming AS ai_supports_streaming
"""


def _row_to_target(row) -> Target:
    return Target(
        baseurl=row.get("baseurl") or "",
        path=row.get("path") or "/",
        method=row.get("method") or "POST",
        ai_interface_type=row.get("ai_interface_type"),
        ai_model_family_guess=row.get("ai_model_family_guess"),
        ai_model_ids=row.get("ai_model_ids"),
        ai_supports_tools=row.get("ai_supports_tools"),
        ai_supports_streaming=row.get("ai_supports_streaming"),
    )


def load_targets(
    session,
    user_id: str,
    project_id: str,
    interface_types: list[str] | None = None,
    selected: list[dict] | None = None,
) -> list[Target]:
    """Load attack targets from the graph.

    - `selected`: explicit picker rows ({baseurl, path, method}); each is matched
      to its Endpoint and enriched. This is the normal UI path (the user must
      explicitly select which nodes to attack, §2).
    - else: load every Endpoint carrying an `ai_interface_type` (optionally
      narrowed to `interface_types`). Convenience for headless/skeleton runs.
    """
    if selected:
        return _load_selected(session, user_id, project_id, selected)
    return _load_all_ai(session, user_id, project_id, interface_types)


def _load_all_ai(session, user_id, project_id, interface_types) -> list[Target]:
    cypher = f"""
        MATCH (e:Endpoint {{user_id: $uid, project_id: $pid}})
        WHERE e.ai_interface_type IS NOT NULL
          AND ($ifaces IS NULL OR e.ai_interface_type IN $ifaces)
        RETURN {_RETURN}
    """
    rows = session.run(cypher, uid=user_id, pid=project_id, ifaces=interface_types)
    targets = [_row_to_target(r.data()) for r in rows]
    logger.info(
        f"Target loader: {len(targets)} AI endpoint(s) "
        f"(filter={interface_types or 'any ai_interface_type'})"
    )
    return targets


def _load_selected(session, user_id, project_id, selected) -> list[Target]:
    targets: list[Target] = []
    for sel in selected:
        baseurl = sel.get("baseurl")
        path = sel.get("path") or "/"
        method = sel.get("method")
        if not baseurl:
            logger.warning(f"Skipping selection without baseurl: {sel}")
            continue
        cypher = f"""
            MATCH (e:Endpoint {{baseurl: $baseurl, user_id: $uid, project_id: $pid}})
            WHERE e.path = $path AND ($method IS NULL OR coalesce(e.method,'POST') = $method)
            // Prefer the AI-typed endpoint over a bare sibling on the same path.
            WITH e ORDER BY (CASE WHEN e.ai_interface_type IS NOT NULL THEN 0 ELSE 1 END) LIMIT 1
            RETURN {_RETURN}
        """
        row = session.run(
            cypher, baseurl=baseurl, path=path, method=method,
            uid=user_id, pid=project_id,
        ).single()
        if row:
            targets.append(_row_to_target(row.data()))
        else:
            # The picker selected something that isn't in the graph; surface a
            # placeholder target from the raw selection so the run is honest
            # about what was requested vs found.
            logger.warning(f"Selected endpoint not found in graph: {baseurl} {path}")
            targets.append(Target(baseurl=baseurl, path=path, method=method or "POST"))
    logger.info(f"Target loader: {len(targets)} selected endpoint(s)")
    return targets
