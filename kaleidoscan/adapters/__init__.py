"""Built-in adapter registry (C1). Adding a scanner = one module + one line here."""
from __future__ import annotations

from importlib.metadata import entry_points

from kaleidoscan.adapters.agent_ingest import AgentIngestAdapter
from kaleidoscan.adapters.bandit import BanditAdapter
from kaleidoscan.adapters.bearer import BearerAdapter
from kaleidoscan.adapters.binary_ingest import BinaryIngestAdapter
from kaleidoscan.adapters.codeql import CodeqlAdapter
from kaleidoscan.adapters.flawfinder import FlawfinderAdapter
from kaleidoscan.adapters.flowscope import FlowscopeAdapter
from kaleidoscan.adapters.gosec import GosecAdapter
from kaleidoscan.adapters.semgrep import SemgrepAdapter

BUILTIN = {a.info.id: a for a in (
    FlowscopeAdapter, SemgrepAdapter, BanditAdapter, GosecAdapter, FlawfinderAdapter,
    BearerAdapter, CodeqlAdapter, BinaryIngestAdapter, AgentIngestAdapter)}


def registry() -> dict[str, type]:
    """Built-ins plus third-party adapters from the `kaleidoscan.adapters` entry-point group."""
    reg = dict(BUILTIN)
    for ep in entry_points(group="kaleidoscan.adapters"):
        reg.setdefault(ep.name, ep.load())
    return reg


def get(scanner_id: str, **kw):
    try:
        return registry()[scanner_id](**kw)
    except KeyError:
        raise KeyError(f"unknown scanner {scanner_id!r}; known: {sorted(registry())}") from None
