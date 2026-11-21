"""Built-in adapter registry (C1). Adding a scanner = one module + one line here."""
from __future__ import annotations

from importlib.metadata import entry_points

from kaleidoscan.adapters.flowscope import FlowscopeAdapter

BUILTIN = {"flowscope": FlowscopeAdapter}


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
