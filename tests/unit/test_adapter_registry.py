import pytest

from kaleidoscan import adapters
from kaleidoscan.types import ScannerInfo

pytestmark = pytest.mark.unit

EXPECTED = {"flowscope", "semgrep", "bandit", "gosec", "flawfinder", "bearer", "codeql",
            "binary-analysis", "llm-agent-review", "gitleaks", "osv-scanner"}


def test_all_baseline_scanners_registered():
    assert EXPECTED <= set(adapters.registry())


@pytest.mark.parametrize("sid", sorted(EXPECTED))
def test_each_adapter_satisfies_contract(sid):
    a = adapters.get(sid)
    assert isinstance(a.info, ScannerInfo) and a.info.id == sid
    assert callable(a.detect) and callable(a.applicable) and callable(a.run)
    ok, _ = a.detect()
    assert isinstance(ok, bool)


def test_only_codeql_is_restricted():
    assert {i for i in EXPECTED if adapters.get(i).info.restricted} == {"codeql"}
