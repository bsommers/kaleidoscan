import pytest

from kaleidoscan.severity import map_severity

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("score,sev", [
    (10, "critical"), (9.0, "critical"), (8.99, "high"), (7.0, "high"), (6.99, "medium"),
    (4.0, "medium"), (3.99, "low"), (0.1, "low"), ("9.8", "critical"),
])
def test_security_severity_thresholds(score, sev):
    assert map_severity("x", "note", score)[0] == sev


@pytest.mark.parametrize("bad", [0, 0.0, -1, 11, "abc", True, None])
def test_security_severity_zero_or_invalid_falls_back(bad):
    assert map_severity("x", "warning", bad) == ("medium", "medium")


@pytest.mark.parametrize("level,sev", [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")])
def test_sarif_levels(level, sev):
    assert map_severity("other", level)[0] == sev


@pytest.mark.parametrize("native,sev", [("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low")])
def test_bandit_native(native, sev):
    assert map_severity("bandit", None, None, native) == (sev, "high")


@pytest.mark.parametrize("lvl,sev", [("ERROR", "high"), ("WARNING", "medium"), ("INFO", "low")])
def test_semgrep_native(lvl, sev):
    assert map_severity("semgrep", lvl)[0] == sev


def test_unknown_is_medium_unknown_never_low():
    assert map_severity("x") == ("medium", "unknown")
    assert map_severity("x", "bogus") == ("medium", "unknown")
    assert map_severity("bandit", None, None, "WEIRD") == ("medium", "unknown")


def test_security_severity_beats_level():
    assert map_severity("semgrep", "note", 9.5)[0] == "critical"
