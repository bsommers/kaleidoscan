"""T-DYN config part: `dynamic:` is reserved."""
import pytest

from kaleidoscan.config import ConfigError, Pipeline, parse_config

pytestmark = pytest.mark.unit
BASE = {"version": 1, "target": {"path": "."}, "scanners": []}


def test_field_reserved_default_none(tmp_path):
    assert "dynamic" in Pipeline.model_fields
    assert parse_config(BASE, base_dir=tmp_path).dynamic is None


@pytest.mark.parametrize("v", [{}, {"tool": "zap"}, "zap", True, 0, []])
def test_any_non_null_dynamic_errors(tmp_path, v):
    with pytest.raises(ConfigError, match="dynamic testing not implemented"):
        parse_config({**BASE, "dynamic": v}, base_dir=tmp_path)
