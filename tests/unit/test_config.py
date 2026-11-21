"""T-CFG and T-DYN (config part): C4 pipeline definition."""
from __future__ import annotations

from pathlib import Path

import pytest

from kaleidoscan.config import (
    PROFILES, ConfigError, Pipeline, load_config, parse_config,
)

pytestmark = pytest.mark.unit

MINIMAL = "version: 1\ntarget: {path: .}\nscanners:\n  - {id: flowscope}\n"


def write(tmp_path: Path, text: str, name: str = "kaleidoscan.yaml") -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def test_valid_minimal_with_defaults(tmp_path):
    (tmp_path / "src").mkdir()
    cfg = load_config(write(tmp_path, MINIMAL))
    assert isinstance(cfg, Pipeline)
    assert cfg.version == 1 and cfg.name == "default"
    assert cfg.scanners[0].id == "flowscope" and cfg.scanners[0].enabled is True
    assert cfg.dynamic is None
    assert cfg.limits.timeout_s == 600 and cfg.limits.max_output_mb == 64 and cfg.limits.max_parallel == 4
    assert cfg.policy.fail_on.severity_at_least == "high"
    assert cfg.reports == ["sarif", "html", "markdown", "junit", "json"]


def test_full_c4_example_loads(tmp_path):
    (tmp_path / "rules").mkdir()
    cfg = load_config(write(tmp_path, """
version: 1
name: default
target: {path: ".", exclude: ["**/node_modules/**", "**/.venv/**"]}
scanners:
  - {id: flowscope, enabled: true}
  - {id: semgrep, enabled: true, config: {rules: ["p/ci"], offline_rules: "./rules"}}
  - {id: bandit, enabled: true}
  - {id: gitleaks, enabled: true}
dynamic: null
policy:
  fail_on: {severity_at_least: high, new_only: true, baseline: "baseline.sarif"}
  require_scanners: [flowscope]
  suppressions: "./.kaleidoscan-ignore.yaml"
reports: [sarif, html, markdown, junit, json]
limits: {timeout_s: 600, max_output_mb: 64, max_parallel: 4}
"""))
    assert [s.id for s in cfg.scanners] == ["flowscope", "semgrep", "bandit", "gitleaks"]
    assert cfg.scanners[1].config["rules"] == ["p/ci"]
    assert cfg.policy.fail_on.new_only is True
    assert cfg.policy.require_scanners == ["flowscope"]


@pytest.mark.parametrize("text", [
    MINIMAL + "bogus: 1\n",                                              # top level
    "version: 1\ntarget: {path: ., extra: 1}\nscanners: []\n",           # target
    "version: 1\ntarget: {path: .}\nscanners: [{id: bandit, nope: 1}]\n",  # scanner
    "version: 1\ntarget: {path: .}\nscanners: []\nlimits: {x: 1}\n",     # limits
    "version: 1\ntarget: {path: .}\nscanners: []\npolicy: {y: 1}\n",     # policy
    "version: 1\ntarget: {path: .}\nscanners: []\npolicy: {fail_on: {z: 1}}\n",
])
def test_unknown_key_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


@pytest.mark.parametrize("val", ["{}", "true", "{tool: zap}", "zap", "[]", "0"])
def test_dynamic_set_is_not_implemented_error(tmp_path, val):
    with pytest.raises(ConfigError, match="dynamic testing not implemented"):
        load_config(write(tmp_path, MINIMAL + f"dynamic: {val}\n"))


def test_dynamic_null_and_absent_ok(tmp_path):
    assert load_config(write(tmp_path, MINIMAL + "dynamic: null\n")).dynamic is None
    assert load_config(write(tmp_path, MINIMAL, "b.yaml")).dynamic is None


@pytest.mark.parametrize("sev", ["HIGH", "severe", "", "none ", 5])
def test_bad_severity_rejected(tmp_path, sev):
    t = f"{MINIMAL}policy: {{fail_on: {{severity_at_least: {sev!r}}}}}\n"
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, t))


@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low", "info"])
def test_good_severities(tmp_path, sev):
    cfg = load_config(write(tmp_path, f"{MINIMAL}policy: {{fail_on: {{severity_at_least: {sev}}}}}\n"))
    assert cfg.policy.fail_on.severity_at_least == sev


def test_missing_target_rejected(tmp_path):
    with pytest.raises(ConfigError, match="target"):
        load_config(write(tmp_path, "version: 1\nscanners: []\n"))
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, "version: 1\ntarget: {}\nscanners: []\n"))


def test_missing_scanners_rejected(tmp_path):
    with pytest.raises(ConfigError, match="scanners"):
        load_config(write(tmp_path, "version: 1\ntarget: {path: .}\n"))


@pytest.mark.parametrize("text", ["", "- a\n- b\n", "just a string", "version: [1\n"])
def test_non_mapping_or_bad_yaml(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


@pytest.mark.parametrize("v", ["2", "0", "'1'", "one"])
def test_bad_version(tmp_path, v):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, MINIMAL.replace("version: 1", f"version: {v}")))


def test_duplicate_scanner_ids_rejected(tmp_path):
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(write(tmp_path, "version: 1\ntarget: {path: .}\nscanners: [{id: bandit}, {id: bandit}]\n"))


def test_unknown_scanner_id_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown scanner"):
        load_config(write(tmp_path, "version: 1\ntarget: {path: .}\nscanners: [{id: nosuch}]\n"))


def test_require_scanners_must_be_enabled_scanners(tmp_path):
    t = MINIMAL + "policy: {require_scanners: [bandit]}\n"
    with pytest.raises(ConfigError, match="require_scanners"):
        load_config(write(tmp_path, t))
    t2 = "version: 1\ntarget: {path: .}\nscanners: [{id: bandit, enabled: false}]\npolicy: {require_scanners: [bandit]}\n"
    with pytest.raises(ConfigError, match="require_scanners"):
        load_config(write(tmp_path, t2))


@pytest.mark.parametrize("limits", [
    "timeout_s: 0", "timeout_s: -1", "max_output_mb: 0", "max_parallel: 0",
    "max_parallel: 1000", "timeout_s: 1.5", "timeout_s: abc",
])
def test_limits_bounds(tmp_path, limits):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, f"{MINIMAL}limits: {{{limits}}}\n"))


def test_bad_report_format_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, MINIMAL + "reports: [pdf]\n"))


def test_relative_paths_resolved_against_config_dir(tmp_path, monkeypatch):
    sub = tmp_path / "proj" / "conf"
    sub.mkdir(parents=True)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    p = write(sub, """
version: 1
target: {path: ../src}
scanners: [{id: semgrep, config: {offline_rules: ./rules}}]
policy:
  fail_on: {baseline: baseline.sarif}
  suppressions: ./.kaleidoscan-ignore.yaml
""")
    cfg = load_config(p)
    assert cfg.target.path == (tmp_path / "proj" / "src")
    assert cfg.target.path.is_absolute()
    assert cfg.policy.fail_on.baseline == sub.resolve() / "baseline.sarif"
    assert cfg.policy.suppressions == sub.resolve() / ".kaleidoscan-ignore.yaml"
    assert cfg.scanners[0].config["offline_rules"] == str(sub.resolve() / "rules")


def test_absolute_paths_kept(tmp_path):
    cfg = load_config(write(tmp_path, f"version: 1\ntarget: {{path: {tmp_path}}}\nscanners: []\n"))
    assert cfg.target.path == tmp_path.resolve()


def test_exclude_globs_not_path_resolved(tmp_path):
    cfg = load_config(write(tmp_path, "version: 1\ntarget: {path: ., exclude: ['**/x/**']}\nscanners: []\n"))
    assert cfg.target.exclude == ["**/x/**"]


def test_parse_config_dict_uses_base_dir(tmp_path):
    cfg = parse_config({"version": 1, "target": {"path": "a"}, "scanners": []}, base_dir=tmp_path)
    assert cfg.target.path == tmp_path.resolve() / "a"


def test_pipeline_hash_stable_and_sensitive(tmp_path):
    a = load_config(write(tmp_path, MINIMAL))
    b = load_config(write(tmp_path, MINIMAL, "b.yaml"))
    assert a.hash() == b.hash() and len(a.hash()) == 12
    c = load_config(write(tmp_path, MINIMAL + "limits: {timeout_s: 5}\n", "c.yaml"))
    assert c.hash() != a.hash()
    assert a.pipeline_id() == f"default@{a.hash()}"


# ---- profiles ----
def test_profile_names():
    assert set(PROFILES) == {"fast", "full", "ci"}


FULL = """
version: 1
target: {path: .}
scanners:
  - {id: flowscope}
  - {id: semgrep}
  - {id: bandit}
  - {id: gitleaks}
  - {id: trivy}
policy: {require_scanners: [flowscope]}
"""


def test_profile_none_leaves_config(tmp_path):
    cfg = load_config(write(tmp_path, FULL))
    assert all(s.enabled for s in cfg.scanners)
    assert cfg.limits.timeout_s == 600


def test_profile_fast_restricts_scanners_and_timeout(tmp_path):
    cfg = load_config(write(tmp_path, FULL), profile="fast")
    on = {s.id for s in cfg.scanners if s.enabled}
    assert on == {"flowscope", "semgrep", "bandit", "gitleaks"}
    assert cfg.limits.timeout_s <= 120
    assert cfg.policy.require_scanners == ["flowscope"]


def test_profile_full_enables_all_listed(tmp_path):
    t = FULL.replace("{id: trivy}", "{id: trivy, enabled: false}")
    cfg = load_config(write(tmp_path, t), profile="full")
    assert all(s.enabled for s in cfg.scanners)


def test_profile_ci_policy_and_reports(tmp_path):
    cfg = load_config(write(tmp_path, FULL), profile="ci")
    assert cfg.policy.fail_on.new_only is True
    assert "sarif" in cfg.reports and "junit" in cfg.reports
    assert cfg.reports == ["sarif", "junit", "json"]


def test_profile_never_enables_unlisted_scanner(tmp_path):
    t = "version: 1\ntarget: {path: .}\nscanners: [{id: bandit}]\n"
    cfg = load_config(write(tmp_path, t), profile="fast")
    assert [s.id for s in cfg.scanners] == ["bandit"]


def test_profile_fast_disabling_required_scanner_is_error(tmp_path):
    t = "version: 1\ntarget: {path: .}\nscanners: [{id: trivy}]\npolicy: {require_scanners: [trivy]}\n"
    with pytest.raises(ConfigError, match="require_scanners"):
        load_config(write(tmp_path, t), profile="fast")


def test_unknown_profile(tmp_path):
    with pytest.raises(ConfigError, match="unknown profile"):
        load_config(write(tmp_path, FULL), profile="turbo")


def test_profile_does_not_mutate_or_rehash_base(tmp_path):
    base = load_config(write(tmp_path, FULL))
    h = base.hash()
    load_config(write(tmp_path, FULL), profile="fast")
    assert base.hash() == h


def test_profile_cannot_override_dynamic_guard(tmp_path):
    with pytest.raises(ConfigError, match="dynamic testing not implemented"):
        load_config(write(tmp_path, FULL + "dynamic: {x: 1}\n"), profile="ci")


def test_error_messages_name_location(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(write(tmp_path, MINIMAL + "limits: {timeout_s: 0}\n"))
    assert "limits.timeout_s" in str(e.value)
