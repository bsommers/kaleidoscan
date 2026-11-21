"""T-CLI (doctor) + smoke. C5: exit codes 0-4, --json stdout is only JSON, logs on stderr."""
import ast
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

import kaleidoscan

pytestmark = pytest.mark.smoke
EMPTY_PATH = "/nonexistent-kaleidoscan-path"


def test_version_flag(run_cli):
    r = run_cli("--version")
    assert r.returncode == 0
    assert kaleidoscan.__version__ in r.stdout


def test_no_args_is_usage_error(run_cli):
    r = run_cli()
    assert r.returncode == 2


def test_unknown_subcommand_exit_2(run_cli):
    assert run_cli("bogus").returncode == 2


def test_help_lists_doctor(run_cli):
    r = run_cli("--help")
    assert r.returncode == 0 and "doctor" in r.stdout


def test_doctor_help(run_cli):
    r = run_cli("doctor", "--help")
    assert r.returncode == 0 and "--json" in r.stdout and "--strict" in r.stdout


def test_doctor_json_is_only_json_on_stdout(run_cli):
    r = run_cli("doctor", "--json", path=EMPTY_PATH)
    assert r.returncode == 0
    data = json.loads(r.stdout)  # raises if any noise
    assert data["schema"] == "kaleidoscan.doctor/1"
    assert data["version"] == kaleidoscan.__version__
    assert data["python"].startswith(f"{sys.version_info.major}.{sys.version_info.minor}")
    ids = {t["id"] for t in data["tools"]}
    assert {"flowscope", "semgrep", "bandit", "gosec", "gitleaks", "osv-scanner"} <= ids
    assert all(t["status"] == "missing" for t in data["tools"])  # empty PATH


def test_doctor_detects_fake_tool_and_version(run_cli, fake_bin):
    d = fake_bin("bandit", out="bandit 1.7.9")
    r = run_cli("doctor", "--json", path=str(d))
    tools = {t["id"]: t for t in json.loads(r.stdout)["tools"]}
    assert tools["bandit"]["status"] == "ok"
    assert "1.7.9" in tools["bandit"]["version"]
    assert tools["semgrep"]["status"] == "missing"


def test_doctor_tool_nonzero_version_is_error_not_crash(run_cli, fake_bin):
    d = fake_bin("gosec", out="boom", code=3)
    r = run_cli("doctor", "--json", path=str(d))
    assert r.returncode == 0
    tools = {t["id"]: t for t in json.loads(r.stdout)["tools"]}
    assert tools["gosec"]["status"] == "error"


def test_doctor_flowscope_bin_env_overrides_path(run_cli, fake_bin):
    d = fake_bin("my-flowscope", out="flowscope 0.9.0")
    r = run_cli("doctor", "--json", path=EMPTY_PATH, env={"FLOWSCOPE_BIN": str(d / "my-flowscope")})
    tools = {t["id"]: t for t in json.loads(r.stdout)["tools"]}
    assert tools["flowscope"]["status"] == "ok" and tools["flowscope"]["channel"] == "FLOWSCOPE_BIN"


def test_doctor_strict_exit_3_when_required_missing(run_cli):
    r = run_cli("doctor", "--strict", path=EMPTY_PATH)
    assert r.returncode == 3
    assert "flowscope" in r.stdout


def test_doctor_strict_exit_0_when_required_present(run_cli, fake_bin):
    d = fake_bin("flowscope", out="flowscope 1.0.0")
    assert run_cli("doctor", "--strict", path=str(d)).returncode == 0


def test_doctor_text_mentions_every_tool(run_cli):
    r = run_cli("doctor", path=EMPTY_PATH)
    assert r.returncode == 0
    for tid in ("flowscope", "semgrep", "bandit", "gosec", "gitleaks", "osv-scanner"):
        assert tid in r.stdout


def test_entry_points_declared(root):
    text = (root / "pyproject.toml").read_text()
    assert re.search(r'^kaleidoscan\s*=\s*"kaleidoscan.cli:main"', text, re.M)
    assert re.search(r'^kscan\s*=\s*"kaleidoscan.cli:main"', text, re.M)


def test_installed_console_scripts_if_present():
    for name in ("kaleidoscan", "kscan"):
        if shutil.which(name) is None:
            pytest.skip(f"{name} not on PATH (not installed into active env)")


def test_main_returns_int():
    from kaleidoscan.cli import main

    assert main(["--version"]) == 0


@pytest.mark.security
def test_no_shell_true_anywhere(root):
    """T-SEC: AST lint, no shell=True and no os.system in package or scripts."""
    offenders = []
    for p in list((root / "kaleidoscan").rglob("*.py")) + list((root / "scripts").glob("*.py")):
        for node in ast.walk(ast.parse(p.read_text())):
            if isinstance(node, ast.keyword) and node.arg == "shell" and getattr(node.value, "value", None) is True:
                offenders.append(f"{p}:{node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "system" and getattr(node.func.value, "id", "") == "os":
                offenders.append(f"{p}:{node.lineno}")
    assert not offenders, offenders
