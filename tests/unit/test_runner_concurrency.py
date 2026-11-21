"""T-CONC: parallel pool, run-dir uniqueness, atomic writes."""
import json
import multiprocessing as mp
import os
import threading
import time
from pathlib import Path

import pytest

from kaleidoscan.runner import atomic_write, create_run_dir, run_parallel

pytestmark = [pytest.mark.unit]


class FakeAdapter:
    def __init__(self, id, delay=0.0, raises=False, hang=False):
        self.info = type("I", (), {"id": id})()
        self.delay, self.raises, self.hang = delay, raises, hang
        self.running = 0

    def run(self, t, cfg, *, timeout_s):
        if self.raises:
            raise RuntimeError("boom token=abc123456789")
        if self.hang:
            time.sleep(30)
        time.sleep(self.delay)
        return type("R", (), {"scanner_id": self.info.id, "status": "ok", "detail": ""})()


def _by_id(rs):
    return {r.scanner_id: r for r in rs}


def test_one_hangs_others_finish():
    ads = [FakeAdapter("a", 0.1), FakeAdapter("hang", hang=True), FakeAdapter("b", 0.1)]
    t = time.monotonic()
    rs = _by_id(run_parallel(ads, None, None, timeout_s=1, max_parallel=3, grace_s=0.5))
    assert time.monotonic() - t < 8
    assert str(rs["a"].status) == "ok" and str(rs["b"].status) == "ok"
    assert str(rs["hang"].status) == "timeout"


def test_exception_becomes_error_result_redacted():
    rs = _by_id(run_parallel([FakeAdapter("bad", raises=True), FakeAdapter("g")], None, None, timeout_s=5, max_parallel=2))
    assert str(rs["bad"].status) == "error" and "abc123456789" not in rs["bad"].detail
    assert str(rs["g"].status) == "ok"


def test_order_preserved_and_max_parallel_respected():
    cur = {"n": 0, "max": 0}
    lock = threading.Lock()

    class A(FakeAdapter):
        def run(self, t, cfg, *, timeout_s):
            with lock:
                cur["n"] += 1; cur["max"] = max(cur["max"], cur["n"])
            time.sleep(0.15)
            with lock:
                cur["n"] -= 1
            return super().run(t, cfg, timeout_s=timeout_s)

    ads = [A(f"s{i}") for i in range(8)]
    rs = run_parallel(ads, None, None, timeout_s=10, max_parallel=2)
    assert [r.scanner_id for r in rs] == [f"s{i}" for i in range(8)]
    assert cur["max"] <= 2


def test_max_parallel_validated():
    with pytest.raises(ValueError):
        run_parallel([], None, None, timeout_s=1, max_parallel=0)


def test_run_dirs_unique_under_contention(tmp_path):
    out, errs = [], []

    def go():
        try:
            out.append(create_run_dir(tmp_path))
        except Exception as e:  # pragma: no cover
            errs.append(e)

    ts = [threading.Thread(target=go) for _ in range(40)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errs and len({p for _, p in out}) == 40 and len({i for i, _ in out}) == 40
    assert all(p.parent == tmp_path / "runs" and p.is_dir() for _, p in out)


def test_run_dir_collision_refused(tmp_path):
    rid, p = create_run_dir(tmp_path)
    with pytest.raises(FileExistsError):
        create_run_dir(tmp_path, run_id=rid)


@pytest.mark.parametrize("rid", ["../x", "a/b", "", ".", "a\x00b"])
def test_bad_run_id_rejected(tmp_path, rid):
    with pytest.raises(ValueError):
        create_run_dir(tmp_path, run_id=rid)


def test_atomic_write_no_temp_leftovers_and_replaces(tmp_path):
    f = tmp_path / "summary.json"
    atomic_write(f, b'{"a":1}')
    atomic_write(f, '{"a":2}')
    assert json.loads(f.read_text()) == {"a": 2}
    assert [p.name for p in tmp_path.iterdir()] == ["summary.json"]


def test_atomic_write_refuses_symlink_escape(tmp_path):
    outside = tmp_path / "outside"; outside.write_text("keep")
    d = tmp_path / "run"; d.mkdir()
    (d / "summary.json").symlink_to(outside)
    atomic_write(d / "summary.json", "new")  # replaces the link itself, not target
    assert outside.read_text() == "keep" and not (d / "summary.json").is_symlink()


def _writer(path, i):
    atomic_write(Path(path), json.dumps({"i": i, "pad": "x" * 200000}))


def test_concurrent_writers_never_expose_partial(tmp_path):
    f = tmp_path / "summary.json"
    atomic_write(f, json.dumps({"i": -1}))
    stop = threading.Event(); bad = []

    def reader():
        while not stop.is_set():
            try:
                json.loads(f.read_text())
            except Exception as e:
                bad.append(e)

    th = threading.Thread(target=reader); th.start()
    ps = [mp.get_context("spawn").Process(target=_writer, args=(str(f), i)) for i in range(6)]
    [p.start() for p in ps]; [p.join(30) for p in ps]
    stop.set(); th.join()
    assert not bad and json.loads(f.read_text())["i"] in range(6)


def _killed_writer(path):
    import kaleidoscan.runner as r
    orig = os.replace
    def die(*a, **k):
        os._exit(9)  # killed between temp write and publish
    r.os.replace = die
    r.atomic_write(Path(path), "x" * 100000)


@pytest.mark.torture
def test_kill_mid_write_leaves_no_partial_target(tmp_path):
    f = tmp_path / "summary.json"
    p = mp.get_context("spawn").Process(target=_killed_writer, args=(str(f),))
    p.start(); p.join(30)
    assert not f.exists()
