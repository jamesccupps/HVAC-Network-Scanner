"""packaging/virustotal.py against a fake VirusTotal API on loopback: upload,
reuse of an existing report, rescan, the Microsoft gate, and every way of
not getting a verdict (which must not hold a release)."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packaging"))
import virustotal as vt  # noqa: E402

KEY = "test-key"
CLEAN = {"Microsoft": {"category": "undetected", "result": None},
         "ESET-NOD32": {"category": "undetected", "result": None},
         "SecureAge": {"category": "malicious", "result": "Malicious"},
         "Avast": {"category": "type-unsupported", "result": None}}
STATS = {"malicious": 1, "suspicious": 0, "undetected": 2, "harmless": 0, "type-unsupported": 1}


class FakeVT:
    def __init__(self, results=CLEAN, stats=STATS, polls=2, fail_with=None):
        self.files, self.analyses, self.log = {}, {}, []
        self.results, self.stats, self.polls, self.fail_with = results, stats, polls, fail_with
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None):
                body = json.dumps(obj or {}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _route(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                fake.log.append((method, self.path, len(body)))
                if fake.fail_with:
                    return self._send(fake.fail_with)
                if self.headers.get("x-apikey") != KEY:
                    return self._send(401)
                p = self.path.removeprefix("/api/v3")
                if method == "GET" and p.startswith("/files/"):
                    sha = p.split("/")[2]
                    if sha in fake.files:
                        return self._send(200, {"data": {"attributes": fake.files[sha]}})
                    return self._send(404)
                if method == "POST" and p == "/files":
                    assert b'name="file"' in body and self.headers["Content-Type"].startswith(
                        "multipart/form-data; boundary=")
                    fake.analyses["a-up"] = [0]
                    return self._send(200, {"data": {"type": "analysis", "id": "a-up"}})
                if method == "POST" and p.endswith("/analyse"):
                    fake.analyses["a-re"] = [0]
                    return self._send(200, {"data": {"type": "analysis", "id": "a-re"}})
                if method == "GET" and p.startswith("/analyses/"):
                    seen = fake.analyses[p.split("/")[2]]
                    seen[0] += 1
                    if seen[0] <= fake.polls:
                        return self._send(200, {"data": {"attributes": {"status": "queued"}}})
                    return self._send(200, {"data": {"attributes": {
                        "status": "completed", "stats": fake.stats, "results": fake.results}}})
                return self._send(400)

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.server.server_address[1]}/api/v3"


@pytest.fixture
def fake(monkeypatch):
    servers = []

    def make(**kw):
        f = FakeVT(**kw)
        servers.append(f)
        monkeypatch.setattr(vt, "API", f.api)
        return f
    monkeypatch.setattr(vt, "POLL_S", 0)
    monkeypatch.setattr(vt, "QUOTA_WAIT_S", 0)
    monkeypatch.setenv("VT_API_KEY", KEY)
    yield make
    for f in servers:
        f.server.shutdown()


@pytest.fixture
def exe(tmp_path):
    p = tmp_path / "HVACNetworkScanner.exe"
    p.write_bytes(b"MZ" + bytes(4096))
    return p


def _run(exe, tmp_path, *extra):
    report, summary = tmp_path / "vt.json", tmp_path / "summary.md"
    code = vt.main([str(exe), "--report", str(report), "--summary", str(summary), *extra])
    return code, json.loads(report.read_text(encoding="utf-8")), summary.read_text(encoding="utf-8")


def test_a_new_file_is_uploaded_and_ml_hits_are_reported_not_fatal(fake, exe, tmp_path):
    f = fake()
    code, v, md = _run(exe, tmp_path)
    assert code == 0
    assert v["status"] == "scanned" and v["source"] == "upload" and v["engines"] == 3
    assert v["flagged"] == [{"engine": "SecureAge", "category": "malicious", "result": "Malicious"}]
    assert v["blocking"] == [] and v["link"].endswith(v["sha256"])
    assert "**1 of 3 engines**" in md and "SecureAge" in md
    assert [m for m, *_ in f.log].count("POST") == 1


def test_a_known_file_reuses_its_report_without_uploading(fake, exe, tmp_path):
    import hashlib
    f = fake()
    f.files[hashlib.sha256(exe.read_bytes()).hexdigest()] = {
        "last_analysis_results": CLEAN, "last_analysis_stats": STATS}
    code, v, _ = _run(exe, tmp_path)
    assert code == 0 and v["source"] == "existing report"
    assert all(m == "GET" for m, *_ in f.log)


def test_rescan_asks_for_a_fresh_analysis(fake, exe, tmp_path):
    import hashlib
    f = fake()
    f.files[hashlib.sha256(exe.read_bytes()).hexdigest()] = {
        "last_analysis_results": CLEAN, "last_analysis_stats": STATS}
    code, v, _ = _run(exe, tmp_path, "--rescan")
    assert code == 0 and v["source"] == "rescan"
    assert any(m == "POST" and p.endswith("/analyse") for m, p, _ in f.log)


def test_microsoft_flagging_it_fails_the_check(fake, exe, tmp_path):
    fake(results={**CLEAN, "Microsoft": {"category": "malicious", "result": "Trojan:Win32/Wacatac"}},
         stats={**STATS, "malicious": 2})
    code, v, md = _run(exe, tmp_path)
    assert code == 1 and v["blocking"] == ["Microsoft"]
    assert "don't publish" in md


@pytest.mark.parametrize("setup,reason", [
    (dict(fail_with=500), "HTTP 500"),
    (dict(fail_with=429), "HTTP 429"),
    (dict(polls=10_000), "no result after"),
])
def test_no_verdict_is_a_warning_not_a_failure(fake, exe, tmp_path, setup, reason):
    fake(**setup)
    code, v, md = _run(exe, tmp_path, "--wait", "0.05")
    assert code == 0 and v["status"] == "not scanned" and reason in v["reason"]
    assert "not scanned" in md


def test_a_wrong_key_or_no_key_is_not_scanned(fake, exe, tmp_path, monkeypatch):
    f = fake()
    monkeypatch.setenv("VT_API_KEY", "wrong")
    code, v, _ = _run(exe, tmp_path)
    assert code == 0 and "refused the key" in v["reason"]
    monkeypatch.delenv("VT_API_KEY")
    asked = len(f.log)
    code, v, _ = _run(exe, tmp_path)
    assert code == 0 and v["reason"] == "no VT_API_KEY" and len(f.log) == asked


def test_missing_file_is_bad_usage(tmp_path):
    assert vt.main([str(tmp_path / "nope.exe")]) == 2


def test_the_script_uses_only_the_standard_library():
    import ast
    src = (Path(vt.__file__)).read_text(encoding="utf-8")
    mods = {n.names[0].name.split(".")[0] if isinstance(n, ast.Import) else (n.module or "").split(".")[0]
            for n in ast.walk(ast.parse(src)) if isinstance(n, (ast.Import, ast.ImportFrom))}
    assert mods <= set(sys.stdlib_module_names) | {"__future__"}, mods
