"""The executable's signing in ci.yml keeps to its rules.

Two jobs hold a signing identity: authenticode (Azure Artifact Signing, as
James Cupps) and attest (Sigstore, the build attestation). Anything running in
such a job could sign whatever it liked, so they run only pinned actions and
the repository's own PowerShell: nothing from PyPI, and never the program. The
SHA-256 published beside the exe, and the attestation, must be of the file
that was tested, which is the signed one. See the comment above windows-exe in
ci.yml.

Read as text (the project has no YAML dependency): a job is everything under
a two-space-indented ``name:`` line in ``jobs:``.
"""

import re
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def _jobs():
    text = CI.read_text(encoding="utf-8").replace("\r\n", "\n")
    jobs, name = {}, None
    for line in text[text.index("\njobs:\n"):].split("\n")[2:]:
        head = re.match(r"^ {2}([A-Za-z][\w-]*):\s*$", line)
        if head:
            name = head.group(1)
            jobs[name] = []
        elif name and not re.match(r"^\s*#", line):
            jobs[name].append(re.sub(r"\s+#\s.*$", "", line))  # trailing comments too
    return {k: "\n".join(v) for k, v in jobs.items()}


JOBS = _jobs()


def _with(pattern):
    return sorted(k for k, v in JOBS.items() if re.search(pattern, v))


def test_only_the_signing_jobs_get_an_identity():
    assert _with(r"id-token:\s*write") == ["attest", "authenticode"]


def test_only_authenticode_signs_in_to_azure_from_the_release_environment():
    assert _with(r"secrets\.AZURE_") == ["authenticode"]
    assert _with(r"(?m)^\s*environment:\s*release\s*$") == ["authenticode"]
    assert re.search(r"(?m)^\s*if:\s*startsWith\(github\.ref, 'refs/tags/v'\)\s*$", JOBS["authenticode"])
    assert "./packaging/authenticode.ps1 -File dist\\HVACNetworkScanner.exe" in JOBS["authenticode"]


@pytest.mark.parametrize("job", ["authenticode", "attest"])
def test_signing_jobs_run_no_pypi_code_and_never_the_program(job):
    ran = re.findall(r"\bpip\b|\bpython\b|setup-python|PyInstaller|requirements|Start-Process|test_update|self-test", JOBS[job])
    assert ran == []


def test_the_build_job_has_no_secrets_and_no_identity():
    assert "secrets." not in JOBS["windows-exe"]
    assert "id-token" not in JOBS["windows-exe"]


def test_the_signed_file_is_tested_then_hashed_then_attested():
    verify = JOBS["verify"]
    assert "needs: [windows-exe, authenticode]" in verify
    assert "'HVACNetworkScanner-signed'" in verify
    order = [verify.index(step) for step in (
        "check_signatures.ps1 -Publisher 'CN=James Cupps, O=James Cupps'",
        "--self-test",
        "./packaging/test_update.ps1",
        "HVACNetworkScanner.exe.sha256",
        "name: HVACNetworkScanner-windows-exe",
    )]
    assert order == sorted(order)
    attest = JOBS["attest"]
    assert "needs: verify" in attest
    assert "name: HVACNetworkScanner-windows-exe" in attest
    assert "subject-path: dist/HVACNetworkScanner.exe" in attest
