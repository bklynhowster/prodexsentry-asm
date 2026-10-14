"""318 (2026-10-14) — the daily digest job exists on this instance and carries no
other tenant's identity.

Howie, after the Command digest: "Do we have something similar for prodex?" The
code was here all along; the job file was not. This pins the job file's shape so
the mirror never regresses into the hazard the Command copy warns about: a
workflow-level `|| 'literal'` fallback that would send one tenant's posture as,
or to, the other. Command's own literals are Command's identity and are allowed
there; nothing else is allowed anywhere.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows" / "alerter.yml"


def _text() -> str:
    """The job without its comment lines — prose may mention a fallback; YAML may not carry one."""
    if not WF.exists():
        pytest.skip("this instance runs no digest job")
    return "\n".join(ln for ln in WF.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#"))


def test_318_the_digest_job_runs_daily_and_by_hand():
    t = _text()
    assert 'cron: "0 12 * * *"' in t
    assert "workflow_dispatch" in t and "dry_run" in t
    assert "python scripts/alerter/run_alerter.py" in t


def test_318_identity_comes_from_repo_variables_and_never_from_another_tenant():
    t = _text()
    for var in ("ALERTER_FROM", "ALERTER_FROM_NAME", "ALERTER_TO", "ALERTER_PORTAL_URL", "ALERTER_DASHBOARD_URL"):
        assert re.search(rf"{var}:\s+\$\{{\{{ vars\.{var}", t), f"{var} is read from a repo variable"
    # Any literal fallback may only be Command's own identity, and only in Command's repo.
    for m in re.finditer(r"\|\|\s*'([^']*)'", t):
        lit = m.group(1)
        assert re.search(r"commandcompanies\.com|COMMANDsentry|howiehow@mac\.com|hdygktppfvuspnumpfuq|commandsentry-portal", lit), \
            f"a workflow fallback carries a non-Command literal: {lit!r}"
        assert ROOT.name != "prodexsentry-asm" or "prodex" in lit.lower(), f"Prodex's job must not fall back to {lit!r}"


def test_318_the_mirror_carries_no_command_literal_at_all():
    t = _text()
    if "prodex" not in ROOT.name.lower():
        pytest.skip("Command's job keeps its own literals")
    for bad in ("commandcompanies.com", "COMMANDsentry", "howiehow@mac.com", "hdygktppfvuspnumpfuq", "commandsentry-portal.netlify.app"):
        assert bad not in t, f"Command identity in Prodex's digest job: {bad}"


def test_318_the_transport_matches_the_canary():
    """The canary (11:00 UTC) proves the transport daily; the digest must use the same one."""
    t = _text()
    canary = ROOT / ".github" / "workflows" / "mail-canary.yml"
    if not canary.exists():
        pytest.skip("no canary on this instance")
    c = canary.read_text(encoding="utf-8")
    for var in ("MAIL_PROVIDER", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS"):
        assert (f"{var}:" in c) == (f"{var}:" in t), f"{var}: the digest and the canary must read the same transport"
