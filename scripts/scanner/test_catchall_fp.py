"""Tests for the catch-all false-positive fixes (Fix A + Fix B).

Spec: prodexsentry-asm/CATCHALL_FP_FIX_SPEC.md (4.7-reviewed, verdict REVISE;
this file is 4.7 must-fix #6 / Hole 9, and the biggest-risk anchor).

What these lock:
  - Fix A (run_light.check_common_paths) VERIFY-THEN-SUPPRESS ordering — a
    HIGH content-marker match ALWAYS wins over catch-all suppression, so a
    real /.env is never silently eaten (anchor commit 59ad6a13). The
    load-bearing case is test_resolve_disposition_high_marker_wins_over_catchall.
  - Fix A catch-all detection (_is_catchall): two-probe, both-2xx, hash-match.
  - Fix A per-file secret markers (verify_secret_content): a bare 200 serving
    HTML is not a leak; the body must carry the secret's shape.
  - Fix B (run_medium) calibration retry + FAIL-CLOSED: retry-exhaustion must
    surface calib_ok=False so the caller SKIPS ffuf (marks it degraded), never
    silently falls through to per-path emit (Hole 5 — the whole point of Fix B).

Run:  pytest scripts/scanner/test_catchall_fp.py -v
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import run_light as L  # noqa: E402
import run_medium as M  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════
# Fix A — _is_catchall (pure two-probe catch-all decision, hole 2)
# ═══════════════════════════════════════════════════════════════════════

def test_is_catchall_both_2xx_same_hash_is_true():
    assert L._is_catchall((200, 200), ("hA", "hA")) is True


def test_is_catchall_2xx_variants_204_206_count():
    # 204/206 are 2xx too — a catch-all could answer with either.
    assert L._is_catchall((204, 206), ("hA", "hA")) is True


def test_is_catchall_different_hashes_is_false():
    # Both 200 but bodies differ → host discriminates → NOT a catch-all.
    assert L._is_catchall((200, 200), ("hA", "hB")) is False


def test_is_catchall_one_non_2xx_is_false():
    # A 404 on one probe means the host DOES 404 random paths → discriminates.
    assert L._is_catchall((200, 404), ("hA", "hA")) is False


def test_is_catchall_redirect_is_not_2xx_is_false():
    assert L._is_catchall((301, 301), ("hA", "hA")) is False


# ═══════════════════════════════════════════════════════════════════════
# Fix A — verify_secret_content (per-file secret markers; holes 4, 6)
# A 200 is NOT a leak: the body must carry the real secret's shape.
# ═══════════════════════════════════════════════════════════════════════

def test_verify_env_two_assignment_lines_is_true():
    assert L.verify_secret_content("/.env", "API_KEY=abc\nDB_URL=xyz") is True


def test_verify_env_html_body_is_false():
    # The catch-all SPA index served for /.env — not a secret.
    assert L.verify_secret_content("/.env", "<html>Loading…</html>") is False


def test_verify_env_single_line_is_false():
    # >= 2 assignment lines required (hole 4): a lone `foo=bar` false-positives
    # on random HTML/JS.
    assert L.verify_secret_content("/.env", "single_var=lonely") is False


def test_verify_env_ignores_comment_lines():
    # Comments don't count toward the 2-line floor, but two real vars do.
    assert L.verify_secret_content("/.env", "# comment\nAPI_KEY=abc\nDB=1") is True


def test_verify_git_config_core_marker_is_true():
    assert L.verify_secret_content(
        "/.git/config", "[core]\n\trepositoryformatversion = 0") is True


def test_verify_git_config_html_is_false():
    assert L.verify_secret_content("/.git/config", "<html>nope</html>") is False


def test_verify_git_head_ref_is_true():
    assert L.verify_secret_content("/.git/HEAD", "ref: refs/heads/main") is True


def test_verify_git_head_detached_sha_is_true():
    assert L.verify_secret_content(
        "/.git/HEAD", "0123456789abcdef0123456789abcdef01234567\n") is True


def test_verify_git_head_html_is_false():
    assert L.verify_secret_content("/.git/HEAD", "<html>404</html>") is False


def test_verify_wpconfig_bak_db_marker_is_true():
    assert L.verify_secret_content(
        "/wp-config.php.bak", "<?php define('DB_PASSWORD', 'hunter2');") is True


def test_verify_wpconfig_bak_bare_php_is_false():
    # A bare <?php is table-stakes on any PHP host; require DB_* (hole 6).
    assert L.verify_secret_content("/wp-config.php.bak", "<?php echo 1; ?>") is False


def test_verify_unknown_path_never_matches():
    # Path not in the marker table → cannot be a verified HIGH.
    assert L.verify_secret_content("/robots.txt", "API_KEY=abc\nB=2") is False


def test_verify_empty_body_is_false():
    assert L.verify_secret_content("/.env", "") is False


# ═══════════════════════════════════════════════════════════════════════
# Fix A — resolve_path_disposition (VERIFY-THEN-SUPPRESS ordering)
# 4.7 BIGGEST RISK: this ordering getting inverted. Anchored here.
# ═══════════════════════════════════════════════════════════════════════

def test_resolve_disposition_high_marker_wins_over_catchall():
    """THE anchor (4.7 biggest-risk / commit 59ad6a13). On a catch-all host
    (matches_baseline=True) a verified HIGH secret STILL emits HIGH — verify
    beats suppress. If this ever returns 'SUPPRESS', a real /.env is being
    eaten and the 59ad6a13 regression is back."""
    assert L.resolve_path_disposition("HIGH", marker_match=True,
                                      matches_baseline=True) == "HIGH"


def test_resolve_disposition_high_marker_no_baseline_is_high():
    assert L.resolve_path_disposition("HIGH", marker_match=True,
                                      matches_baseline=False) == "HIGH"


def test_resolve_disposition_high_no_marker_on_catchall_suppresses():
    assert L.resolve_path_disposition("HIGH", marker_match=False,
                                      matches_baseline=True) == "SUPPRESS"


def test_resolve_disposition_high_no_marker_no_baseline_is_info():
    # 2xx but body isn't the secret shape and isn't the catch-all page →
    # INFO for manual review, NOT HIGH.
    assert L.resolve_path_disposition("HIGH", marker_match=False,
                                      matches_baseline=False) == "INFO"


def test_resolve_disposition_nonhigh_on_catchall_suppresses():
    assert L.resolve_path_disposition("MODERATE", marker_match=False,
                                      matches_baseline=True) == "SUPPRESS"


def test_resolve_disposition_nonhigh_no_baseline_emits():
    assert L.resolve_path_disposition("INFO", marker_match=False,
                                      matches_baseline=False) == "EMIT"


# ═══════════════════════════════════════════════════════════════════════
# Fix B — _probe_calibration_path retry (hole 5 half 1: transient blip recovers)
# ═══════════════════════════════════════════════════════════════════════

def _seq_probe(results):
    """Return a stub for _probe_calibration_path_once yielding `results` in
    order, and a counter list so tests can assert call count."""
    calls = {"n": 0}

    def _stub(ctx):
        i = calls["n"]
        calls["n"] += 1
        return results[i]
    return _stub, calls


def test_calib_retry_recovers_after_two_transient_misses(monkeypatch):
    # [0, 0, 200] → the retry rides through two status-0 blips and returns 200.
    stub, calls = _seq_probe([(0, None), (0, None), (200, None)])
    monkeypatch.setattr(M, "_probe_calibration_path_once", stub)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    status, loc = M._probe_calibration_path(object())
    assert status == 200
    assert calls["n"] == 3


def test_calib_retry_exhaustion_returns_zero(monkeypatch):
    # [0, 0, 0] → all attempts miss → (0, None). The caller MUST treat this as
    # calibration failure, not "no catch-all".
    stub, calls = _seq_probe([(0, None), (0, None), (0, None)])
    monkeypatch.setattr(M, "_probe_calibration_path_once", stub)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    status, loc = M._probe_calibration_path(object())
    assert status == 0
    assert calls["n"] == M.CALIB_PROBE_ATTEMPTS  # exhausted the full budget


def test_calib_retry_first_hit_no_wasted_attempts(monkeypatch):
    # A clean first probe returns immediately — no retry, no sleep.
    stub, calls = _seq_probe([(403, None)])
    monkeypatch.setattr(M, "_probe_calibration_path_once", stub)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)
    status, loc = M._probe_calibration_path(object())
    assert (status, calls["n"]) == (403, 1)


# ═══════════════════════════════════════════════════════════════════════
# Fix B — detect_ffuf_catchall calib_ok 3-tuple (hole 5 half 2: FAIL CLOSED)
# ═══════════════════════════════════════════════════════════════════════

def _two_probe(first, second):
    """Stub _probe_calibration_path (the RETRYING wrapper) to return `first`
    then `second` on successive calls."""
    seq = [first, second]
    calls = {"n": 0}

    def _stub(ctx):
        r = seq[calls["n"]]
        calls["n"] += 1
        return r
    return _stub


def test_detect_ffuf_catchall_probe_exhaustion_is_calib_false(monkeypatch):
    """THE Fix B point (Hole 5): if the calibration probe exhausts its retries
    (status 0), detect_ffuf_catchall returns calib_ok=False — the caller
    fails closed and skips ffuf. It must NOT return (None, None, True), which
    would let per-path emit run against an undetected catch-all."""
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((0, None), (0, None)))
    redirect, status, calib_ok = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    assert (redirect, status, calib_ok) == (None, None, False)


def test_detect_ffuf_catchall_status_catchall_is_calib_true(monkeypatch):
    # Both probes 200 → status catch-all detected; calib ran clean.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None), (200, None)))
    redirect, status, calib_ok = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    assert (redirect, status, calib_ok) == (None, 200, True)


def test_detect_ffuf_catchall_redirect_catchall_is_calib_true(monkeypatch):
    # Both probes 301 → same Location → redirect catch-all (#33 path).
    monkeypatch.setattr(
        M, "_probe_calibration_path", _two_probe((301, "/x"), (301, "/x")))
    redirect, status, calib_ok = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    assert (redirect, status, calib_ok) == ("/x", None, True)


def test_detect_ffuf_catchall_discriminating_host_is_calib_true(monkeypatch):
    # 200 then 404 → the host discriminates → no catch-all, but calibration
    # DID run cleanly → calib_ok=True (do NOT fail closed on a healthy host).
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((200, None), (404, None)))
    redirect, status, calib_ok = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    assert (redirect, status, calib_ok) == (None, None, True)


def test_detect_ffuf_catchall_both_404_is_not_catchall(monkeypatch):
    # 404==404 but 404 is excluded (it's the expected random-path answer) →
    # host discriminates, calib clean.
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe((404, None), (404, None)))
    redirect, status, calib_ok = M.detect_ffuf_catchall(types.SimpleNamespace(hostname="h"))
    assert (redirect, status, calib_ok) == (None, None, True)


def test_backward_compat_redirect_wrapper_unpacks_3_tuple(monkeypatch):
    """The #33 thin wrapper detect_ffuf_catchall_redirect must unpack the new
    3-tuple, not the old 2-tuple (else ValueError at runtime). Returns just the
    redirect Location on a redirect catch-all."""
    monkeypatch.setattr(
        M, "_probe_calibration_path", _two_probe((307, "/go"), (307, "/go")))
    assert M.detect_ffuf_catchall_redirect(
        types.SimpleNamespace(hostname="h")) == "/go"


# ═══════════════════════════════════════════════════════════════════════
# Medium classify_ffuf_severity regression pin.
# .env+200 → HIGH is INTENTIONAL and safe ONLY because Fix B suppresses ffuf
# entirely on a catch-all host upstream (calibration). On a DISCRIMINATING
# host, a 200 on /.env is a real hit and HIGH is correct. This pins the matrix
# so nobody "fixes" it by blanket-downgrading (that was the 59ad6a13 mistake).
# ═══════════════════════════════════════════════════════════════════════

def test_classify_secret_200_is_high():
    assert M.classify_ffuf_severity(".env", "https://h/.env", 200) == "HIGH"


def test_classify_admin_200_is_moderate():
    assert M.classify_ffuf_severity("admin", "https://h/admin", 200) == "MODERATE"


def test_classify_secret_403_is_low():
    assert M.classify_ffuf_severity(".env", "https://h/.env", 403) == "LOW"


def test_classify_generic_200_is_info():
    assert M.classify_ffuf_severity("about", "https://h/about", 200) == "INFO"


def test_classify_secret_redirect_is_info():
    assert M.classify_ffuf_severity(".env", "https://h/.env", 301) == "INFO"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
