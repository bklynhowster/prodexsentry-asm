"""
test_dns_posture.py — Ship A2 email-auth check correctness.

Guards the four fixes in run_light.check_dns_posture (Obsidian 184 §9/§10,
4.7 rulings S1-S6):

  1. DMARC organisational-domain inheritance, RFC 7489 §6.6.3.
  2. SPF suppression on non-sending subdomains.
  3. Bare-IP guard.
  4. DKIM evidence-only (never asserts absence).

WHY THESE FIXTURES ARE REAL RECORDS: every DMARC string below was measured
from live DNS on 2026-08-27 via 8.8.8.8/1.1.1.1/9.9.9.9. The two estates
produce OPPOSITE correct answers, and a fix validated against only one of
them ships a bug into the other:

  * prodexlabs.com publishes p=quarantine with NO sp=  -> subdomains INHERIT
    enforcement -> the 55 per-subdomain findings were FALSE POSITIVES.
  * 5 of 7 Command apexes publish NO DMARC at all      -> nothing to inherit
    -> the same findings there are TRUE POSITIVES and must keep firing.

Run: cd scripts/scanner && python3 -m pytest test_dns_posture.py -v
     (or plain `python3 test_dns_posture.py`)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from run_light import dmarc_effective_policy, is_sending_host  # noqa: E402

# ── Measured live 2026-08-27 ────────────────────────────────────────────────
PRODEX = "v=DMARC1; p=quarantine; rua=mailto:dmarc@prodexlabs.com; pct=100"
CMDCO = "v=DMARC1; p=none; pct=100; rua=mailto:dkimreport@commandcompanies.com"
BESSEMER = "v=DMARC1; p=reject; fo=1; rua=mailto:dmarc_rua"


# ── DMARC inheritance ───────────────────────────────────────────────────────

def test_apex_policy_is_its_own_p_tag():
    assert dmarc_effective_policy(PRODEX, for_subdomain=False) == "quarantine"
    assert dmarc_effective_policy(CMDCO, for_subdomain=False) == "none"
    assert dmarc_effective_policy(BESSEMER, for_subdomain=False) == "reject"


def test_subdomain_inherits_org_p_when_no_sp():
    """THE bug. gov.prodexlabs.com has no _dmarc record but IS protected."""
    assert dmarc_effective_policy(PRODEX, for_subdomain=True) == "quarantine"


def test_sp_overrides_p_for_subdomains_only():
    rec = "v=DMARC1; p=reject; sp=none"
    assert dmarc_effective_policy(rec, for_subdomain=True) == "none"
    assert dmarc_effective_policy(rec, for_subdomain=False) == "reject"


def test_absent_record_yields_no_policy():
    assert dmarc_effective_policy(None, for_subdomain=False) is None
    assert dmarc_effective_policy(None, for_subdomain=True) is None


def test_tag_parsing_is_whitespace_and_case_insensitive():
    assert dmarc_effective_policy("V=DMARC1;P=Quarantine", for_subdomain=False) == "quarantine"
    assert dmarc_effective_policy("v=DMARC1 ;  p = reject ", for_subdomain=False) == "reject"


# ── The two estates must produce OPPOSITE answers ───────────────────────────

def test_prodex_subdomain_is_protected_so_finding_is_suppressed():
    """Suppressing these is what closed 55 false positives."""
    assert dmarc_effective_policy(PRODEX, for_subdomain=True) in ("quarantine", "reject")


def test_command_subdomain_is_unprotected_so_finding_still_fires():
    """REGRESSION GUARD: a fix tuned only to Prodex would wrongly suppress
    ~60 genuine Command findings. Apex publishes nothing -> nothing inherits."""
    assert dmarc_effective_policy(None, for_subdomain=True) not in ("quarantine", "reject")


def test_p_none_does_not_count_as_protection():
    """commandcompanies.com: DMARC published, but monitoring-only. Its
    subdomains are NOT protected by inheritance."""
    assert dmarc_effective_policy(CMDCO, for_subdomain=True) == "none"
    assert dmarc_effective_policy(CMDCO, for_subdomain=True) not in ("quarantine", "reject")


# ── Sending-host inference (4.7 R3: MX/own-SPF primary, naming secondary) ───

def test_mx_presence_is_a_high_confidence_signal():
    v = is_sending_host("anything.example.com", False, ["10 mx1.hc3765-17.iphmx.com."])
    assert v["is_sending_host"] is True
    assert v["inference_confidence"] == "high"


def test_own_spf_is_a_high_confidence_signal():
    v = is_sending_host("foo.example.com", True, [])
    assert v["is_sending_host"] is True
    assert v["inference_confidence"] == "high"


def test_naming_pattern_alone_is_heuristic_not_high():
    """4.7 risk #3 — naming may false-positive, so it must be marked as the
    weaker signal rather than silently treated as proof."""
    v = is_sending_host("smtp.example.com", False, [])
    assert v["is_sending_host"] is True
    assert v["inference_confidence"] == "heuristic"


def test_plain_subdomain_is_not_a_sending_host():
    v = is_sending_host("gov.prodexlabs.com", False, [])
    assert v["is_sending_host"] is False
    assert v["signals"] == {"mx_present": False, "own_spf": False, "naming_pattern": False}


def test_signals_are_reported_for_diagnosability():
    """Operator asking 'why was X treated as sending?' must get an answer."""
    v = is_sending_host("mail.example.com", False, ["10 mx.example.net."])
    assert v["signals"]["mx_present"] is True
    assert v["signals"]["naming_pattern"] is True


def _all_tests():
    return [v for k, v in globals().items() if k.startswith("test_") and callable(v)]


def main() -> int:
    tests = _all_tests()
    # FLOOR: this suite must never pass by collecting nothing.
    # See feedback_checks_that_pass_by_never_running.
    assert len(tests) >= 13, f"expected >=13 tests, collected {len(tests)}"
    failed: list[tuple[str, str]] = []
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed.append((t.__name__, str(e)))
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed.append((t.__name__, f"{type(e).__name__}: {e}"))
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print()
    print(f"{len(tests) - len(failed)} / {len(tests)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
