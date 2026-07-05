# Catch-All False-Positive Fixes — Spec (for 4.7)

**Status:** Draft for 4.7 review · **Date:** 2026-07-05
**Scope:** scanner (`*-asm`) — `run_light.py` + `run_medium.py`. Prodex first, port to Command.
**Trigger:** prosalud medium surfaced 99 "Accessible path" findings; live-probing revealed a fleet-wide **200-catch-all** false-positive class that also inflated the HIGH count with phantom `/.env` "leaks."

---

## 1. Evidence (live-probed, not inferred)

`prosalud.prodexlabs.com` and 17 other hosts return the **identical HTTP 200 body** for `/`, `/admin`, `/.env`, `/.git/config`, `/.aws/credentials`, **and a random garbage path** (`/cs-nonsense-<uuid>`) — same length, same body hash. They are SPA / catch-all routers that serve their index page for every path.

Consequence: every "path returns 200" finding on these hosts is noise. Fleet audit — **18 of 19** hosts with `Exposed path` findings are catch-alls (root body == random-garbage body); only `docs` discriminates (root 308, random 404).

**Impact corrected:** the "18 hosts leak `/.env` → 72 HIGH" story was a catch-all artifact. **There is no real credential/`.git` exposure on the fleet.** After clearing (marked `false_positive`, reversible): fleet HIGH went **72 → 0**, CRITICAL 0. 336 findings cleared total (192 `Accessible path` + 144 `Exposed path`).

## 2. Two root-cause bugs

### Bug A — Light sensitive-path check has NO catch-all guard AND NO content verification
`run_light.py check_common_paths()` (L531) HEAD-probes a hardcoded list (`COMMON_PATHS`, L96) — `/.env`, `/.git/config`, `/.git/HEAD`, `/wp-config.php.bak` = **HIGH** — and emits `Exposed path: <p> (HTTP <code>)` (L549-560) whenever the code is `200/204/206`. It never asks "does a random path also 200?" and never inspects the body. On a catch-all host, all four HIGH paths "exist" → **4 phantom HIGH per host.** This is the source of the 72 HIGH.

### Bug B — Medium ffuf catch-all calibration is single-probe-fragile
`run_medium.py detect_ffuf_catchall()` (L1506) probes **two** random paths via `_probe_calibration_path`; on `status == 0` it **immediately bails** to `(None, None)` — no retry. Through the Mullvad tunnel under scan load, one hiccuped probe silently disables detection. It fired correctly on ~16 hosts (they got the collapsed "Host returns HTTP 200 to N paths uniformly" summary) but **failed on prosalud + uat** → 96 individual `Accessible path` FPs each. Same single-probe fragility 4.7 caught in the post-chunk healthcheck.

## 3. Proposed fixes

### Fix A — `check_common_paths` gets a control-probe + content verification
1. **Control probe:** before the loop, GET a random nonsense path. If it returns `200/204/206`, the host is a catch-all → **suppress the per-path findings** and emit ONE informational "host serves 200 to arbitrary paths (catch-all); sensitive-path probing not meaningful."
2. **Content verification (defense in depth, applies even off-catch-all):** for the HIGH secret paths, require a content marker in the body before emitting HIGH — not a bare 200:
   - `/.env` → a line matching `^\s*[A-Z0-9_]+=` (env assignment)
   - `/.git/config` → `[core]`
   - `/.git/HEAD` → `ref:` or a 40-hex SHA
   - `/wp-config.php.bak` → `<?php` / `DB_NAME` / `DB_PASSWORD`
   A 200 serving HTML is not a secret leak. If the marker is absent → downgrade to INFO ("path returns 200 but content isn't the expected secret") or suppress.

### Fix B — retry the ffuf calibration probe
Wrap `_probe_calibration_path` in a bounded retry (mirror `healthcheck_with_retry`): require each of the two probes to actually land (non-zero status) before concluding "no catch-all"; retry on `status == 0`. A transient tunnel blip must not silently disable suppression.

### Durable fix (Phase B, kind-aware scanning)
A `web` host that's a SPA catch-all should not be dir-fuzzed OR sensitive-path-probed at all — Phase B's kind-aware profiles would skip both, making A/B the interim guardrails. (Ties to HOST_CHARACTERIZATION_SPEC.md.)

## 4. Open questions for 4.7 (please rule)

1. **Content-verify approach:** per-file-type markers (§3 Fix A.2) vs. "body != control-path body" (compare to the catch-all baseline) vs. **both**? Markers are stricter but list-maintenance; body-compare is generic but misses a real secret that happens to share the catch-all length.
2. **Share calibration?** Should Light's control-probe reuse Medium's `detect_ffuf_catchall` logic (one code path), or stay a lightweight independent probe (Light has no ffuf)?
3. **Retry params** for `_probe_calibration_path` (attempts / delay) — match `POST_ROTATE_SETTLE_*` (3 / 5s) or lighter?
4. **59ad6a13-class risk:** a control-probe that suppresses could hide a REAL `/.env` on a host that also 200s random paths. Does content-verification (§3 Fix A.2) fully defend this, so suppression is safe? Confirm the layering (verify-then-suppress vs suppress-then-verify).
5. **Cleanup already applied:** 336 findings marked `false_positive` (reversible). After the fix + a re-scan, do these re-resolve cleanly, or should the cleared rows be handled differently?
6. **Phantom Phase-B gate:** non-resolving CT-ghosts (`access`, `ftp2`) are `owned` but can't be scanned. Confirm the Phase-B gate becomes `owned AND discovery_status='confirmed_live' AND kind IN (NULL,'unknown') = 0` (exclude phantoms), not just `owned`.
7. **Test bar:** both fixes are pure-function-testable (`is_catchall(control_code)`, `verify_secret_content(path, body)`, retry semantics). Add to `test_degradation.py` alongside the existing `classify_ffuf_severity` cases (which currently assert `.env`+200 → HIGH — those tests will need updating to reflect content-verification).

## 5. Cleanup status (done)
- 192 `Accessible path` (prosalud, uat) + 144 `Exposed path` (18 catch-all hosts) → `current_status='false_positive'` (reversible; audit trail preserved).
- Not touched: `docs` (discriminates); `cooked`'s single `Accessible path` (real, host discriminates); the "Host returns HTTP 200 to N paths uniformly" summaries (correct catch-all reporting); `Path exists (redirect → :8080/assets/)` on 6 hosts (different pattern — **unaudited, flag for a look**).
