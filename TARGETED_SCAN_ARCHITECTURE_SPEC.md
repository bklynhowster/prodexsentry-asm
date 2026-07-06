# Targeted / Characterization-Driven Scan Architecture — Spec v2

**Status:** v2 — 4.7-ruled 2026-07-05 (7 rulings folded in by number + fleet-scale & silent-narrowing guards). **Date:** 2026-07-05
**Scope:** scanner (`prodexsentry-asm`) scan-execution model. Prodex first, port to Command.
**Completes:** `HOST_CHARACTERIZATION_SPEC.md` (this is its Phase B — kind-aware → full service-aware).

---

## 1. Thesis
Characterization answered *"what is this box?"* (kind, ports, service fingerprints, WAF, hosting). This spec **uses** that answer: derive role(s) from discovery → dispatch the checks that match those roles, instead of one generic all-tools scan. A 3389 box gets the RDP threat model; an nginx SPA gets the web/JS pack; nobody fuzzes XSS at a DB port. (Empirically: tonight's generic heavy probe fired ~18k nuclei templates at a static SPA for 17 info items, ran WordPress tooling at a non-WP host, and nikto reported catch-all phantoms.)

## 2. Core model — THREE orthogonal axes (ruling 1: CORRECT)
Role is **not** a peer to light/medium/heavy. Three axes; only one grows unbounded:
1. **Intensity** — `light|medium|heavy` (scalar enum, unchanged). *How hard we push.* Kept out of role for the same reason `kind` never entered `scan_intensity_t`: intensity is a **scalar**, role is a **set/vector** (a host is web + RDP + SMB at once). Collapsing them explodes a 6×3 combo enum and can't express "web at heavy AND RDP at medium on one host."
2. **Profile** — composable role/service packs (`web-spa`, `api`, `wordpress`, `rdp`, `smb`, `ssh`, `mail`, `db`, `infra`…). **Data, not scripts** — a matrix. Host's effective profile = **union** of packs matched by open services + app fingerprint. Add a role = add a row.
3. **Engine** — actual machinery. New engine earned by **fundamentally different execution** (HTTP verbs vs. protocol handshakes vs. headless-browser+auth), not by a new role. Different engines have different degraded-detection signals (HTTP status vs. TCP-refused/protocol-timeout vs. DOM-load-fail) and independent SHA-validation. Expected: `http` (existing run_light/medium/heavy.py — all web-ish profiles), NEW `network` (RDP/SMB/SSH/DB/mail; nmap NSE + nuclei network/tcp), later `dast` (browser/auth'd; Playwright/ZAP).

**Escape hatches (ruling 1 — document so nobody smuggles them into `network`):** two roles WILL earn their own engine later, neither on this roadmap — **OT/ICS** (Modbus/DNP3/MQTT/S7: plcscan/isf, state-machine convos, safety-of-plant probe constraints → `run_ot.py` when Command's OT footprint lands) and **cloud-config posture** (Prowler/CloudSploit-style, API-first credentialed, different data model → own engine if we ever audit account posture vs. network attack surface). **Mail stays inside `network`** — SMTP is small-protocol-client work whose tooling (nmap NSE `smtp-open-relay`/`smtp-enum-users`, swaks) lives in the network toolchain; a separate mail engine is redundant machinery.

**Anti-goal:** `run_rdp.py`/`run_web.py`/`run_api.py` as scripts — duplicated machinery. Profiles are data an engine consumes.

## 3. Characterization inputs (already captured by discovery)
Dispatcher reads `asset_surface.surface_data.subdomains[]` + `assets`: `services[]{port,service,tls}` (primary role signal), `fingerprint{tech[],server}` (app-layer refinement), `kind`+`kind_confidence`, `waf{vendor,detected,confidence}` (→ delivery axis §7), hosting-org/IP (→ GCP membership §7). Derive-and-dispatch; no new discovery work.

## 4. Role/service → check-pack matrix
Declarative `scripts/scanner/matrix/roles.yaml` (§8 on representation). Each row: `trigger` (service/port/fingerprint), `engine`, **two-column exposure severity**, `auth_detection` (method), `nuclei_tags`, `aux_tools`, `probes`.

**Two-column severity (ruling 3):** emit at the auth-modified severity; both signals into evidence.

| role / trigger | engine | base_sev (no auth handshake) | auth_detected_sev | auth-detection method |
|---|---|---|---|---|
| `db` 5432/3306/1433/6379/27017/9200 | network | **CRITICAL** | **HIGH** | Postgres startup-msg challenge; Redis `NOAUTH`/accepted `INFO`; Mongo handshake |
| `rdp` 3389 | network | **HIGH** (CRITICAL if no NLA) | HIGH | NLA-required negotiation |
| `smb` 445 | network | **HIGH** | HIGH (still exposed w/ signing) | null-session accept |
| `ssh` 22 | network | MODERATE | LOW | pubkey-only vs. password auth |
| `mail` 25/465/587/110/143 | network | MODERATE | — | STARTTLS + relay test |
| `web-spa` http+SPA fp | http | (per-finding) | — | — |
| `api` http+/api\|GraphQL fp | http | (per-finding) | — | — |
| `wordpress` http+WP fp | http | (per-finding) | — | — |
| `infra` mgmt/IPMI/k8s-api | network+http | **HIGH** | HIGH | default-cred / panel auth |
| **unmatched open port** | network | **MODERATE** | — | none — generic exposure + note for matrix backfill |
| `redirect`/`dead` | — | INFO/none | — | — |

**Unmatrixed-port fallback (silent-narrowing guard):** a `services[]` port with no matrix row (e.g. 1521 Oracle) → generic exposure finding at MODERATE + note to `scan_run_artifacts` for backfill. Never a silent gap.

## 5. Universal baseline — no-blind-spot rule (rulings 2 & 7; non-negotiable)
Targeted scanning's failure mode is **mischaracterization → coverage blind spot**. Guard: a thin universal baseline runs on hosts **regardless of role/kind**; role packs only ever *add* depth.

**Baseline content (ruling 7 — option 3, precise by data source):** (a) ports/services **READ from discovery's** cached naabu/fingerprintx; (b) run **fresh**: TLS audit, security-header light-nuclei, DNS/email posture, and **the exposure checks for all sensitive services**.
- **Staleness gate:** discovery >72h old for a host → force a **fresh** port sweep (don't trust stale cache). `sudo -n true` check → fallback `nmap -sT` (runner-sudo historically fragile).
- **Exposure emission is NOT source-conditional:** fires unconditionally even on cached ports — no "re-probe first" gate that could swallow the finding.
- **Intensity split:** `light` = discovery-cache-only (no fresh probes; bounded by 24h discovery cadence — light doesn't role-narrow so the small gap is acceptable for a ~5-min scan). `medium`/`heavy` = full baseline.
- **Asymmetry rule (from HOST_CHARACTERIZATION ruling 1):** targeting may *expand* coverage freely; may *narrow below baseline* **never**. **Baseline ALWAYS runs regardless of kind_confidence; kind narrows only the ADDITIONAL role-specific probes on top of baseline, never the baseline itself.** (Guards the low-confidence-web-host-with-open-3389 case.)

## 6. Exposure-is-the-finding (ruling 3: direction right, auth-modifiable)
For network-role services, internet exposure IS the finding — emitted at the two-column severity (§4) **before** any CVE check. **Exposure ⟂ CVE coexistence:** an exposed BlueKeep-vuln RDP is BOTH a HIGH exposure finding AND a CRITICAL CVE finding — **distinct `check_name`, distinct rows, distinct remediation** (close port vs. patch). `UPSERT_FINDING_SQL` must **preserve-higher-severity** so a later CVE upgrade can't clobber the exposure row and vice-versa — **verify current UPSERT semantics; add a test if not covered** (fleet-scale race #3).

## 7. Delivery axis — WAF/hosting-aware "HOW" (ruling 4: gate right, add runtime defense)
Profile = *what* to run; this = *how* to deliver. Reads `waf.vendor` + GCP membership.

**GCP/Cloud-Armor no-VPN branch** (absorbs old #3): confirmed-Armor **and** no throttling → `use_vpn=false` + GCP profile modifier (no tunnel, higher rate, Armor-tuned payloads). Rationale: Armor is signature-based, not IP/rate/UA (proven prosalud: 17,776 req + 40 rapid + all scanner UAs, zero throttle); the tunnel is pure downside (also the medium hard-fail class). Same `vpn_decision` hook as the Pressable **force-VPN** block, inverse condition. Pressable block stays as-is.

**Bulletproof Armor gate (3 signals, before ever skipping VPN):**
1. Passive: IP ∈ Google ranges (`https://www.gstatic.com/ipranges/goog.json`, cached by syncToken) + `via: 1.1 google` + cert issuer `O=Google Trust Services`.
2. Active: `<script>alert(1)</script>` → **HTTP 400** with Google *"your client has issued a malformed or illegal request"* body (Armor blocks with 400, not 403). **Store the exact matched block-string in `scan_run_artifacts` on every gate pass** → signature-drift detectable. **Weekly canary** against a known-Armor target to catch Google changing the body text.
3. Gate-time rate probe: **10 requests @ 5 req/s, benign `GET /` normal Mozilla UA, against the attack-face URL.** Any 4xx/5xx that isn't a normal 404 → **keep VPN.** Cache gate result per-target, **24h TTL** (fleet-scale: 27 hosts × 10 probes else per scan).

**Runtime abort-and-re-route (ruling 4 — NON-NEGOTIABLE, lands in P2):** the 10-req gate proves "small burst OK," not "5,000-req scan OK" — an adaptive policy throttling at request 200 is invisible to it. So during a no-VPN scan, if 429/challenge/throttle exceeds **~5% of requests** → **ABORT the scan_run, re-queue with `force_vpn=true`, log the adaptive-throttle to the target's delivery metadata** (re-cache "keep VPN" until re-evaluated). The gate is not the only defense.

**Armor payload modifiers** (rotation is useless → payload shape is the lever): double-encoding (beats Armor's traversal rule), JSON-wrapped SQLi, **PUT/PATCH + >8KB body** (Armor inspects ~8KB of POST only), content-type confusion (WAFFLED/HTTP-Normalizer), **serverless/origin hunt** (`*.run.app` default URL bypasses LB+Armor). **FortiGate/rate-based WAFs keep VPN+rotation** (opposite profile — bans by content/TLS-fingerprint per IP).

## 8. Profile representation & the validated-SHA regime (ruling 5)
Scan behavior must be `f(git SHA, target)` (ADR-001 validated-SHA regime). A hot-editable matrix breaks it (same SHA, different behavior after an edit). Therefore:
- **`scripts/scanner/matrix/roles.yaml` in-repo = source of truth** — PR-reviewed, versioned with code, part of the validated-SHA promotion gate.
- **Portal displays it read-only** (materialized DB mirror synced on deploy). A "propose matrix change" UI can open a GitHub PR from the operator session (merge stays human-gated) — not P1.
- **Operator escape hatch:** `assets.scan_overrides` jsonb — per-asset temporary pack disable/enable (e.g. "skip wpscan on fragile customer-portal"), auditable via `admin_audit_log`, reversible, doesn't touch the base matrix.
- **Matrix-version stamping:** each `scan_run` records the git SHA of `roles.yaml` at scan-start into `scan_run_artifacts` (reproducibility; guards "matrix PR merged mid-scan" — running scan uses process-loaded matrix, next scan uses new).
- **Loader validates once per Python process** (module-level: shape, engine refs exist, `exposure_severity ∈ valid set`) → scanner **fails LOUD at startup** if invalid, never mid-scan (fleet-scale #4).

## 9. Cross-engine execution — LINKED RUNS (ruling 6)
One `scan_run` per engine invocation (NOT one merged run). Add `scan_run.parent_run_id uuid null` (or reuse `scan_queue.correlation_id`). Each engine run: own `scanner_version`, `tools_run`, `tool_status`, `scan_quality`; **set-equality `tools_run == tool_status.keys()` holds per-run.** Why not merged: independent per-engine SHA validation; independent degradation (http WAF-ban shouldn't kill network coverage); independent reporting cadence (http ~5min emits without waiting on network ~30min); `note-127` source map already keys off `scan_run.source`.
- **delta_close/regress scope stays per-child-run per-source** (round-6 SQL already does this — a `commandsentry_medium` run doesn't delta-close a `commandsentry_network` finding). **Verify no code path forces delta_close at parent granularity** (fleet-scale race #1).
- **Portal rolls up children under `parent_run_id`; parent `scan_quality` = worst-of-children** (any child degraded → parent degraded, shown prominently — guards "engine skipped via missing dep displays clean").

## 10. Dispatcher (per-host assembly, at scan-time from current data)
1. Read discovery (services/fingerprint/kind/waf/hosting). 2. **Baseline** (§5). 3. **Profiles** = union of matched matrix rows, split by engine. 4. **Delivery** decision (§7). 5. **Intensity** tunes depth (light=baseline-cache-only; medium=baseline+primary packs; heavy=baseline+all matched packs+evasion/fuzz). 6. Emit exposure findings immediately; run packs on their engines as linked runs; close_out with trust-layer invariants.
- **Engine-side batching (fleet-scale #2):** the network engine runs **ONE nmap NSE invocation covering all matched network packs**, not a subprocess-per-pack. A DC with `[22,25,88,135,139,389,445,3389,5985]` unions 6+ packs → one batched run, not six.

## 11. Schema
`scan_intensity_t` unchanged. NEW: `scan_run.parent_run_id uuid null` (linked runs); `scan_run.scan_profile text[]` (assembled pack set, provenance) **with a GIN index** (fleet-scale #6 — portal filters `'rdp' = ANY(scan_profile)`); `assets.scan_overrides jsonb`. Matrix-version → `scan_run_artifacts`. Engines: run_light/medium/heavy.py = **http engine** at 3 intensities; add `run_network.py`, later `run_dast.py`. Reuse close_out / mark_tool_skipped / degradation / size-hash catch-all calibration / Armor-400 block-detection.

## 12. Fleet-scale guards (consolidated — all required)
1. Cross-engine delta_close race → per-child-run per-source scope; no parent-granularity delta_close.
2. Multi-role union blowup → engine-side batching (one NSE run).
3. Exposure↔CVE severity race → preserve-higher UPSERT + test.
4. YAML compile cost → validate-once-per-process, fail-loud at startup.
5. Rate-probe cost → 24h per-target gate cache.
6. `scan_profile[]` portal filter → GIN index.

## 13. Silent-narrowing guards (consolidated — a profile must NEVER cut below baseline)
1. Low-confidence kind → **baseline always runs regardless of confidence**; kind narrows only additional probes (§5).
2. Unmatrixed port → generic-exposure fallback (§4).
3. Discovery staleness on cached ports → force fresh sweep >72h (§5).
4. No-VPN adaptive under-scan → runtime abort-and-re-route (§7).
5. Engine skipped via missing dep → parent scan_quality = worst-of-children (§9).
6. Matrix PR merged mid-scan → matrix-version stamped per run (§8).

**Biggest stacked risk (do NOT defer any fix past P2):** a low-confidence-kind host on GCP-Armor infra passes the no-VPN gate, hits adaptive throttling mid-scan, and its profile narrowed baseline away because "kind said web-spa" — three silent-failure classes stacking. Guarded by three P2 fixes together: **(a) baseline always runs; (b) runtime abort-and-re-route; (c) parent-degradation rollup.**

## 14. Phasing (ruling 7: right order + 2 additions)
- **P0 (now):** scanner edits #1 (Armor 400-block detection) + #2 (size/hash catch-all calibration) — independent wins, pure code-tighten.
- **P1:** matrix + dispatcher + **universal baseline (precisely: discovery-read ports + fresh TLS/headers/DNS, staleness-gated, light=cache-only)**, on the existing `http` engine at current intensities. Proves matrix machinery before a new engine exists.
- **P2:** GCP/Armor detector + `vpn_decision` no-VPN branch + Armor payload modifiers **+ runtime abort-and-re-route + parent-degradation rollup** (all three biggest-risk fixes here, none deferred).
- **P3:** `network` engine (RDP/SMB/SSH/DB/mail) — largest coverage expansion; linked-runs model keeps it stateless from http.
- **P4:** `dast` engine (browser/auth'd) — waits on auth creds (~next week).
- Fleet-wide black-box scan re-runs on top of P1–P3 as they land.

## 15. Open questions — resolved by 4.7
Q1 profile repr → §8 (repo YAML source-of-truth + read-only portal mirror + scan_overrides). Q2 mail engine → §2 (stays in network). Q3 intensity×profile depth → §10 (light/medium/heavy depth ladder). Q4 exposure severity → §4/§6 (two-column auth-modified). Q5 baseline cost → §5 (discovery-read + staleness gate + light=cache-only). Q6 rate-probe safety → §7 (10 req @ 5 rps, 24h cache) + runtime abort. Q7 cross-engine close_out → §9 (linked runs). All closed.
