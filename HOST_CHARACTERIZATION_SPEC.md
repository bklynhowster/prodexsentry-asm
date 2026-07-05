# Host Characterization Redesign — Spec v2 (post-4.7 rulings)

**Status:** Ruled by 4.7 2026-07-05 · GO for Phase A with 6 pre-build revisions (all folded in below)
**Scope:** scanner (`*-asm`) + portal. **Prodex first**, port to Command.
**Origin:** 2026-07-04 Medium drain — docs/preview/azure-demo each degraded for a different reason because Medium scans every host identically.
**This version** incorporates all rulings ①–⑬ and the 13 holes. See §17 for the ruling→section map. Changes from v1 are marked `[R#]` / `[H:§]`.

---

## 1. Problem
Medium scans **every** host as `https://<host>:443/` at root, one tool set, blanket root-probe health. It never asks what a host *is*. Observed 2026-07-04: `preview` (API, 404 at root) killed by nikto; `docs` (live Vercel docs, root 308-redirects) timed out nuclei on the shell; `azure-demo` (dead Front Door, 504) scanned instead of flagged. And `confirmed_live` only means "DNS resolves," not "serves an app."

## 2. Key insight — the data already exists
Daily discovery scan (engine 3.0.0) already runs naabu/fingerprintx/httpx(redirect-following)/wafw00f and stores per-host `reachability{live,http_status,title}`, `fingerprint{tech[],server}`, `waf{vendor,detected}`, `services[{port,service,tls}]`, `dns`, `hosts[{asn}]` in `asset_surface.surface_data.subdomains[]` (with a top-level `schema_version`). This is a **derive-and-wire** problem. `asset_kind_t` already exists (`web/portal/api/mail/ftp/staging/infra/unknown`); add `redirect` + `dead`.

## 3. Goals / Non-goals
**Goals (v1 Full):** derive `kind` fleet-wide; branch Medium on kind (target/tools/health); dead→finding; portal surfacing; per-kind profiles.
**Non-goals (v1):** new discovery tooling; ML classification; active API fuzzing `[R⑫]`; touching the discovery engine.

## 4. Data model
Extend `asset_kind_t` with `redirect`, `dead`. `kind` holds the **functional** kind only.

**Staging is a modifier, not a kind `[R H:§5.7]`:** add `is_staging boolean`. The legacy enum value `staging` is deprecated — the 4 currently-`staging` assets re-derive to their functional kind + `is_staging=true`. (Enum value stays for back-compat; derivation never writes it.)

New columns on `assets`:
| column | type | notes |
|---|---|---|
| `scan_url` | text NULL | resolved canonical/redirect target — set **only** if target is an owned asset `[R④]` |
| `kind_confidence` | **enum** `kind_conf_t (high\|medium\|low)` + CHECK `[R⑦]` | not text |
| `kind_source` | text `derived\|manual` | `manual` never overwritten by derivation |
| `kind_evidence` | jsonb | the signals used **+ `surface_schema_version` stamped at derive time** `[R⑦]` |
| `kind_updated_at` | timestamptz | |
| `kind_drift` | boolean `[R⑤]` | true when `derived≠manual AND derived confidence=high` |
| `is_staging` | boolean `[R H:§5.7]` | non-prod modifier |

## 5. Derivation rules — ordered, first match wins (revised per holes)

**Rule 0 — schema gate `[R⑨]`:** read `surface_data.schema_version`. Unknown version → **log + skip** (do not derive; leave prior `kind`). Explicit per-version support required.

**Rule 1 — dead `[R②][H:§5.1]`:** `reachability.live == false` **OR** `http_status` in the 5xx-class `{500,502,503,504,520,521,522,523,524,525,526,527}` (Cloudflare 52x widened; **title-match dropped** — vendor-fragile). Label `dead` at `high` confidence **only** with the temporal gate: **≥3 consecutive dead-signal discovery observations**. <3 → `dead` at `low` + admin flag, not yet trusted. (Scan-claim confirmation probe is a separate spatial gate, §8.)

**Rule 2 — live HTTP present → HTTP-kind branch (before mail/ftp `[R H:§5-order]`):** if any live HTTP service:
- **WAF-refused first `[R H:§5.4]`:** `waf.detected==true AND http_status==403` → not `api`; treat as WAF-gated, fall through to web/portal shape on the underlying signal (a 403 from a WAF ≠ an API deny).
- **portal before web `[R H:§5.6]`:** `http_status==401` OR login-form/auth markers → **`portal`**.
- **api:** `http_status==403` (non-WAF) OR (`http_status==404` AND `title` null AND no HTML/CMS tech) OR JSON content-type at root → **`api`** (raise to high on JSON/api-path corroboration).
- **redirect `[R④][R H:§5.2]`:** root is 3xx to a **different eTLD+1** (not just different hostname — apex→www is internal, stays `web`) → **`redirect`**. Set `scan_url = target` **only if** target resolves to an `ownership='owned'` asset; else `scan_url=NULL`, disposition = shell-only, emit INFO "root redirect to off-scope target `<t>`; not followed."
- **web `[R H:§5.5]`:** 2xx, or 3xx→own path, with `title` non-empty **AND** (`content_length > THRESHOLD` OR HTML body observable) — guards SPA `title="Loading…"`. If root 3xx→own canonical, `scan_url = canonical`. → **`web`**.

**Rule 3 — no live HTTP:** mail ports (25/465/587/993/995) dominant → `mail`; port 21 → `ftp`; other non-HTTP services → `infra`; nothing → `unknown`.

**Rule 4 — staging modifier:** set `is_staging` from hostname/tag conventions, independent of `kind`.

**Rule 5 — unknown fallback `[R③]`:** couldn't classify → leave `kind=unknown`; Medium gives it **today's full-web behavior**, tags findings `kind_unknown`, and raises an admin-queue flag. "If we can't classify, we scan." Loud, not silent.

Hostname is **corroborating only, never decisive** (azure-demo/preview proved names lie).

## 6. Derivation step
`scripts/normalize/derive_asset_kind.py`: reads `surface_data` → §5 → writes `kind` + `scan_url` + `kind_*` + `is_staging`. Version-gated `[R⑨]`. Idempotent. Never overwrites `kind_source=manual`; instead sets `kind_drift` when derived disagrees at high confidence `[R⑤]`. Runs as one-time **backfill** + after each discovery scan.

## 7. Kind-aware Medium — scan profiles
`run_medium.py` reads `kind`/`scan_url` from the descriptor and branches:

| kind | target | tools | notes |
|---|---|---|---|
| `web` | `scan_url` or `https://host/` | full (nuclei-web, nikto, ffuf, katana) | **must be code-verified byte-equivalent to today** `[R H:§7-web]` — no silent regression on the fleet majority |
| `api` | `scan_url` or root | nuclei(exposures/tech); **no** nikto, **no** ffuf dir-brute, **no** active fuzz (v1.1) `[R⑫]` | fixes preview |
| `portal` | login URL | web templates, **GET/HEAD/OPTIONS only unless overridden**, template-tag exclusion list, **no auth attacks** `[R H:§7-portal]` | |
| `redirect` | — | **shell-only: TLS + headers, no follow** `[R⑪][H]` | target is scanned by **its own** Medium (own scan_run_id / risk clock / auto-close); display grouping via cluster view (note-118). fixes docs |
| `dead` | — | **skip via `mark_tool_skipped` for every planned tool** `[R H:§7-dead]` | must be a clean path through `close_out` so `tools_run == tool_status.keys()` set-equality holds and the trust-layer still sees an emitting scan (heavy learned this at P4). Skip ≠ omit. |
| `mail/ftp/infra` | service | service checks only | out of Medium HTTP scope |

## 8. Kind-aware health (supersedes blanket root probe; folds task #6)
- **At-scan-time refresh `[R①]`:** before branching, probe `scan_url` (or `https://host/`). **N-probe mandate `[R H:§8]`: 3 probes, 3s apart, 2-of-3 threshold** — no single-ping verdicts.
- **Asymmetric disagreement `[R①]`:** stored `dead` but probe returns **any** HTTP → coverage-*expanding*, safe → run today's blanket web scan **this run** + emit `kind_stale_at_scan` + flag re-derive. Stored `web` but probe times out → coverage-*contracting*, unsafe → **do NOT auto-flip to dead**; proceed with stored profile.
- **Scan-claim dead confirmation `[R②]`:** a `dead`-labeled host gets a fresh probe at claim; any "live" → escalate to full web scan + re-derive. (Temporal gate §5.1 + this spatial gate = both required before dead ever gates scanning.)
- **Reachability taxonomy (task #6):** separate **banned** (403/429 **+ a concrete challenge signal** — vendor challenge-body substring / JS-challenge script / challenge cookie; starting set: Cloudflare `cf-chl`, FortiGate `fwbbot`, Akamai `_abck`) from **unavailable** (5xx/timeout) from **normal-for-kind** (api 404 = healthy; api 5xx = degraded; api 2xx = healthy) `[R H:§7-api]`.
- **DNS multi-answer `[R H:§8]`:** reason about which resolved IP was actually reached (round-robin/geo-DNS can look dead from one runner IP, live from another) — don't declare unavailable on a single-IP miss when other A-records exist.

## 9. Dead-endpoint finding
Check `dead_endpoint`, severity **LOW `[R⑬]`** (resolvable-but-non-serving = subdomain-takeover setup, not hygiene); **MODERATE** only if takeover-ready (CNAME to a public-take provider with no active claim). Emitted for `kind=dead` once the §5.1 temporal gate is met. Remediation: decommission the DNS record or restore origin.

## 10. Portal surfacing
Per-asset **kind chip** (+ confidence + evidence tooltip) and a **`kind_drift` chip** `[R⑤]`. Fleet **kind breakdown** on dashboard. Filter/group by kind. Shared portal code → both deployments.

## 11. Migrations — two files, decoupled `[R⑥]`
1. **`NNNN_asset_kind_enum_and_cols.sql`** — `ALTER TYPE asset_kind_t ADD VALUE 'redirect'; ADD VALUE 'dead';` + create `kind_conf_t` + add the §4 columns. **No BEGIN/COMMIT wrap around `ADD VALUE`.** Applied + committed **before** any code that writes the new values (same pattern as `history_status_t`, schema.sql L72).
2. Code deploy (derivation + backfill + branching) lands after (1) is live.

## 12. Phased rollout
- **Phase A — derive + backfill + portal surfacing. NO scan-behavior change `[R⑧]`.** Ship the 6 pre-build revisions (below). Eyeball the 25 labels; run **one Medium against a `dead`-labeled host with today's behavior** to bank the baseline. This scan-behavior-neutrality is the first line of defense against the biggest risk — do not erode it.
- **Phase B — kind-aware Medium** (§7–8 branching). Validate on docs/preview/azure-demo + a `web` regression host.
- **Phase C — dead-as-finding + auto-drop, gated `[R⑩]`:** auto-drop a `dead` host from the fleet only on **≥N consecutive dead observations + age ≥X days + a human-visible admin action**. Never auto-drop on first classify.

### Phase A — the 6 required pre-build revisions (all folded above)
1. Version-gate derivation vs `schema_version` `[R⑨]` — §5 Rule 0, §6.
2. Redirect-target ownership guard on `scan_url` `[R④]` — §5 Rule 2, §4.
3. Multi-observation gate + confirmation probe for `dead` `[R②]` — §5.1, §8.
4. Kind-drift surface for manual overrides `[R⑤]` — §4, §6, §10.
5. Fix §5.6 portal-before-web ordering `[R H:§5.6]` — §5 Rule 2.
6. Reconcile staging as modifier not kind `[R H:§5.7]` — §4, §5 Rule 4.

## 13. Validation
Derivation: the 25 classify sanely; known 4 land web/api/web(redirect)/dead; every `unknown` spot-checked. Medium (Phase B): docs scans canonical & completes, preview skips nikto & completes, azure-demo skipped+finding, a `web` host **byte-identical** to today. `dead`-skip path proven clean through `close_out` (set-equality intact).

## 14. Cross-instance
Prodex first. Port scanner + migration to `commandsentry-asm`; **version-gate `[R⑨]`** — do not assume Command's `surface_data` schema_version matches; refuse-and-log on unknown. Portal change ships to both (shared code).

## 15. Open product decisions — RULED
⑩ dead: flag first, auto-drop later (gated). ⑪ redirect: light shell + target as own asset (cluster view for display). ⑫ api: conservative v1, fuzzing→v1.1. ⑬ dead_endpoint: LOW (MODERATE if takeover-ready).

## 16. (superseded — see §17 ruling log)

## 17. Ruling application log (traceability — cite `[R#]` in code comments)
- **① refresh** → §8 (at-scan probe, N-probe, asymmetric disagreement).
- **② dead gate** → §5.1 (temporal ≥3 obs) + §8 (scan-claim confirmation).
- **③ unknown** → §5 Rule 5 (full-web + kind_unknown tag + admin flag).
- **④ redirect scope** → §4 (scan_url owned-only) + §5 Rule 2 (off-scope shell-only + INFO).
- **⑤ drift** → §4 (`kind_drift`) + §6 + §10 (chip).
- **⑥ migration** → §11 (two decoupled files).
- **⑦ columns** → §4 (`kind_confidence` enum+CHECK, `surface_schema_version` in evidence).
- **⑧ don't move dead-skip up** → §12 Phase A neutrality preserved.
- **⑨ version-gate** → §5 Rule 0, §6, §14.
- **⑩ auto-drop gate** → §12 Phase C.
- **⑪ redirect depth** → §7 (shell-only; target = own asset).
- **⑫ api conservative** → §7 + §3 non-goals.
- **⑬ severity** → §9 (LOW/MODERATE).
- **Holes:** §5.1 (drop title, widen 5xx), §5.2 (eTLD+1), §5.4 (401≠403, WAF-first), §5.5 (title+body), §5.6 (portal before web), §5.7 (staging modifier), §5-order (HTTP before mail/ftp), §7 (redirect no-follow, api 5xx=degraded, dead skip-not-omit + close_out, portal methods, web byte-equiv), §8 (challenge concretization, N-probe, DNS multi-answer).

**Biggest risk (4.7):** a live `web` asset silently mis-derives `dead`, drops out under Phase C auto-drop, stops being scanned — invisible until incident. Rulings ②④⑤⑧⑩ all guard this. Phase A scan-neutrality is the first defense; do not erode under time pressure.
