# Device-class cloud inheritance — signal-mismatch fix (for 4.7)

**Status:** finding proven against live Prodex data; requesting numbered rulings before any code.
**Date:** 2026-07-13
**Scope:** `scripts/db/device_class_runner.py` (`classify_asset`), both instances. No schema change.
**Related prior rulings:** E2 (cloud inheritance), D2/D3 (classifier + confidence bar), D4 (confirmed-only routing). This proposes a correction to **E2**.

---

## TL;DR

The device-class runner inherits `device_class='cloud_endpoint'` **only when `assets.is_cloud_endpoint = true`** (`classify_asset`, runner line 172). But `is_cloud_endpoint` is set to the cloud provider's **`rotating`** flag — a *churn-suppression* signal, not a *cloud-hosted* signal. Static cloud compute (GCP VM, EC2, Azure VM) is `rotating:false`, so it never inherits `cloud_endpoint`. On Prodex — which is all static GCP — that means the classifier recognizes the provider on 27/27 assets but marks only 2 as `cloud_endpoint`; the 24 GCP assets fall through to `unknown`.

The fix keys device-class cloud topology on `cloud_provider` (is the asset cloud-hosted?) instead of `is_cloud_endpoint` (is it behind a rotating pool?). Requesting rulings F1–F7 below.

---

## The finding (proven, not theoretical)

Ran the shipped classifier (`scripts/normalize/derive_cloud_endpoint.py` + `scripts/asm/cloud_providers.yaml`) against Prodex's real ASM data (`data/assets/prodexlabs.json`, 27 subdomains) — the same input the importer feeds on the next `asm-discover`:

| metric | count |
|---|---|
| `cloud_provider` stamped | **27 / 27** (gcp 24, azure 1, aws 1, akamai 1) |
| `is_cloud_endpoint = true` | **2 / 27** |
| `is_cloud_endpoint = false`, provider known | **25 / 27** (incl. **all 24 GCP**) |
| no classification | 0 |

Per-asset evidence (why each flag lands where it does):

| asset | provider | is_cloud_endpoint | reason |
|---|---|---|---|
| `prodexlabs.com` | gcp | **false** | ASN AS396982 (Google), no CNAME → static compute |
| `atlantis-gcp.prodexlabs.com` | gcp | **false** | Google ASN, static |
| `docs.prodexlabs.com` | aws | **false** | CNAME `cname.mintlify-dns.com`, Amazon ASN → static |
| `azure-demo.prodexlabs.com` | azure | true | CNAME `...z02.azurefd.net` → matches `.azurefd.net` rotating override (Azure Front Door = CDN) |
| `link.prodexlabs.com` | akamai | true | Akamai (`rotating:true`) — email-tracking edge |
| …20 more GCP… | gcp | **false** | static Google compute |

The only two `true` results are genuine **rotating CDN edges** (Azure Front Door, Akamai) — not compute. Every static-compute asset (all GCP, the AWS/Mintlify one) is `false`. The flags are behaving exactly as designed — the design just isn't the signal device-class wants.

**Live consequence if we dispatch as-is:** `asm-discover` → importer stamps `cloud_provider` on 27/27 (good), but the device-class dry-run inherits `cloud_endpoint` on only ~2 and leaves ~25 (all the GCP apps) at `unknown`. Not the outcome the port was for.

---

## Root cause — two different axes conflated

`cloud_providers.yaml` header (lines 11–14) defines the flag explicitly:

```
#   rotating: true   -> asset gets is_cloud_endpoint=true (per-IP surface changes are
#                       pool churn — suppress). Reserve for providers that front an
#                       asset behind a large ROTATING IP pool (mail / CDN / edge).
#   rotating: false  -> cloud_provider is recorded for context, but is_cloud_endpoint
#                       stays false.
```

So `is_cloud_endpoint` answers **"is this behind a rotating IP pool, so suppress per-IP surface-diff noise?"** It is a scanning/observability concern. Provider rotating flags: `microsoft_o365`, `cloudflare`, `akamai` = true; `gcp`, `aws`, `azure` = false.

`device_class='cloud_endpoint'` is a **topology role** — "this asset is a managed cloud endpoint, not a bare origin or an appliance." A static GCP VM is a cloud endpoint by topology, regardless of whether its IP rotates.

`classify_asset` (runner line 172) borrowed the churn flag as the topology key:

```python
def classify_asset(cur, a, fps, th, fresh_days, nuclei_re):
    if a["is_cloud_endpoint"]:                      # <-- rotating-pool flag, not "cloud-hosted"
        ... return device_class='cloud_endpoint', confidence='confirmed' ...
    return classify(gather_observations(...), fps, th)   # else fingerprint path -> unknown for GCP
```

Command didn't expose this because the Command cloud asset that classified (`email.commandcompanies.com`) is o365 = `rotating:true`. Prodex being all static GCP is what surfaced it — the reconciliation working on the primary instance is the whole reason the port mattered.

---

## Proposed fix + decision points (please rule F1–F7)

### F1 — Change the inheritance signal
Gate device-class cloud topology on **`cloud_provider IS NOT NULL`** (asset is cloud-hosted), not `is_cloud_endpoint = true` (asset is behind a rotating pool).
**Recommend: yes.** It's the correct axis for a topology role and turns 27/27 Prodex assets cloud-aware.

### F2 — Map to the right class (cloud_endpoint vs cdn)
The two flags together already encode the topology, so don't collapse them:
- `cloud_provider` set **AND `is_cloud_endpoint = false`** (static compute: GCP / EC2 / Azure VM) → **`cloud_endpoint`**
- `cloud_provider` set **AND `is_cloud_endpoint = true`** (rotating edge: Cloudflare / Akamai / CloudFront / Azure Front Door / o365) → **`cdn`**

**Recommend: this two-way split.** Evidence: the only 2 `true` Prodex assets are a CDN front and Akamai — labeling them `cloud_endpoint` would be wrong; they're `cdn`. (`cdn` already exists as a role and Pressable maps to it.)
**Alternative if you prefer simpler v1:** all `cloud_provider` → `cloud_endpoint`, ignore the cdn split for now. Your call.

### F3 — Precedence vs appliance / WAF / edge fingerprints
Today cloud inheritance runs **before** the fingerprint classifier (L172 before L179), so cloud wins. But an asset can be cloud-hosted **and** fronted by a WAF/appliance (e.g., a GCP app behind Cloudflare WAF; a Fortinet on a cloud IP). Question: when a decisive appliance/waf/edge fingerprint **and** a `cloud_provider` are both present, which `device_class` wins?
**Recommend: fingerprint wins — run `classify()` first, fall back to cloud inheritance.** "A WAF hosted on GCP is still a WAF"; the appliance/edge role is the more specific, more scan-relevant topology. This **reverses E2's cloud-first ordering** — flagging explicitly.

### F4 — Confidence calibration
Inherited `cloud_endpoint` is stamped `confidence='confirmed'`. Classifier tiers (strongest first): CNAME suffix > ASN/ASN-org > IP-prefix. Most Prodex GCP assets match by **ASN-org** (`google llc` / AS396982 / AS15169).
**Recommend: CNAME or ASN/ASN-org match = `confirmed`; IP-prefix-only = `suspected`.** ASN ownership is authoritative (it *is* Google's ASN), so ASN-org earns confirmed; a bare IP-prefix guess doesn't. Calibrate as you see fit.

### F5 — Leave `is_cloud_endpoint` alone
Do **not** change `is_cloud_endpoint`'s meaning or its existing consumer (surface-diff churn suppression). Device-class simply stops using it as the topology key and reads `cloud_provider` (optionally the flag to split cloud_endpoint vs cdn per F2).
**Recommend: yes — no change to the flag or its consumers; this stays isolated to `classify_asset`.**

### F6 — Both instances
Command has the same latent gap (its static-cloud assets, if any, also mis-stay `unknown`; only the o365 rotating ones showed). Apply the fix to **both** repos. Command `cloud_provider` is the `cloud_provider_t` enum, Prodex is `text` — `IS NOT NULL` behaves identically on both, no divergence.
**Recommend: yes — parity, same commit set.**

### F7 — Routing (D4) implication — acknowledge now, specify in Phase B
Marking 24 GCP assets confirmed `cloud_endpoint` means when Phase B routing turns on, D4 routes them as cloud. Does `cloud_endpoint` get its own ROE (e.g., "don't naabu-port-scan managed cloud IPs — shared provider infra / abuse-detection risk"), or is it "scan normally, it's just a host on GCP"?
**Recommend: defer the ROE specifics to Phase B, but acknowledge the consequence now** so the soak data reads correctly. The current soak is classify-only (nothing routes), so it's safe to stamp during the soak.

---

## Blast radius / safety
- Change is confined to `classify_asset` in `device_class_runner.py` (plus evidence-provenance fields to record which signal/tier drove it). No schema change, no migration.
- Soak is classify-only (D4 confirmed-only routing not active) → stamping more `cloud_endpoint` during the soak changes **no** scan behavior; it only makes the dry-run/soak audit meaningful on Prodex.
- `is_cloud_endpoint` and its churn-suppression consumer untouched (F5).

## Test plan (post-ruling)
1. Unit: extend the runner self-test — feed the 4 archetypes (GCP static → cloud_endpoint/confirmed; AWS-static → cloud_endpoint; azurefd/akamai → cdn per F2; GCP-behind-appliance-fingerprint → appliance wins per F3).
2. Local dry-run vs `prodexlabs.json`: expect 24 → cloud_endpoint, 2 → cdn, 1 aws → cloud_endpoint (27/27 cloud-aware, 0 unknown-from-cloud).
3. Live Prodex dry-run after next `asm-discover`: confirm the DB matches the local prediction; check `device_class_dryrun` rows + provenance/confidence.
4. Command regression: confirm o365/rotating assets still classify (now possibly re-labeled cdn per F2 — expected, note in soak report) and nothing else moves.

## Open question for you (beyond F1–F7)
F2's cdn split and F3's precedence flip are the two with real downstream reach. If you'd rather I keep v1 minimal (all cloud_provider → cloud_endpoint, keep cloud-first ordering) and defer cdn-split + precedence to a follow-up, say so and I'll scope it that way.
