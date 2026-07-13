PASTEABLE PROMPT FOR 4.7
========================
(Self-contained — 4.7 does not need the repo. Return numbered rulings F1–F7; correct any recommendation you disagree with.)

---

You ratified the device-class classifier earlier (D1–D7, E1–E6). E2 was: the runner inherits `device_class='cloud_endpoint'` from `assets.is_cloud_endpoint = true`, with provenance in evidence, re-derived every run. I need to correct E2 based on live data. Please rule on F1–F7.

**The bug.** `is_cloud_endpoint` is not a "cloud-hosted" flag — it's set to the cloud provider's `rotating` flag, which exists to suppress per-IP surface-diff churn for assets behind rotating IP pools (mail/CDN/edge). Provider rotating flags: o365 / Cloudflare / Akamai = true; **GCP / AWS / Azure = false**. So static cloud compute never sets `is_cloud_endpoint`, and the runner never inherits `cloud_endpoint` for it.

**Proven against live Prodex data** (Prodex = all static GCP; ran the shipped classifier over the real 27-asset ASM doc):
- `cloud_provider` stamped: **27/27** (gcp 24, azure 1, aws 1, akamai 1) — provider detection is perfect.
- `is_cloud_endpoint = true`: **2/27** — and both are genuine CDN edges (one CNAME `...azurefd.net` = Azure Front Door via a rotating override; one Akamai). NOT compute.
- `is_cloud_endpoint = false`: **25/27**, including all 24 GCP compute assets.
- So as-is, the device-class dry-run would label ~2 assets `cloud_endpoint` and leave ~24 GCP apps at `unknown`. The provider stamping lands; the topology classification doesn't.

**Root cause:** two axes were conflated. `is_cloud_endpoint` = "behind a rotating pool → suppress churn" (a scanning/observability concern). `device_class='cloud_endpoint'` = a topology role ("managed cloud endpoint, not a bare origin or appliance"). A static GCP VM is a cloud endpoint by topology even though its IP doesn't rotate.

**Requested rulings (my recommendation in brackets — override freely):**

- **F1 — Inheritance signal.** Key device-class cloud topology on `cloud_provider IS NOT NULL` (cloud-hosted), not `is_cloud_endpoint = true` (rotating pool). [Recommend: yes.]

- **F2 — Class mapping.** Use both flags: `cloud_provider` set + `is_cloud_endpoint=false` (static compute: GCP/EC2/Azure-VM) → `cloud_endpoint`; `cloud_provider` set + `is_cloud_endpoint=true` (rotating edge: Cloudflare/Akamai/CloudFront/Azure Front Door/o365) → `cdn`. [Recommend: this split. Alternative: all `cloud_provider` → `cloud_endpoint` for a simpler v1 — your call.]

- **F3 — Precedence vs appliance/WAF/edge fingerprints.** When a decisive appliance/waf/edge fingerprint AND a `cloud_provider` are both present, which wins? [Recommend: fingerprint wins — run the fingerprint classifier first, fall back to cloud. "A WAF hosted on GCP is still a WAF." This reverses E2's cloud-first ordering — flagging explicitly.]

- **F4 — Confidence.** Inherited `cloud_endpoint` is currently `confidence='confirmed'`. Classifier tiers: CNAME > ASN/ASN-org > IP-prefix; most GCP assets match by ASN-org. [Recommend: CNAME or ASN/ASN-org = confirmed (ASN ownership is authoritative); IP-prefix-only = suspected.]

- **F5 — Leave `is_cloud_endpoint` alone.** Don't change the flag's meaning or its churn-suppression consumer; device-class just stops using it as the key. [Recommend: yes — change isolated to the runner's `classify_asset`.]

- **F6 — Both instances.** Command has the same latent gap (only its o365/rotating cloud asset classified). Apply to both repos; `cloud_provider` is enum on Command / text on Prodex but `IS NOT NULL` is identical. [Recommend: yes, parity.]

- **F7 — Routing (D4).** Confirmed `cloud_endpoint` on static GCP means Phase-B D4 would route them as cloud. Does `cloud_endpoint` get its own ROE (e.g., don't port-scan managed cloud IPs) or "scan normally"? [Recommend: defer ROE to Phase B; acknowledge now. Current soak is classify-only, so stamping is safe.]

If you'd prefer I keep v1 minimal — all `cloud_provider` → `cloud_endpoint`, keep cloud-first ordering, defer F2's cdn-split and F3's precedence flip to a follow-up — say so and I'll scope it that way.

Return F1–F7 as numbered rulings.
