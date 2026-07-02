# prodexsentry-asm

Attack-surface discovery + vulnerability scanning engine for **PRODEXsentry**
(Prodex Labs). Isolated instance — writes only to the Prodex Supabase, scans
only apexes listed in `data/targets.yml` that are also marked `ownership='owned'`
in the database (ROE gate). No connection to any other deployment.

## Layout
- `scanner/` — discovery engine (asm-discover.sh), tool installer, wordlists, profiles
- `scripts/scanner/` — light/medium/heavy scan runners (Python)
- `scripts/db/` — importers + migrations (schema already applied to Prodex Supabase)
- `docker/Dockerfile` — the scanner toolbox image (built to `ghcr.io/<owner>/prodexsentry-scanner`)
- `.github/workflows/` — build-scanner-image, asm-discover, scanner

## Required secret
- `SUPABASE_DSN` — Prodex session-pooler DSN (the only secret needed for v1)

## First run
1. Push → `build-scanner-image` builds the scanner image automatically.
2. Add an authorized apex to `data/targets.yml` **and** as an `owned` asset in the portal.
3. Run **ASM Discover** (workflow_dispatch) with the target id → it chains into **scanner**.
