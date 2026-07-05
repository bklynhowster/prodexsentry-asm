-- ============================================================================
-- MIGRATION — 2026-07-05a — asset_kind_t += 'redirect', 'dead'
--
-- Part of the Host Characterization redesign (HOST_CHARACTERIZATION_SPEC.md,
-- Phase A). Adds two functional host kinds:
--   redirect — root 3xx to a DIFFERENT eTLD+1 (pure redirector shell)
--   dead     — resolves but no working backend (5xx-class / reachability
--              live=false)
--
-- Per 4.7 ruling 6: the enum ADD VALUE lands in its OWN migration, applied +
-- committed BEFORE the column migration (20260705b) and BEFORE any code that
-- writes the new values (derive_asset_kind.py). Schema change is decoupled
-- from the code deploy.
--
-- ADD VALUE constraints:
--   ALTER TYPE ... ADD VALUE cannot run inside a DO block or an explicit
--   transaction (Postgres). Top-level only — this file has NO BEGIN/COMMIT
--   wrap; psql runs each statement in its own implicit txn under autocommit.
--   Mirrors schema.sql L72 + migration 20260629c.
--
-- IF NOT EXISTS -> idempotent, safe to re-apply.
--
-- Apply with:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260705a_asset_kind_add_redirect_dead.sql
-- ============================================================================

ALTER TYPE public.asset_kind_t ADD VALUE IF NOT EXISTS 'redirect';
ALTER TYPE public.asset_kind_t ADD VALUE IF NOT EXISTS 'dead';

-- ============================================================================
-- SANITY — after apply:
--   SELECT unnest(enum_range(NULL::public.asset_kind_t));
--   -- expect: web, portal, api, mail, ftp, staging, infra, unknown,
--   --         redirect, dead
-- ============================================================================
