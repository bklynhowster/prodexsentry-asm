-- ============================================================================
-- MIGRATION — 2026-07-06b — finding_source_t += 'commandsentry_exposure'
--
-- Targeted-scan P1a (TARGETED_SCAN_ARCHITECTURE_SPEC.md §6). Adds a DISTINCT
-- finding source for the exposure-is-the-finding rows emitted by run_medium's
-- new decision layer (internet-exposed RDP/SMB/DB/... = a finding by presence).
--
-- WHY A DISTINCT SOURCE (isolation, not cosmetics):
--   exposure findings must NEVER be false-closed. Giving them their own source
--   isolates them from BOTH auto-closers with ZERO edits to those trust-critical
--   functions:
--     1. delta_close_for_scan_run / regress_observed_for_scan_run are SOURCE-
--        SCOPED to f"commandsentry_{intensity}" (= commandsentry_medium here).
--        A commandsentry_exposure row is simply never in their WHERE set.
--     2. The note-127 cron (asm_autoclose_stale_findings) gates on
--        asm_autoclose_producer_patterns(source), which returns NULL for any
--        source not in its explicit map. commandsentry_exposure is absent ->
--        NULL -> ineligible -> the cron never touches an exposure finding.
--   => zero false-close path in P1a. Port-closed UX is handled by the
--   STALE/PRESUMED-REMEDIATED display-state machine (visual aging, no hard
--   close). Real exposure lifecycle arrives with the P3 network engine, which
--   will write this SAME source with its own delta_close.
--
-- ADDITIVE ONLY. Existing source values unchanged. Mirrors the proven idempotent
-- DO-block pattern from 20260528b (ALTER TYPE ... ADD VALUE, guarded by a
-- pg_enum existence check). NOT wrapped in BEGIN/COMMIT — an ADD VALUE that is
-- not USED in the same txn is fine standalone, and the DO block only adds.
--
-- Apply:
--   psql "$SUPABASE_DSN" -f scripts/db/migrations/20260706b_finding_source_commandsentry_exposure.sql
--
-- Must be applied BEFORE the run_medium build carrying the P1a wiring runs,
-- else exposure-finding INSERTs fail with:
--   InvalidTextRepresentation: invalid input value for enum
--   finding_source_t: "commandsentry_exposure"
-- ============================================================================

do $$
begin
  if not exists (
    select 1 from pg_enum
    where enumlabel = 'commandsentry_exposure'
      and enumtypid = (select oid from pg_type where typname = 'finding_source_t')
  ) then
    alter type public.finding_source_t add value 'commandsentry_exposure';
  end if;
end $$;

-- 4.7 ruling 3: correct the scan_run.matrix_version_sha comment on any instance
-- where 20260706a already applied the old "roles.yaml SHA" wording. The column
-- stamps get_scanner_version() = the whole-repo GITHUB_SHA (the matrix lives
-- in-repo under that SHA), not a per-file blob SHA. Idempotent (comment replace).
-- Safe outside a txn and does NOT use the new enum value.
COMMENT ON COLUMN public.scan_run.matrix_version_sha IS
  'git SHA of the scanner commit at scan-start (GITHUB_SHA). Reproducibility '
  'guarantee — a scan is f(commit SHA, target); the matrix lives at '
  'scripts/scanner/matrix/roles.yaml under that SHA. If per-file matrix change '
  'detection becomes a common need, add a separate matrix_yaml_sha column.';

-- ============================================================================
-- POST-APPLY VERIFICATION
--   select enumlabel from pg_enum
--   where enumtypid = (select oid from pg_type where typname = 'finding_source_t')
--   order by enumsortorder;
-- Expected: 'commandsentry_exposure' present.
--
-- Confirm it is INELIGIBLE for the note-127 cron (must return NULL):
--   select public.asm_autoclose_producer_patterns('commandsentry_exposure');
-- ============================================================================
