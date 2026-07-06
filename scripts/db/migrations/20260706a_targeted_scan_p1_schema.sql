-- 20260706a_targeted_scan_p1_schema.sql
-- Targeted-scan P1 schema — TARGETED_SCAN_ARCHITECTURE_SPEC.md §8/§11, 4.7 ruling 4c.
-- Additive + idempotent (IF NOT EXISTS). No enum changes: exposure findings reuse
-- finding_category_t='info_disclosure' (verified present). Single BEGIN/COMMIT
-- (mirrors 20260705b — no ADD VALUE, so no decoupled-file requirement).
BEGIN;

ALTER TABLE public.scan_run
  ADD COLUMN IF NOT EXISTS scan_profile text[],
  ADD COLUMN IF NOT EXISTS parent_run_id uuid
    REFERENCES public.scan_run(scan_run_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS matrix_version_sha text;

CREATE INDEX IF NOT EXISTS idx_scan_run_scan_profile
  ON public.scan_run USING GIN (scan_profile);
-- Partial: most rows are standalone (parent_run_id NULL) → keep the index small.
CREATE INDEX IF NOT EXISTS idx_scan_run_parent_run_id
  ON public.scan_run (parent_run_id) WHERE parent_run_id IS NOT NULL;

ALTER TABLE public.assets
  ADD COLUMN IF NOT EXISTS scan_overrides jsonb;

COMMENT ON COLUMN public.scan_run.scan_profile IS
  'Sorted UNION of matched role names from build_scan_plan (targeted-scan P1). '
  'Populated at plan-time; NULL for pre-P1 runs. GIN-indexed for role filtering.';
COMMENT ON COLUMN public.scan_run.parent_run_id IS
  'Linked-runs model (4.7 ruling 6): per-engine child scan_runs reference the '
  'parent. NULL for standalone runs. FK ON DELETE SET NULL.';
COMMENT ON COLUMN public.scan_run.matrix_version_sha IS
  'git SHA of the scanner commit at scan-start (GITHUB_SHA). Reproducibility '
  'guarantee — a scan is f(commit SHA, target); the matrix lives at '
  'scripts/scanner/matrix/roles.yaml under that SHA. If per-file matrix change '
  'detection becomes a common need, add a separate matrix_yaml_sha column.';
COMMENT ON COLUMN public.assets.scan_overrides IS
  'Per-asset knob to disable/enable specific packs; layers on top of the matrix. '
  'Small, auditable via admin_audit_log, reversible. NULL = matrix decides.';

COMMIT;
