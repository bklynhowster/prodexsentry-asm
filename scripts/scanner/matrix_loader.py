#!/usr/bin/env python3
"""Role/service check-pack matrix — loader + selection (P1).

Spec: TARGETED_SCAN_ARCHITECTURE_SPEC.md §4/§8. The matrix (matrix/roles.yaml)
is the repo-versioned SOURCE OF TRUTH (4.7 ruling 5) — scan behavior stays
f(git SHA, target), so it is NEVER hot-edited. This loader validates it ONCE
per process and FAILS LOUD at startup on any invalid shape (4.7 fleet-scale #4)
rather than blowing up mid-scan.

Two responsibilities, both pure/testable:
  1. load_matrix()  — parse + validate roles.yaml, raise MatrixError on any fault.
  2. match_roles()  — given a host's open ports + fingerprint + kind, return the
     UNION of role packs it matches (role is a vector, not a scalar) plus any
     open ports no role covered (→ unmatched-port fallback, never a silent gap).
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Iterable

try:
    import yaml
except ImportError as e:  # pragma: no cover — image-dep guard
    raise ImportError(
        "PyYAML is required to load the role matrix but is not installed. "
        "Add `pyyaml` to docker/Dockerfile's pip3 install and rebuild the "
        "scanner image (build-scanner-image.yml)."
    ) from e


class MatrixError(Exception):
    """Raised (LOUD, at load time) when roles.yaml is missing or malformed."""


_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "matrix", "roles.yaml")
_WEB_MATCH_KEY = "http"


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise MatrixError(msg)


def load_matrix(path: str | None = None) -> dict:
    """Parse + validate roles.yaml. Raises MatrixError on ANY fault — never
    returns a partially-valid matrix. Validation covers the shape the dispatcher
    and emit paths depend on, so a typo fails at startup, not mid-scan."""
    path = path or _DEFAULT_PATH
    _require(os.path.isfile(path), f"role matrix not found at {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            m = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        raise MatrixError(f"role matrix is not valid YAML: {e}") from e

    _require(isinstance(m, dict), "role matrix must be a mapping at the top level")
    _require(m.get("version") == 1, f"unsupported matrix version: {m.get('version')!r} (want 1)")

    sev = m.get("severity_levels")
    engines = m.get("engines")
    _require(isinstance(sev, list) and sev, "severity_levels must be a non-empty list")
    _require(isinstance(engines, list) and engines, "engines must be a non-empty list")
    sev_set, eng_set = set(sev), set(engines)

    # baseline (spec §5) — the anti-blind-spot floor.
    base = m.get("baseline")
    _require(isinstance(base, dict), "baseline block is required (spec §5)")
    for k in ("read_from_discovery", "fresh", "staleness_hours", "light_cache_only"):
        _require(k in base, f"baseline is missing required key '{k}'")
    _require(isinstance(base["staleness_hours"], int) and base["staleness_hours"] > 0,
             "baseline.staleness_hours must be a positive int")

    # unmatched-port fallback — no open port is ever a silent gap.
    unm = m.get("unmatched_port")
    _require(isinstance(unm, dict), "unmatched_port fallback is required")
    _require(unm.get("engine") in eng_set, f"unmatched_port.engine invalid: {unm.get('engine')!r}")
    _require(unm.get("base_severity") in sev_set,
             f"unmatched_port.base_severity invalid: {unm.get('base_severity')!r}")

    roles = m.get("roles")
    _require(isinstance(roles, dict) and roles, "roles must be a non-empty mapping")
    for name, r in roles.items():
        _require(isinstance(r, dict), f"role '{name}' must be a mapping")
        _require(r.get("engine") in eng_set,
                 f"role '{name}': engine {r.get('engine')!r} not in {sorted(eng_set)}")
        match = r.get("match")
        _require(isinstance(match, dict) and match, f"role '{name}': match is required and non-empty")
        _require(any(k in match for k in ("ports", "http", "fingerprint_any")),
                 f"role '{name}': match needs at least one of ports/http/fingerprint_any")
        if "ports" in match:
            _require(isinstance(match["ports"], list) and all(isinstance(p, int) for p in match["ports"]),
                     f"role '{name}': match.ports must be a list of ints")
        for skey in ("base_severity", "auth_detected_severity"):
            if skey in r and r[skey] is not None:
                _require(r[skey] in sev_set, f"role '{name}': {skey} {r[skey]!r} not a valid severity")
    return m


@lru_cache(maxsize=1)
def get_matrix() -> dict:
    """Process-cached matrix — validation runs ONCE (4.7 fleet-scale #4).
    Call at scanner startup so a bad matrix fails loud before any scanning."""
    return load_matrix()


def _fp_hit(fingerprint_any: list[str], tokens: set[str]) -> bool:
    """True if any matrix token is a substring of any host fingerprint token."""
    return any(any(want in tok for tok in tokens) for want in fingerprint_any)


def match_roles(
    matrix: dict,
    open_ports: Iterable[int],
    fingerprint_tokens: Iterable[str] | None = None,
    has_http: bool | None = None,
    kind: str | None = None,
) -> tuple[list[str], list[int]]:
    """Pure per-host selection. Returns (matched_role_names, unmatched_open_ports).

    - Role is a VECTOR: every network role whose port is open is matched (union).
    - Exactly ONE web role is chosen for an http host — the most specific by
      `priority` whose fingerprint matches, else `web-generic` (the http catch-all).
    - kind redirect/dead → engine 'none', return just that (no scanning).
    - unmatched_open_ports = open ports no role covered → dispatcher emits the
      unmatched-port fallback (never a silent gap).
    """
    roles = matrix["roles"]
    ports = set(int(p) for p in open_ports)
    tokens = set(t.lower() for t in (fingerprint_tokens or []))
    if has_http is None:
        has_http = (80 in ports) or (443 in ports)

    if kind in ("redirect", "dead") and kind in roles:
        return [kind], []

    matched: list[str] = []
    covered: set[int] = set()

    # Network roles: union of every role whose port(s) are open.
    for name, r in roles.items():
        rp = r.get("match", {}).get("ports")
        if rp:
            hit = ports.intersection(rp)
            if hit:
                matched.append(name)
                covered |= hit

    # Web roles: pick exactly one (highest priority fingerprint match, else generic).
    if has_http:
        web_candidates = []
        for name, r in roles.items():
            match = r.get("match", {})
            if not match.get(_WEB_MATCH_KEY):
                continue
            fp = match.get("fingerprint_any")
            if fp is None or _fp_hit(fp, tokens):   # no fp req = always eligible
                web_candidates.append((r.get("priority", 0), name))
        if web_candidates:
            matched.append(max(web_candidates)[1])
        covered |= ports.intersection({80, 443})

    unmatched = sorted(ports - covered)
    return matched, unmatched
