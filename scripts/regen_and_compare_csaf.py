#!/usr/bin/env python3
"""Regenerate CSAF from committed SBOM and compare to baseline (normalize volatile fields)."""

from __future__ import annotations

import copy
import json
import os
import re
import sys
from typing import Any, Dict, List, Set, Tuple

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# SBOM4EDK2 on PYTHONPATH or sibling checkout
for _candidate in (
    os.environ.get("SBOM4EDK2_DIR"),
    r"C:\temp\test\SBOM4EDK2",
    "/mnt/c/temp/test/SBOM4EDK2",
):
    if _candidate and os.path.isdir(os.path.join(_candidate, "sbom4edk2")):
        if _candidate not in sys.path:
            sys.path.insert(0, _candidate)
        break

from vex4edk2.batch import load_project_env
from vex4edk2.csaf import write_csaf

TAG = os.environ.get("VEX4EDK2_TAG", "edk2-stable202411")
CDX = os.path.join(_REPO, "sbom", f"{TAG}.cdx.json")
BASELINE = os.path.join(_REPO, "vex", f"{TAG}.csaf.json")
FRESH = os.path.join(_REPO, "cache", "scratch", TAG, "edk2.csaf.fresh.json")


def _normalize_csaf(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(doc)
    tracking = out.get("document", {}).get("tracking", {})
    for key in ("initial_release_date", "current_release_date"):
        if key in tracking:
            tracking[key] = "NORMALIZED"
    gen = tracking.get("generator") or {}
    if "date" in gen:
        gen["date"] = "NORMALIZED"
    for rev in tracking.get("revision_history") or []:
        if "date" in rev:
            rev["date"] = "NORMALIZED"
    notes = out.get("document", {}).get("notes") or []
    for note in notes:
        if note.get("category") == "summary" and isinstance(note.get("text"), str):
            note["text"] = re.sub(
                r"uswid [^\s)]+",
                "uswid NORMALIZED",
                note["text"],
            )
    # Stable ordering for product_tree branches
    pt = out.get("product_tree") or {}
    if "branches" in pt:
        pt["branches"] = sorted(
            pt["branches"],
            key=lambda b: json.dumps(b, sort_keys=True),
        )
    vulns = out.get("vulnerabilities") or []
    for v in vulns:
        v.pop("release_date", None)
    out["vulnerabilities"] = sorted(
        vulns, key=lambda v: v.get("cve_id") or v.get("id") or ""
    )
    return out


def _cve_set(doc: Dict[str, Any]) -> Set[str]:
    ids: Set[str] = set()
    for v in doc.get("vulnerabilities") or []:
        cve = v.get("cve_id") or v.get("id") or ""
        if cve.upper().startswith("CVE-"):
            ids.add(cve.upper())
    return ids


def main() -> int:
    load_project_env()
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key or "\r" in api_key:
        print("ERROR: NVD_API_KEY missing or still contains CR")
        return 1

    if not os.path.isfile(CDX):
        print(f"ERROR: missing SBOM {CDX}")
        return 1

    from sbom4edk2.cve_analyzer import generate_cve_report
    from sbom4edk2.ghsa import scan_sbom_with_ghsa

    os.makedirs(os.path.dirname(FRESH), exist_ok=True)
    scratch = os.path.dirname(FRESH)
    xlsx = os.path.join(scratch, "CVE_List.xlsx")
    ghsa_xlsx = os.path.join(scratch, "CVE_List_ghsa.xlsx")

    print(f"NVD scan for {TAG} …")
    nvd_df = generate_cve_report(CDX, api_key, output_xlsx=xlsx)
    nvd_rows = 0 if nvd_df is None else len(nvd_df)

    print(f"GHSA scan for {TAG} …")
    ghsa_df = scan_sbom_with_ghsa(CDX, output_xlsx=ghsa_xlsx)
    ghsa_rows = 0 if ghsa_df is None else len(ghsa_df)

    write_csaf(CDX, FRESH, release_tag=TAG, nvd_df=nvd_df, ghsa_df=ghsa_df)

    with open(BASELINE, encoding="utf-8") as fh:
        baseline = json.load(fh)
    with open(FRESH, encoding="utf-8") as fh:
        fresh = json.load(fh)

    base_cves = _cve_set(baseline)
    fresh_cves = _cve_set(fresh)
    norm_match = _normalize_csaf(baseline) == _normalize_csaf(fresh)

    print(f"Baseline vulnerabilities: {len(baseline.get('vulnerabilities') or [])} ({len(base_cves)} CVE IDs)")
    print(f"Fresh vulnerabilities:    {len(fresh.get('vulnerabilities') or [])} ({len(fresh_cves)} CVE IDs)")
    print(f"CVE set match: {base_cves == fresh_cves}")
    print(f"Normalized document match: {norm_match}")
    if base_cves != fresh_cves:
        print("Only in baseline:", sorted(base_cves - fresh_cves))
        print("Only in fresh:", sorted(fresh_cves - base_cves))
    print(f"Fresh CSAF written to: {FRESH}")
    return 0 if base_cves == fresh_cves and norm_match else 2


if __name__ == "__main__":
    sys.exit(main())
