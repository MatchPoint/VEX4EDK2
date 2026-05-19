"""Build CSAF 2.0 VEX documents from CycloneDX SBOMs and CVE scan results."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import pandas as pd

from . import __version__ as vex4edk2_version

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_PRODUCT_ID_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def product_id_from_bom_ref(bom_ref: str) -> str:
    """Derive a stable CSAF product_id from a CycloneDX bom-ref."""
    if not bom_ref:
        return "product-unknown"
    safe = _PRODUCT_ID_SAFE.sub("_", bom_ref.strip())
    if len(safe) > 120:
        safe = safe[:120]
    return f"pid-{safe}"


def _load_cdx(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _build_product_entries(cdx: dict) -> tuple[dict, Dict[str, str]]:
    """Return (product_tree root branch, bom_ref -> product_id)."""
    ref_to_pid: Dict[str, str] = {}
    branches: List[dict] = []

    primary = cdx.get("metadata", {}).get("component") or {}
    if primary:
        pref = primary.get("bom-ref") or primary.get("cpe") or "edk2-primary"
        pid = product_id_from_bom_ref(str(pref))
        ref_to_pid[str(pref)] = pid
        pname = primary.get("name") or "EDK II"
        pver = primary.get("version") or ""
        branches.append(
            {
                "name": pname,
                "category": "product_name",
                "branches": [
                    {
                        "name": pver or "unknown",
                        "category": "product_version",
                        "product": {
                            "product_id": pid,
                            "name": f"{pname} {pver}".strip(),
                        },
                    }
                ],
            }
        )

    for comp in cdx.get("components") or []:
        if not isinstance(comp, dict):
            continue
        bom_ref = comp.get("bom-ref") or comp.get("cpe")
        if not bom_ref:
            continue
        bom_ref = str(bom_ref)
        if bom_ref in ref_to_pid:
            continue
        pid = product_id_from_bom_ref(bom_ref)
        ref_to_pid[bom_ref] = pid
        cname = comp.get("name") or "component"
        cver = comp.get("version") or ""
        branches.append(
            {
                "name": cname,
                "category": "product_name",
                "branches": [
                    {
                        "name": cver or "unknown",
                        "category": "product_version",
                        "product": {
                            "product_id": pid,
                            "name": f"{cname} {cver}".strip(),
                        },
                    }
                ],
            }
        )

    product_tree = {
        "branches": [
            {
                "name": "TianoCore",
                "category": "vendor",
                "branches": branches or [
                    {
                        "name": "EDK II",
                        "category": "product_name",
                        "product": {
                            "product_id": "pid-edk2",
                            "name": "EDK II",
                        },
                    }
                ],
            }
        ]
    }
    return product_tree, ref_to_pid


def _cpe_to_bom_ref_map(cdx: dict) -> Dict[str, str]:
    """Map CPE strings used in NVD reports to bom-ref keys."""
    out: Dict[str, str] = {}
    primary = cdx.get("metadata", {}).get("component") or {}
    if primary.get("cpe") and primary.get("bom-ref"):
        out[str(primary["cpe"])] = str(primary["bom-ref"])
    for comp in cdx.get("components") or []:
        if not isinstance(comp, dict):
            continue
        cpe = comp.get("cpe")
        bom_ref = comp.get("bom-ref")
        if cpe and bom_ref:
            out[str(cpe)] = str(bom_ref)
    return out


def _primary_product_id(ref_to_pid: Dict[str, str], cdx: dict) -> Optional[str]:
    primary = cdx.get("metadata", {}).get("component") or {}
    pref = primary.get("bom-ref") or primary.get("cpe")
    if pref:
        return ref_to_pid.get(str(pref))
    return next(iter(ref_to_pid.values()), None)


def _vulnerability_entry(
    cve_id: str,
    affected_pids: Set[str],
    *,
    title: str = "",
    description: str = "",
    score: Optional[float] = None,
    cvss_vector: Optional[str] = None,
    references: Optional[List[dict]] = None,
    ghsa_id: Optional[str] = None,
) -> dict:
    notes: List[dict] = []
    if description:
        notes.append(
            {
                "category": "description",
                "text": description[:4000],
                "title": "Description",
            }
        )
    if ghsa_id:
        notes.append(
            {
                "category": "other",
                "text": ghsa_id,
                "title": "GitHub Security Advisory",
            }
        )

    vuln: Dict[str, Any] = {
        "title": title or cve_id,
        "cve": cve_id,
        "product_status": {
            "known_affected": sorted(affected_pids),
        },
    }
    if notes:
        vuln["notes"] = notes
    if references:
        vuln["references"] = references

    if score is not None and affected_pids:
        entry: Dict[str, Any] = {
            "version": "3.1",
            "baseScore": float(score),
        }
        if cvss_vector:
            entry["vectorString"] = cvss_vector
        vuln["scores"] = [
            {
                "products": sorted(affected_pids),
                "cvss_v3": entry,
            }
        ]

    return vuln


def build_csaf_document(
    cdx_path: str,
    *,
    release_tag: str,
    nvd_df: Optional[pd.DataFrame] = None,
    ghsa_df: Optional[pd.DataFrame] = None,
) -> dict:
    """Assemble a CSAF 2.0 VEX document from SBOM + scan DataFrames."""
    cdx = _load_cdx(cdx_path)
    product_tree, ref_to_pid = _build_product_entries(cdx)
    cpe_to_ref = _cpe_to_bom_ref_map(cdx)
    primary_pid = _primary_product_id(ref_to_pid, cdx)

    # CVE -> set of product_ids
    affected: Dict[str, Dict[str, Any]] = {}

    if nvd_df is not None and not nvd_df.empty:
        for _, row in nvd_df.iterrows():
            cve_id = str(row.get("id") or "")
            if not _CVE_RE.match(cve_id):
                continue
            cpe_pattern = str(row.get("cpe_pattern") or "")
            bom_ref = cpe_to_ref.get(cpe_pattern)
            pid = ref_to_pid.get(bom_ref) if bom_ref else None
            if not pid:
                comp_name = str(row.get("name") or "")
                for ref, p in ref_to_pid.items():
                    if comp_name and comp_name in ref:
                        pid = p
                        break
            if not pid:
                continue

            rec = affected.setdefault(
                cve_id,
                {
                    "pids": set(),
                    "title": cve_id,
                    "description": str(row.get("descriptions") or ""),
                    "score": row.get("score"),
                    "cvss_vector": row.get("CVSSString"),
                    "references": [],
                    "ghsa_id": None,
                },
            )
            rec["pids"].add(pid)
            if row.get("score") is not None and pd.notna(row.get("score")):
                rec["score"] = row.get("score")
            if row.get("CVSSString"):
                rec["cvss_vector"] = row.get("CVSSString")

    if ghsa_df is not None and not ghsa_df.empty:
        for _, row in ghsa_df.iterrows():
            cve_id = str(row.get("id") or "")
            if not _CVE_RE.match(cve_id):
                continue
            pid = primary_pid
            if not pid:
                continue
            rec = affected.setdefault(
                cve_id,
                {
                    "pids": set(),
                    "title": str(row.get("descriptions") or cve_id)[:200],
                    "description": str(row.get("descriptions") or ""),
                    "score": row.get("score"),
                    "cvss_vector": row.get("CVSSString"),
                    "references": [],
                    "ghsa_id": str(row.get("ghsa_id") or ""),
                },
            )
            rec["pids"].add(pid)
            url = row.get("url")
            if url and pd.notna(url):
                rec["references"] = [
                    {"url": str(url), "summary": "TianoCore GHSA advisory"}
                ]
            if row.get("ghsa_id"):
                rec["ghsa_id"] = str(row.get("ghsa_id"))

    vulnerabilities: List[dict] = []
    for cve_id, rec in sorted(affected.items()):
        score = rec.get("score")
        if score is not None and pd.isna(score):
            score = None
        vulnerabilities.append(
            _vulnerability_entry(
                cve_id,
                rec["pids"],
                title=str(rec.get("title") or cve_id),
                description=str(rec.get("description") or ""),
                score=float(score) if score is not None else None,
                cvss_vector=str(rec["cvss_vector"]) if rec.get("cvss_vector") else None,
                references=rec.get("references") or None,
                ghsa_id=rec.get("ghsa_id"),
            )
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = f"vex4edk2-{release_tag}"

    try:
        from uswid import __version__ as uswid_version
    except ImportError:
        uswid_version = "unknown"

    return {
        "document": {
            "category": "csaf_vex",
            "title": f"VEX for {release_tag}",
            "tracking": {
                "id": doc_id,
                "version": "1.0.0",
                "status": "final",
                "revision_history": [
                    {
                        "number": "1.0.0",
                        "date": now,
                        "summary": f"Automated VEX from SBOM4EDK2 scan of {release_tag}",
                    }
                ],
                "initial_release_date": now,
                "current_release_date": now,
                "generator": {
                    "engine": {
                        "name": "VEX4EDK2",
                        "version": vex4edk2_version,
                    },
                    "author": "Brian Mullen",
                    "date": now,
                },
            },
            "notes": [
                {
                    "category": "summary",
                    "text": (
                        f"Machine-generated CSAF VEX for TianoCore {release_tag}. "
                        f"SBOM produced by USWID SBOM (uswid {uswid_version}). "
                        "Component CVEs from NVD CPE matching; platform advisories "
                        "from TianoCore GitHub Security Advisories."
                    ),
                    "title": "Summary",
                }
            ],
        },
        "product_tree": product_tree,
        "vulnerabilities": vulnerabilities,
    }


def write_csaf(
    cdx_path: str,
    output_path: str,
    *,
    release_tag: str,
    nvd_df: Optional[pd.DataFrame] = None,
    ghsa_df: Optional[pd.DataFrame] = None,
) -> str:
    """Build and write a CSAF JSON file; return *output_path*."""
    doc = build_csaf_document(
        cdx_path,
        release_tag=release_tag,
        nvd_df=nvd_df,
        ghsa_df=ghsa_df,
    )
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    logger.info(
        "Wrote CSAF VEX %s (%d vulnerabilities)",
        output_path,
        len(doc.get("vulnerabilities") or []),
    )
    return output_path
