"""Parse CycloneDX JSON SBOMs for CVE scanning (no SBOM generation)."""

from __future__ import annotations

import json
import logging
from typing import Optional

from .cpe import build_cpe_pattern

logger = logging.getLogger(__name__)


def _load_sbom(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.error("SBOM file not found: %s", path)
        return None
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        return None


def parse_sbom(path: str) -> list[dict]:
    """Parse a CycloneDX JSON file and return its ``components[]`` list only."""
    data = _load_sbom(path)
    if not data:
        return []
    components = _extract_components(data)
    logger.info("Parsed %d components from %s", len(components), path)
    return components


def _component_identity(comp: dict) -> Optional[str]:
    ref = comp.get("bom-ref") or comp.get("cpe")
    return str(ref) if ref else None


def components_for_cve_scan(path: str) -> tuple[list[dict], Optional[str]]:
    """Return SBOM components to scan with NVD, including ``metadata.component``.

    The primary EDK II firmware entry is always first. Components whose CPE
    pattern matches the primary are skipped to avoid duplicate NVD API calls.

    Returns ``(scan_list, primary_identity)`` where *primary_identity* is the
    ``bom-ref`` or ``cpe`` of ``metadata.component`` when present.
    """
    data = _load_sbom(path)
    if not data:
        return [], None

    primary = _extract_primary_component(data)
    primary_key = _component_identity(primary) if primary else None
    components = _extract_components(data)
    ordered: list[dict] = []
    if primary:
        ordered.append(primary)
    ordered.extend(components)
    deduped = _dedupe_by_cpe_pattern(ordered)
    logger.info(
        "CVE scan list: %d entries (%d from components[], primary=%s) in %s",
        len(deduped),
        len(components),
        bool(primary),
        path,
    )
    return deduped, primary_key


def _extract_primary_component(data: dict) -> Optional[dict]:
    if not isinstance(data, dict):
        return None
    meta = data.get("metadata") or {}
    if not isinstance(meta, dict):
        return None
    primary = meta.get("component")
    return primary if isinstance(primary, dict) else None


def _dedupe_by_cpe_pattern(components: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        cpe = build_cpe_pattern(comp)
        if cpe:
            if cpe in seen:
                continue
            seen.add(cpe)
        out.append(comp)
    return out


def _extract_components(data: dict) -> list[dict]:
    if not isinstance(data, dict):
        return []
    if "components" in data:
        comps = data["components"]
    elif "metadata" in data:
        meta = data.get("metadata", {}).get("component", {})
        comps = meta.get("components", []) if isinstance(meta, dict) else []
    else:
        return []
    return comps if isinstance(comps, list) else []
