"""Parse CycloneDX JSON SBOMs for CVE scanning (no SBOM generation)."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def parse_sbom(path: str) -> list[dict]:
    """Parse a CycloneDX JSON file and return its component list."""
    logger.info("Parsing SBOM file: %s", path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        logger.error("SBOM file not found: %s", path)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", path, exc)
        return []

    components = _extract_components(data)
    logger.info("Parsed %d components from %s", len(components), path)
    return components


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
