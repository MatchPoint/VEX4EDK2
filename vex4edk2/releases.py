"""EDK II quarterly stable release tag selection."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import List, Optional

_QUARTERLY_STABLE_RE = re.compile(r"^edk2-stable(\d{6})$")
_TAG_WITH_POINT_RE = re.compile(r"^edk2-stable(\d{6})(?:\.\d+)?$")
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})$")


def yyyymm_from_tag(tag: str) -> Optional[int]:
    """Return the six-digit YYYYMM integer from *tag*, or None."""
    m = _TAG_WITH_POINT_RE.match(tag)
    return int(m.group(1)) if m else None


def is_quarterly_stable_tag(tag: str) -> bool:
    """True for ``edk2-stableYYYYMM`` without ``-rc`` or ``.NN`` point suffix."""
    return _QUARTERLY_STABLE_RE.match(tag) is not None


def parse_date_bound(value: str) -> int:
    """Parse ``YYYY-MM`` to an inclusive YYYYMM integer (e.g. ``2021-05`` → ``202105``)."""
    text = (value or "").strip()
    m = _DATE_RE.match(text)
    if not m:
        raise ValueError(
            f"Invalid date {value!r}: expected YYYY-MM (e.g. 2021-05 or 2026-02)"
        )
    year = int(m.group(1))
    month = int(m.group(2))
    if month < 1 or month > 12:
        raise ValueError(f"Invalid month in date {value!r}")
    return year * 100 + month


def filter_tags_by_yyyymm_range(
    tags: List[str],
    from_yyyymm: int,
    to_yyyymm: int,
) -> List[str]:
    """Return quarterly stable tags whose YYYYMM lies in ``[from_yyyymm, to_yyyymm]``."""
    if from_yyyymm > to_yyyymm:
        raise ValueError(
            f"--from-date YYYYMM {from_yyyymm} is after --to-date YYYYMM {to_yyyymm}"
        )
    out: List[str] = []
    for tag in tags:
        if not is_quarterly_stable_tag(tag):
            continue
        yyyymm = yyyymm_from_tag(tag)
        if yyyymm is not None and from_yyyymm <= yyyymm <= to_yyyymm:
            out.append(tag)
    return sorted(out, key=lambda t: yyyymm_from_tag(t) or 0)


def quarterly_tags_in_range(
    from_date: str,
    to_date: str,
    *,
    cache_dir: Optional[str] = None,
    edk2_dir: Optional[str] = None,
    reference: Optional[datetime] = None,
) -> List[str]:
    """Discover ``edk2-stableYYYYMM`` tags from git and filter by calendar range.

    *from_date* and *to_date* are ``YYYY-MM`` strings (inclusive). Requires
    *cache_dir* (mirror fetch) and/or *edk2_dir* (local clone) to list remote tags.
    """
    from_yyyymm = parse_date_bound(from_date)
    to_yyyymm = parse_date_bound(to_date)
    ref = reference or datetime.now(timezone.utc)
    to_cap = ref.year * 100 + ref.month
    if to_yyyymm > to_cap:
        to_yyyymm = to_cap

    from vex4edk2.edk2_checkout import discover_quarterly_stable_tags

    all_tags = discover_quarterly_stable_tags(
        cache_dir=cache_dir,
        edk2_dir=edk2_dir,
    )
    return filter_tags_by_yyyymm_range(all_tags, from_yyyymm, to_yyyymm)


def tags_with_committed_outputs(repo_root: str) -> List[str]:
    """Return sorted quarterly tags that have ``sbom/<tag>.cdx.json`` in *repo_root*."""
    sbom_dir = os.path.join(repo_root, "sbom")
    if not os.path.isdir(sbom_dir):
        return []
    out: List[str] = []
    for name in os.listdir(sbom_dir):
        if not name.endswith(".cdx.json"):
            continue
        tag = name[: -len(".cdx.json")]
        if is_quarterly_stable_tag(tag):
            out.append(tag)
    return sorted(out, key=lambda t: yyyymm_from_tag(t) or 0)


def resolve_tip_output_name(edk2_dir: str) -> str:
    """Label for SBOM/VEX filenames when scanning the current development tip."""
    from sbom4edk2.edk2_version import describe_edk2_version

    label, _, _ = describe_edk2_version(edk2_dir)
    safe = re.sub(r'[<>:"/\\|?*]', "_", label)
    return safe or "edk2-tip"
