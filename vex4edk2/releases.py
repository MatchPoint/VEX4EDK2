"""EDK II quarterly stable release tag selection."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional

# Quarterly stable tags from May 2024 through edk2-stable202602 (plan v1).
QUARTERLY_TAGS_LAST_TWO_YEARS: tuple[str, ...] = (
    "edk2-stable202405",
    "edk2-stable202408",
    "edk2-stable202411",
    "edk2-stable202502",
    "edk2-stable202505",
    "edk2-stable202508",
    "edk2-stable202511",
    "edk2-stable202602",
)

_TAG_RE = re.compile(r"^edk2-stable(\d{6})(?:\.\d+)?$")


def yyyymm_from_tag(tag: str) -> Optional[int]:
    """Return the six-digit YYYYMM integer from *tag*, or None."""
    m = _TAG_RE.match(tag)
    return int(m.group(1)) if m else None


def quarterly_tags(
    *,
    years: int = 2,
    reference: Optional[datetime] = None,
) -> List[str]:
    """Return quarterly stable tags within the last *years* calendar years.

    Uses the fixed plan list when *years* is 2 and *reference* is unset;
    otherwise filters ``edk2-stableYYYYMM`` tags by YYYYMM window.
    """
    if years == 2 and reference is None:
        return list(QUARTERLY_TAGS_LAST_TWO_YEARS)

    ref = reference or datetime.now(timezone.utc)
    cutoff = ref.year - years
    cutoff_yyyymm = cutoff * 100 + ref.month

    out: List[str] = []
    for tag in QUARTERLY_TAGS_LAST_TWO_YEARS:
        yyyymm = yyyymm_from_tag(tag)
        if yyyymm is not None and yyyymm >= cutoff_yyyymm:
            out.append(tag)
    return out
