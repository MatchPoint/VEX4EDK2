"""Orchestrate NVD, Grype, and GHSA CVE scans on a CycloneDX SBOM."""

from __future__ import annotations

import logging
import os
from typing import Optional

import pandas as pd

from .cve_analyzer import generate_cve_report
from .ghsa import scan_sbom_with_ghsa
from .grype import is_grype_available, scan_sbom_with_grype

logger = logging.getLogger(__name__)


def resolve_scanner(requested: str, api_key: str | None) -> tuple[bool, bool]:
    """Return (use_nvd, use_grype) for *requested* scanner and key availability."""
    if requested == "auto":
        if api_key:
            logger.info("NVD_API_KEY found — using NVD scanner.")
            return True, False
        logger.info("No NVD_API_KEY — falling back to grype scanner.")
        return False, True
    return requested in ("nvd", "both"), requested in ("grype", "both")


def run_cve_scans(
    cdx_path: str,
    *,
    api_key: str | None = None,
    scanner: str = "auto",
    use_ghsa: bool = True,
    output_dir: str | None = None,
    nvd_xlsx: str | None = None,
    grype_xlsx: str | None = None,
    ghsa_xlsx: str | None = None,
) -> dict[str, Optional[pd.DataFrame]]:
    """Run configured scanners on *cdx_path* and return DataFrames by source."""
    use_nvd, use_grype = resolve_scanner(scanner, api_key)

    if use_nvd and not api_key:
        raise ValueError(
            f"NVD API key required for --scanner {scanner!r} "
            "(use -k/--apikey or NVD_API_KEY)"
        )

    if use_grype and not is_grype_available():
        if scanner == "grype":
            raise RuntimeError("grype binary not found")
        logger.warning("grype not found — skipping grype scan")
        use_grype = False

    base = os.path.splitext(os.path.basename(cdx_path))[0]
    out_dir = output_dir or os.path.dirname(os.path.abspath(cdx_path)) or "."

    nvd_path = nvd_xlsx or os.path.join(out_dir, "CVE_List.xlsx")
    grype_path = grype_xlsx or os.path.join(out_dir, f"CVE_List_grype_{base}.xlsx")
    ghsa_path = ghsa_xlsx or os.path.join(out_dir, f"CVE_List_ghsa_{base}.xlsx")

    result: dict[str, Optional[pd.DataFrame]] = {
        "nvd": None,
        "grype": None,
        "ghsa": None,
    }

    if use_nvd:
        result["nvd"] = generate_cve_report(cdx_path, api_key, output_xlsx=nvd_path)

    if use_grype:
        result["grype"] = scan_sbom_with_grype(cdx_path, output_xlsx=grype_path)

    if use_ghsa:
        result["ghsa"] = scan_sbom_with_ghsa(cdx_path, output_xlsx=ghsa_path)

    return result


def main(argv: list[str] | None = None) -> None:
    """CLI entry: CVE scan on an existing CycloneDX SBOM (Scenario 3)."""
    import argparse
    import os
    import sys

    from dotenv import load_dotenv

    from .grype import is_grype_available

    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Generate CVE list from an existing SBOM (.cdx.json) file.",
    )
    parser.add_argument("cdx_file", help="Path to CycloneDX SBOM (.cdx.json)")
    parser.add_argument("-k", "--apikey", default=None, help="NVD API key")
    parser.add_argument(
        "--scanner",
        default="auto",
        choices=["auto", "nvd", "grype", "both"],
    )
    parser.add_argument(
        "--no-ghsa",
        dest="ghsa",
        action="store_false",
        default=True,
    )
    args = parser.parse_args(argv)

    api_key = args.apikey or os.environ.get("NVD_API_KEY")
    use_nvd, use_grype = resolve_scanner(args.scanner, api_key)

    if use_nvd and not api_key:
        print(
            f"NVD API key required for --scanner {args.scanner}",
            file=sys.stderr,
        )
        sys.exit(1)

    if use_grype and not is_grype_available():
        if args.scanner == "grype":
            print("grype binary not found", file=sys.stderr)
            sys.exit(1)
        use_grype = False

    try:
        run_cve_scans(
            args.cdx_file,
            api_key=api_key,
            scanner=args.scanner,
            use_ghsa=args.ghsa,
        )
    except (ValueError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
