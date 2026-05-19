"""Batch orchestrator: SBOM + CSAF VEX per quarterly EDK II release."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from . import __version__
from .csaf import write_csaf
from .edk2_checkout import (
    edk2_tree_for_tag,
    ensure_uswid_data,
    remove_worktree,
)
from .releases import quarterly_tags

logger = logging.getLogger(__name__)


def _import_sbom4edk2():
    try:
        from sbom4edk2.cve_analyzer import generate_cve_report
        from sbom4edk2.ghsa import scan_sbom_with_ghsa
        from sbom4edk2.sbom import generate_sbom_from_checkout
    except ImportError as exc:
        raise SystemExit(
            "sbom4edk2 is not installed. Install SBOM4EDK2 first, e.g.:\n"
            "  pip install -e /path/to/SBOM4EDK2\n"
            "  pip install -e /path/to/python-uswid-sbom\n"
        ) from exc
    return generate_sbom_from_checkout, generate_cve_report, scan_sbom_with_ghsa


def release_output_paths(releases_dir: str, tag: str) -> tuple[str, str]:
    """Return (cdx_path, csaf_path) under releases/<tag>/."""
    base = os.path.join(releases_dir, tag)
    return (
        os.path.join(base, "edk2.cdx.json"),
        os.path.join(base, "edk2.csaf.json"),
    )


def outputs_complete(cdx_path: str, csaf_path: str) -> bool:
    return os.path.isfile(cdx_path) and os.path.isfile(csaf_path)


def scan_release(
    tag: str,
    *,
    cache_dir: str,
    releases_dir: str,
    uswid_data: str,
    api_key: Optional[str],
    sbom_type: str = "source",
    use_nvd: bool = True,
    use_ghsa: bool = True,
    write_xlsx: bool = False,
    keep_worktree: bool = False,
    edk2_dir: Optional[str] = None,
    use_current: bool = False,
    restore_edk2: bool = True,
) -> Dict[str, Any]:
    """Run the full pipeline for one release tag; return manifest entry dict."""
    generate_sbom, generate_cve_report, scan_sbom_with_ghsa = _import_sbom4edk2()

    cdx_path, csaf_path = release_output_paths(releases_dir, tag)
    os.makedirs(os.path.dirname(cdx_path), exist_ok=True)

    entry: Dict[str, Any] = {
        "tag": tag,
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cdx": cdx_path,
        "csaf": csaf_path,
        "status": "failed",
        "edk2_dir": os.path.realpath(edk2_dir) if edk2_dir else None,
        "use_current": use_current,
    }

    restore_after = restore_edk2 and not keep_worktree
    with edk2_tree_for_tag(
        tag,
        cache_dir=cache_dir,
        edk2_dir=edk2_dir,
        use_current=use_current,
        restore_after=restore_after,
    ) as (tree_path, mirror, wt_path):
        try:
            release_dir = os.path.join(releases_dir, tag)
            old_cwd = os.getcwd()
            try:
                os.chdir(release_dir)
                logger.info("Generating SBOM for %s from %s", tag, tree_path)
                generated = generate_sbom(
                    location=tree_path,
                    output_name="edk2",
                    uswid_data=uswid_data,
                    sbom_type=sbom_type,
                )
            finally:
                os.chdir(old_cwd)

            if not generated or not os.path.isfile(cdx_path):
                raise RuntimeError(f"SBOM generation failed for {tag}")

            nvd_df = None
            ghsa_df = None

            if use_nvd:
                if not api_key:
                    raise RuntimeError(
                        "NVD_API_KEY required for NVD scan (or pass --no-nvd)"
                    )
                xlsx = (
                    os.path.join(release_dir, "CVE_List.xlsx")
                    if write_xlsx
                    else os.path.join(cache_dir, "scratch", tag, "CVE_List.xlsx")
                )
                os.makedirs(os.path.dirname(xlsx), exist_ok=True)
                nvd_df = generate_cve_report(cdx_path, api_key, output_xlsx=xlsx)

            if use_ghsa:
                ghsa_xlsx = (
                    os.path.join(release_dir, "CVE_List_ghsa_edk2.xlsx")
                    if write_xlsx
                    else os.path.join(cache_dir, "scratch", tag, "CVE_List_ghsa.xlsx")
                )
                os.makedirs(os.path.dirname(ghsa_xlsx), exist_ok=True)
                ghsa_df = scan_sbom_with_ghsa(cdx_path, output_xlsx=ghsa_xlsx)

            write_csaf(
                cdx_path,
                csaf_path,
                release_tag=tag,
                nvd_df=nvd_df,
                ghsa_df=ghsa_df,
            )

            entry["status"] = "ok"
            entry["vulnerability_count"] = 0
            try:
                with open(csaf_path, encoding="utf-8") as fh:
                    csaf_doc = json.load(fh)
                entry["vulnerability_count"] = len(
                    csaf_doc.get("vulnerabilities") or []
                )
            except OSError:
                pass

            try:
                from uswid import __version__ as uswid_version

                entry["uswid_version"] = uswid_version
            except ImportError:
                entry["uswid_version"] = None

            entry["finished_at"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            logger.info("Completed %s → %s", tag, release_dir)
            return entry

        finally:
            if mirror and wt_path and not keep_worktree:
                remove_worktree(mirror, wt_path)


def update_manifest(manifest_path: str, entry: Dict[str, Any]) -> None:
    """Append or replace one tag entry in manifest.json."""
    data: Dict[str, Any] = {"releases": []}
    if os.path.isfile(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            data = json.load(fh)
    releases: List[dict] = data.get("releases") or []
    releases = [r for r in releases if r.get("tag") != entry.get("tag")]
    releases.append(entry)
    releases.sort(key=lambda r: r.get("tag") or "")
    data["releases"] = releases
    data["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["vex4edk2_version"] = __version__
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def main(argv: Optional[List[str]] = None) -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Generate quarterly EDK II SBOM + CSAF VEX bundles.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Process all quarterly tags")
    group.add_argument("--tag", metavar="TAG", help="Process a single edk2-stableYYYYMM tag")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List tags that would be processed and exit",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip tags that already have edk2.cdx.json and edk2.csaf.json",
    )
    parser.add_argument(
        "--cache-dir",
        default="cache",
        help="Directory for edk2 mirror, worktrees, uswid-data (default: cache)",
    )
    parser.add_argument(
        "--releases-dir",
        default="releases",
        help="Output directory for per-tag folders (default: releases)",
    )
    parser.add_argument(
        "--uswid-data",
        default=None,
        help="Path to uswid-data (default: cache/uswid-data)",
    )
    parser.add_argument(
        "--sbom-type",
        default="source",
        choices=["source", "build", "binary"],
    )
    parser.add_argument("--no-nvd", action="store_true", help="Skip NVD CVE scan")
    parser.add_argument("--no-ghsa", action="store_true", help="Skip GHSA scan")
    parser.add_argument(
        "--write-xlsx",
        action="store_true",
        help="Write CVE_List.xlsx files into each release folder",
    )
    parser.add_argument(
        "--keep-worktree",
        action="store_true",
        help=(
            "Do not remove git worktrees after each tag (mirror mode), or leave "
            "an --edk2-dir clone on the last checked-out tag instead of restoring HEAD"
        ),
    )
    parser.add_argument(
        "-l",
        "--edk2-dir",
        metavar="DIR",
        default=None,
        help=(
            "Use an existing EDK II git clone instead of cache/worktrees. "
            "Each tag is checked out in this repo unless --use-current is set. "
            "Also read from EDK2_DIR in the environment if unset."
        ),
    )
    parser.add_argument(
        "--use-current",
        action="store_true",
        help=(
            "With --edk2-dir: do not run git checkout; scan the tree as-is "
            "(use when the clone is already at the intended release). "
            "Only valid with a single --tag."
        ),
    )
    parser.add_argument(
        "-k",
        "--apikey",
        default=None,
        help="NVD API key (overrides NVD_API_KEY from .env)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    cache_dir = os.path.abspath(args.cache_dir)
    releases_dir = os.path.abspath(args.releases_dir)

    if args.tag:
        tags = [args.tag]
    else:
        tags = quarterly_tags()

    edk2_dir = args.edk2_dir or os.environ.get("EDK2_DIR")
    if edk2_dir:
        edk2_dir = os.path.abspath(edk2_dir)

    if args.use_current and not edk2_dir:
        logger.error("--use-current requires --edk2-dir (or EDK2_DIR)")
        sys.exit(1)
    if args.use_current and args.all:
        logger.error("--use-current cannot be used with --all (one tag at a time)")
        sys.exit(1)

    if args.dry_run:
        for tag in tags:
            cdx, csaf = release_output_paths(releases_dir, tag)
            mode = f"edk2-dir={edk2_dir}" if edk2_dir else "worktree"
            if edk2_dir and args.use_current:
                mode = f"edk2-dir={edk2_dir} (current HEAD)"
            print(f"{tag} [{mode}]\n  {cdx}\n  {csaf}")
        return

    uswid_data = args.uswid_data or ensure_uswid_data(cache_dir)

    api_key = args.apikey or os.environ.get("NVD_API_KEY")
    use_nvd = not args.no_nvd
    if use_nvd and not api_key:
        logger.error("NVD_API_KEY required (use --no-nvd to skip NVD)")
        sys.exit(1)

    manifest_path = os.path.join(releases_dir, "..", "manifest.json")
    manifest_path = os.path.abspath(manifest_path)

    failures = 0
    for tag in tags:
        cdx_path, csaf_path = release_output_paths(releases_dir, tag)
        if args.skip_existing and outputs_complete(cdx_path, csaf_path):
            logger.info("Skipping %s (outputs exist)", tag)
            continue

        logger.info("=== Processing %s ===", tag)
        try:
            entry = scan_release(
                tag,
                cache_dir=cache_dir,
                releases_dir=releases_dir,
                uswid_data=uswid_data,
                api_key=api_key,
                sbom_type=args.sbom_type,
                use_nvd=use_nvd,
                use_ghsa=not args.no_ghsa,
                write_xlsx=args.write_xlsx,
                keep_worktree=args.keep_worktree,
                edk2_dir=edk2_dir,
                use_current=args.use_current,
                restore_edk2=not args.keep_worktree,
            )
            update_manifest(manifest_path, entry)
        except Exception as exc:
            failures += 1
            logger.error("Failed %s: %s", tag, exc, exc_info=True)
            update_manifest(
                manifest_path,
                {
                    "tag": tag,
                    "status": "failed",
                    "error": str(exc),
                    "finished_at": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                },
            )

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
