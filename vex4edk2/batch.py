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

# Env vars that must not carry Windows CRLF into HTTP headers or git paths.
_ENV_KEYS_TO_NORMALIZE = ("NVD_API_KEY", "GITHUB_TOKEN", "EDK2_DIR")


def normalize_env_value(value: Optional[str]) -> Optional[str]:
    """Strip whitespace and CR/LF from a dotenv or shell-sourced value."""
    if value is None:
        return None
    return value.strip().strip("\r\n")


def load_project_env() -> None:
    """Load ``.env`` and normalize known keys (safe for CRLF-encoded files on WSL)."""
    load_dotenv()
    for key in _ENV_KEYS_TO_NORMALIZE:
        if key in os.environ:
            os.environ[key] = normalize_env_value(os.environ[key]) or ""


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


def release_output_paths(repo_root: str, tag: str) -> tuple[str, str]:
    """Return (cdx_path, csaf_path) under sbom/ and vex/ with the release tag in each filename."""
    return (
        os.path.join(repo_root, "sbom", f"{tag}.cdx.json"),
        os.path.join(repo_root, "vex", f"{tag}.csaf.json"),
    )


def outputs_complete(cdx_path: str, csaf_path: str) -> bool:
    return os.path.isfile(cdx_path) and os.path.isfile(csaf_path)


def scan_release(
    tag: str,
    *,
    cache_dir: str,
    repo_root: str,
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

    cdx_path, csaf_path = release_output_paths(repo_root, tag)
    sbom_dir = os.path.dirname(cdx_path)
    vex_dir = os.path.dirname(csaf_path)
    os.makedirs(sbom_dir, exist_ok=True)
    os.makedirs(vex_dir, exist_ok=True)
    scratch_dir = os.path.join(cache_dir, "scratch", tag)
    os.makedirs(scratch_dir, exist_ok=True)

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
            old_cwd = os.getcwd()
            try:
                os.chdir(sbom_dir)
                logger.info("Generating SBOM for %s from %s", tag, tree_path)
                generated = generate_sbom(
                    location=tree_path,
                    output_name=tag,
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
                xlsx = os.path.join(scratch_dir, "CVE_List.xlsx")
                nvd_df = generate_cve_report(cdx_path, api_key, output_xlsx=xlsx)

            if use_ghsa:
                ghsa_xlsx = os.path.join(scratch_dir, "CVE_List_ghsa.xlsx")
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
            logger.info("Completed %s → %s and %s", tag, cdx_path, csaf_path)
            return entry

        finally:
            if mirror and wt_path and not keep_worktree:
                remove_worktree(mirror, wt_path)


def regenerate_vex_from_sbom(
    tag: str,
    *,
    cache_dir: str,
    repo_root: str,
    api_key: Optional[str],
    use_nvd: bool = True,
    use_ghsa: bool = True,
) -> Dict[str, Any]:
    """Rebuild CSAF VEX from an existing sbom/<tag>.cdx.json without regenerating the SBOM."""
    _, generate_cve_report, scan_sbom_with_ghsa = _import_sbom4edk2()

    cdx_path, csaf_path = release_output_paths(repo_root, tag)
    if not os.path.isfile(cdx_path):
        raise FileNotFoundError(f"SBOM not found: {cdx_path}")

    os.makedirs(os.path.dirname(csaf_path), exist_ok=True)
    scratch_dir = os.path.join(cache_dir, "scratch", tag)
    os.makedirs(scratch_dir, exist_ok=True)

    entry: Dict[str, Any] = {
        "tag": tag,
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cdx": cdx_path,
        "csaf": csaf_path,
        "status": "failed",
        "vex_only": True,
    }

    nvd_df = None
    ghsa_df = None

    if use_nvd:
        if not api_key:
            raise RuntimeError("NVD_API_KEY required for NVD scan (or pass --no-nvd)")
        xlsx = os.path.join(scratch_dir, "CVE_List.xlsx")
        nvd_df = generate_cve_report(cdx_path, api_key, output_xlsx=xlsx)

    if use_ghsa:
        ghsa_xlsx = os.path.join(scratch_dir, "CVE_List_ghsa.xlsx")
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
        entry["vulnerability_count"] = len(csaf_doc.get("vulnerabilities") or [])
    except OSError:
        pass

    entry["finished_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.info("Refreshed VEX for %s → %s", tag, csaf_path)
    return entry


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
    load_project_env()
    parser = argparse.ArgumentParser(
        description="Generate quarterly EDK II SBOM + CSAF VEX bundles.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Process all quarterly tags")
    group.add_argument("--tag", metavar="TAG", help="Process a single edk2-stableYYYYMM tag")
    parser.add_argument(
        "--vex-only",
        action="store_true",
        help="Regenerate vex/<tag>.csaf.json from existing sbom/<tag>.cdx.json (skip SBOM generation)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List tags that would be processed and exit",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip tags that already have sbom/<tag>.cdx.json and vex/<tag>.csaf.json",
    )
    parser.add_argument(
        "--cache-dir",
        default="cache",
        help="Directory for edk2 mirror, worktrees, uswid-data (default: cache)",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root containing sbom/ and vex/ outputs (default: .)",
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
        help="Keep CVE_List.xlsx files under cache/scratch/<tag>/ (default: same, flag retained for scripts)",
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
    repo_root = os.path.abspath(args.repo_root)

    if args.tag:
        tags = [args.tag]
    else:
        tags = quarterly_tags()

    edk2_dir = normalize_env_value(args.edk2_dir or os.environ.get("EDK2_DIR"))
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
            cdx, csaf = release_output_paths(repo_root, tag)
            if args.vex_only:
                mode = "vex-only (existing SBOM)"
            else:
                mode = f"edk2-dir={edk2_dir}" if edk2_dir else "worktree"
                if edk2_dir and args.use_current:
                    mode = f"edk2-dir={edk2_dir} (current HEAD)"
            print(f"{tag} [{mode}]\n  {cdx}\n  {csaf}")
        return

    api_key = normalize_env_value(args.apikey or os.environ.get("NVD_API_KEY"))
    use_nvd = not args.no_nvd
    if use_nvd and not api_key:
        logger.error("NVD_API_KEY required (use --no-nvd to skip NVD)")
        sys.exit(1)

    if args.vex_only:
        manifest_path = os.path.join(repo_root, "manifest.json")
        failures = 0
        for tag in tags:
            cdx_path, csaf_path = release_output_paths(repo_root, tag)
            if args.skip_existing and os.path.isfile(csaf_path):
                logger.info("Skipping %s (VEX exists)", tag)
                continue
            logger.info("=== Refreshing VEX for %s ===", tag)
            try:
                entry = regenerate_vex_from_sbom(
                    tag,
                    cache_dir=cache_dir,
                    repo_root=repo_root,
                    api_key=api_key,
                    use_nvd=use_nvd,
                    use_ghsa=not args.no_ghsa,
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
                        "finished_at": datetime.now(UTC).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                    },
                )
        if failures:
            sys.exit(1)
        return

    uswid_data = args.uswid_data or ensure_uswid_data(cache_dir)

    manifest_path = os.path.join(repo_root, "manifest.json")

    failures = 0
    for tag in tags:
        cdx_path, csaf_path = release_output_paths(repo_root, tag)
        if args.skip_existing and outputs_complete(cdx_path, csaf_path):
            logger.info("Skipping %s (outputs exist)", tag)
            continue

        logger.info("=== Processing %s ===", tag)
        try:
            entry = scan_release(
                tag,
                cache_dir=cache_dir,
                repo_root=repo_root,
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
