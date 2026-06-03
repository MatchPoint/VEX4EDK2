# AGENTS.md — VEX4EDK2

Instructions for AI agents working in **MatchPoint/VEX4EDK2**.

## Role in the ecosystem

VEX4EDK2 is a **quarterly batch publisher**: for each `edk2-stableYYYYMM` tag it produces committed artifacts under `sbom/` and `vex/`.

| Repo | Role |
|------|------|
| **SBOM4EDK2** | EDK2 **source** CycloneDX SBOM only (native; uswid-data templates) |
| **uswid-data** | Curated CDX templates (Hughsie; data-only checkout) |
| **python-uswid** | Optional build/binary SBOM tooling (not required by VEX4EDK2) |
| **VEX4EDK2** (this repo) | Git checkout per tag → invoke SBOM4EDK2 → write CSAF VEX → commit `sbom/<tag>.cdx.json` + `vex/<tag>.csaf.json` |

**Related agent docs:** [SBOM4EDK2 `AGENTS.md`](https://github.com/MatchPoint/SBOM4EDK2/blob/main/AGENTS.md).

## Architecture

```text
vex4edk2.batch
    │
    ├── edk2_checkout.py     git mirror / worktree / --edk2-dir checkout + submodule scrub
    │
    ├── sbom4edk2.sbom       generate_sbom_from_checkout (source SBOM; PYTHONPATH)
    ├── vex4edk2.cve_analyzer + nvd + ghsa + grype (cve_scan)   CVE DataFrames (GHSA: [README](../README.md#tianocore-ghsa-advisories))
    │
    └── csaf.py              build_csaf_document / write_csaf
            │
            ▼
    sbom/<tag>.cdx.json
    vex/<tag>.csaf.json
```

### What belongs in this repo

| In scope | Out of scope (other repos) |
|----------|----------------------------|
| Quarterly tag list, manifest.json | Submodule version normalization → `sbom4edk2` |
| EDK2 mirror/worktree/`--edk2-dir` lifecycle | Per-`.inf` build SBOMs → `python-uswid` |
| CSAF VEX document structure | Source SBOM assembly → `sbom4edk2` |
| `vex4edk2/` CVE scanners (`nvd`, `grype`, `ghsa`, `cve_scan`) | Source SBOM assembly → `sbom4edk2` |
| `load_project_env()` CRLF-safe `.env` loading | |

## Environment setup

```bash
python -m venv venv && source venv/bin/activate   # or Windows equivalent
pip install -r requirements.txt
pip install -e .

# SBOM4EDK2 is not on PyPI:
export PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH

cp .env.example .env   # NVD_API_KEY required for full CSAF (NVD rows)
```

Use **LF line endings** in `.env` (or rely on `load_project_env()` which strips `\r` from `NVD_API_KEY`, `GITHUB_TOKEN`, `EDK2_DIR`).

## Running

```bash
python -m vex4edk2.batch --tag edk2-stable202411 --dry-run
python -m vex4edk2.batch --tag edk2-stable202411 --edk2-dir /path/to/edk2
python -m vex4edk2.batch --from-date 2021-05 --to-date 2026-02 --skip-existing
```

Verify CSAF parity against committed baseline:

```bash
python scripts/regen_and_compare_csaf.py
```

## Gotchas

- **Do not implement SBOM assembly here.** Call `generate_sbom_from_checkout`; never add per-`.inf` pools or CDX merge helpers.
- **CVE scanners live in `vex4edk2/`** (`cve_analyzer`, `nvd`, `grype`, `ghsa`, `cve_scan`). SBOM4EDK2 produces `.cdx.json` only.
- **Scenario 3 (CVE-only):** `python scripts/get_cve_response.py <sbom.cdx.json>` or `vex4edk2-cve-scan`.
- **`sbom/` and `vex/` are version-controlled.** Batch output updates belong in git unless the user says otherwise; `cache/` and `.env` stay gitignored.
- **Submodule scrub between tags** (`edk2_checkout.scrub_submodules`) is required for older EDK2 tags; do not skip without cause.
- **CSAF v1 is machine-generated only** — NVD component CVEs + applicable GHSA advisories; no manual VEX justifications in scope.
- **Full batch is long-running** (submodule init + NVD per tag). Use `--skip-existing` for resume.

## Tests

```bash
pip install -e .
export PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH
python -m unittest discover -s tests -v
```

See [docs/testing.md](docs/testing.md). Committed `vex/*.csaf.json` files must carry
`tracking.generator.engine.version` equal to `vex4edk2.__version__`; regenerate with
`python -m vex4edk2.batch --from-date … --to-date … --vex-only` after a version bump.
