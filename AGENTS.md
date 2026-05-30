# AGENTS.md — VEX4EDK2

Instructions for AI agents working in **MatchPoint/VEX4EDK2**.

## Role in the ecosystem

VEX4EDK2 is a **quarterly batch publisher**: for each `edk2-stableYYYYMM` tag it produces committed artifacts under `sbom/` and `vex/`.

| Repo | Role |
|------|------|
| **python-uswid-sbom** | SBOM creation (`uswid --primary-dir`) |
| **SBOM4EDK2** | Orchestration + CVE scanners (NVD, Grype, GHSA) |
| **VEX4EDK2** (this repo) | Git checkout per tag → invoke SBOM4EDK2 → write CSAF VEX → commit `sbom/<tag>.cdx.json` + `vex/<tag>.csaf.json` |

**Related agent docs:** [python-uswid-sbom `AGENTS.md`](https://github.com/MatchPoint/python-uswid-sbom/blob/main/AGENTS.md), [SBOM4EDK2 `AGENTS.md`](https://github.com/MatchPoint/SBOM4EDK2/blob/main/AGENTS.md).

## Architecture

```text
vex4edk2.batch
    │
    ├── edk2_checkout.py     git mirror / worktree / --edk2-dir checkout + submodule scrub
    │
    ├── sbom4edk2.sbom       generate_sbom_from_checkout → uswid CLI  (PYTHONPATH)
    ├── sbom4edk2.cve_analyzer + nvd + ghsa   NVD + GHSA DataFrames
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
| Quarterly tag list, manifest.json | Submodule version normalization → `uswid.submodule` |
| EDK2 mirror/worktree/`--edk2-dir` lifecycle | CycloneDX merge / `.inf` parsing → `uswid` |
| CSAF VEX document structure | NVD CPE matching logic → `sbom4edk2.nvd` / `cpe.py` |
| `load_project_env()` CRLF-safe `.env` loading | GHSA applicability rules → `sbom4edk2.ghsa` |

## Environment setup

```bash
python -m venv venv && source venv/bin/activate   # or Windows equivalent
pip install -r requirements.txt
pip install -e /path/to/python-uswid-sbom
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
python -m vex4edk2.batch --all --skip-existing
```

Verify CSAF parity against committed baseline:

```bash
python scripts/regen_and_compare_csaf.py
```

## Gotchas

- **Do not implement SBOM assembly here.** Call `generate_sbom_from_checkout`; never add per-`.inf` pools or CDX merge helpers.
- **Do not duplicate CVE scanner logic.** Import from `sbom4edk2` on `PYTHONPATH`; extend scanners there if needed.
- **`sbom/` and `vex/` are version-controlled.** Batch output updates belong in git unless the user says otherwise; `cache/` and `.env` stay gitignored.
- **Submodule scrub between tags** (`edk2_checkout.scrub_submodules`) is required for older EDK2 tags; do not skip without cause.
- **CSAF v1 is machine-generated only** — NVD component CVEs + applicable GHSA advisories; no manual VEX justifications in scope.
- **Full batch is long-running** (submodule init + NVD per tag). Use `--skip-existing` for resume.

## Tests

```bash
PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH python -m unittest discover -s tests -v
```
