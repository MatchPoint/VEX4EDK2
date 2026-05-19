# VEX4EDK2

Batch-generate **CycloneDX SBOMs** and **CSAF 2.0 VEX** documents for quarterly [TianoCore EDK II](https://github.com/tianocore/edk2) stable releases (last two years).

Each release is stored under `releases/<tag>/`:

| File | Description |
|------|-------------|
| `edk2.cdx.json` | Source SBOM (via [SBOM4EDK2](https://github.com/MatchPoint/python-uswid-sbom) + `uswid --primary-dir`) |
| `edk2.csaf.json` | CSAF VEX profile document (NVD component CVEs + applicable TianoCore GHSA advisories) |

The `releases/` tree is **version-controlled**: each quarterly tag folder contains the
generated `edk2.cdx.json` and `edk2.csaf.json` artifacts (Excel CVE reports stay
gitignored). See `manifest.json` for batch scan metadata.

## License

BSD 2-Clause — see [LICENSE](LICENSE) (same as [SBOM4EDK2](https://github.com/MatchPoint/SBOM4EDK2)).

## Prerequisites

- Python 3.10+
- `git` (worktrees + submodules)
- [SBOM4EDK2](https://github.com/MatchPoint/SBOM4EDK2) checkout — provides `sbom4edk2` on `PYTHONPATH`
- [python-uswid-sbom](https://github.com/MatchPoint/python-uswid-sbom) — provides `uswid` (SBOM engine)
- NVD API key (free) for component CVE lookup

## Setup

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux:   source venv/bin/activate

pip install -r requirements.txt
pip install -e /path/to/python-uswid-sbom
pip install -e .

# SBOM4EDK2 is not packaged on PyPI; add its repo root to PYTHONPATH:
#   export PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH   # Linux
#   $env:PYTHONPATH="C:\path\to\SBOM4EDK2;$env:PYTHONPATH"  # Windows

cp .env.example .env
# Edit .env: NVD_API_KEY=...
```

## Usage

```bash
# List quarterly tags (dry run)
python -m vex4edk2.batch --all --dry-run

# Process all 8 quarterly releases (long-running; submodule + NVD per tag)
python -m vex4edk2.batch --all

# Reuse your EDK II clone (checks out each tag; scrubs submodules between tags)
python -m vex4edk2.batch --all --edk2-dir /path/to/edk2 --skip-existing

# Single release (debug)
python -m vex4edk2.batch --tag edk2-stable202411

# Resume: skip folders that already have both outputs
python -m vex4edk2.batch --all --skip-existing

# Optional: keep CVE Excel reports in each release folder
python -m vex4edk2.batch --tag edk2-stable202411 --write-xlsx
```

### Using an existing EDK II clone

If you already have EDK II checked out (for example the tree used by SBOM4EDK2),
pass `--edk2-dir` or set `EDK2_DIR` in `.env`. See [docs/edk2-checkout.md](docs/edk2-checkout.md).

```powershell
# Scan the checkout as-is (no git checkout) — typical for your current tree
$env:EDK2_DIR = "C:\temp\test\SBOM4EDK2\edk2"
python -m vex4edk2.batch --tag edk2-stable202602 --edk2-dir $env:EDK2_DIR --use-current

# Or: checkout a specific tag in your clone, then restore HEAD when done
python -m vex4edk2.batch --tag edk2-stable202411 --edk2-dir C:\temp\test\SBOM4EDK2\edk2
```

Equivalent wrapper:

```bash
python scripts/batch_scan_releases.py --all --skip-existing
```

## Release tags (v1)

Quarterly stable only (no `-rc`, no `.01` point releases):

`edk2-stable202405`, `202408`, `202411`, `202502`, `202505`, `202508`, `202511`, `202602`

## Layout

```
VEX4EDK2/
  cache/              # gitignored: edk2 mirror, worktrees, uswid-data
  releases/           # committed: per-tag edk2.cdx.json + edk2.csaf.json
    edk2-stable202411/
      edk2.cdx.json
      edk2.csaf.json
  manifest.json       # scan status per tag (updated by batch)
  vex4edk2/
    batch.py          # CLI orchestrator
    csaf.py           # CSAF VEX writer
    edk2_checkout.py  # git mirror, worktrees, or --edk2-dir checkout
  docs/
    edk2-checkout.md  # --edk2-dir / --use-current guide
```

## CSAF scope

v1 documents are **machine-generated**:

- **NVD:** CVEs matched per component CPE in the SBOM → `product_status.known_affected`
- **GHSA:** TianoCore EDK II advisories applicable to the release YYYYMM → primary firmware product

Manual VEX justifications (`not_affected`, etc.) are out of scope for v1.

## Tests

```bash
pip install -e .
python -m pytest tests/ -v
```

Tests include unit checks for CSAF/CLI/checkout logic and a guard that all eight
quarterly folders under `releases/` contain both JSON artifacts.

## Related projects

| Project | Role |
|---------|------|
| [python-uswid-sbom](https://github.com/MatchPoint/python-uswid-sbom) | CycloneDX SBOM generation, UEFI SBOM Guidelines |
| SBOM4EDK2 | Clone/scan orchestration, NVD + GHSA scanners |
| [uswid-data](https://github.com/hughsie/uswid-data) | Submodule CDX templates with `@VCS_*@` placeholders |
