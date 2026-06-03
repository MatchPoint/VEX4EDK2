# Testing

## Unit tests

No EDK II checkout, NVD API key, or live network is required for the default suite.

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

# SBOM4EDK2 is not on PyPI — required for batch import smoke tests only
export PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH

python -m unittest discover -s tests -v
# or: python -m pytest tests/ -v
```

| File | Coverage |
|------|----------|
| `tests/test_csaf.py` | CSAF document shape, generator `engine.version`, SBOM4EDK2 summary note |
| `tests/test_cve_scan.py` | CPE patterns, GHSA version logic, NVD/Grype/GHSA mocks |
| `tests/test_batch_smoke.py` | CLI helpers, `.env` CRLF normalization, manifest `vex4edk2_version` |
| `tests/test_releases_outputs.py` | All eight `sbom/` + `vex/` artifacts; CSAF metadata vs package version |

## Version metadata in CSAF

Each `vex/<tag>.csaf.json` includes:

```json
"tracking": {
  "generator": {
    "engine": { "name": "VEX4EDK2", "version": "<package version>" }
  }
}
```

The summary note references the SBOM tool: `SBOM produced by SBOM4EDK2 (<version>)`.

`tests/test_releases_outputs.py` includes gated checks that committed CSAF files
match the installed `vex4edk2.__version__` and reference SBOM4EDK2 in the summary
note. Those tests are **skipped** until `vex/` is regenerated; after refresh they
run automatically. Regenerate with:

```bash
python -m vex4edk2.batch --all --vex-only
```

## What unit tests assert

- Quarterly tag list (eight `edk2-stableYYYYMM` releases)
- CSAF merges NVD component CVEs and applicable TianoCore GHSA rows
- `manifest.json` updates include `vex4edk2_version` and per-release `sbom4edk2_version`
- CVE scanners import from `vex4edk2` (not SBOM4EDK2)
- `load_project_env()` strips CRLF from `NVD_API_KEY` / `EDK2_DIR` (WSL-safe `.env`)

## Integration (optional)

Full batch or single-tag scan against a real EDK II tree — see [README](../README.md)
and [edk2-checkout.md](edk2-checkout.md). Compare regenerated CSAF to baseline:

```bash
python scripts/regen_and_compare_csaf.py
```

## CI

Run `python -m unittest discover -s tests` on changes to `vex4edk2/`, `tests/`, or
committed `sbom/` / `vex/` artifacts. Set `PYTHONPATH` to a pinned SBOM4EDK2 checkout
when running import smoke tests in CI.
