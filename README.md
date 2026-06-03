# VEX4EDK2

Batch-generate **CycloneDX SBOMs** and **CSAF 2.0 VEX** documents for [TianoCore EDK II](https://github.com/tianocore/edk2) stable releases, a single release, or the current development tip.

## What VEX4EDK2 produces

For each EDK II release label (quarterly stable tag or tip `git describe` name), a batch run writes paired artifacts and records progress in `manifest.json`:

| File | Description |
|------|-------------|
| `sbom/<label>.cdx.json` | Source SBOM from [SBOM4EDK2](https://github.com/MatchPoint/SBOM4EDK2) |
| `vex/<label>.csaf.json` | CSAF 2.0 VEX profile — machine-readable vulnerability status for that release |
| `manifest.json` | Per-tag scan metadata (status, paths, vulnerability count, SBOM4EDK2 version, timestamps) |

The `sbom/` and `vex/` trees are **version-controlled** for quarterly stables you choose to publish. Each scan also writes NVD/GHSA **Excel CVE reports** under `cache/scratch/<tag>/` (`CVE_List.xlsx`, `CVE_List_ghsa.xlsx`) for review; they are **gitignored** and kept by default.

### CSAF VEX contents

Each `vex/<label>.csaf.json` document includes:

- **Product tree** — TianoCore EDK II firmware (primary product) plus SBOM components with stable `product_id` values derived from CycloneDX `bom-ref`.
- **Component CVEs (NVD)** — CVEs matched to SBOM component CPEs via the NVD API, including every entry in `components[]` **and** the primary EDK II product in `metadata.component` (same CPE as the platform firmware). Each entry lists affected components under `vulnerabilities[].product_status.known_affected`. Batch runs use NVD for this step; see [Component CVE sourcing](#component-cve-sourcing-nvd-vs-grype).
- **Platform CVEs (GHSA + NVD)** — Published [TianoCore EDK II GitHub Security Advisories](https://github.com/tianocore/edk2/security/advisories) that apply to the release’s YYYYMM version, **plus** NVD CVEs tied to the primary `tianocore:edk2` CPE from the SBOM (version field such as `edk2-stable202602`). GHSA-sourced rows include a link to the advisory page and the GHSA identifier in document notes; NVD-only platform CVEs (no matching GHSA) **are in scope** when NVD associates them with that versioned `edk2` CPE. Legacy NVD product name `tianocore:edk_ii` (UDK-era versions only) is **not** queried — it would attach pre-2020 CVEs to modern quarterly releases. Platform issues are attributed to the primary EDK II firmware product, not individual submodules.
- **NVD platform CVEs not in CSAF** — [26 NVD `tianocore:edk2` CVEs](docs/nvd-edk2-platform-cves-not-in-csaf.md) with no GHSA and no reliable `edk2-stableYYYYMM` mapping are documented separately; they are **not** listed in quarterly CSAF until versioning can be determined.

v1 documents are **machine-generated** and report `known_affected` status only. Manual VEX justifications (`not_affected`, `fixed`, and similar) are out of scope.

See [Component CVE sourcing](#component-cve-sourcing-nvd-vs-grype) and [TianoCore GHSA advisories](#tianocore-ghsa-advisories) below for how each feed is configured.

### Run modes

Three CLI patterns cover the same SBOM → CVE scan → CSAF pipeline:

| Mode | CLI | Use when |
|------|-----|----------|
| **Date range** | `--from-date YYYY-MM --to-date YYYY-MM` | Quarterly batch over many stables; tags discovered from git (`edk2-stableYYYYMM` only — no `-rc`, no `.01` point releases) |
| **Single tag** | `--tag edk2-stableYYYYMM` | One quarterly release |
| **Tip** | `--tip --edk2-dir …` | Current development tree (`git describe` label; no checkout) |

`--skip-existing` resumes a batch; `--vex-only` rebuilds CSAF from committed SBOMs without checking out EDK II. Pass `--cleanup-scratch-excel` to delete the scratch Excel files after each successful CSAF write (default is to keep them). Details in [Usage](#usage).

### Component CVE sourcing (NVD vs Grype)

VEX4EDK2 can build component CVE lists from **NVD** (live API, CPE-based) or **Grype** (local scanner, SBOM input). **GHSA** is a third, separate feed for TianoCore platform advisories — not a substitute for either scanner ([below](#tianocore-ghsa-advisories)).

| | **NVD** | **Grype** |
|---|---------|-----------|
| **What it does** | Queries the [NVD API](https://nvd.nist.gov/developers) per SBOM CPE pattern (`metadata.component` + `components[]`) | Runs the [Grype](https://github.com/anchore/grype) CLI against the CycloneDX SBOM |
| **Requirements** | Free `NVD_API_KEY` ([request here](https://nvd.nist.gov/developers/request-an-api-key)); network access | `grype` binary on PATH (or `~/.local/bin/grype` on Linux/WSL; `winget install Anchore.Grype` on Windows) |
| **Matching** | CPE 2.3 patterns built from SBOM metadata | CPE and PURL; merges NVD, GitHub Advisory, OSV, and other DBs Grype ships |
| **Output** | `CVE_List.xlsx` | `CVE_List_grype_<sbom>.xlsx` (includes EPSS when available) |
| **Local storage** | No vulnerability database on disk (network-only) | Grype vulnerability DB (~600 MB on first download; cached under Grype’s data directory, e.g. `~/.cache/grype` on Linux) |
| **Speed** | Slower: per-component NVD HTTP calls and API rate limits | Fast after the DB is present: local scan of the SBOM |
| **Used in batch CSAF** | Yes — default for `vex/<label>.csaf.json` component CVEs | No — standalone CVE Excel reports only |
| **Typical tradeoff** | Authoritative NVD CPE records; no large local DB; same path batch uses for published VEX | No API key; broader matching and EPSS; one-time DB download and disk use; CVE rows may differ from strict NVD lookup |

**Observed timing (eight quarterly SBOMs, component CVE step only):** with `NVD_API_KEY`, roughly **12 minutes** end-to-end for all eight releases; with Grype after the vulnerability database is already on disk, roughly **7 seconds** for the same eight runs via `get_cve_response.py` / `--scanner grype`. First Grype use still pays the **~600 MB** database download (and update time) before those fast runs. Published batch CSAF in this repo uses the NVD path unless you change the tooling.

**Which CLI uses which scanner**

| Entry point | Default behavior |
|-------------|------------------|
| `python -m vex4edk2.batch` (and `scripts/batch_scan_releases.py`) | NVD when `NVD_API_KEY` is set; fails at startup if the key is missing unless you pass `--no-nvd` |
| `python scripts/get_cve_response.py` / `vex4edk2-cve-scan` | `--scanner auto` (default): NVD when `NVD_API_KEY` is set, otherwise Grype |

#### Configure NVD

1. Copy `.env.example` to `.env` and set `NVD_API_KEY=…`, or export the variable in your shell.
2. Optional override on the command line: `-k` / `--apikey`.

**Batch** (SBOM + CSAF):

```bash
# .env: NVD_API_KEY=your-key
python -m vex4edk2.batch --tag edk2-stable202411

# Skip component CVE lookup (CSAF still includes applicable GHSA advisories unless --no-ghsa)
python -m vex4edk2.batch --tag edk2-stable202411 --no-nvd
```

**Standalone CVE report** on an existing SBOM:

```bash
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json --scanner nvd
# or: vex4edk2-cve-scan sbom/edk2-stable202411.cdx.json --scanner nvd
```

#### Configure Grype

Install Grype so VEX4EDK2 can find it (`grype` on PATH is enough; see `vex4edk2/grype.py` for extra search paths).

```bash
# Linux / WSL
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b ~/.local/bin

# Windows
winget install Anchore.Grype

# First run: download/update the local vulnerability database (~600 MB)
grype db update
```

**Standalone CVE report** (Grype does not feed batch CSAF today):

```bash
# Explicit Grype scan (no NVD key needed)
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json --scanner grype

# Default auto: Grype when NVD_API_KEY is unset
unset NVD_API_KEY   # Linux; omit key from .env on Windows
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json

# Run both scanners and write both Excel files
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json --scanner both -k "$NVD_API_KEY"
```

Scanner flags for the standalone tool: `--scanner auto|nvd|grype|both` (default `auto`), `-k` / `--apikey`, and `--no-ghsa` to skip the TianoCore GHSA Excel pass.

### TianoCore GHSA advisories

Platform CVE coverage uses **both** feeds: NVD on the primary EDK II CPE (including CVEs that never received a TianoCore GHSA) and the GitHub advisories API below. Advisories often appear on GitHub months before NVD indexes them; NVD-only platform CVEs are still included in CSAF output. VEX4EDK2 queries the public [TianoCore EDK II security advisories API](https://github.com/tianocore/edk2/security/advisories?state=published) on every scan (no API key required; optional `GITHUB_TOKEN` raises rate limits).

For each advisory, the tool:

1. Reads the SBOM’s EDK II version as a six-digit **YYYYMM** integer (for example `202602` from `edk2-stable202602` or the metadata CPE).
2. Evaluates GitHub’s version constraints (for example `<=202508` or `>=202311, <202402`) against that release.
3. Skips advisories already fixed in the scanned release (patched in a later stable).
4. Merges applicable advisories into the CSAF `vulnerabilities[]` list alongside NVD component matches.

In the CSAF output, each GHSA-sourced entry includes the CVE identifier, summary text, CVSS score when published, a `references[]` link to the advisory on GitHub, and a note titled **GitHub Security Advisory** with the GHSA ID (for example `GHSA-xxxx-xxxx-xxxx`).

To skip GHSA on a batch run, pass `--no-ghsa` (independent of `--no-nvd`). On standalone CVE scans, use `--no-ghsa` with `get_cve_response.py` / `vex4edk2-cve-scan`.

## License

BSD 2-Clause — see [LICENSE](LICENSE) (same as [SBOM4EDK2](https://github.com/MatchPoint/SBOM4EDK2)).

## Prerequisites

- Python 3.10+
- `git` (worktrees + submodules)
- [SBOM4EDK2](https://github.com/MatchPoint/SBOM4EDK2) checkout — provides `sbom4edk2` on `PYTHONPATH`
- [hughsie/uswid-data](https://github.com/hughsie/uswid-data) — CDX templates for `--uswid-data`
- **Component CVE lookup:** `NVD_API_KEY` for batch and for NVD-mode scans ([free key](https://nvd.nist.gov/developers/request-an-api-key)), **or** [Grype](https://github.com/anchore/grype) for standalone `--scanner grype` / `auto` without a key ([details](#component-cve-sourcing-nvd-vs-grype))

## Setup

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux:   source venv/bin/activate

pip install -r requirements.txt
pip install -e .

# SBOM4EDK2 is not packaged on PyPI; add its repo root to PYTHONPATH:
#   export PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH   # Linux
#   $env:PYTHONPATH="C:\path\to\SBOM4EDK2;$env:PYTHONPATH"  # Windows

cp .env.example .env
# Edit .env: NVD_API_KEY=... (required for batch; optional for standalone if using Grype via --scanner auto/grype)
```

## Usage

### Quarterly releases in a date range

Pass inclusive **`YYYY-MM`** bounds. The batch lists `edk2-stableYYYYMM` tags from git (via `cache/edk2-mirror` and/or your `--edk2-dir` clone) and processes every quarterly stable whose month falls in the range.

```bash
# List tags that would run (five calendar years: May 2021 through Feb 2026)
python -m vex4edk2.batch \
  --from-date 2021-05 \
  --to-date 2026-02 \
  --dry-run

# Generate SBOM + VEX for all quarterly stables in that range (long-running)
python -m vex4edk2.batch \
  --from-date 2021-05 \
  --to-date 2026-02

# Same range, reuse your EDK II clone (checkout each tag; scrubs submodules between tags)
python -m vex4edk2.batch \
  --from-date 2021-05 \
  --to-date 2026-02 \
  --edk2-dir /path/to/edk2 \
  --skip-existing

# Resume: skip tags that already have both sbom/<tag>.cdx.json and vex/<tag>.csaf.json
python -m vex4edk2.batch \
  --from-date 2024-05 \
  --to-date 2026-02 \
  --skip-existing

# Refresh VEX only from committed SBOMs (no EDK II checkout)
python -m vex4edk2.batch \
  --from-date 2021-05 \
  --to-date 2026-02 \
  --vex-only
```

The committed artifacts in this repository today cover **2024-05 through 2026-02** (eight quarterly stables). Extend the range (for example back to **2021-05**) when you need five years of history.

### One specific quarterly release

```bash
python -m vex4edk2.batch --tag edk2-stable202411

# Delete scratch Excel after CSAF is written (default keeps them under cache/scratch/<tag>/)
python -m vex4edk2.batch --tag edk2-stable202411 --cleanup-scratch-excel
```

### Tip of EDK II development (current tree)

Scan the checkout **as-is** (no `git checkout`). Output names come from `git describe` (for example `edk2-stable202602+196.g0fe6b755f2`).

```bash
export EDK2_DIR=/path/to/edk2   # or: --edk2-dir /path/to/edk2

python -m vex4edk2.batch --tip --edk2-dir "$EDK2_DIR"
```

```powershell
$env:EDK2_DIR = "C:\path\to\edk2"
python -m vex4edk2.batch --tip --edk2-dir $env:EDK2_DIR
```

You can also scan a tree that is already on a release tag without checking out again:

```bash
python -m vex4edk2.batch --tag edk2-stable202602 --edk2-dir /path/to/edk2 --use-current
```

See [docs/edk2-checkout.md](docs/edk2-checkout.md) for mirror worktrees vs `--edk2-dir`.

### CVE-only on an existing SBOM

Standalone scans use `vex4edk2.cve_scan` (wrapper: `scripts/get_cve_response.py` or `vex4edk2-cve-scan`). Default `--scanner auto` picks NVD when `NVD_API_KEY` is set, otherwise Grype. See [Component CVE sourcing](#component-cve-sourcing-nvd-vs-grype).

```bash
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json
# or: vex4edk2-cve-scan sbom/edk2-stable202411.cdx.json

# Force Grype (no NVD key) or run both
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json --scanner grype
python scripts/get_cve_response.py sbom/edk2-stable202411.cdx.json --scanner both -k "$NVD_API_KEY"
```

### Wrapper script

```bash
python scripts/batch_scan_releases.py \
  --from-date 2021-05 \
  --to-date 2026-02 \
  --skip-existing
```

## Layout

```
VEX4EDK2/
  cache/              # gitignored: edk2 mirror, worktrees, uswid-data
  sbom/               # committed: <label>.cdx.json per release or tip
  vex/                # committed: <label>.csaf.json per release or tip
  manifest.json       # scan status per tag (updated by batch)
  vex4edk2/
    batch.py          # CLI orchestrator
    releases.py       # date-range tag selection (git discovery)
    csaf.py           # CSAF VEX writer
    cve_scan.py       # NVD / Grype / GHSA orchestration
    edk2_checkout.py  # git mirror, worktrees, tag listing
  scripts/
    get_cve_response.py
    batch_scan_releases.py
  docs/
    testing.md
    edk2-checkout.md
```

## Tests

```bash
pip install -e .
export PYTHONPATH=/path/to/SBOM4EDK2:$PYTHONPATH
python -m unittest discover -s tests -v
```

Details: [docs/testing.md](docs/testing.md).

## Related projects

| Project | Role |
|---------|------|
| SBOM4EDK2 | EDK2 **source** CycloneDX SBOM (native; v0.6.0+) |
| VEX4EDK2 (this repo) | Batch SBOM/VEX + NVD / Grype / GHSA → CSAF VEX |
| [python-uswid](https://github.com/hughsie/python-uswid) | Optional build/binary SBOM tooling |
| [uswid-data](https://github.com/hughsie/uswid-data) | Submodule CDX templates with `@VCS_*@` placeholders |
