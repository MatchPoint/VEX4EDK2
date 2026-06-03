# NVD platform CVEs not mapped into quarterly CSAF VEX

This document lists **TianoCore EDK II platform CVEs** that appear in the [NVD](https://nvd.nist.gov/) under product `tianocore:edk2` but are **not** emitted into any `vex/edk2-stableYYYYMM.csaf.json` file produced by VEX4EDK2.

## Why these CVEs are omitted

Quarterly CSAF documents attribute platform issues using:

1. **[TianoCore GitHub Security Advisories (GHSA)](https://github.com/tianocore/edk2/security/advisories)** — version ranges in `YYYYMM` form (e.g. `<=202508`), which map to `edk2-stableYYYYMM` releases.
2. **NVD lookup on the SBOM primary CPE** — `cpe:2.3:a:tianocore:edk2:edk2-stableYYYYMM:…` from `metadata.component`.

The CVEs below have **no published GHSA** (as of the last review). NVD associates them with `tianocore:edk2` using version tokens that **do not align** with quarterly stable tags (`edk2-stable202602`, etc.): wildcards (`-`, `*`), SVN revisions, calendar dates, or bare `YYYYMM` fields that are not wired into our per-release NVD pass. Until NVD configurations can be translated reliably to `edk2-stableYYYYMM`, VEX4EDK2 **does not** place them on a specific quarterly `known_affected` product — avoiding false “affects 2026” attribution.

**Risk:** These issues may still be relevant for older trees or for compliance views that expect full NVD `tianocore:edk2` coverage. Review NVD entries and TianoCore release notes directly.

## How this list was built

- Union of CVEs returned by NVD `cpeMatchString` `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` (32 dictionary CPEs, 30 unique CVE IDs).
- Minus CVE IDs that appear on a **published** `tianocore/edk2` GHSA (12 advisories → 12 CVE IDs; 4 overlap the NVD union).
- **26 CVEs** remain (NVD platform, no GHSA).
- CPE `criteria` and bounds from each CVE’s NVD `configurations` → vulnerable `cpeMatch` (fetched via NVD API 2.0).

Related GHSA-only platform CVEs (not in this table) are tracked in CSAF when advisories apply; see batch `CVE_List_ghsa.xlsx` under `cache/scratch/<tag>/`.

## CVE catalog (26)

| CVE | NVD vulnerable CPE criteria | Version bounds (NVD) |
|-----|----------------------------|----------------------|
| [CVE-2014-4859](https://nvd.nist.gov/vuln/detail/CVE-2014-4859) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2014-4860](https://nvd.nist.gov/vuln/detail/CVE-2014-4860) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2014-8271](https://nvd.nist.gov/vuln/detail/CVE-2014-8271) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndExcluding=svn_16280` |
| [CVE-2017-5731](https://nvd.nist.gov/vuln/detail/CVE-2017-5731) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndExcluding=2017-11-07` |
| [CVE-2019-14553](https://nvd.nist.gov/vuln/detail/CVE-2019-14553) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2019-14559](https://nvd.nist.gov/vuln/detail/CVE-2019-14559) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2019-14562](https://nvd.nist.gov/vuln/detail/CVE-2019-14562) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2019-14563](https://nvd.nist.gov/vuln/detail/CVE-2019-14563) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2019-14575](https://nvd.nist.gov/vuln/detail/CVE-2019-14575) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2019-14584](https://nvd.nist.gov/vuln/detail/CVE-2019-14584) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndExcluding=2020-10-21` |
| [CVE-2019-14586](https://nvd.nist.gov/vuln/detail/CVE-2019-14586) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2019-14587](https://nvd.nist.gov/vuln/detail/CVE-2019-14587) | `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*` | — |
| [CVE-2021-28210](https://nvd.nist.gov/vuln/detail/CVE-2021-28210) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndExcluding=202008` |
| [CVE-2021-28211](https://nvd.nist.gov/vuln/detail/CVE-2021-28211) | `cpe:2.3:a:tianocore:edk2:202008:*:*:*:*:*:*:*` | — |
| [CVE-2021-28213](https://nvd.nist.gov/vuln/detail/CVE-2021-28213) | `cpe:2.3:a:tianocore:edk2:201905:*:*:*:*:*:*:*` | — |
| [CVE-2021-38575](https://nvd.nist.gov/vuln/detail/CVE-2021-38575) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202105` |
| [CVE-2021-38576](https://nvd.nist.gov/vuln/detail/CVE-2021-38576) | `cpe:2.3:a:tianocore:edk2:201808:*:*:*:*:*:*:*` … `202105:*:*:*:*:*:*:*` (12 discrete versions; see [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-38576)) | — |
| [CVE-2021-38578](https://nvd.nist.gov/vuln/detail/CVE-2021-38578) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202202` |
| [CVE-2023-45230](https://nvd.nist.gov/vuln/detail/CVE-2023-45230) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45231](https://nvd.nist.gov/vuln/detail/CVE-2023-45231) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45232](https://nvd.nist.gov/vuln/detail/CVE-2023-45232) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45233](https://nvd.nist.gov/vuln/detail/CVE-2023-45233) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45234](https://nvd.nist.gov/vuln/detail/CVE-2023-45234) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45235](https://nvd.nist.gov/vuln/detail/CVE-2023-45235) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45236](https://nvd.nist.gov/vuln/detail/CVE-2023-45236) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |
| [CVE-2023-45237](https://nvd.nist.gov/vuln/detail/CVE-2023-45237) | `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` | `versionEndIncluding=202311` |

### CVE-2021-38576 — discrete NVD version CPEs

`201808`, `201811`, `201903`, `201905`, `201908`, `201911`, `202002`, `202005`, `202008`, `202011`, `202102`, `202105` (each as `cpe:2.3:a:tianocore:edk2:<version>:*:*:*:*:*:*:*`).

### CVE-2023-45230 – CVE-2023-45237

Same advisory family as [CVE-2023-45229](https://nvd.nist.gov/vuln/detail/CVE-2023-45229), which **does** have a [GHSA](https://github.com/tianocore/edk2/security/advisories) and appears in CSAF when the release YYYYMM is in range. Sibling CVE IDs are listed here because NVD does not publish a matching GHSA per ID.

## GHSA platform CVEs (for contrast)

These **are** mapped into CSAF when the release version matches; they are **not** duplicated in the table above:

| CVE | In NVD `edk2` union? |
|-----|----------------------|
| CVE-2022-36763, CVE-2022-36764, CVE-2022-36765 | Yes |
| CVE-2023-45229 | Yes |
| CVE-2024-1298, CVE-2024-38796, CVE-2024-38797, CVE-2024-38798, CVE-2024-38805 | GHSA only (not in NVD `edk2` union at last review) |
| CVE-2025-2295, CVE-2025-2296, CVE-2025-3770 | GHSA only |

## Maintenance

Reconcile this list when:

- TianoCore publishes new GHSAs for previously NVD-only IDs.
- VEX4EDK2 gains NVD configuration → `edk2-stableYYYYMM` mapping and emits these CVEs in CSAF (then remove or annotate rows here).
- NVD changes `tianocore:edk2` CPE configurations materially.

Last reviewed: **2026-06-03** (NVD API 2.0, published `tianocore/edk2` GHSAs).
