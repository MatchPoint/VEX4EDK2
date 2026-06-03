# NVD platform CVEs not mapped into quarterly CSAF VEX

This document lists **TianoCore EDK II platform CVEs** that appear in the [NVD](https://nvd.nist.gov/) under product `tianocore:edk2` but are **not** emitted into any `vex/edk2-stableYYYYMM.csaf.json` file produced by VEX4EDK2.

## Why these CVEs are omitted

Quarterly CSAF documents attribute platform issues using:

1. **[TianoCore GitHub Security Advisories (GHSA)](https://github.com/tianocore/edk2/security/advisories)** — version ranges in `YYYYMM` form (e.g. `<=202508`), which map to `edk2-stableYYYYMM` releases.
2. **NVD lookup on the SBOM primary CPE** — `cpe:2.3:a:tianocore:edk2:edk2-stableYYYYMM:…` from `metadata.component`.

The CVEs in the catalog below have **no published GHSA** at the time the catalog was reconciled against [TianoCore advisories](https://github.com/tianocore/edk2/security/advisories?state=published). NVD associates them with `tianocore:edk2` using version tokens that **do not align** with quarterly stable tags (`edk2-stableYYYYMM`): wildcards (`-`, `*`), SVN revisions, calendar dates, or bare `YYYYMM` fields that are not wired into our per-release NVD pass. Until NVD configurations can be translated reliably to `edk2-stableYYYYMM`, VEX4EDK2 **does not** place them on a specific quarterly `known_affected` product — avoiding false attribution to modern stables.

**Risk:** These issues may still be relevant for older trees or for compliance views that expect full NVD `tianocore:edk2` coverage. Review NVD entries and TianoCore release notes directly.

## How this list was built

Reconciliation rule (repeat when updating this page):

1. **NVD union** — Collect every CVE ID returned for active CPE names matched by `cpeMatchString` `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` (query each resolved `cpeName` via NVD CVE API 2.0; deduplicate by CVE ID).
2. **Subtract GHSAs** — Remove any CVE ID that appears on a **published** [tianocore/edk2 security advisory](https://github.com/tianocore/edk2/security/advisories?state=published) (use each advisory’s `cve_id` or CVE-type identifier; skip test entries such as `***IGNORE***`).
3. **Catalog remainder** — What is left are NVD `tianocore:edk2` platform CVEs with **no matching published GHSA** at reconciliation time. Record each entry’s vulnerable `cpeMatch` `criteria` and version bounds from that CVE’s NVD `configurations`.

The entries below are a **point-in-time catalog** from that procedure. The list will shrink when TianoCore publishes a GHSA for a listed CVE, and may grow when NVD adds new `tianocore:edk2` associations.

Related platform CVEs **with** a published GHSA are mapped into quarterly CSAF when the release YYYYMM matches the advisory range; see batch `CVE_List_ghsa.xlsx` under `cache/scratch/<tag>/`.

## CVE catalog

Snapshot from the reconciliation rule above (NVD + published GHSAs). **Re-run the rule before relying on completeness** — do not assume the row count is fixed.

Each CVE is a subsection (not a table) so IDs render on one line on GitHub, which strips HTML table `style` attributes.

### [CVE-2014-4859](https://nvd.nist.gov/vuln/detail/CVE-2014-4859)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2014-4860](https://nvd.nist.gov/vuln/detail/CVE-2014-4860)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2014-8271](https://nvd.nist.gov/vuln/detail/CVE-2014-8271)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndExcluding=svn_16280`

### [CVE-2017-5731](https://nvd.nist.gov/vuln/detail/CVE-2017-5731)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndExcluding=2017-11-07`

### [CVE-2019-14553](https://nvd.nist.gov/vuln/detail/CVE-2019-14553)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2019-14559](https://nvd.nist.gov/vuln/detail/CVE-2019-14559)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2019-14562](https://nvd.nist.gov/vuln/detail/CVE-2019-14562)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2019-14563](https://nvd.nist.gov/vuln/detail/CVE-2019-14563)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2019-14575](https://nvd.nist.gov/vuln/detail/CVE-2019-14575)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2019-14584](https://nvd.nist.gov/vuln/detail/CVE-2019-14584)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndExcluding=2020-10-21`

### [CVE-2019-14586](https://nvd.nist.gov/vuln/detail/CVE-2019-14586)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2019-14587](https://nvd.nist.gov/vuln/detail/CVE-2019-14587)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2021-28210](https://nvd.nist.gov/vuln/detail/CVE-2021-28210)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndExcluding=202008`

### [CVE-2021-28211](https://nvd.nist.gov/vuln/detail/CVE-2021-28211)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:202008:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2021-28213](https://nvd.nist.gov/vuln/detail/CVE-2021-28213)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:201905:*:*:*:*:*:*:*`
- **Version bounds (NVD):** —

### [CVE-2021-38575](https://nvd.nist.gov/vuln/detail/CVE-2021-38575)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202105`

### [CVE-2021-38576](https://nvd.nist.gov/vuln/detail/CVE-2021-38576)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:201808:*:*:*:*:*:*:*` … `202105:*:*:*:*:*:*:*` (multiple discrete NVD version fields; see [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-38576))
- **Version bounds (NVD):** —

### [CVE-2021-38578](https://nvd.nist.gov/vuln/detail/CVE-2021-38578)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202202`

### [CVE-2023-45230](https://nvd.nist.gov/vuln/detail/CVE-2023-45230)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45231](https://nvd.nist.gov/vuln/detail/CVE-2023-45231)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45232](https://nvd.nist.gov/vuln/detail/CVE-2023-45232)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45233](https://nvd.nist.gov/vuln/detail/CVE-2023-45233)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45234](https://nvd.nist.gov/vuln/detail/CVE-2023-45234)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45235](https://nvd.nist.gov/vuln/detail/CVE-2023-45235)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45236](https://nvd.nist.gov/vuln/detail/CVE-2023-45236)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### [CVE-2023-45237](https://nvd.nist.gov/vuln/detail/CVE-2023-45237)

- **NVD vulnerable CPE criteria:** `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*`
- **Version bounds (NVD):** `versionEndIncluding=202311`

### CVE-2021-38576 — discrete NVD version CPEs

`201808`, `201811`, `201903`, `201905`, `201908`, `201911`, `202002`, `202005`, `202008`, `202011`, `202102`, `202105` (each as `cpe:2.3:a:tianocore:edk2:<version>:*:*:*:*:*:*:*`).

### CVE-2023-45230 – CVE-2023-45237

Same advisory family as [CVE-2023-45229](https://nvd.nist.gov/vuln/detail/CVE-2023-45229), which **does** have a [GHSA](https://github.com/tianocore/edk2/security/advisories) and appears in CSAF when the release YYYYMM is in range. Sibling CVE IDs are listed here because NVD does not publish a matching GHSA per ID.

## GHSA platform CVEs (for contrast)

Platform issues **with** a published GHSA are the normal path into quarterly CSAF: VEX4EDK2 applies the advisory’s YYYYMM range to the SBOM release. Those CVE IDs are **not** listed in the catalog above.

At reconciliation time, platform CVEs fall into three buckets:

| Bucket | Meaning |
|--------|---------|
| **GHSA only** | Published advisory exists; CVE may or may not yet appear under NVD `tianocore:edk2`. CSAF uses GHSA when the release is in range. |
| **Both GHSA and NVD `edk2`** | Same CVE ID in the NVD union and on a published GHSA — CSAF uses GHSA for release mapping; NVD is redundant for platform attribution. |
| **NVD `edk2` only** | Entries in the catalog — no published GHSA yet, and no reliable `edk2-stableYYYYMM` mapping in VEX4EDK2. |

For the current set of published advisories and release-level applicability, use the [GitHub advisory list](https://github.com/tianocore/edk2/security/advisories?state=published) and per-tag `CVE_List_ghsa.xlsx` from batch output — not a frozen CVE list in this file.

## Maintenance

Update this document when:

- TianoCore publishes a new GHSA whose CVE ID was listed here (remove that entry after re-running the reconciliation rule).
- NVD adds or changes `tianocore:edk2` CPE configurations for platform CVEs (add or edit entries; refresh CPE/bounds from NVD API 2.0).
- VEX4EDK2 begins emitting a catalog CVE in quarterly CSAF via `edk2-stableYYYYMM` mapping (remove or annotate the entry).

Prefer **git commit history** on this file for when the catalog last changed; avoid embedding advisory counts or “last reviewed” dates that go stale immediately when a new GHSA ships.
