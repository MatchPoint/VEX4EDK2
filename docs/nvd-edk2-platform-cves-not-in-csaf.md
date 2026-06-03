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

<!-- HTML table: nowrap CVE column; GitHub/Cursor ignore most width hints but honor white-space -->
<table>
<colgroup>
<col style="width: 10em">
<col>
<col style="width: 16em">
</colgroup>
<thead>
<tr>
<th style="white-space: nowrap">CVE</th>
<th>NVD vulnerable CPE criteria</th>
<th style="white-space: nowrap">Version bounds (NVD)</th>
</tr>
</thead>
<tbody>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2014-4859">CVE-2014-4859</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2014-4860">CVE-2014-4860</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2014-8271">CVE-2014-8271</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndExcluding=svn_16280</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2017-5731">CVE-2017-5731</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndExcluding=2017-11-07</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14553">CVE-2019-14553</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14559">CVE-2019-14559</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14562">CVE-2019-14562</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14563">CVE-2019-14563</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14575">CVE-2019-14575</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14584">CVE-2019-14584</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndExcluding=2020-10-21</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14586">CVE-2019-14586</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2019-14587">CVE-2019-14587</a></td><td><code>cpe:2.3:a:tianocore:edk2:-:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-28210">CVE-2021-28210</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndExcluding=202008</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-28211">CVE-2021-28211</a></td><td><code>cpe:2.3:a:tianocore:edk2:202008:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-28213">CVE-2021-28213</a></td><td><code>cpe:2.3:a:tianocore:edk2:201905:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38575">CVE-2021-38575</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202105</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38576">CVE-2021-38576</a></td><td><code>cpe:2.3:a:tianocore:edk2:201808:*:*:*:*:*:*:*</code> … <code>202105:*:*:*:*:*:*:*</code> (12 discrete versions; see <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38576">NVD</a>)</td><td style="white-space: nowrap">—</td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38578">CVE-2021-38578</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202202</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45230">CVE-2023-45230</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45231">CVE-2023-45231</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45232">CVE-2023-45232</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45233">CVE-2023-45233</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45234">CVE-2023-45234</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45235">CVE-2023-45235</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45236">CVE-2023-45236</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2023-45237">CVE-2023-45237</a></td><td><code>cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*</code></td><td style="white-space: nowrap"><code>versionEndIncluding=202311</code></td></tr>
</tbody>
</table>

### CVE-2021-38576 — discrete NVD version CPEs

`201808`, `201811`, `201903`, `201905`, `201908`, `201911`, `202002`, `202005`, `202008`, `202011`, `202102`, `202105` (each as `cpe:2.3:a:tianocore:edk2:<version>:*:*:*:*:*:*:*`).

### CVE-2023-45230 – CVE-2023-45237

Same advisory family as [CVE-2023-45229](https://nvd.nist.gov/vuln/detail/CVE-2023-45229), which **does** have a [GHSA](https://github.com/tianocore/edk2/security/advisories) and appears in CSAF when the release YYYYMM is in range. Sibling CVE IDs are listed here because NVD does not publish a matching GHSA per ID.

## GHSA platform CVEs (for contrast)

These **are** mapped into CSAF when the release version matches; they are **not** duplicated in the table above:

<table>
<colgroup>
<col style="width: 28em">
<col>
</colgroup>
<thead>
<tr>
<th style="white-space: nowrap">CVE</th>
<th>In NVD <code>edk2</code> union?</th>
</tr>
</thead>
<tbody>
<tr><td style="white-space: nowrap">CVE-2022-36763, CVE-2022-36764, CVE-2022-36765</td><td>Yes</td></tr>
<tr><td style="white-space: nowrap">CVE-2023-45229</td><td>Yes</td></tr>
<tr><td style="white-space: nowrap">CVE-2024-1298, CVE-2024-38796, CVE-2024-38797, CVE-2024-38798, CVE-2024-38805</td><td>GHSA only (not in NVD <code>edk2</code> union at last review)</td></tr>
<tr><td style="white-space: nowrap">CVE-2025-2295, CVE-2025-2296, CVE-2025-3770</td><td>GHSA only</td></tr>
</tbody>
</table>

## Maintenance

Reconcile this list when:

- TianoCore publishes new GHSAs for previously NVD-only IDs.
- VEX4EDK2 gains NVD configuration → `edk2-stableYYYYMM` mapping and emits these CVEs in CSAF (then remove or annotate rows here).
- NVD changes `tianocore:edk2` CPE configurations materially.

Last reviewed: **2026-06-03** (NVD API 2.0, published `tianocore/edk2` GHSAs).
