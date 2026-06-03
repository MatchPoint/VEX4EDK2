# NVD platform CVEs not mapped into quarterly CSAF VEX

This document lists **TianoCore EDK II platform CVEs** that appear in the [NVD](https://nvd.nist.gov/) under product `tianocore:edk2` but are **not** emitted into any `vex/edk2-stableYYYYMM.csaf.json` file produced by VEX4EDK2.

## Why these CVEs are omitted

Quarterly CSAF documents attribute platform issues using:

1. **[TianoCore GitHub Security Advisories (GHSA)](https://github.com/tianocore/edk2/security/advisories)** — version ranges in `YYYYMM` form (e.g. `<=202508`), which map to `edk2-stableYYYYMM` releases.
2. **NVD lookup on the SBOM primary CPE** — `cpe:2.3:a:tianocore:edk2:edk2-stableYYYYMM:…` from `metadata.component`.

The CVEs in the catalog below have **no published GHSA** at the time the table was reconciled against [TianoCore advisories](https://github.com/tianocore/edk2/security/advisories?state=published). NVD associates them with `tianocore:edk2` using version tokens that **do not align** with quarterly stable tags (`edk2-stableYYYYMM`): wildcards (`-`, `*`), SVN revisions, calendar dates, or bare `YYYYMM` fields that are not wired into our per-release NVD pass. Until NVD configurations can be translated reliably to `edk2-stableYYYYMM`, VEX4EDK2 **does not** place them on a specific quarterly `known_affected` product — avoiding false attribution to modern stables.

**Risk:** These issues may still be relevant for older trees or for compliance views that expect full NVD `tianocore:edk2` coverage. Review NVD entries and TianoCore release notes directly.

## How this list was built

Reconciliation rule (repeat when updating this page):

1. **NVD union** — Collect every CVE ID returned for active CPE names matched by `cpeMatchString` `cpe:2.3:a:tianocore:edk2:*:*:*:*:*:*:*:*` (query each resolved `cpeName` via NVD CVE API 2.0; deduplicate by CVE ID).
2. **Subtract GHSAs** — Remove any CVE ID that appears on a **published** [tianocore/edk2 security advisory](https://github.com/tianocore/edk2/security/advisories?state=published) (use each advisory’s `cve_id` or CVE-type identifier; skip test entries such as `***IGNORE***`).
3. **Catalog remainder** — What is left are NVD `tianocore:edk2` platform CVEs with **no matching published GHSA** at reconciliation time. Record each row’s vulnerable `cpeMatch` `criteria` and version bounds from that CVE’s NVD `configurations`.

The table below is a **point-in-time catalog** from that procedure. It will shrink when TianoCore publishes a GHSA for a listed CVE, and may grow when NVD adds new `tianocore:edk2` associations.

Related platform CVEs **with** a published GHSA are mapped into quarterly CSAF when the release YYYYMM matches the advisory range; see batch `CVE_List_ghsa.xlsx` under `cache/scratch/<tag>/`.

## CVE catalog

Snapshot from the reconciliation rule above (NVD + published GHSAs). **Re-run the rule before relying on completeness** — do not assume the row count is fixed.

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
<tr><td style="white-space: nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38576">CVE-2021-38576</a></td><td><code>cpe:2.3:a:tianocore:edk2:201808:*:*:*:*:*:*:*</code> … <code>202105:*:*:*:*:*:*:*</code> (multiple discrete NVD version fields; see <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-38576">NVD</a>)</td><td style="white-space: nowrap">—</td></tr>
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

Platform issues **with** a published GHSA are the normal path into quarterly CSAF: VEX4EDK2 applies the advisory’s YYYYMM range to the SBOM release. Those CVE IDs are **not** listed in the catalog table above.

At reconciliation time, platform CVEs fall into three buckets:

| Bucket | Meaning |
|--------|---------|
| **GHSA only** | Published advisory exists; CVE may or may not yet appear under NVD `tianocore:edk2`. CSAF uses GHSA when the release is in range. |
| **Both GHSA and NVD `edk2`** | Same CVE ID in the NVD union and on a published GHSA — CSAF uses GHSA for release mapping; NVD is redundant for platform attribution. |
| **NVD `edk2` only** | Rows in the catalog table — no published GHSA yet, and no reliable `edk2-stableYYYYMM` mapping in VEX4EDK2. |

For the current set of published advisories and release-level applicability, use the [GitHub advisory list](https://github.com/tianocore/edk2/security/advisories?state=published) and per-tag `CVE_List_ghsa.xlsx` from batch output — not a frozen CVE list in this file.

## Maintenance

Update this document when:

- TianoCore publishes a new GHSA whose CVE ID was listed here (remove that row after re-running the reconciliation rule).
- NVD adds or changes `tianocore:edk2` CPE configurations for platform CVEs (add or edit rows; refresh CPE/bounds from NVD API 2.0).
- VEX4EDK2 begins emitting a catalog CVE in quarterly CSAF via `edk2-stableYYYYMM` mapping (remove or annotate the row).

Prefer **git commit history** on this file for when the table last changed; avoid embedding advisory counts or “last reviewed” dates that go stale immediately when a new GHSA ships.
