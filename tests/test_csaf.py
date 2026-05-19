"""Unit tests for vex4edk2.csaf (no network)."""

from __future__ import annotations

import json
import os
import unittest

import pandas as pd

from vex4edk2.csaf import build_csaf_document, product_id_from_bom_ref, write_csaf
from vex4edk2.releases import quarterly_tags, yyyymm_from_tag

_FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "minimal.cdx.json"
)


class TestReleases(unittest.TestCase):
    def test_quarterly_list(self) -> None:
        tags = quarterly_tags()
        self.assertIn("edk2-stable202405", tags)
        self.assertIn("edk2-stable202602", tags)
        self.assertEqual(len(tags), 8)

    def test_yyyymm_from_tag(self) -> None:
        self.assertEqual(yyyymm_from_tag("edk2-stable202411"), 202411)


class TestCsaf(unittest.TestCase):
    def test_product_id_sanitise(self) -> None:
        pid = product_id_from_bom_ref("cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*")
        self.assertTrue(pid.startswith("pid-"))

    def test_build_csaf_merges_nvd_and_ghsa(self) -> None:
        nvd_df = pd.DataFrame(
            [
                {
                    "id": "CVE-2024-0001",
                    "name": "openssl",
                    "version": "3.5.1",
                    "cpe_pattern": "cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*",
                    "descriptions": "Test NVD",
                    "score": 7.5,
                    "CVSSString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }
            ]
        )
        ghsa_df = pd.DataFrame(
            [
                {
                    "id": "CVE-2025-3770",
                    "ghsa_id": "GHSA-vx5v-4gg6-6qxr",
                    "name": "EDK II",
                    "descriptions": "Platform advisory",
                    "score": 8.0,
                    "url": "https://github.com/tianocore/edk2/security/advisories/1",
                }
            ]
        )
        doc = build_csaf_document(
            _FIXTURE,
            release_tag="edk2-stable202411",
            nvd_df=nvd_df,
            ghsa_df=ghsa_df,
        )
        self.assertEqual(doc["document"]["category"], "csaf_vex")
        self.assertEqual(doc["document"]["tracking"]["id"], "vex4edk2-edk2-stable202411")
        vulns = doc["vulnerabilities"]
        cves = {v["cve"] for v in vulns}
        self.assertIn("CVE-2024-0001", cves)
        self.assertIn("CVE-2025-3770", cves)
        openssl = next(v for v in vulns if v["cve"] == "CVE-2024-0001")
        self.assertTrue(openssl["product_status"]["known_affected"])

    def test_write_csaf_file(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "edk2.csaf.json")
            write_csaf(
                _FIXTURE,
                out,
                release_tag="edk2-stable202411",
                nvd_df=pd.DataFrame(),
                ghsa_df=pd.DataFrame(),
            )
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("product_tree", data)
            self.assertIn("document", data)


if __name__ == "__main__":
    unittest.main()
