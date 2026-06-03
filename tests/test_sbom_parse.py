"""Tests for vex4edk2.sbom_parse."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from vex4edk2.sbom_parse import components_for_cve_scan, parse_sbom


class TestSbomParse(unittest.TestCase):
    def _write_sbom(self, data: dict) -> str:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cdx.json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            return fh.name

    def test_parse_sbom_returns_components_only(self):
        path = self._write_sbom(
            {
                "metadata": {
                    "component": {
                        "name": "EDK II",
                        "version": "202411",
                        "cpe": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*",
                    }
                },
                "components": [
                    {
                        "name": "openssl",
                        "version": "3.5.1",
                        "cpe": "cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*",
                    }
                ],
            }
        )
        try:
            comps = parse_sbom(path)
            self.assertEqual(len(comps), 1)
            self.assertEqual(comps[0]["name"], "openssl")
        finally:
            os.unlink(path)

    def test_components_for_cve_scan_includes_primary_first(self):
        primary_cpe = "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*"
        path = self._write_sbom(
            {
                "metadata": {
                    "component": {
                        "bom-ref": "pkg:github/tianocore/edk2@edk2-stable202411",
                        "name": "EDK II",
                        "version": "202411",
                        "cpe": primary_cpe,
                        "licenses": [{"license": {"id": "BSD-2-Clause"}}],
                    }
                },
                "components": [
                    {
                        "name": "openssl",
                        "version": "3.5.1",
                        "cpe": "cpe:2.3:a:openssl:openssl:3.5.1:*:*:*:*:*:*:*",
                        "licenses": [{"license": {"id": "Apache-2.0"}}],
                    }
                ],
            }
        )
        try:
            scan_list, primary_key = components_for_cve_scan(path)
            self.assertEqual(primary_key, "pkg:github/tianocore/edk2@edk2-stable202411")
            self.assertEqual(len(scan_list), 2)
            self.assertEqual(scan_list[0]["name"], "EDK II")
            self.assertEqual(scan_list[1]["name"], "openssl")
        finally:
            os.unlink(path)

    def test_components_for_cve_scan_dedupes_primary_cpe_in_components(self):
        cpe = "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*"
        path = self._write_sbom(
            {
                "metadata": {
                    "component": {
                        "bom-ref": "primary-ref",
                        "name": "EDK II",
                        "version": "202411",
                        "cpe": cpe,
                        "licenses": [{"license": {"id": "BSD-2-Clause"}}],
                    }
                },
                "components": [
                    {
                        "bom-ref": "duplicate-ref",
                        "name": "edk2-copy",
                        "version": "202411",
                        "cpe": cpe,
                        "licenses": [{"license": {"id": "BSD-2-Clause"}}],
                    },
                    {
                        "name": "zlib",
                        "version": "1.3.1",
                        "cpe": "cpe:2.3:a:zlib:zlib:1.3.1:*:*:*:*:*:*:*",
                    },
                ],
            }
        )
        try:
            scan_list, _ = components_for_cve_scan(path)
            self.assertEqual(len(scan_list), 2)
            names = [c["name"] for c in scan_list]
            self.assertEqual(names[0], "EDK II")
            self.assertEqual(names[1], "zlib")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
