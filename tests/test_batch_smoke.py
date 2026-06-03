"""Smoke tests for batch CLI (no full EDK II clone)."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from vex4edk2 import __version__ as vex4edk2_version
from vex4edk2.batch import (
    cleanup_scratch_excel_reports,
    load_project_env,
    main,
    normalize_env_value,
    outputs_complete,
    release_output_paths,
    update_manifest,
)


class TestBatchHelpers(unittest.TestCase):
    def test_normalize_env_value_strips_crlf(self) -> None:
        self.assertEqual(normalize_env_value("abc\r\n"), "abc")
        self.assertEqual(normalize_env_value("  key-with-cr\r  "), "key-with-cr")

    def test_load_project_env_strips_crlf_from_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = os.path.join(tmp, ".env")
            with open(env_path, "wb") as fh:
                fh.write(b"NVD_API_KEY=test-key-value\r\n")
            with mock.patch("vex4edk2.batch.load_dotenv") as load_mock:
                def _inject(**_kwargs):
                    os.environ["NVD_API_KEY"] = "test-key-value\r"

                load_mock.side_effect = _inject
                load_project_env()
            self.assertEqual(os.environ.get("NVD_API_KEY"), "test-key-value")
            os.environ.pop("NVD_API_KEY", None)

    def test_outputs_complete_false(self) -> None:
        self.assertFalse(outputs_complete("/nonexistent/a.cdx.json", "/nonexistent/b.csaf.json"))

    def test_release_output_paths(self) -> None:
        cdx, csaf = release_output_paths("/tmp/repo", "edk2-stable202411")
        self.assertTrue(cdx.endswith(os.path.join("sbom", "edk2-stable202411.cdx.json")))
        self.assertTrue(csaf.endswith(os.path.join("vex", "edk2-stable202411.csaf.json")))

    def test_cleanup_scratch_excel_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keep = os.path.join(tmp, "CVE_List.xlsx")
            remove = os.path.join(tmp, "CVE_List_ghsa.xlsx")
            with open(keep, "w", encoding="utf-8") as fh:
                fh.write("stay")
            with open(remove, "w", encoding="utf-8") as fh:
                fh.write("go")
            cleanup_scratch_excel_reports(remove)
            self.assertFalse(os.path.isfile(remove))
            self.assertTrue(os.path.isfile(keep))


class TestBatchEdk2DirCli(unittest.TestCase):
    def test_dry_run_shows_edk2_dir_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(
                    [
                        "--tag",
                        "edk2-stable202602",
                        "--dry-run",
                        "--edk2-dir",
                        tmp,
                        "--use-current",
                        "--repo-root",
                        tmp,
                    ]
                )
            out = buf.getvalue()
            self.assertIn("edk2-stable202602", out)
            self.assertIn("edk2-dir=", out)
            self.assertIn("current HEAD", out)

    def test_use_current_without_edk2_dir_exits(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "EDK2_DIR"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch("sys.exit", side_effect=SystemExit) as mock_exit:
                with self.assertRaises(SystemExit):
                    main(["--tag", "edk2-stable202602", "--use-current"])
        mock_exit.assert_called_with(1)

    def test_edk2_dir_from_env_in_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {"EDK2_DIR": tmp}, clear=False):
                with redirect_stdout(buf):
                    main(
                        [
                            "--tag",
                            "edk2-stable202411",
                            "--dry-run",
                            "--repo-root",
                            tmp,
                        ]
                    )
            self.assertIn(os.path.realpath(tmp), buf.getvalue())


class TestManifest(unittest.TestCase):
    def test_update_manifest_records_vex4edk2_version(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = os.path.join(tmp, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump({"releases": []}, fh)
            update_manifest(
                manifest_path,
                {"tag": "edk2-stable202411", "status": "ok"},
            )
            with open(manifest_path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["vex4edk2_version"], vex4edk2_version)


class TestPipelineImports(unittest.TestCase):
    def test_import_sbom_generator(self) -> None:
        from vex4edk2.batch import _import_sbom_generator

        generate_sbom = _import_sbom_generator()
        self.assertTrue(callable(generate_sbom))

    def test_import_cve_scanners(self) -> None:
        from vex4edk2.batch import _import_cve_scanners

        generate_cve, scan_ghsa = _import_cve_scanners()
        self.assertTrue(callable(generate_cve))
        self.assertTrue(callable(scan_ghsa))


if __name__ == "__main__":
    unittest.main()
