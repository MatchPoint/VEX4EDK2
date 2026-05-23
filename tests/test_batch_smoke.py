"""Smoke tests for batch CLI (no full EDK II clone)."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from vex4edk2.batch import (
    load_project_env,
    main,
    normalize_env_value,
    outputs_complete,
    release_output_paths,
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
        cdx, csaf = release_output_paths("/tmp/releases", "edk2-stable202411")
        self.assertTrue(cdx.endswith(os.path.join("edk2-stable202411", "edk2.cdx.json")))
        self.assertTrue(csaf.endswith(os.path.join("edk2-stable202411", "edk2.csaf.json")))


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
                        "--releases-dir",
                        os.path.join(tmp, "releases"),
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
                            "--releases-dir",
                            os.path.join(tmp, "releases"),
                        ]
                    )
            self.assertIn(os.path.realpath(tmp), buf.getvalue())


@unittest.skipUnless(
    "sbom4edk2" in sys.modules
    or any(
        os.path.isdir(os.path.join(p, "sbom4edk2"))
        for p in os.environ.get("PYTHONPATH", "").split(os.pathsep)
        if p
    ),
    "sbom4edk2 not on PYTHONPATH",
)
class TestSbom4edk2Import(unittest.TestCase):
    def test_import_sbom4edk2(self) -> None:
        from vex4edk2.batch import _import_sbom4edk2

        generate_sbom, generate_cve, scan_ghsa = _import_sbom4edk2()
        self.assertTrue(callable(generate_sbom))
        self.assertTrue(callable(generate_cve))
        self.assertTrue(callable(scan_ghsa))


if __name__ == "__main__":
    unittest.main()
