"""Verify committed quarterly release artifacts under sbom/ and vex/."""

from __future__ import annotations

import json
import os
import unittest

from vex4edk2 import __version__ as vex4edk2_version
from vex4edk2.batch import outputs_complete, release_output_paths
from vex4edk2.releases import tags_with_committed_outputs

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _committed_vex_matches_package() -> bool:
    """False when checked-in vex/*.csaf.json predates the installed package version."""
    committed = tags_with_committed_outputs(_REPO_ROOT)
    if not committed:
        return False
    _, csaf_path = release_output_paths(_REPO_ROOT, committed[0])
    with open(csaf_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    engine = doc["document"]["tracking"]["generator"]["engine"]
    return engine.get("version") == vex4edk2_version


class TestCommittedReleases(unittest.TestCase):
    def test_committed_quarterly_tags_have_sbom_and_csaf(self) -> None:
        repo_root = _REPO_ROOT
        committed = tags_with_committed_outputs(repo_root)
        self.assertGreater(
            len(committed),
            0,
            "expected at least one sbom/edk2-stableYYYYMM.cdx.json",
        )
        for tag in committed:
            cdx, csaf = release_output_paths(repo_root, tag)
            with self.subTest(tag=tag):
                self.assertTrue(
                    outputs_complete(cdx, csaf),
                    f"missing {cdx} or {csaf}",
                )

    def test_csaf_author_and_category(self) -> None:
        from vex4edk2.csaf import (
            VEX_DOCUMENT_AUTHOR_EMAIL,
            VEX_DOCUMENT_AUTHOR_NAME,
        )

        committed = tags_with_committed_outputs(_REPO_ROOT)
        self.assertGreater(len(committed), 0)
        _, csaf_path = release_output_paths(_REPO_ROOT, committed[0])
        with open(csaf_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["document"]["category"], "csaf_vex")
        generator = doc["document"]["tracking"]["generator"]
        self.assertEqual(generator["author"], VEX_DOCUMENT_AUTHOR_NAME)
        publisher = doc["document"]["publisher"]
        self.assertEqual(publisher["name"], VEX_DOCUMENT_AUTHOR_NAME)
        self.assertIn(VEX_DOCUMENT_AUTHOR_EMAIL, publisher["contact_details"])

    @unittest.skipUnless(
        _committed_vex_matches_package(),
        "Committed vex/ stale — refresh with batch --from-date/--to-date --vex-only",
    )
    def test_csaf_generator_engine_version(self) -> None:
        """Committed vex/*.csaf.json must match the installed VEX4EDK2 package version."""
        committed = tags_with_committed_outputs(_REPO_ROOT)
        _, csaf_path = release_output_paths(_REPO_ROOT, committed[0])
        with open(csaf_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        engine = doc["document"]["tracking"]["generator"]["engine"]
        self.assertEqual(engine["name"], "VEX4EDK2")
        self.assertEqual(
            engine["version"],
            vex4edk2_version,
            "Regenerate vex/ with batch --from-date/--to-date --vex-only",
        )

    @unittest.skipUnless(
        _committed_vex_matches_package(),
        "Committed vex/ stale — refresh with batch --from-date/--to-date --vex-only",
    )
    def test_csaf_summary_mentions_sbom4edk2(self) -> None:
        committed = tags_with_committed_outputs(_REPO_ROOT)
        _, csaf_path = release_output_paths(_REPO_ROOT, committed[-1])
        with open(csaf_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        notes = doc["document"].get("notes") or []
        summary = next((n for n in notes if n.get("category") == "summary"), None)
        self.assertIsNotNone(summary)
        text = summary.get("text") or ""
        self.assertIn("SBOM4EDK2", text)
        self.assertNotIn("USWID SBOM", text)


if __name__ == "__main__":
    unittest.main()
