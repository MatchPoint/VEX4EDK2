"""Verify committed quarterly release artifacts under releases/."""

from __future__ import annotations

import json
import os
import unittest

from vex4edk2.batch import outputs_complete, release_output_paths
from vex4edk2.releases import QUARTERLY_TAGS_LAST_TWO_YEARS

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCommittedReleases(unittest.TestCase):
    def test_all_quarterly_tags_have_sbom_and_csaf(self) -> None:
        releases_dir = os.path.join(_REPO_ROOT, "releases")
        for tag in QUARTERLY_TAGS_LAST_TWO_YEARS:
            cdx, csaf = release_output_paths(releases_dir, tag)
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

        _, csaf_path = release_output_paths(
            os.path.join(_REPO_ROOT, "releases"),
            QUARTERLY_TAGS_LAST_TWO_YEARS[0],
        )
        with open(csaf_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["document"]["category"], "csaf_vex")
        generator = doc["document"]["tracking"]["generator"]
        self.assertEqual(generator["author"], VEX_DOCUMENT_AUTHOR_NAME)
        publisher = doc["document"]["publisher"]
        self.assertEqual(publisher["name"], VEX_DOCUMENT_AUTHOR_NAME)
        self.assertIn(VEX_DOCUMENT_AUTHOR_EMAIL, publisher["contact_details"])


if __name__ == "__main__":
    unittest.main()
