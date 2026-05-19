"""Tests for release tag helpers."""

import unittest

from vex4edk2.releases import QUARTERLY_TAGS_LAST_TWO_YEARS


class TestQuarterlyTags(unittest.TestCase):
    def test_no_rc_or_point_releases(self) -> None:
        for tag in QUARTERLY_TAGS_LAST_TWO_YEARS:
            self.assertNotIn("-rc", tag)
            self.assertNotIn(".01", tag)
