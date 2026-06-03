"""Tests for release tag helpers."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from vex4edk2.releases import (
    filter_tags_by_yyyymm_range,
    is_quarterly_stable_tag,
    parse_date_bound,
    quarterly_tags_in_range,
    yyyymm_from_tag,
)

_SAMPLE_TAGS = [
    "edk2-stable202105",
    "edk2-stable202108",
    "edk2-stable202405",
    "edk2-stable202408",
    "edk2-stable202602",
    "edk2-stable202411-rc1",
    "edk2-stable202411.01",
]


class TestQuarterlyTags(unittest.TestCase):
    def test_is_quarterly_stable_tag(self) -> None:
        self.assertTrue(is_quarterly_stable_tag("edk2-stable202411"))
        self.assertFalse(is_quarterly_stable_tag("edk2-stable202411-rc1"))
        self.assertFalse(is_quarterly_stable_tag("edk2-stable202411.01"))

    def test_parse_date_bound(self) -> None:
        self.assertEqual(parse_date_bound("2021-05"), 202105)
        self.assertEqual(parse_date_bound("2026-02"), 202602)

    def test_parse_date_bound_invalid(self) -> None:
        with self.assertRaises(ValueError):
            parse_date_bound("2026-13")

    def test_filter_tags_by_yyyymm_range(self) -> None:
        got = filter_tags_by_yyyymm_range(_SAMPLE_TAGS, 202405, 202602)
        self.assertEqual(
            got,
            ["edk2-stable202405", "edk2-stable202408", "edk2-stable202602"],
        )

    def test_filter_five_year_window(self) -> None:
        got = filter_tags_by_yyyymm_range(_SAMPLE_TAGS, 202105, 202602)
        self.assertEqual(
            got,
            [
                "edk2-stable202105",
                "edk2-stable202108",
                "edk2-stable202405",
                "edk2-stable202408",
                "edk2-stable202602",
            ],
        )

    def test_yyyymm_from_tag(self) -> None:
        self.assertEqual(yyyymm_from_tag("edk2-stable202411"), 202411)

    @patch("vex4edk2.edk2_checkout.discover_quarterly_stable_tags")
    def test_quarterly_tags_in_range(self, discover) -> None:
        discover.return_value = _SAMPLE_TAGS
        tags = quarterly_tags_in_range(
            "2024-05",
            "2026-02",
            cache_dir="/tmp/cache",
            reference=__import__("datetime").datetime(2026, 6, 1),
        )
        self.assertEqual(
            tags,
            ["edk2-stable202405", "edk2-stable202408", "edk2-stable202602"],
        )
        discover.assert_called_once()
