"""Unit tests for vex4edk2.edk2_checkout (mocked git)."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from vex4edk2.edk2_checkout import (
    checkout_tag_in_repo,
    edk2_tree_for_tag,
    scrub_submodules,
    validate_edk2_repo,
)


class TestValidateEdk2Repo(unittest.TestCase):
    def test_requires_git_and_mdepkg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                validate_edk2_repo(tmp)
            os.makedirs(os.path.join(tmp, ".git"))
            with self.assertRaises(ValueError):
                validate_edk2_repo(tmp)
            os.makedirs(os.path.join(tmp, "MdePkg"))
            path = validate_edk2_repo(tmp)
            self.assertEqual(path, os.path.realpath(tmp))


class TestScrubSubmodules(unittest.TestCase):
    @mock.patch("vex4edk2.edk2_checkout._run_git_optional")
    @mock.patch("vex4edk2.edk2_checkout._scrub_git_worktree")
    @mock.patch(
        "vex4edk2.edk2_checkout._submodule_paths",
        return_value=["/fake/edk2/CryptoPkg/Library/OpensslLib/openssl"],
    )
    def test_scrub_cleans_listed_paths_and_foreach(
        self,
        mock_paths: mock.MagicMock,
        mock_scrub: mock.MagicMock,
        mock_git: mock.MagicMock,
    ) -> None:
        scrub_submodules("/fake/edk2")
        mock_scrub.assert_called_once_with(
            "/fake/edk2/CryptoPkg/Library/OpensslLib/openssl"
        )
        calls = [c[0][0] for c in mock_git.call_args_list]
        self.assertEqual(
            calls[0],
            ["submodule", "foreach", "--recursive", "git", "clean", "-fdx"],
        )
        self.assertEqual(
            calls[1],
            ["submodule", "foreach", "--recursive", "git", "reset", "--hard"],
        )


class TestCheckoutTagInRepo(unittest.TestCase):
    @mock.patch("vex4edk2.edk2_checkout.scrub_submodules")
    @mock.patch("vex4edk2.edk2_checkout._run_git")
    def test_checkout_runs_fetch_checkout_submodules(
        self,
        mock_git: mock.MagicMock,
        mock_scrub: mock.MagicMock,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".git"))
            os.makedirs(os.path.join(tmp, "MdePkg"))
            checkout_tag_in_repo(tmp, "edk2-stable202411")
        calls = [c[0][0] for c in mock_git.call_args_list]
        self.assertEqual(calls[0], ["fetch", "--tags", "--prune", "origin"])
        self.assertEqual(calls[1], ["checkout", "--detach", "edk2-stable202411"])
        mock_scrub.assert_called_once()
        self.assertEqual(
            calls[-1],
            ["submodule", "update", "--init", "--recursive", "--force"],
        )


class TestEdk2TreeForTag(unittest.TestCase):
    @mock.patch("vex4edk2.edk2_checkout.restore_git_ref")
    @mock.patch("vex4edk2.edk2_checkout.checkout_tag_in_repo")
    @mock.patch("vex4edk2.edk2_checkout.read_git_head", return_value="main")
    def test_edk2_dir_checkouts_and_restores(
        self,
        mock_head: mock.MagicMock,
        mock_checkout: mock.MagicMock,
        mock_restore: mock.MagicMock,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".git"))
            os.makedirs(os.path.join(tmp, "MdePkg"))
            with edk2_tree_for_tag(
                "edk2-stable202411",
                cache_dir="/unused",
                edk2_dir=tmp,
                restore_after=True,
            ) as (tree_path, mirror, wt):
                self.assertEqual(tree_path, os.path.realpath(tmp))
                self.assertIsNone(mirror)
                self.assertIsNone(wt)
            mock_checkout.assert_called_once()
            mock_restore.assert_called_once_with(os.path.realpath(tmp), "main")

    @mock.patch("vex4edk2.edk2_checkout.checkout_tag_in_repo")
    @mock.patch("vex4edk2.edk2_checkout.read_git_head")
    def test_use_current_skips_checkout(
        self,
        mock_head: mock.MagicMock,
        mock_checkout: mock.MagicMock,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".git"))
            os.makedirs(os.path.join(tmp, "MdePkg"))
            with edk2_tree_for_tag(
                "edk2-stable202602",
                cache_dir="/unused",
                edk2_dir=tmp,
                use_current=True,
            ) as (tree_path, _, _):
                self.assertEqual(tree_path, os.path.realpath(tmp))
            mock_head.assert_not_called()
            mock_checkout.assert_not_called()


if __name__ == "__main__":
    unittest.main()
