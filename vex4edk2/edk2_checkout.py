"""Git mirror, worktrees, and in-place checkout for historical EDK II releases."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from contextlib import contextmanager
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

EDK2_REPO_URL = "https://github.com/tianocore/edk2.git"
USWID_DATA_REPO_URL = "https://github.com/hughsie/uswid-data.git"


def _run_git(args: list[str], *, cwd: Optional[str] = None) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")


def _run_git_optional(args: list[str], *, cwd: Optional[str] = None) -> None:
    """Run git; log and continue on failure (used when scrubbing dirty submodules)."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        logger.warning("git %s in %s: %s", " ".join(args), cwd or ".", stderr)


def ensure_edk2_mirror(cache_dir: str) -> str:
    """Clone or fetch the EDK II mirror; return its path."""
    mirror = os.path.join(cache_dir, "edk2-mirror")
    if os.path.isdir(os.path.join(mirror, ".git")):
        logger.info("Fetching EDK II mirror %s", mirror)
        _run_git(["fetch", "--tags", "--prune", "origin"], cwd=mirror)
        return mirror

    os.makedirs(cache_dir, exist_ok=True)
    logger.info("Cloning EDK II mirror into %s", mirror)
    _run_git(
        [
            "clone",
            "--filter=blob:none",
            EDK2_REPO_URL,
            mirror,
        ]
    )
    _run_git(["fetch", "--tags", "--prune", "origin"], cwd=mirror)
    return mirror


def ensure_uswid_data(cache_dir: str) -> str:
    """Clone or pull uswid-data templates; return path."""
    dest = os.path.join(cache_dir, "uswid-data")
    if os.path.isdir(os.path.join(dest, ".git")):
        logger.info("Updating uswid-data in %s", dest)
        _run_git(["pull", "--ff-only"], cwd=dest)
        return dest

    os.makedirs(cache_dir, exist_ok=True)
    logger.info("Cloning uswid-data into %s", dest)
    _run_git(["clone", "--depth", "1", USWID_DATA_REPO_URL, dest])
    return dest


def checkout_tag_worktree(
    mirror: str,
    tag: str,
    worktrees_root: str,
    *,
    init_submodules: bool = True,
) -> str:
    """Create (or reuse) a detached worktree at *tag*; return worktree path."""
    os.makedirs(worktrees_root, exist_ok=True)
    wt_path = os.path.join(worktrees_root, tag)

    if os.path.isdir(wt_path):
        logger.info("Removing existing worktree %s", wt_path)
        try:
            _run_git(["worktree", "remove", "--force", wt_path], cwd=mirror)
        except RuntimeError:
            shutil.rmtree(wt_path, ignore_errors=True)

    logger.info("Adding worktree %s at %s", tag, wt_path)
    _run_git(["worktree", "add", "--detach", wt_path, tag], cwd=mirror)

    if init_submodules:
        logger.info("Initialising submodules in %s (may take several minutes)", wt_path)
        _run_git(
            ["submodule", "update", "--init", "--recursive"],
            cwd=wt_path,
        )

    return wt_path


def remove_worktree(mirror: str, worktree_path: str) -> None:
    """Remove a worktree and delete its directory."""
    if not os.path.isdir(worktree_path):
        return
    try:
        _run_git(["worktree", "remove", "--force", worktree_path], cwd=mirror)
    except RuntimeError as exc:
        logger.warning("worktree remove failed: %s", exc)
        shutil.rmtree(worktree_path, ignore_errors=True)


def validate_edk2_repo(edk2_dir: str) -> str:
    """Return the absolute path if *edk2_dir* looks like an EDK II git checkout."""
    path = os.path.realpath(edk2_dir)
    if not os.path.isdir(path):
        raise ValueError(f"EDK II path is not a directory: {edk2_dir!r}")
    if not os.path.isdir(os.path.join(path, ".git")):
        raise ValueError(f"Not a git repository: {path}")
    if not os.path.isdir(os.path.join(path, "MdePkg")):
        raise ValueError(
            f"{path} does not look like an EDK II tree (missing MdePkg/). "
            "Point --edk2-dir at the repository root."
        )
    return path


def read_git_head(edk2_dir: str) -> str:
    """Return the symbolic or abbreviated HEAD ref/commit in *edk2_dir*."""
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=edk2_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=edk2_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    ref = result.stdout.strip()
    if ref == "HEAD":
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=edk2_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    return ref


def _submodule_paths(edk2_dir: str) -> list[str]:
    """Return absolute paths for every entry in ``.gitmodules``."""
    result = subprocess.run(
        ["git", "config", "-f", ".gitmodules", "--get-regexp", r"path"],
        cwd=edk2_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    paths: list[str] = []
    if result.returncode != 0:
        return paths
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            paths.append(os.path.join(edk2_dir, parts[1].replace("/", os.sep)))
    return paths


def _scrub_git_worktree(path: str) -> None:
    if not os.path.isdir(os.path.join(path, ".git")):
        return
    _run_git_optional(["clean", "-fdx"], cwd=path)
    _run_git_optional(["reset", "--hard"], cwd=path)


def scrub_submodules(edk2_dir: str) -> None:
    """Reset and remove untracked files in all submodules before a tag sync.

    Reusing one EDK II clone across quarterly tags leaves debris (e.g. OpenSSL
    fuzz corpora from a newer pin) that blocks ``git submodule update``.
    """
    logger.info("Scrubbing submodules in %s", edk2_dir)
    for sub_path in _submodule_paths(edk2_dir):
        _scrub_git_worktree(sub_path)
    _run_git_optional(
        ["submodule", "foreach", "--recursive", "git", "clean", "-fdx"],
        cwd=edk2_dir,
    )
    _run_git_optional(
        ["submodule", "foreach", "--recursive", "git", "reset", "--hard"],
        cwd=edk2_dir,
    )


def checkout_tag_in_repo(
    edk2_dir: str,
    tag: str,
    *,
    fetch_tags: bool = True,
    init_submodules: bool = True,
) -> None:
    """Check out detached *tag* in an existing EDK II clone and sync submodules."""
    validate_edk2_repo(edk2_dir)
    if fetch_tags:
        logger.info("Fetching tags in %s", edk2_dir)
        _run_git(["fetch", "--tags", "--prune", "origin"], cwd=edk2_dir)
    logger.info("Checking out %s in %s", tag, edk2_dir)
    _run_git(["checkout", "--detach", tag], cwd=edk2_dir)
    if init_submodules:
        scrub_submodules(edk2_dir)
        logger.info("Initialising submodules in %s (may take several minutes)", edk2_dir)
        _run_git(
            ["submodule", "update", "--init", "--recursive", "--force"],
            cwd=edk2_dir,
        )


def restore_git_ref(edk2_dir: str, ref: str) -> None:
    """Restore *edk2_dir* to a previously saved HEAD ref or commit."""
    if not ref:
        return
    logger.info("Restoring %s to %s", edk2_dir, ref)
    try:
        _run_git(["checkout", ref], cwd=edk2_dir)
    except RuntimeError:
        _run_git(["checkout", "--detach", ref], cwd=edk2_dir)
    scrub_submodules(edk2_dir)
    _run_git(
        ["submodule", "update", "--init", "--recursive", "--force"],
        cwd=edk2_dir,
    )


@contextmanager
def edk2_tree_for_tag(
    tag: str,
    *,
    cache_dir: str,
    edk2_dir: Optional[str] = None,
    use_current: bool = False,
    restore_after: bool = True,
    init_submodules: bool = True,
) -> Iterator[tuple[str, Optional[str], Optional[str]]]:
    """Yield ``(tree_path, mirror_or_none, worktree_or_none)`` for SBOM generation.

    When *edk2_dir* is set, uses that clone (optionally checking out *tag*).
    Otherwise creates a detached worktree under *cache_dir*/worktrees/<tag>.

    If *use_current* is true, *edk2_dir* is required and no ``git checkout`` is
    performed (the tree must already match the intended release).

    When *restore_after* is true and a tag checkout was performed in *edk2_dir*,
    the original HEAD is restored on exit.
    """
    if edk2_dir:
        repo = validate_edk2_repo(edk2_dir)
        saved_head: Optional[str] = None
        if use_current:
            logger.info("Using current checkout in %s (no git checkout)", repo)
            yield repo, None, None
            return
        saved_head = read_git_head(repo)
        try:
            checkout_tag_in_repo(repo, tag, init_submodules=init_submodules)
            yield repo, None, None
        finally:
            if restore_after and saved_head is not None:
                restore_git_ref(repo, saved_head)
        return

    mirror = ensure_edk2_mirror(cache_dir)
    worktrees_root = os.path.join(cache_dir, "worktrees")
    wt_path = checkout_tag_worktree(
        mirror, tag, worktrees_root, init_submodules=init_submodules
    )
    try:
        yield wt_path, mirror, wt_path
    finally:
        pass
