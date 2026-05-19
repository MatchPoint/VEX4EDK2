# EDK II source tree options

VEX4EDK2 can obtain EDK II source in two ways.

## Default: mirror + worktrees (no local clone required)

The batch tool keeps a shared clone under `cache/edk2-mirror` and checks out each
release tag in an isolated worktree under `cache/worktrees/<tag>/`. Your machine
never needs a full EDK II tree outside the cache.

```bash
python -m vex4edk2.batch --tag edk2-stable202411
```

## Existing clone: `--edk2-dir`

If you already have [tianocore/edk2](https://github.com/tianocore/edk2) cloned,
point the batch tool at it:

```bash
python -m vex4edk2.batch --tag edk2-stable202411 \
  --edk2-dir /path/to/edk2
```

For each tag (or a single `--tag`), VEX4EDK2 will:

1. Save the current `HEAD` ref
2. `git fetch --tags` and `git checkout --detach <tag>`
3. Scrub submodule working trees (`git clean -fdx` / `reset --hard`) so pins from
   older tags are not blocked by debris (for example OpenSSL fuzz corpora)
4. `git submodule update --init --recursive --force`
5. Run the SBOM4EDK2 pipeline on that tree
6. Restore the original `HEAD` (unless `--keep-worktree` is set)

### Environment variable

You can set a default path in `.env`:

```ini
EDK2_DIR=C:\temp\test\SBOM4EDK2\edk2
```

Then omit `--edk2-dir` on the command line.

### Scan the checkout you already have (`--use-current`)

When the clone is **already** at the release you want (for example
`edk2-stable202602` with submodules populated), skip git operations:

```bash
python -m vex4edk2.batch --tag edk2-stable202602 \
  --edk2-dir C:\temp\test\SBOM4EDK2\edk2 \
  --use-current
```

`--use-current` is only valid with a single `--tag`, not with `--all`.

### Batch all releases with one clone

`--all` with `--edk2-dir` still works: each quarterly tag is checked out in turn,
submodules are refreshed, and `HEAD` is restored after each tag (unless
`--keep-worktree` leaves the tree on the last processed tag).

```bash
python -m vex4edk2.batch --all --skip-existing \
  --edk2-dir C:\path\to\edk2
```

Expect this to modify your clone repeatedly; commit or stash local work first.

## Comparison

| Mode | Best for |
|------|----------|
| Worktree (default) | Clean machine, no existing EDK II tree, parallel-friendly cache |
| `--edk2-dir` | You already use SBOM4EDK2’s `edk2/` checkout |
| `--edk2-dir --use-current` | One-off scan of the tree you have open now |
