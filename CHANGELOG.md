# Changelog

## Read this before creating a tag

**The version in `pyproject.toml` and the git tag must be the same number.**

A tag whose name disagrees with the declared version is a *stray tag*, and PyPI
makes strays worse than npm or Packagist do: **a version, once uploaded, can
never be reused.** Not overwritten, not deleted and re-uploaded, not corrected
in place. So a wrong number does not merely confuse — it permanently burns that
number.

Before tagging:

1. **Read this file.** It records what has been released and what the next
   number is.
2. Set that number in `pyproject.toml`.
3. Commit the version bump on its own, so the tag points at a release-only
   commit.
4. Tag the same number with a `v` prefix — `0.2.1` in `pyproject.toml` means
   `v0.2.1` as the tag, never anything else.
5. Push the branch, then the tag.
6. Confirm the release exists: <https://pypi.org/project/panda/#history>
7. Add it to the table below.

Only two numbers matter, and they must match. Not another PANDA SDK's version,
not a date, not the branch.

## Released

`pyproject.toml` declares `0.2.0`, and `v0.2.0` is the most recent tag. Those
two agree, which is the rule this file exists to enforce.

| Version | Date | What it was |
|---|---|---|
| `v0.2.0` | 2026-08-16 | CLI non-interactive mode documentation. |
| `v0.1.6` | 2026-08-14 | README corrected PANDA CLI workflow. |
| `v0.4.2` | 2026-08-14 | README corrected PANDA CLI workflow. |
| `v0.1.5` | 2026-08-14 | Author name correction. |

## Why there are two version lines

The tags run `v0.1.5`, `v0.4.2`, `v0.1.6`, `v0.2.0` in date order. The version
was re-based mid-series, so `v0.1.6` is *newer* than `v0.4.2` and `v0.2.0` is
newer than both. The numbers do not tell you the order; the dates do.

`v0.2.0` is the version to build on.

## Unresolved: PyPI serves releases this repository does not know about

PyPI's release history is:

```
0.1, 0.1.1, 0.1.2, 0.1.3, 0.1.4, 0.1.5, 0.3.0-dev, 0.3.1
```

**`0.3.0-dev` and `0.3.1` are not tags in this repository, and no commit here
declares those versions.** They were uploaded from somewhere and the trace was
not kept. Meanwhile `v0.1.6`, `v0.4.2` and `v0.2.0` — which *are* tagged here —
were never uploaded.

Two consequences worth knowing:

- `pip install panda` currently installs `0.3.1`, whose relationship to any
  commit in this repository is unknown. It is not the code that `v0.2.0`
  points at.
- Because PyPI never frees a version number, `0.3.1` cannot be withdrawn and
  reissued. Whatever that upload contains is permanent.

Nobody should tag `0.3.x` or `0.4.x` here without first establishing what was
uploaded under those numbers, or the repository will end up with two different
things sharing one version.
