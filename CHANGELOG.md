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

`pyproject.toml` and `src/panda/__init__.py` both declare `0.2.1`, and `v0.2.1`
is the most recent tag. All three agree, which is the rule this file exists to
enforce.

| Version | Date | What it was |
|---|---|---|
| `v0.2.2` | 2026-10-13 | Two defects found by the test suite, which had been red since before `0.2.1` and was read as test noise. |
| `v0.2.1` | 2026-10-13 | First release since `0.1.0` to reach PyPI. `panda.__version__` no longer reports a number that matches nothing. |
| `v0.2.0` | 2026-08-16 | CLI non-interactive mode documentation. **Tagged but never uploaded** — superseded by `0.2.1`. |
| `v0.1.6` | 2026-08-14 | README corrected PANDA CLI workflow. |
| `v0.4.2` | 2026-08-14 | README corrected PANDA CLI workflow. |
| `v0.1.5` | 2026-08-14 | Author name correction. |

## Why there are two version lines

The tags run `v0.1.5`, `v0.4.2`, `v0.1.6`, `v0.2.0` in date order. The version
was re-based mid-series, so `v0.1.6` is *newer* than `v0.4.2` and `v0.2.0` is
newer than both. The numbers do not tell you the order; the dates do.

`v0.2.0` is the version to build on.

## What 0.2.2 fixed

Both were found by running the test suite, which had been failing since before
`0.2.1` and was assumed to be test noise. Most of it was — a `shutil.rmtree`
that named the fixture instead of the variable, base64 keys of the wrong
length, tokens that were the wrong length, expectations left behind by earlier
changes. Two were not.

**`MalformedEnvelopeError` existed twice**, as two unrelated classes — one in
`errors.py`, one in `envelope.py`. The name exported from `panda.crypto` was
the first; the envelope parser and the cipher raised the second. So
`except panda.crypto.MalformedEnvelopeError` caught nothing at all, and a
malformed envelope escaped any handler written to catch it. There is now one
class, and it is catchable as `MalformedEnvelopeError`, as `EnvelopeError`,
and as `PandaError`.

**A credentials file with an unknown field looked missing.** `read_credentials`
passed the parsed JSON straight into `PandaCredentials(**data)`, so any
unrecognised key raised `TypeError` — which the handler caught alongside
genuinely corrupt JSON and turned into `None`. A file written by a newer CLI,
or holding one extra field, made `panda status` report an uninitialised
project with no explanation. Unknown fields are now dropped, and only
unparsable JSON returns `None`.

Also: `panda --version` reported `0.1.0` from a literal in `cli/commands.py`
while everything else said `0.2.0`. The CLI now reads the package version.

## What 0.2.1 settled

The package is published as **`panda-crypto-py`** — not `panda`, which is
somebody else's package on PyPI and has nothing to do with PANDA. Worth writing
down, because a changelog is a bad place to get that wrong.

Before `0.2.1`, three things disagreed:

| | |
|---|---|
| PyPI | `0.1.0` — the only release ever uploaded (2026-08-14) |
| `pyproject.toml` | `0.2.0` |
| `src/panda/__init__.py` | `0.1.0` |
| Most recent tag | `v0.2.0` |

So `pip install panda-crypto-py` installed code from before the CLI work while
the repository said `0.2.0`, and anything reading `panda.__version__` at runtime
reported `0.1.0` — a number matching neither the tag nor the upload. `v0.2.0`
was tagged and never published.

`0.2.1` is the first version where all of them agree. `v0.2.0` remains as a tag
that was never released; it is recorded above rather than deleted, because the
history is more useful than a tidy tag list.

**`__version__` in `src/panda/__init__.py` is still kept in step with
`pyproject.toml` by hand.** Nothing enforces it, which is how the two drifted
apart in the first place. A test that reads both and compares them would be
worth adding.
