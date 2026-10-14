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


## Licence: MIT to Apache-2.0

Every repository now carries a verbatim Apache License 2.0 and a NOTICE file
naming the copyright holder. Four of the six had no licence file at all, and
`panda-node` had no `license` field in its manifest either — it declared
nothing while listing a `LICENSE` in `files` that did not exist, so what npm
actually published was unlicensed.

Apache-2.0 over MIT for one reason: an express patent grant. MIT is silent on
patents, and this is cryptographic software that other agencies and vendors are
expected to embed in their own systems — the grant, and the retaliation clause
that comes with it, is the part that matters when a third party deploys it.
Apache-2.0 is no less permissive, so nothing about adoption gets harder.

GPL was considered and rejected: copyleft would block exactly the cross-agency
adoption this project exists for, and sit badly with public procurement.

**What is already published does not change.** A licence cannot be altered
retroactively on an artifact that has been released, so panda-py 0.2.1-0.2.3 on
PyPI and panda-php 0.2.1-0.2.2 on Packagist stay MIT, panda-node 0.5.0 on npm
stays unlicensed, and the Go tags through v0.5.1 carry no licence text
either. This applies from the next release of each.

The `LICENSE` file is the canonical text byte-for-byte — verified against its
published SHA-256, `cfc7749b...523d30` — so it stays comparable to every other
copy of it.

## Released

`pyproject.toml` and `src/panda/__init__.py` both declare `0.2.7`, and `v0.2.7`
is the most recent tag. All three agree, which is the rule this file exists to
enforce — `scripts/check_version.py` now fails the release unless they do.

The paragraph above is itself the instance of the failure it describes. While
`0.2.3` was being cut it still said `0.2.1`; while `0.2.7` was being cut it
still said `0.2.5`, having not been updated for `0.2.6`. Twice, in the text
warning about it. The check script is the answer to that, and the form matters:
a paragraph cannot enforce itself, which is exactly why the same defect keeps
appearing in files like this one.

| Version | Date | What it was |
|---|---|---|
| `v0.2.7` | 2026-10-14 | The blind index trimmed Python's whitespace set, not the specification's. |
| `v0.2.6` | 2026-10-14 | The CLI died on a Windows console that cannot encode its output. |
| `v0.2.5` | 2026-10-14 | `--skip-key-gen`, and releases now go through GitHub Actions with OIDC. |
| `v0.2.4` | 2026-10-14 | `init` gains `--quick` and `--kid`; it had no non-interactive path at all. **Tagged but never published** — superseded by `0.2.5` before anything was uploaded. |
| `v0.2.3` | 2026-10-13 | The portal gate did not exist here; `{"valid": "false"}` was read as approval. |
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

`v0.2.5` is the version to build on.

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

## What 0.2.7 fixes

**The blind index trimmed a different set of characters than the spec says.**

`str.strip()` with no argument uses `str.isspace()`. That is not Unicode
`White_Space`: it additionally strips `U+001C`-`U+001F`, the ASCII information
separators, which are control characters rather than whitespace. `panda-php`
and `panda-go` leave them alone, so a value carrying a trailing `U+001C` — the
kind of thing that arrives from a paste or an export — indexed differently here
than in the other SDKs. A blind index that differs between implementations is
not a lookup that fails loudly; it is a row written by one SDK that the others
cannot find.

`_WHITE_SPACE` is now written out explicitly and passed to `strip()`. `re` is
no help, and that is worth knowing before reaching for it: `\s` matches on the
same predicate as `isspace()`, so `re.sub(r"^\s+", ...)` carries the identical
bug.

The fix landed with three vectors in `panda-spec` — one for each of `U+0085`,
`U+001C` and `U+FEFF` — which `verify_interop.js` runs against all four SDKs:
164 checks, up from 152. Reverting this file's change fails exactly the
`U+001C` vector and nothing else, which is what makes it a test of this fix
rather than of the harness.

The submodule pin moves to `panda-spec` `v3`, the tag that carries those
vectors. A pin left at `v2` would keep passing, and would be passing a smaller
set of checks than the spec now defines.

## What 0.2.6 fixes

**`panda init` did not run on a default Windows console.** Nearly every message
this CLI prints begins with a tick or a warning sign, and on a console whose
encoding is cp1252 `print` raises:

    UnicodeEncodeError: 'charmap' codec can't encode character '✓'

The command died at its first success line — after writing some of its files
and before finishing, which is the worst place to stop. The three other SDKs
were unaffected: Go, Node and PHP write UTF-8 bytes and never ask an encoding
layer's permission.

For a project aimed at government developers, Windows is the likely case, and
the workflow the documentation opens with is exactly the one that failed.

`main()` now reconfigures stdout and stderr to UTF-8 with `errors="replace"`.
Not `errors="replace"` alone: that would keep the console's encoding and lose
the tick on every Windows console, including the ones that can render it.
Streams without a `reconfigure` — a test runner's capture object, a caller's
`StringIO` — are left untouched.

Reproduced in the test suite by forcing the encoding rather than mocking it,
because the failure is in the encoding layer and a mock would replace the thing
under test.

## What 0.2.5 adds

### `--skip-key-gen`

panda-php and panda-go had it; panda-node gained it in the same batch. A flag
present in three SDKs and absent from the fourth is the defect this whole
sequence started from. It applies to the wizard as well as to quick mode,
matching panda-go, which honours it on both paths.

### A release workflow, and CI

**This repository had no CI at all** — no `.github` directory, the only one of
the six without one. Both CLI defects found this week were found by running the
binaries: panda-php's `init` could not start, panda-go's `--kid` was accepted
and discarded. Nothing here ran them.

`ci.yml` tests on 3.10 and 3.12, checks the declared versions, and — the cheap
guard against the panda-php failure mode — runs the CLI and asserts its flags
exist. Every unit test passed there while the command could not start.

`release.yml` publishes with OIDC trusted publishing. No token, and the manual
`twine upload` is gone: it was the last release step in this project that
needed a human.

PyPI is the one registry that cannot be corrected afterwards — a version
number, once uploaded, is never freed — so the release workflow checks more
than the npm one does. `scripts/check_version.py` fails unless the tag,
`pyproject.toml` and `src/panda/__init__.py` agree, which they have not always
done here. The final step before publishing installs the built wheel into an
empty virtualenv and runs it, asserting the version it reports, `init --quick
--kid`, and `init --quick --skip-key-gen`. That is the check that would have
caught panda-node 0.5.3 reporting itself as 0.1.0.

**`v0.2.4` is tagged and was never published.** `--skip-key-gen` and the
workflows landed after the tag and before anything was uploaded, so `0.2.5`
carries them. Nothing was burned — PyPI has never seen `0.2.4`, and the number
remains free, which is not true once an upload succeeds.

## What 0.2.4 fixes

`panda init` always prompted. There was no way to run it without a person
answering, so there was no one-liner for a CI pipeline, a Dockerfile or a
provisioning script — while panda-node, panda-php and panda-go all had
`--quick`. A documented workflow that works in three SDKs and not the fourth is
a workflow that is wrong for whoever picked this one; the CLI guide had been
papering over it by printing a different command for each language.

`--quick --token <token> --kid <key-id>` now runs to completion with no input:
local provider, one key, credentials written.

The gate is fail-closed **with no override** on this path. The wizard can offer
"Continue anyway?" because a person is there to answer it. `--quick` cannot
ask, so a token that fails validation exits 1 and writes nothing, and a missing
token is an error rather than a prompt. The token may come from
`PANDA_ACCESS_TOKEN`, so it need not appear in shell history or the process
list.

The key-writing code is shared between the two paths now (`_write_local_key`)
rather than written twice. Two implementations of "write the key to .env" that
differ — one writing `PANDA_DEFAULT_KID` and one not — is how a project ends up
with a `.env` whose contents depend on which command created it.

Eight tests, each closing stdin. A prompt on this path is a hang rather than a
failure, and a hang is the wrong outcome in CI. Disabling the quick branch
fails seven of them.

## What 0.2.3 fixes

### The portal gate, which this SDK did not have

Three things, in the order they were found. Each one was found by the one
before it.

### The pattern

`validate_token_format()` accepted 48 hex characters only. `panda-node`,
`panda-php` and `panda-go` accepted 48 or 64, so a 64-character token that
every other SDK considered valid was rejected here — the one implementation
that would have said no being the one in use. The pattern is now pinned in
`panda-spec/token-format.md`, with vectors that `verify_interop.js` runs
against all four SDKs.

### The portal, which was never called

Writing that document's status table meant writing down, by hand, which
implementations actually consult the portal. That is how this surfaced:

**This SDK performed no portal validation at all.** The other three POST the
token to the portal before generating a key and fail closed if it cannot be
reached. `panda-py` checked the shape of the string and proceeded, so a
revoked token, one already activated by another application, and one that was
never issued all initialised successfully. The format check is the weaker half
of the gate and the only half that was running — a well-formed token is
precisely what an unauthorised caller would have.

It now validates against the portal, in both the interactive and the
non-interactive path, and fails closed: a timeout, a refused connection, a 5xx,
or a body that will not parse all stop `init` and generate nothing. The demo
token still skips the portal — no request is made — and
`PANDA_SKIP_ONLINE_VALIDATION=1` still disables it for tests.

The token logic moved out of `panda/cli/commands.py` into
`panda/crypto/token.py`, where `panda-go` and `panda-php` keep theirs. It was
in the CLI as a second copy of the pattern, which is the copy that had drifted.

### `{"valid": "false"}` was read as approval

Found while writing the tests for the above, and worse than either.

The check was `if not result["valid"]`. A non-empty string is truthy in Python
— and in JavaScript and PHP — so a portal response *explicitly saying the
token is not valid* was read as consent and a key was generated. So were
`{"valid": "no"}` and `{"valid": 1}`. Only the literal boolean `true` counts
now, and every other value is a refusal.

`panda-go` had always refused these, because decoding a JSON string into a Go
`bool` fails. It was the only one of the four that was right, and the
disagreement is what made the bug visible.

### One more, from PHP rather than here

`panda-php`'s portal call referenced `CURLOPT_CONNECT_TIMEOUT`, a constant that
does not exist — the real name is `CURLOPT_CONNECTTIMEOUT`, with no underscore
between CONNECT and TIMEOUT. On PHP 8 an undefined constant is a fatal error,
so that SDK's portal call had never once run. Recorded here because it is the
same defect class as the two above: a code path that was never executed, so
nothing could notice it was broken.

### Tests

`tests/security/test_token_portal_validation.py`, 33 tests, all mocking
`urlopen` — the suite must not depend on whether a live government portal is
reachable, and a test that reached it would be asserting against production.
`tests/conftest.py` disables online validation for every other test, so no
existing test can accidentally make a request.

The CLI wiring is covered separately and for real: a subprocess, a local HTTP
server, 15 assertions. `init` genuinely calls the portal, and a refusal
genuinely produces no `.panda` directory and no key. Unit tests prove a
function behaves; they do not prove anything calls it, which is the defect
being fixed.
