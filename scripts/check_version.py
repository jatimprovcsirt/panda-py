"""Fail unless every place the version is declared agrees.

panda-py declares its version twice — `pyproject.toml` and
`src/panda/__init__.py` — and a third time in git, as the tag. This repository
has shipped a release where they disagreed, and PyPI is the one registry that
cannot be corrected afterwards: a version number, once uploaded, is never
freed. Not overwritten, not deleted and re-uploaded. So a mismatch here does
not merely confuse, it burns the number.

    python scripts/check_version.py

In CI on a tag build the tag is checked too. Outside CI, or on a branch, the
tag check is skipped with a note rather than failing — a developer running this
before committing has no tag to compare against, and a check that fails for a
reason the developer cannot fix is a check that gets ignored.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def read_pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # Deliberately not tomllib: that is Python 3.11+, and this package supports
    # 3.10. A regex over the [project] table is enough for one string field and
    # keeps the check runnable on every supported version.
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("[check-version] FAILED — no version in pyproject.toml")
    return match.group(1)


def read_dunder_version() -> str:
    text = (ROOT / "src" / "panda" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("[check-version] FAILED — no __version__ in src/panda/__init__.py")
    return match.group(1)


def read_tag() -> str | None:
    """The tag being built, or None when there is nothing to compare against."""
    ref = os.environ.get("GITHUB_REF_NAME")
    if ref and os.environ.get("GITHUB_REF_TYPE") == "tag":
        return ref[1:] if ref.startswith("v") else ref
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return out[1:] if out.startswith("v") else out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def main() -> int:
    pyproject = read_pyproject_version()
    dunder = read_dunder_version()
    tag = read_tag()

    problems = []
    if pyproject != dunder:
        problems.append(f"pyproject.toml says {pyproject}, src/panda/__init__.py says {dunder}")
    if tag is not None and tag != pyproject:
        problems.append(f"the tag says {tag}, the package says {pyproject}")

    if problems:
        sys.stderr.write(
            "[check-version] FAILED — the declared versions disagree.\n\n"
            + "".join(f"  x {p}\n" for p in problems)
            + "\nPyPI never frees a version number. A wrong one is not corrected,\n"
            "it is burned — so this has to be right before the upload, not after.\n"
        )
        return 1

    where = f"pyproject.toml, src/panda/__init__.py" + (f", tag v{tag}" if tag else "")
    sys.stderr.write(f"[check-version] ok — {pyproject} ({where})\n")
    if tag is None:
        sys.stderr.write("[check-version] note: no tag to compare against, skipped\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
