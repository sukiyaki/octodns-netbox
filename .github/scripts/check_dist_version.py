"""Check that dist/ holds one wheel and one sdist of the version of the tag.

    GITHUB_REF_NAME=v0.6.0rc1 python .github/scripts/check_dist_version.py

hatch-vcs builds the tag's version in its normalized form, so the tag
v0.6.0-rc1 builds 0.6.0rc1. The check compares packaging.version.Version
objects, which compare normalized versions. It writes the version and whether
it is a pre-release to $GITHUB_OUTPUT.

hatch-vcs keeps the local version label of a tag, so the tag v0.6.0+review
builds 0.6.0+review. PyPI rejects a local version when the pypi job uploads
it, so the check stops such a tag before that job runs.
"""

import os
import sys
from pathlib import Path

from packaging.utils import parse_sdist_filename, parse_wheel_filename
from packaging.version import Version

tag = os.environ["GITHUB_REF_NAME"]
version = Version(tag)
if version.local is not None:
    sys.exit(
        f"::error::Tag {tag} is version {version}, which has the local version "
        f"label {version.local}. PyPI rejects local versions, so tag the "
        f"version without the + part, such as v{version.public}."
    )
dist = Path("dist")
wheels = [parse_wheel_filename(path.name)[1] for path in dist.glob("*.whl")]
sdists = [parse_sdist_filename(path.name)[1] for path in dist.glob("*.tar.gz")]
if wheels != [version] or sdists != [version]:
    sys.exit(
        f"::error::Tag {tag} is version {version}, but dist/ holds the wheels "
        f"{[str(v) for v in wheels]} and the sdists {[str(v) for v in sdists]}."
    )
with open(os.environ["GITHUB_OUTPUT"], "a") as output:
    output.write(f"version={version}\n")
    output.write(f"prerelease={str(version.is_prerelease).lower()}\n")
print(f"dist/ holds the wheel and the sdist of {version}.")
