# Contributing

Report a bug or ask for a feature in [GitHub issues](https://github.com/sukiyaki/octodns-netbox/issues).
For a bug, include these:

- The config of the source, without the token.
- The versions of octodns-netbox, octoDNS, pynetbox, and NetBox.
- The records you expected and the records you got.

Do not report a vulnerability in an issue.
Follow [SECURITY.md](https://github.com/sukiyaki/octodns-netbox/blob/main/SECURITY.md) instead.

## Set up the project

You need these tools:

- [uv](https://docs.astral.sh/uv/getting-started/installation/) 0.13.9 or later.
  `pyproject.toml` sets this minimum, and an older uv stops with an error.
- Docker with Docker Compose, for the live tests only.

1. Clone the repository, or your fork of it:

   ```sh
   git clone https://github.com/sukiyaki/octodns-netbox.git
   cd octodns-netbox
   ```

2. Install the dependencies and the Git hook:

   ```sh
   uv sync
   uv run pre-commit install
   ```

   The hook runs the linters on the files of each commit.
   Each linter runs through `uv run --locked`, so uv must be on your `PATH`.

## Run the linters

```sh
uv run --locked pre-commit run --all-files
```

The hooks run ruff, mypy in strict mode, the checks of pre-commit-hooks, and zizmor.
zizmor checks the workflows in `.github/workflows/` for security problems, offline.
`uv.lock` pins each tool, and `pyproject.toml` holds their settings.

## Run the unit tests

```sh
uv run --locked pytest
```

The unit tests replay the NetBox responses in `tests/fixtures/` and compare the zones with `tests/live/expected/`.
`tests/live/test_run.py` checks, with Docker replaced, which Compose projects and files the live run touches.
The unit tests need no network.
The run fails when coverage is below 100%.

## Test the lowest dependency versions

The `lowest` job in CI installs each direct dependency at its lower bound, on Python 3.11.
On octoDNS 1.10, the source takes the code path for octoDNS before 1.22.

To run the same tests:

```sh
export UV_RESOLUTION=lowest-direct
uv sync --python 3.11
uv tree --depth 1
uv run pytest
```

`uv sync` rewrites `uv.lock` for the lowest versions.
Restore it when you are done:

```sh
unset UV_RESOLUTION
git checkout uv.lock
uv sync
```

## Run the live tests

The live tests start NetBox in Docker, add IP addresses to it, and dump every zone in `tests/live/cases.py` with octoDNS.
They pass when the zones match `tests/live/expected/`.
A run takes about four minutes, most of it while NetBox starts.

```sh
uv run tests/live/run.py --netbox 4.7 --token-version 2
```

- `--netbox` takes `4.0` or `4.7`.
- `--token-version` takes `1` or `2`.
  NetBox 4.0 has only v1 tokens.
- Each run writes the zones, logs, and differences to a new directory under `tests/live/output/`, such as `tests/live/output/netbox-4.7-token-v2-k3j9x2a1/`, and prints its path.
  Git ignores `tests/live/output/`.
  Use `--output-dir` to write somewhere else.
- The output directory must be new, empty, or the output of an earlier run that has ended.
  The output of a run holds a `run.json`.
  In the output of an earlier run, the run replaces only the files that it writes.
- A run creates `run.lock` in its output directory before it changes anything there, and deletes the file when it ends.
  `run.lock` holds the process ID of the run.
  A second run with the same output directory stops when `run.lock` exists, also when both runs start at the same moment.
- Each run starts NetBox in its own Docker Compose project, `octodns-netbox-live-` followed by 8 random hexadecimal digits, and removes the project at the end.
  Two runs can share a machine.
- `--project-name` sets the name, and the run stops if that project already has containers.
  Give each run its own name.
  Two runs that start at the same moment with the same name both pass that check, because Docker Compose has no way to create a project only when it does not exist.
- Ctrl-C stops the run, and the run still removes its project and writes `run.json`, with the result `interrupted`.
  This holds also when Ctrl-C comes while the run saves the NetBox log.
  If the run is killed, remove its project with `docker compose --project-name <name> down --volumes`, and delete its output directory.
  A killed run leaves `run.lock` behind, and every later run with that directory stops until you delete the file.

The exit status is 0 when the zones and fixtures match, 1 when they differ or a step fails, and 2 when `tests/live/expected/` has no zones.

On NetBox 4.7, the run also compares the responses it records with `tests/fixtures/`.

The `live` workflow runs these rows on each pull request, every Monday, and on demand:

| Row | NetBox | Token | Python | Dependencies |
| --- | --- | --- | --- | --- |
| `netbox-4.0-token-v1` | 4.0 | v1 | 3.15 | locked |
| `netbox-4.0-token-v1-lowest` | 4.0 | v1 | 3.11 | lowest direct |
| `netbox-4.7-token-v1` | 4.7 | v1 | 3.11 | locked |
| `netbox-4.7-token-v2` | 4.7 | v2 | 3.15 | locked |
| `netbox-4.7-token-v2-lowest` | 4.7 | v2 | 3.11 | lowest direct |

The unit tests replay the responses recorded from NetBox 4.7 with each pynetbox release that `uv.lock` resolves, and with pynetbox 7.4.1 in the `lowest` job.
They check the method, URL, and query string of each request.
The recordings hold no second page and no request headers, so the live rows check what the replay cannot: how each NetBox release answers, page by page, and how it takes each kind of token.
Each row checks one thing that no other row checks:

- `netbox-4.0-token-v1` runs the newest pynetbox in `uv.lock` against the oldest supported NetBox.
- `netbox-4.0-token-v1-lowest` runs pynetbox 7.4.1 and the other lower bounds against the oldest supported NetBox.
- `netbox-4.7-token-v1` checks a v1 token on NetBox 4.5 and later, which looks up a v1 token by another path than a v2 token.
  It runs on Python 3.11, where `uv.lock` resolves an older pynetbox than on Python 3.15, so each pynetbox release in `uv.lock` meets a real NetBox.
- `netbox-4.7-token-v2` checks a v2 token sent as `Bearer`, as the pynetbox releases in `uv.lock` send it.
- `netbox-4.7-token-v2-lowest` checks a v2 token sent as `Token`, as pynetbox 7.4.1 sends it.

## Change what the source returns

The unit tests replay recordings, so a change to the records comes with a live case.
Do not edit the files in `tests/fixtures/` by hand.

1. Add IP addresses to `IPS` in `tests/live/seed.py`.
   Use addresses and names that no existing case reads, so the existing expected zones stay the same.
2. Add a `Case` to `cases()` in `tests/live/cases.py`.
3. Run `uv run tests/live/run.py --netbox 4.7 --record-fixtures`.
   The run writes `tests/fixtures/<case>.json` and exits with 1, because `tests/live/expected/<case>/` does not exist yet.
4. Review the zones in `zones/<case>/` of the output directory, whose path the run prints.
   Copy them to `tests/live/expected/<case>/`.
5. Run the unit tests and the live tests again.

## Record the fixtures again

A NetBox release can change its responses.
The `netbox-4.7` rows then fail with "The recording differs from tests/fixtures".

1. Record the responses of NetBox 4.7 again:

   ```sh
   uv run tests/live/run.py --netbox 4.7 --record-fixtures
   ```

2. Review the changes and commit them:

   ```sh
   git diff --stat tests/fixtures
   ```

## Release a version

You need write access to the repository.
PyPI does not accept the same version twice, so check the tag before you push it.

1. Make sure that CI passes on `main`.
2. Tag `main` with `v` followed by a PEP 440 version, such as `v0.6.0` or `v0.6.0rc1`, and push the tag:

   ```sh
   git switch main
   git pull --ff-only
   git tag v0.6.0
   git push origin v0.6.0
   ```

   The `release` workflow builds the wheel and the sdist with the same steps as the `build` job in CI, which run `twine check`.
   It checks that their version is the version of the tag.
   It compares normalized versions, so the tag `v0.6.0-rc1` also builds and releases `0.6.0rc1`.
   It uploads them to PyPI through Trusted Publishing, in the `pypi` environment.
   It then creates the GitHub release with generated notes and both files.
   A pre-release version, such as `0.6.0rc1` or `0.6.0.dev1`, becomes a pre-release on GitHub.
3. Edit the GitHub release.
   Above the generated notes, add the breaking changes and the steps to upgrade.

The `pypi` job uploads the files with `pypa/gh-action-pypi-publish`, the action that PyPI documents for Trusted Publishing.
The action also creates the attestations of both files.
The workflow pins the action to a commit, but the action runs the container image `ghcr.io/pypa/gh-action-pypi-publish:<commit>`, and the maintainers of the action can push a new image under that tag.
Apart from the runner image `ubuntu-latest`, that tag is the one reference in the `pypi` job that can change.

If the workflow stops before the `pypi` job uploads the files, delete the tag, fix the problem, and tag again:

```sh
git push origin --delete v0.6.0
git tag --delete v0.6.0
```

After PyPI has the version, do not delete or move the tag.
Release the fix as the next version.

## Update dependencies

Renovate opens the update pull requests, as `renovate.json` sets.

- Dev dependencies, the lint tools and Twine included, come in one pull request that updates `uv.lock`.
  Minor and patch updates merge when CI passes.
- GitHub Actions come in one pull request.
  Minor and patch updates merge when CI passes.
  Each workflow pins every action to a commit and names its version in a comment, and Renovate updates both.
- A runtime dependency update widens its range in `pyproject.toml` and never merges by itself.
  The wider range tells users that the package supports the new version, so a person reviews the changelog of the dependency and the results of CI.
- For each Dependabot alert, Renovate opens a pull request that updates the package to the first fixed version.
  The pull request opens at once, outside any schedule, with the `security` label, and it never merges by itself.
  Dependabot itself opens no pull requests.
- Each Monday, Renovate refreshes `uv.lock`.
- The build backend comes in one pull request, after you approve it on the Dependency Dashboard issue.
  `build-constraint-dependencies` under `[tool.uv]` in `pyproject.toml` pins hatchling, hatch-vcs, and every package they need, because `uv build` installs them in an environment of its own.
  `uv.lock` records these pins, and Renovate does not update `uv.lock` for them.
  Run `uv lock` on the branch of the pull request and push the result, or CI fails with "The lockfile needs to be updated".
  If an update adds a package to the build environment, add its pin too.
  `uv build -v` lists each package that it selects, in lines that start with `DEBUG Selecting:`.

Renovate does not raise the minimum version of uv.
To raise it:

1. Update uv with `uv self update`.
2. Set `required-version` under `[tool.uv]` in `pyproject.toml` to the new version.
3. Run `uv lock`, and commit `pyproject.toml` and `uv.lock`.

CI installs the newest uv that `required-version` allows.

## Update NetBox

Renovate updates the NetBox image tags in `IMAGE_TAGS` in `tests/live/run.py`.
Its NetBox pull requests never merge by themselves.

For a new patch release, Renovate opens the pull request, and the `live` workflow runs on it.
If a `netbox-4.7` row reports that the recording differs, [record the fixtures again](#record-the-fixtures-again) on that branch.

A new minor release waits for approval on the Dependency Dashboard issue.
After you approve it, update these on its branch:

1. `IMAGE_TAGS` and `FIXTURES_NETBOX` in `tests/live/run.py`.
2. The rows in `.github/workflows/live.yml`.
3. The fixtures, [recorded again](#record-the-fixtures-again) from the new release.
4. The NetBox row of the support table in `README.md`.

## Open a pull request

- Put one change in each commit.
  Write the subject as `type(scope): subject`, as the Git history does.
- Run the linters and the unit tests before you push.
  CI runs the `lint`, `test`, `lowest`, `build`, and `live` jobs.
- Update `README.md` or `docs/` when users can see the change.
