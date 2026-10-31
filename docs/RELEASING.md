# Releasing Garnet Guard

Garnet Guard is published to PyPI as `garnet-guard` by `.github/workflows/release.yml`. The workflow uses PyPI Trusted Publishing, so no API token is stored anywhere, and every file carries a PEP 740 attestation that ties it to this repository and workflow (SPEC §11).

## What the release workflow does

A tag `v*` pushed to the repository starts it:

1. **CI** runs the full CI workflow (lint, typecheck, import contracts, tests on Python 3.11 to 3.14, build).
2. **Build** checks that the tagged commit is on `main` and that the tag equals `v` + the version in `pyproject.toml`, then builds the sdist and wheel.
3. **Publish** runs in the `pypi` environment, which waits for the maintainer's approval. It has only the `id-token: write` permission. `pypa/gh-action-pypi-publish` uploads the files and their attestations.
4. **Verify** downloads each file's attestation back from PyPI and verifies it against this repository with `pypi-attestations`. A failure here means a published file can't be traced to this repository and needs investigating before anyone is told to upgrade.
5. **Sign build provenance** (beside Publish) records, with `actions/attest-build-provenance`, which workflow run built each file from which commit, signs that record with Sigstore and stores it on GitHub. It has only `id-token: write`, `attestations: write` and `contents: read`, and runs nothing from the package.
6. **Draft the GitHub release**, after Verify passes, creates a draft release for the tag with the same wheel and sdist, the signed provenance (`garnet_guard-<version>.provenance.sigstore.json`) and `SHA256SUMS.txt`. Its notes are the version's section of `CHANGELOG.md`; a version with no section stops the job. A version with `a`, `b` or `rc` in it is marked as a pre-release. If a draft for the tag already exists, the files are added to it. Releases are immutable once published, so files can't be added to a published one and the job stops.

## Cutting a release

1. Open a PR that sets `version` in `pyproject.toml`, moves the `Unreleased` entries in `CHANGELOG.md` under the new version, and updates `uv.lock` (`uv lock`).
2. Merge it to `main`.
3. Tag the merge commit and push the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -s v0.2.0 -m "Garnet Guard 0.2.0"
   git push origin v0.2.0
   ```

4. Approve the `pypi` deployment on the workflow run (Actions → Release → Review deployments).
5. Confirm the Verify job passed and the release page on PyPI shows the attestations.
6. Open **Releases**, find the draft for the tag, check its notes and files (wheel, sdist, `.provenance.sigstore.json`, `SHA256SUMS.txt`), and click **Publish release**. Don't create the GitHub release by hand first: once published it is locked and the files can't be attached.

## Checking a release yourself

Anyone can check that a file came from this repository's release workflow, whether it was downloaded from PyPI or from the GitHub release:

```sh
gh attestation verify garnet_guard-0.3.0-py3-none-any.whl --repo Orca-Solutions/garnet-guard
# offline, with the bundle attached to the GitHub release:
gh attestation verify garnet_guard-0.3.0-py3-none-any.whl --repo Orca-Solutions/garnet-guard \
  --bundle garnet_guard-0.3.0.provenance.sigstore.json
sha256sum -c SHA256SUMS.txt
```

The PyPI attestations are checked with `pypi-attestations verify pypi --repository https://github.com/Orca-Solutions/garnet-guard pypi:<file>`, as the Verify job does.

## One-time setup (maintainer)

These need an account owner and can't be done from the repository. All of them were done before 0.1.0a1 was published on 2026-10-30; they are kept here for reference and for a move to another account.

### PyPI

1. Sign in to pypi.org with 2FA enabled.
2. Add a **pending trusted publisher** at <https://pypi.org/manage/account/publishing/> → "GitHub":
   - PyPI project name: `garnet-guard`
   - Owner: `orca-solutions`
   - Repository name: `garnet-guard`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. A pending publisher does not reserve the name. The project is created, and the name claimed, by the first successful publish. 0.1.0a1 claimed `garnet-guard` on 2026-10-30.

### GitHub repository settings

1. **Environment.** Settings → Environments → New environment `pypi`:
   - Required reviewers: `jfricano`. Leave "Prevent self-review" off, because the maintainer is also the person who pushes the tag.
   - Deployment branches and tags: "Selected branches and tags", add a **tag** rule `v*`.
2. **Tag ruleset.** Settings → Rules → Rulesets → New tag ruleset, target `v*`, restrict creation, update and deletion, with only repository admins in the bypass list.
3. **Branch ruleset for `main`.** Settings → Rules → Rulesets → New branch ruleset, target the default branch:
   - Require a pull request before merging (0 required approvals while there is one maintainer).
   - Require status checks to pass: `Lint and typecheck`, `Tests (Python 3.11)`, `Tests (Python 3.12)`, `Tests (Python 3.13)`, `Tests (Python 3.14)`, `Build distributions`.
   - Require signed commits.
   - Block force pushes and restrict deletions.
4. **Actions.** Settings → Actions → General:
   - Workflow permissions: "Read repository contents and packages permissions".
   - Leave "Allow GitHub Actions to create and approve pull requests" off.
   - Turn on "Require actions to be pinned to a full-length commit SHA" if the setting is offered.
5. **Security.** Settings → Advanced Security: turn on private vulnerability reporting (SECURITY.md depends on it), Dependabot alerts and Dependabot security updates. Scorecard results appear under Security → Code scanning after its first run on `main`.
