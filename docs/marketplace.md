# GitHub Marketplace listing

This file covers how Garnet Guard gets listed on GitHub Marketplace. Only the maintainer publishes (PROJECT_BRIEF.md, Permissions). Nothing here is done automatically.

## Listing content

| Field | Value | Source |
|---|---|---|
| Name | Garnet Guard | `action.yml` `name`. It must be unique on Marketplace. The publish form checks this. |
| Description | A second reviewer for every dependency update. Checks each changed package against the release you trusted. | `action.yml` `description`. The one-liner comes from the brand kit's messaging. |
| Icon and colour | `search`, `red` | `action.yml` `branding`. Marketplace allows only Feather icons, so the pomegranate mark can't appear here (brand kit, Launch assets). |
| Primary category | Security | Chosen on the release form. |
| Secondary category | Dependency management | Chosen on the release form. |
| Listing page | The repository README | Marketplace shows the README, so its first screen is the listing. |

## Requirements GitHub checks

From [Publishing actions in GitHub Marketplace](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace):

- The repository is public. It already is.
- Exactly one `action.yml` sits at the repository root. `action/comment/action.yml` is a second action in a subfolder. Subfolder actions aren't listed, but they can still be used by path.
- The account publishing has two-factor authentication.
- An owner of `orca-solutions` has accepted the GitHub Marketplace Developer Agreement. The link is on the release page.

## Before the first listing

1. Merge `garnet check` (lockfile diffing). The Action calls it, so the Action can't run without it.
2. Try the Action on a test repository: a Dependabot pull request, a Renovate pull request and a fork pull request with the two-workflow pattern. Put a link to a real comment in the README, ideally the lightning 2.6.2 replay (brand kit, The PR comment).
3. Turn on immutable releases in the repository settings, so a published tag can't be moved.

## Publishing (maintainer)

1. Create a signed tag for the release on `main`, for example `v0.1.0`.
2. Open `action.yml` on GitHub and click **Draft a release** in the banner. Alternatively, go to **Releases → Draft a new release**.
3. Tick **Publish this Action to the GitHub Marketplace**. Accept the Developer Agreement if GitHub asks, then wait for "Everything looks good!".
4. Choose **Security** as the primary category and **Dependency management** as the secondary category.
5. Select the tag, set the title (for example "Garnet Guard 0.1.0"), paste the release notes from CHANGELOG.md, and click **Publish release**. GitHub asks for two-factor authentication.
6. In `action/examples/` and `docs/action.md`, replace `<release-commit-sha>` with the release's full commit SHA, in a follow-up pull request.
