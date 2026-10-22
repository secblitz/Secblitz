# Releasing Secblitz

How a version goes from the main branch to users. Everything that can be
automated runs in GitHub Actions from source. Three things stay with the owner
on purpose, because they are the trust anchors:

1. **Signing the update feed.** The key never leaves the owner's machine.
2. **Pressing Publish** on the draft release.
3. **Approving the website deploy** in the GitHub Environment `website`.

```
bump PR -> merge -> tag -> release build (tests, installer tests, attestations) -> DRAFT
  -> owner: check, sign feed offline, upload stable.json, Publish
  -> publish-website.yml: verify -> owner approves -> deploy -> live check
```

## Files that do this

| File | Job |
| --- | --- |
| `scripts/bump-version.py` | Moves the version in every file: Cargo, installer resources, changelog, website, README |
| `scripts/make-sbom.py` | Writes the parts list (CycloneDX SBOM) of one build target from `cargo metadata` and `Cargo.lock` |
| `scripts/release-notes.py` | Prints one version's changelog section (the release text) |
| `.github/workflows/ci.yml` | Tests, lints, tool tests and the workflow security audit (zizmor) on every pull request; the app tests and license check are skipped when only the website or prose changed |
| `.github/workflows/bump-version.yml` | Runs the bump script and opens a pull request |
| `.github/workflows/tag-release.yml` | Tags a merged "Release X.Y.Z" commit and starts the release build on that tag |
| `.github/workflows/release.yml` | Builds, tests the installer, optionally signs, attests and drafts the GitHub Release |
| `.github/workflows/publish-website.yml` | After you publish: verifies the release, deploys the website, checks the live site |
| `.github/workflows/windows.yml` | RustSec audit and the installer harnesses on every pull request, skipped when only the website or prose changed (the release always runs the harnesses) |
| `scripts/build-release.ps1` | The build itself (`-Stage Exe`, `-Stage Setup` or both) |
| `scripts/assemble-site.py` | Builds the exact site tree to deploy from the verified release files |
| `scripts/finalize-site.py` | Writes the real checksum and size into the staged page |
| `scripts/historical-downloads.py` | Older installers that every deploy must carry, with pinned hashes |
| `scripts/historical-downloads.sha256` | The pinned hashes of those older downloads |
| `scripts/verify-live-site.py` | Compares the live site with the deployed files |
| `scripts/requirements-release.txt` | Hash-pinned Python packages for the checks |
| `deploy/package.json`, `deploy/package-lock.json` | The one pinned Cloudflare deploy tool (wrangler) |
| `wrangler.jsonc` | The Cloudflare Pages project name and output folder |
| `.github/dependabot.yml`, `.github/CODEOWNERS` | Weekly updates, and who must review the files that decide what ships |
| `rust-toolchain.toml` | The one pinned compiler (1.93.0) |
| `CHANGELOG.md` | Release notes, in plain words |

## One-time GitHub setup

Do this once, before the first release through this pipeline. The repository
is `secblitz/Secblitz`.

### Repository settings

1. **Settings, Actions, General.**
   - Workflow permissions: "Read repository contents and packages permissions".
     Every workflow also asks for its own permissions, so this is a second lock.
   - Tick "Allow GitHub Actions to create and approve pull requests" (needed by
     `bump-version.yml`).
   - Actions permissions: allow actions created by GitHub and the ones listed
     in the workflows (`ilammy/msvc-dev-cmd`, `Swatinem/rust-cache`,
     `signpath/github-action-submit-signing-request`), and tick "Require actions
     to be pinned to a full-length commit SHA". Every workflow already does this.
   - Fork pull request workflows: require approval for all outside collaborators.
2. **Settings, Code security.** Turn on: Dependabot alerts, Dependabot security
   updates, secret scanning and push protection, private vulnerability
   reporting. Dependabot version updates come from `.github/dependabot.yml`
   (weekly: actions, cargo and the `deploy` folder, with a one week cooldown so a
   poisoned release is pulled before it reaches a pull request).
3. **Settings, General, Releases.** If offered, turn on "Immutable releases", so a
   published release and its files can never be changed or replaced afterwards.
4. **Code owners.** `.github/CODEOWNERS` names `@secblitz` for `.github/`,
   `scripts/`, `installer/`, `website/`, `deploy/`, `wrangler.jsonc`,
   `src/updater/`, the update public key and the update origin.

### Rulesets (Settings, Rules, Rulesets)

**Ruleset "main"**, target: default branch.
- Require a pull request before merging. Required approvals: **0 if you are the
  only maintainer** (GitHub never lets an author approve their own pull request,
  so one required approval would block you from merging your own work). Set it
  to 1 and turn on "Require review from Code Owners" once a second reviewer
  exists. The required status checks below are what gate every merge.
- Do not give anything bypass rights. Note that the setting "Allow GitHub
  Actions to create and approve pull requests" (needed for the bump pull
  request) lets the built-in token approve pull requests, so once you require
  approvals, an approval from `github-actions[bot]` counts. Review what you merge.
- Require status checks to pass: `Rust tests and lints (Windows, MSVC)`,
  `Locales, release tools, version bump and website tests`,
  `Workflow security audit (zizmor)`. Require branches to be up to date.
- Block force pushes. Restrict deletions.
- Add no bypass actors, so the rules apply to the owner too.

A pull request opened by the built-in token (the bump pull request) does not
start CI by itself. Close and reopen it, or push an empty commit to the branch,
so the required checks run.

**Ruleset "release tags"**, target: tags matching `v*`.
- Restrict updates (a tag can never move) and restrict deletions.
- Block force pushes.
- Do **not** turn on "Restrict creations". `tag-release.yml` creates the tag
  with the built-in token, and that token cannot be added to a bypass list.
  With creations open, anyone with write access could create a `v*` tag first on
  an unreviewed commit, and a run on that tag uses that commit's own workflow
  files. Three things limit this: `tag-release.yml` fails loudly when the tag
  already exists on a different commit; the owner check in step 6 below
  requires the attested commit to be the one you expect and an ancestor of
  `main`; and the `signing` and `website` environments need your approval. If
  you want creation closed completely, turn on "Restrict creations" and create
  the tag yourself (or through a GitHub App in the bypass list); the push starts
  `release.yml` (see step 3). Also add a ruleset that blocks creating branches
  named `v*`, so a branch can never share a name with a release tag.

### Environment `website` (Settings, Environments)

The only place the Cloudflare secrets exist.
- Required reviewers: you. If you are the only reviewer, leave "Prevent
  self-review" off, or you cannot approve your own deploy.
- Deployment branches and tags: "Selected branches and tags", add the tag
  pattern `v*` only. No branch is allowed.
- Secret `CLOUDFLARE_API_TOKEN`: see the next section.
- Variable `CLOUDFLARE_ACCOUNT_ID`: the Cloudflare account id (not secret).
- Optional variable `CLOUDFLARE_PAGES_BRANCH`: the Pages production branch, if it
  is not `main`. A deploy to any other branch name becomes a preview, not the
  live site, and the live check at the end then fails.
- Optional variable `SITE_EXTRA_ORIGINS`: more hostnames that must serve the same
  update feed and setup after a deploy, separated by spaces, for example the
  legacy feed host `https://beacons.lol` (its front page may redirect). The app's
  own update origin (`assets/update-origin.txt`) is always checked in full.

### Cloudflare token

Create it at Cloudflare, My Profile, API Tokens, "Create Custom Token".
- Permission: Account, Cloudflare Pages, Edit. Nothing else: no zone, DNS,
  Workers or other account permissions.
- Account resources: include only the one account that holds the project.
  As far as we know Cloudflare cannot scope a Pages token to a single project,
  so keep that account to this site if you can, or make a separate account.
- Set an expiry (for example one year) and note the date to rotate it.
- Store it only as the `website` environment secret `CLOUDFLARE_API_TOKEN`. Do
  not put it in repository secrets, and never in a file in the repository.

The project name comes from `wrangler.jsonc` (`secblitz`). The deploy is a
Pages Direct Upload, so no Git integration is needed on Cloudflare.

### Environment `signing` and SignPath (optional, off until you turn it on)

Create the environment `signing`, restrict it to tags `v*` **and add yourself as a
required reviewer** (as for `website`), so nobody who can push a tag can use the
SignPath token without your approval. Also set the SignPath signing policy to
require manual approval. Put the secret `SIGNPATH_API_TOKEN` in the environment.
`SIGNPATH_ENABLED` **must be a repository variable**, not an environment
variable: `release.yml` reads it once in the `verify` job (which has no
environment) and every later job follows that result. All the other
`SIGNPATH_*` variables can be repository or environment variables:

| Kind | Name | Value |
| --- | --- | --- |
| Secret (`signing` environment) | `SIGNPATH_API_TOKEN` | The API token |
| Variable | `SIGNPATH_ORGANIZATION_ID` | Organization id |
| Variable | `SIGNPATH_PROJECT_SLUG` | Project slug |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | Signing policy slug (for example `release-signing`) |
| Variable | `SIGNPATH_EXE_ARTIFACT_CONFIGURATION_SLUG` | Artifact configuration for the exe |
| Variable | `SIGNPATH_SETUP_ARTIFACT_CONFIGURATION_SLUG` | Artifact configuration for the setup |
| Variable | `SIGNPATH_ENABLED` | `true` to turn the signing jobs on |

See "Turning on SignPath" below for the SignPath side.

### Everything the owner must create

| Where | Kind | Name |
| --- | --- | --- |
| Environment `website` | Secret | `CLOUDFLARE_API_TOKEN` |
| Environment `website` | Variable | `CLOUDFLARE_ACCOUNT_ID` |
| Environment `website` | Variable (optional) | `CLOUDFLARE_PAGES_BRANCH`, `SITE_EXTRA_ORIGINS` |
| Environment `signing` | Secret (when SignPath is on) | `SIGNPATH_API_TOKEN` |
| Repository | Variables (when SignPath is on) | `SIGNPATH_ENABLED` and the five `SIGNPATH_*` slugs above |
| Offline, owner's machine | Ed25519 private key | The update feed key. Never in GitHub |

No other secret exists. The release build itself uses no secret at all.

## Steps

### 1. Write the notes

While you work, add short plain-words entries under `## [Unreleased]` in
`CHANGELOG.md` (Added, Changed, Fixed). No jargon, no em dashes. The release
page shows this text word for word.

### 2. Bump the version (pull request)

Either run the workflow: Actions, Bump version, Run workflow, enter the new
version. Or run it yourself:

```sh
python3 scripts/bump-version.py 0.8.1 --dry-run   # shows what would change, writes nothing
python3 scripts/bump-version.py 0.8.1
python3 scripts/historical-downloads.py record-missing   # pins the older version's download hashes
```

The script updates `Cargo.toml`, `Cargo.lock`, `assets/secblitz.rc`,
`assets/secblitz.manifest`, moves `Unreleased` into a dated `## [0.8.1]`
section, and moves **every version string and download link on the website**
(`website/index.html`, any other text file under `website/`, structured data
such as `softwareVersion`) and in `README.md` to the new version. It resets the
checksum on the page to a placeholder (the real one is written at deploy time),
and adds the setup of the version being replaced to the list of older downloads
in `scripts/stage-pages.py` so its URL keeps working after the next deploy.
`historical-downloads.py record-missing` reads that old version's installer
from the live site and pins its SHA-256 in
`scripts/historical-downloads.sha256` (the workflow does this for you).
The workflow pins a hash only when the live site serves exactly the file of
that version's GitHub release, which must match its `SHA256SUMS` and build
attestation. A version released before attestations existed (0.7.0) needs the
workflow input `previous_release_unattested`, which skips only the attestation
check. Review that diff: the hashes must match what you published.

The script refuses a version that is not greater than the current one, and an
empty `Unreleased` section (override with `--allow-empty`). `--dry-run` never
writes. `--check-site VERSION` writes nothing and fails if the website or
README show any other version. `--site-only` moves just the website and README
for the version `Cargo.toml` already has.

Nothing touches the live website at this point. Only `publish-website.yml`
deploys, and only after you publish the release.

Special case: while a version is being developed, its changelog heading reads
`## [0.8.0] - Unreleased` and `Cargo.toml` already says 0.8.0. To release it,
run `python3 scripts/bump-version.py 0.8.0`, which dates the section and moves
the website to 0.8.0.

The workflow commits "Release X.Y.Z" on branch `release/vX.Y.Z` and opens a
pull request. Read the changelog and website diff, make the required checks
run (see the main ruleset above), then merge. Any merge type works. For squash
or rebase the commit title must stay "Release X.Y.Z" (a trailing "(#12)" is
fine). A plain merge commit is recognised by its branch name `release/vX.Y.Z`,
so do not rename the branch.

### 3. Tag and start the build (automatic)

`tag-release.yml` runs when the merge lands on `main`. It checks that the
commit title, `Cargo.toml`, the changelog and the website agree, creates the
annotated tag `vX.Y.Z` through the API, and then **starts `release.yml`
explicitly on that tag**. This is needed because a tag created with the
built-in token does not start other workflows by itself (GitHub blocks that so
a token cannot trigger runs on its own). The release therefore always runs on
the tag, so the workflow code, the built source and the commit named in the
build attestations are one and the same commit.

If the tag exists but the build did not start (for example the start step
failed): Actions, Release, Run workflow, choose the **tag** (not a branch)
under "Use workflow from" and type the same tag.

If you create the tag yourself instead (for example with "Restrict creations"
on), push it from your machine with your own credentials and it starts
`release.yml` by itself:

```sh
git tag -a v0.8.1 -m "Secblitz 0.8.1" && git push origin v0.8.1
```

### 4. The release build (automatic, ends in a draft)

`release.yml` runs these jobs in order. Any failure stops the line, and nothing
is drafted.

1. `verify`: the run is on a tag, the tag equals the `Cargo.toml` version, the
   commit is on `main`, the changelog has a dated section with entries, the
   website and README show exactly this version, the older downloads all have a
   pinned hash, and the release tool tests pass.
2. `build-exe`: tests, clippy and the build on `windows-latest` with MSVC
   (`build-release.ps1 -Stage Exe`). No cache of any kind. The arm64 jobs
   (`build-exe-arm64`, `sign-exe-arm64`, `build-setup-arm64`,
   `sign-setup-arm64`) do the same natively on a `windows-11-arm` runner
   (`-Arch arm64`) and run beside the x64 ones.
3. `sign-exe`: only if SignPath is on.
4. `build-setup`: packs the Inno Setup from that exe (`-Stage Setup`).
5. `sign-setup`: only if SignPath is on.
6. `test-installer`: runs, for x64 on `windows-2022` and for arm64 on
   `windows-11-arm`, the installer harnesses against the final setup:
   `installer/test-maintenance.ps1`, `installer/test-setup-exit.ps1` (exit
   codes) and `installer/test-lifecycle.ps1` (install, upgrade with a running
   monitor, uninstall preservation). A broken installer stops the release here,
   before any attestation or draft exists.
7. `attest`: writes `SHA256SUMS`, creates build provenance attestations for
   the exe and the setup of each architecture, writes the parts list
   (`secblitz-X.Y.Z-windows-x64.cdx.json` and `...-windows-arm64.cdx.json`,
   CycloneDX, from the tagged source by `scripts/make-sbom.py`) and attests each
   one to the portable exe of its architecture.
8. `draft-release`: creates a **draft** GitHub Release named "Secblitz X.Y.Z"
   with the changelog section as text and the setup, the portable exe and
   `SHA256SUMS` and the two parts lists attached. `SHA256SUMS` still lists only
   the four programs.

Only one release build runs at a time (`concurrency`). To rebuild an existing
tag: Actions, Release, Run workflow, tag chosen under "Use workflow from" and
typed in. If a draft for that tag already exists, delete it first.

### 5. SignPath (optional)

Off until you turn it on. See "Turning on SignPath" below.

### 6. Verify the draft

Download the files from the draft, then:

```sh
gh release download v0.8.1 --dir check          # you are signed in, so drafts work
cd check
sha256sum --check SHA256SUMS
for f in secblitz-0.8.1-windows-x64-setup.exe secblitz-0.8.1-windows-x64.exe \\
         secblitz-0.8.1-windows-arm64-setup.exe secblitz-0.8.1-windows-arm64.exe; do
  gh attestation verify "$f" --repo secblitz/Secblitz \
    --signer-workflow secblitz/Secblitz/.github/workflows/release.yml \
    --source-ref refs/tags/v0.8.1 \
    --source-digest "$(git rev-parse origin/main)"   # the main commit you expect
done
# The release commit must be on main (the attestation names the commit):
git fetch origin && git merge-base --is-ancestor "$(git rev-parse origin/main)" origin/main
```
Use the commit of the "Release X.Y.Z" merge as the digest (check it in the
Actions run, and `git log origin/main`), not just any commit. A tag someone else
created on a different commit fails the digest check.

Each draft also carries the two parts lists. To check that one is the parts list
attested for its program (the website deploy checks the same):

```sh
gh attestation verify secblitz-0.8.1-windows-x64.exe --repo secblitz/Secblitz \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow secblitz/Secblitz/.github/workflows/release.yml \
  --source-ref refs/tags/v0.8.1 --format json > sbom-x64.json
jq -e --slurpfile want secblitz-0.8.1-windows-x64.cdx.json \
  'any(.[]; .verificationResult.statement.predicate == $want[0])' sbom-x64.json
```

The attestation proves the file was built by this repository's `release.yml`
from the tagged commit. The installer tests have already passed (step 4.6; see
the run page). On Windows, if signing was on, also check
`Get-AuthenticodeSignature` shows `Valid` for both files. Install the setup on a
test PC once, by hand.

### 7. Sign the update feed (offline, by the owner)

The update feed key is never in GitHub. On your own machine, with the setup
bytes from the draft (after SignPath, if used) and the key outside the repository:

```sh
python3 scripts/sign-release.py --key /path/to/secret.pem \
  --public-key assets/update-public-key.hex --version 0.8.1 \
  --installer check/secblitz-0.8.1-windows-x64-setup.exe --output check/stable.json
python3 scripts/sign-release.py --key /path/to/secret.pem --arch arm64 \
  --public-key assets/update-public-key.hex --version 0.8.1 \
  --installer check/secblitz-0.8.1-windows-arm64-setup.exe --output check/stable-arm64.json
# The same checks CI will make: signature, version, setup hash, freshness.
python3 scripts/prepare-pages.py --verify-feed check/stable.json \
  --installer-directory check --expected-version 0.8.1
python3 scripts/prepare-pages.py --verify-feed check/stable-arm64.json --arch arm64 \
  --installer-directory check --expected-version 0.8.1
```

Sign only the final bytes you will publish. If the setup changes later (for
example it is re-signed), sign again. The feed is valid for 90 days by default:
do not sign it long before you publish.

### 8. Upload the feed and publish the release

Attach the signed feeds to the draft **under the exact names `stable.json` and
`stable-arm64.json`**:

```sh
gh release upload v0.8.1 check/stable.json check/stable-arm64.json
```

The release must then carry exactly nine files: the setup and the portable exe
for x64 and for arm64, the two parts lists, `SHA256SUMS` and the two feeds. Anything else, or a missing file, stops the
website deploy. Edit the notes if needed, then press Publish (a normal release,
not a pre-release).

### 9. The website deploy (automatic, you approve once)

Publishing starts `publish-website.yml` on the tag.

1. `verify` (no secrets): the run is on the tag, the commit is on `main`,
   `Cargo.toml`, the changelog and the website version all equal the tag, the
   release is final and has exactly the nine files, `SHA256SUMS` matches, all
   four build files pass `gh attestation verify` bound to this repository, to
   `release.yml` as the signer, to `refs/tags/vX.Y.Z` and to the tagged commit,
   the two portable exes also carry a parts list attestation (predicate type
   `https://cyclonedx.org/bom`) from the same workflow, tag and commit,
   and both feeds pass `prepare-pages.py --verify-feed`: signature valid for
   the public key pinned in `assets/update-public-key.hex`, version equals the
   tag, the setup name, size and SHA-256 equal the released setup, not expired.
   Then it fetches the older downloads (each must match its pinned hash), and
   builds the site with `assemble-site.py` (real checksum and size written into
   the page, `prepare-pages.py --require-feed`, then the `stage-pages.py`
   allowlist). The result is fingerprinted.
2. **You approve** in the run page: "Review deployments", environment `website`.
   By now every check has passed, so you only approve a verified result.
3. `deploy`: confirms the site fingerprint is unchanged, installs the pinned
   `wrangler` from `deploy/package-lock.json` with `npm ci`, and runs
   `wrangler pages deploy` with the Cloudflare token. This is the only step that
   sees the token.
4. The live check (`verify-live-site.py`): fetches both feeds, `/`
   (the download page) and both setups from the live origin and
   compares their SHA-256 with the deployed files. A fresh deploy may need a
   short time to reach every edge, so it retries for about five minutes and then
   fails loudly, naming each file that differs.

If a step fails, nothing half-done is hidden: fix the cause and re-run the
workflow (Actions, Publish website, Run workflow, tag chosen under "Use
workflow from" and typed in). A deploy that passed its upload but failed the
live check means the live site is not what you released: investigate before
telling anyone to update.

Installed copies pick the new version up from the live `releases/stable.json`
(x64 builds) or `releases/stable-arm64.json` (native ARM builds), verified with
the pinned key inside the app.

### Staged rollouts and renewals

`scripts/release-authorize.py` (candidate and delivery files) and
`scripts/release-renew.py` still work as before, but the automated deploy only
carries `releases/stable.json` and `releases/stable-arm64.json` (the `stage-pages.py` allowlist). Publish those
extra files by hand, or add them to the allowlist in a reviewed pull request.
Renewing an existing feed (new `published_at` and `expires_at`, same installer)
cannot go through this workflow with "Immutable releases" on, because a
published release's `stable.json` can no longer be replaced. A feed lasts at most
90 days, so renew by publishing a new patch release (the normal flow), or deploy
the renewed feed by hand with `release-renew.py` and wrangler on your own
machine. Do not leave the live feed to expire.

Publishing is refused for any tag that is not the latest release, so a re-run on
an old tag can never roll the website back. The verified site is kept for 30
days, the longest an approval can wait.

## The portable exe

The portable exe is larger than the 25 MiB Cloudflare Pages file limit, so the
website does not host it. It stays on the GitHub release, with its checksum and
build attestation, and the download page links to the latest release. Portable
files of versions before 0.9 are still on the website as older downloads.

## Reproducible build

- One compiler: `rust-toolchain.toml` pins 1.93.0. CI installs exactly that.
- `--locked` on every cargo command, so `Cargo.lock` decides every dependency.
- `build-release.ps1` adds `--remap-path-prefix` for the workspace, cargo home
  and rustup home, `/Brepro` (fixed PE timestamp) and `/PDBALTPATH`, so no
  local path ends up in the exe.
- `SOURCE_DATE_EPOCH` is set from the commit time for tools that honour it.
- Every third-party action is pinned to a full commit SHA, with the version in a comment.
- No cache of any kind in `release.yml` or `publish-website.yml`, so a poisoned
  cache can never reach a release or the website. (`ci.yml` may cache.)

Same source, same compiler and same runner image should give the same exe. The
runner image and Windows SDK can still change over time; the attestation, not a
byte comparison, is the proof of origin.

## How the pipeline is locked down

- Every workflow starts with `permissions: {}` and each job asks only for what it
  needs. Only `draft-release` (create a draft), `tag-release` (create a tag,
  start the build) and `bump-version` (push a branch, open a pull request) can
  write. Only `attest` can mint attestations.
- Every checkout has `persist-credentials: false`. The two jobs that push or
  tag hand the token to that one command and never store it.
- Tag names, inputs and commit messages reach scripts only through environment
  variables, never inside the script text. There is no `pull_request_target`.
- `release.yml` and `publish-website.yml` each run one at a time and never cancel
  a running job.
- The Cloudflare token exists only in the `website` environment, behind a
  required reviewer and the tag rule `v*`. Only the last job sees it, and only
  in the one deploy step.
- The update-feed signing key is never in CI. CI only checks the owner's
  signature with the public key committed in the repository, and the deploy
  refuses anything that does not verify.
- Python packages are installed with `--require-hashes`; the deploy tool with
  `npm ci --ignore-scripts` from a lock file with integrity hashes.
- `ci.yml` runs `zizmor` (pinned, hash-checked) on every pull request.
  Any finding fails the check.
- A weekly Dependabot run proposes updates to actions, crates and the deploy
  tool. Review the pinned SHA and the version comment together.
- Not used on purpose: a third-party runner monitor (StepSecurity
  `harden-runner`). It would add one more third party, with telemetry, inside the
  job that holds the Cloudflare token. Add it in audit mode if you want it.

## Turning on SignPath

Secblitz plans to use the SignPath Foundation (free code signing for open
source). Check their current terms at https://signpath.org/ before applying.
What it needs, as far as we know:

- A public GitHub repository with an OSI-approved licence (Secblitz is MIT).
- Builds that run on GitHub Actions from that repository (this pipeline does).
- A project that is actively maintained, with a clear description, and a
  code signing policy page on the website or README, including the line that
  credits SignPath Foundation. The certificate is issued to the foundation.
- No software that could be treated as malware or a hacking tool. Secblitz
  changes security settings, so describe it plainly. The foundation decides.
- The policy text lives in `docs/CODE_SIGNING.md` and `website/code-signing.html`
  (keep them in step), is linked from the home page, the footer and the README,
  and the fixed footer in `docs/release-footer.md` is added to the release
  body by `release-notes.py --with-footer` once `SIGNPATH_ENABLED` is on, so an
  unsigned release never claims to be signed. The policy page and README must
  be published before applying.
- In the artifact configurations, require the product name `Secblitz` and the
  release version as the product version for every signed file. The build
  checks the same two values (`Assert-ProductMetadata` in `build-release.ps1`).

Once approved:

1. In SignPath, create the project, an artifact configuration for the exe and
   one for the setup (a zip containing one `.exe`, signed with Authenticode),
   and a signing policy. The same two artifact configurations are used for the
   arm64 files, so they must accept `secblitz-*-windows-arm64.exe` and
   `secblitz-*-windows-arm64-setup.exe` as well. Add the GitHub trusted build system and connect it to
   this repository.
2. Create an API token for a submitter user.
3. In GitHub, create the secret and variables listed under "Environment
   `signing` and SignPath" above.
4. Run a release. The exe is signed first, the setup is built from the signed
   exe, then the setup is signed, and the installer tests run on the signed
   setup. A signing policy that needs approval waits for you in SignPath.

Set `SIGNPATH_ENABLED` to anything else, or delete it, to turn signing off again.

Known limit: Inno Setup puts an uninstaller inside the setup. SignPath signs
the outer setup, not that inner uninstaller. The uninstaller is unsigned until
the build is changed to sign it during compilation.

## Known limits

- The installer tests need Inno Setup 6 on the runner image (`ISCC.exe`). The
  fallback download in `build-release.ps1 -DownloadInno` points at a file that
  the Inno Setup site no longer serves (404), so it cannot rescue a runner image
  without Inno Setup. If a release stops at "Inno Setup 6 is not installed",
  install it in the workflow from a source you have checked.
- `docs/website-deployment.md` is the history of the earlier manual deploys. The
  manual way (stage, then `wrangler pages deploy` from your machine) still works
  in an emergency, but the checks in `publish-website.yml` are then yours to do.

## Things CI will never do

- Hold the update-feed signing key or sign `stable.json`.
- Publish a release (it only drafts) or deploy the website without a published
  release and your approval in the `website` environment.
- Push to `main` (the bump workflow opens a pull request instead).
