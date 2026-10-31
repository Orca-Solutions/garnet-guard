"""Rule documentation: the text ``garnet explain`` prints and findings carry."""

from __future__ import annotations

from ..models import RuleDoc, Severity

W, B = Severity.WARN, Severity.BLOCK

# One place for rule links. The site builds these pages from docs/rules/.
RULE_DOCS_BASE = "https://garnetguard.dev/rules/"


def rule_url(rule_id: str) -> str:
    """The rule's docs page, linked from findings, ``explain`` and the PR comment."""
    return f"{RULE_DOCS_BASE}{rule_id}"


_DOCS: tuple[RuleDoc, ...] = (
    RuleDoc(
        "GRN-T001",
        "lost-provenance",
        "diff",
        W,
        "Every file of the trusted version had a verified attestation; the new version has a file without one.",
        "The trusted version was published by CI with a Sigstore attestation proving which repository "
        "and workflow built it. A new file with no attestation was most likely uploaded some other way, "
        "for example with a stolen or leaked API token. That is how lightning 2.6.2 and 2.6.3 were published.",
        "Don't merge yet. Check the project's repository for a release workflow run and a tag for this "
        "version, and its issue tracker or security advisories. If the maintainers confirm a manual release, "
        "add a time-limited ignore.",
    ),
    RuleDoc(
        "GRN-T002",
        "publisher-changed",
        "diff",
        W,
        "The verified source repository differs between the trusted and new versions.",
        "Attestations name the repository whose CI built the release. A different repository means "
        "someone else's CI published this version: a fork, a new home, or an attacker's repository. "
        "Renames are ignored when GitHub's repository id is unchanged.",
        "Confirm the move from the old repository: an announcement or a commit there, or the "
        "project's page linking the new home. Don't rely on the release notes or on what the new "
        "repository says about itself; whoever published the release wrote them.",
    ),
    RuleDoc(
        "GRN-T003",
        "workflow-changed",
        "diff",
        W,
        "Same repository, but the publishing workflow file or deployment environment changed.",
        "Moving publishing to a different workflow or dropping a protected environment is a common "
        "step in a CI takeover, and it bypasses reviewers that the environment required.",
        "Look at the commit that changed the workflow in the project's repository and who approved it.",
    ),
    RuleDoc(
        "GRN-T004",
        "no-matching-tag",
        "diff",
        W,
        "The trusted version had a matching git tag in the source repository; the new version has none.",
        "Projects that tag releases normally tag every release. A version on the registry with no tag "
        "was probably not built from the repository's history, which is typical of a token-based upload. "
        "A tag matches when it is X or vX, alone or after a prefix that names the package or says "
        "release, joined by -, _, == or / (and @ for npm): lightning-2.6.1, release-v1.0.0, "
        "api/v1.4.1 for @opentelemetry/api, prebuilt==1.0.11 for langgraph-prebuilt. X is compared "
        "as a version (tag 2026.01.04 matches 2026.1.4). Both the attested repository "
        "and the project's source URL are searched. chalk 5.6.1 and debug 4.4.2, published from a "
        "phished npm account, had no tag.",
        "Check the repository's tags and releases page. A missing tag can be an oversight, so confirm "
        "with the maintainers before merging.",
    ),
    RuleDoc(
        "GRN-T005",
        "outside-trusted-publishing",
        "diff",
        W,
        "Files of the trusted version came through Trusted Publishing; a new file came with an attestation that didn't.",
        "On PyPI today an attestation implies Trusted Publishing, so a file without either is reported "
        "by GRN-T001 and this rule stays quiet. It exists for registries that separate the two.",
        "As for GRN-T001.",
    ),
    RuleDoc(
        "GRN-T006",
        "files-uploaded-late",
        "absolute",
        W,
        "A file of the new version was uploaded more than 24 hours after the version's first "
        "file. It is a warning when pip would install a late wheel where it installed a file "
        "uploaded on time: the release's first wheel, or a wheel that ranks at or above an "
        "on-time wheel on some machine. Late wheels that only add Python versions or platforms "
        "are info.",
        "PyPI accepts new files on an existing version, for example a wheel for a new platform. "
        "The same feature lets someone with a token add a file to a release that was already "
        "reviewed. pip installs the most specific wheel for the machine, so a late wheel can be "
        "the file that installs in place of the one reviewers saw.",
        "Find the build that made the late file in the project's repository: a CI run on the "
        "release's tag, or a commit or issue that explains a rebuild. Compare it with the "
        "on-time file the evidence says it can replace. If nothing in the repository explains "
        "it, don't merge until the maintainers confirm they uploaded it.",
    ),
    RuleDoc(
        "GRN-T007",
        "invalid-attestation",
        "absolute",
        B,
        "An attestation is present but fails Sigstore verification.",
        "A broken or forged attestation is worse than none: something tried to look trustworthy and failed.",
        "Don't install. Report it to the project and to the registry's security team.",
    ),
    RuleDoc(
        "GRN-T008",
        "hash-mismatch",
        "absolute",
        B,
        "A downloaded file doesn't match the hash the registry published.",
        "The bytes you would install are not the bytes the registry listed. That points to tampering "
        "between the registry and you, or a corrupted mirror.",
        "Don't install. Retry from a clean network and report it if it persists.",
    ),
    RuleDoc(
        "GRN-C001",
        "new-pth-file",
        "diff",
        W,
        "The new version adds a .pth file, or an existing .pth file gained executable `import` lines.",
        "Python runs `import` lines in .pth files in site-packages every time the interpreter starts, "
        "for every program, before any of your code. Almost no package needs a new one. "
        "elementary-data 0.23.3 used exactly this to steal credentials.",
        "Read the .pth file. A legitimate path hook (editable installs, namespace helpers) is in the "
        "repository at the release's tag; check there, not only in the release notes, which whoever "
        "published the release wrote. Otherwise treat the release as compromised.",
    ),
    RuleDoc(
        "GRN-C002",
        "new-build-hook",
        "diff",
        W,
        "setup.py gained sensitive calls or gave one it already made different arguments, the build "
        "backend changed to an unknown or in-tree backend, or an npm preinstall, install or "
        "postinstall script was added or changed. Arguments are compared as written, with keyword "
        "order and formatting left out; a variable is compared by its name, not its value.",
        "Code in setup.py, a custom build backend or an npm install script runs on your machine when "
        "the package is built or installed, before you ever import it. nx 21.5.0 and "
        "@ctrl/tinycolor 4.1.1 (Shai-Hulud) carried their payload in a postinstall script.",
        "Read the setup.py diff, the new backend, or the npm script and the file it runs; for "
        "changed arguments the evidence shows the call before and after. Prefer installing the "
        "wheel if one exists; on npm, `npm install --ignore-scripts` skips the scripts.",
    ),
    RuleDoc(
        "GRN-C003",
        "new-import-time-exec",
        "diff",
        W,
        "Code that runs at import time gained calls that run processes, load code, or use the network. "
        "In test files (tests/, test_*.py, conftest.py) it reports at info, unless a non-test module "
        "imports the file or an entry point names it.",
        "Module top-level code runs the moment anything imports the package, including your test suite "
        "and CI. lightning 2.6.2 started a credential stealer this way, from a thread launched in "
        "lightning/__init__.py.",
        "Read the flagged lines, then find them in the repository: the commit on the default branch "
        "that added them, at the release's tag. Network or subprocess calls at import are rare in "
        "libraries. A condition around the call, such as running only in CI or only when a token is "
        "set, is evidence, not reassurance. Release notes don't settle it: whoever published the "
        "release wrote them.",
    ),
    RuleDoc(
        "GRN-C004",
        "new-binary",
        "diff",
        W,
        "The new version adds native code or bytecode the rules can't read: native code under a "
        "name whose last extension says otherwise (a DLL named .py), any native code when the "
        "trusted release shipped none, a .pyc Python imports with no source beside it, or a "
        "hash-based .pyc that Python loads in place of its source without comparing its code. A "
        "new library in a new folder of a release that already shipped native code is reported "
        "at info.",
        "Content rules read Python source. A payload compiled into a library, or shipped as "
        "bytecode, is invisible to them, and Python loads both. num2words 0.5.15 shipped a "
        "Windows DLL named _build.py and loaded it at import.",
        "Find out why the release needs the file: a new compiled module should appear in the "
        "project's repository, in its build configuration and the CI that builds it. If nothing "
        "there explains a binary, or the file's name hides what it is, don't merge. Bytecode in "
        "__pycache__ can be left over from a build, but Python may run it rather than the .py "
        "beside it: ask the maintainers to drop it from the wheel.",
    ),
    RuleDoc(
        "GRN-C007",
        "code-not-in-source",
        "diff",
        W,
        "A Python file in the new version is not the file at the release's git tag, and it has calls "
        "that run processes, load code or use the network which the source file doesn't.",
        "A release is built from its tagged source, so every Python file in the wheel should be in the "
        "repository at that tag. Generated files differ all the time and have no such calls, so the rule "
        "stays quiet on them. ultralytics 8.3.42 was built by the project's own CI after an attacker "
        "poisoned its cache: the wheel was attested and tagged, and the code that downloaded a miner "
        "was in two files that were never committed.",
        "Open the flagged line and the same file at the tag (linked in the evidence). If the build "
        "generates that code on purpose, add a time-limited ignore with the reason. If not, don't "
        "merge, and tell the maintainers: their build, not their repository, produced the release.",
    ),
    RuleDoc(
        "GRN-C008",
        "new-dependency",
        "diff",
        W,
        "The new version depends on a package the trusted version didn't, or a dependency it "
        "had now installs from somewhere else. It is a warning when the registry has no such "
        "package, when it installs from git, a URL or a path, or when its first release came "
        "less than 90 days before this one (or after it), whoever owns it. An established "
        "dependency is info.",
        "A dependency installs with the package, and a new one gets no comparison of its own: "
        "Garnet has no trusted version of it to diff against. Adding a package the attacker "
        "controls is a quiet way to carry a payload into a trusted one. event-stream 3.3.6 "
        "(npm, 2018) added flatmap-stream, first published five weeks earlier; its next "
        "release carried code that stole bitcoin from users of one wallet app.",
        "Open the new dependency's registry page and repository. Check who publishes it, how "
        "long it has existed, and why this release needs it; the release notes or the commit "
        "that added it should say. A package a few weeks old, with no repository and one "
        "release, needs a look before the update merges.",
    ),
    RuleDoc(
        "GRN-C009",
        "new-entry-point",
        "diff",
        W,
        "The new version's wheel declares an entry point the trusted version's didn't, or points "
        "one at different code. Garnet reads the entry_points.txt of each .dist-info or "
        ".egg-info folder at the wheel's root or under <name>.data/purelib/ or platlib/, line by "
        "line as importlib.metadata does; lines removed, repeated or reordered with nothing new "
        "running are not reported, and in a group whose tool loads every line (setuptools.*, "
        "flake8, keyring and others) only a new target counts. It is a warning for a group another tool loads by itself (pytest11, "
        "setuptools.*, flake8, keyring and others) and for a new script in the wheel's own "
        "entry_points.txt with a common command's name (pip, git, curl and the others on the "
        "rule page) other than the project's own; any other new or changed entry point is info. "
        "A wheel Garnet couldn't read to the end is not compared, and the GRN-E finding says so.",
        "An entry point in an auto-loaded group runs inside another program in the environment "
        "the package is installed in: every pytest run, and setuptools builds that don't isolate "
        "themselves. A package can run code there without being imported, so no import-time rule "
        "sees it. A script named `pip` or `git` can run instead of the real command.",
        "Read the target the evidence names. A library that has never been a pytest plugin "
        "rarely becomes one in a patch release. Find the commit that added or changed the entry "
        "point in the project's repository; if nothing there explains it, don't merge.",
    ),
    RuleDoc(
        "GRN-C010",
        "new-startup-file",
        "diff",
        W,
        "The new version's wheel adds a file that runs or installs outside the package: a "
        "sitecustomize.py or usercustomize.py in site-packages, a script under .data/scripts/, or "
        "a file under .data/data/. It is a warning for the startup modules, for a script named "
        "like a common command and for files under etc/; other scripts and data files are info.",
        "Python imports sitecustomize and usercustomize at every start, like a .pth file, so their "
        "code runs in every Python process in the environment whether or not anything imports the "
        "package. Scripts become commands on PATH, and files under etc/ are read as "
        "configuration by other tools.",
        "Open the file the evidence names. A library rarely needs to run at Python startup or to "
        "install a command named like pip or git. Find the commit that added it in the "
        "project's repository; if nothing there explains it, don't merge.",
    ),
    RuleDoc(
        "GRN-C011",
        "new-js-capability",
        "diff",
        Severity.INFO,
        "The JavaScript an npm package loads uses a module or global the trusted version's "
        "didn't: child_process, net, http, https, dns, vm and similar modules, eval or "
        "Function, fetch, XMLHttpRequest or WebSocket, or variable names in the shape "
        "javascript-obfuscator writes. Garnet follows the package's entry points through its "
        "relative requires and imports, and says whether each use runs when the file loads.",
        "Code added to a module runs when the package is required, and npm install scripts "
        "(GRN-C002) don't cover it. chalk 5.6.1 and debug 4.4.2 (September 2025) changed only "
        "index.js, adding an obfuscated line that rewrote browser network calls.",
        "Open the line the evidence names, then find the commit that added it in the "
        "project's repository. A package that never reached the network or started processes "
        "rarely starts in a patch release. If the repository doesn't have the code, or the "
        "code is obfuscated, don't merge.",
    ),
    RuleDoc(
        "GRN-C012",
        "wheels-differ",
        "diff",
        W,
        "Another wheel of the new version, for a different platform or uploaded late, has a "
        "Python file that differs from the wheel Garnet read and makes a sensitive call the "
        "read wheel's copy doesn't. Garnet compares one wheel per platform family and up to 30 "
        "late wheels; more late wheels than that is GRN-E003. A call any of the trusted "
        "version's wheels for the same platform made in the same file, the one Garnet read "
        "included, isn't new. A differing file Garnet can't parse is GRN-E002, unless the "
        "trusted version's wheel for that platform had the same bytes there, and one over the "
        "parse limit GRN-E003.",
        "Content rules read one wheel, the one pip would install where Garnet runs. A payload "
        "can sit in the Windows or macOS wheel only, and reach every user on that platform "
        "while the wheel Garnet read stays clean.",
        "Compare the file the evidence names with the same file in the project's repository at "
        "the release's tag. Pure Python code is normally the same in every wheel of a "
        "release; if the repository doesn't explain the difference, don't merge.",
    ),
    RuleDoc(
        "GRN-K001",
        "known-malicious",
        "absolute",
        B,
        "OSV lists a MAL- advisory for this version.",
        "A malware feed has already confirmed this version is malicious.",
        "Don't install. If it is already installed anywhere, rotate every credential that machine could reach.",
    ),
    RuleDoc(
        "GRN-E001",
        "fetch-failed",
        "absolute",
        W,
        "Data needed for a rule couldn't be fetched.",
        "Garnet never treats a check it couldn't run as a pass. The finding names the rules that were not evaluated.",
        "Re-run with network access. If it keeps failing, check the URL in the evidence.",
    ),
    RuleDoc(
        "GRN-E002",
        "parse-failed",
        "absolute",
        W,
        "An artifact or a changed file couldn't be parsed.",
        "Content rules couldn't look inside it, so they didn't pass it either.",
        "Inspect the file by hand.",
    ),
    RuleDoc(
        "GRN-E003",
        "budget-exceeded",
        "absolute",
        W,
        "A safety limit (size, entries, compression ratio, parse size or time) was hit, or a "
        "release has more late wheels than GRN-C012 compares.",
        "Limits stop archive bombs and runaway parsing. Content past a limit was not checked. "
        "A late wheel past the 30 GRN-C012 compares wasn't read either, and it can carry code "
        "the wheel Garnet read doesn't.",
        "Inspect what hit the limit by hand. For late wheels, compare each one's Python files "
        "with the wheel Garnet read. If it is expected, ignore this version.",
    ),
)

_DOCS += (
    RuleDoc(
        "GRN-E004",
        "unpinned-requirement",
        "absolute",
        Severity.INFO,
        "A requirements line isn't pinned with ==, so Garnet can't tell which release you'll get.",
        "Without an exact version there is no release to compare. The installer picks one at install "
        "time, and Garnet never sees it.",
        "Pin it (`name==version`), or use a lockfile such as uv.lock or pylock.toml.",
    ),
    RuleDoc(
        "GRN-E005",
        "unsupported-source",
        "absolute",
        Severity.INFO,
        "A dependency comes from a source Garnet doesn't check: git, a local path, a direct URL or a private index.",
        "Garnet compares releases published on PyPI. Code from other sources wasn't checked, and it "
        "isn't passed either.",
        "Review the change to that dependency by hand.",
    ),
)

DOCS: dict[str, RuleDoc] = {d.rule_id: d for d in _DOCS}

# Rules in the SPEC §6.2 catalog that aren't built yet. A policy may already
# name them; they produce no findings until they ship.
PLANNED: frozenset[str] = frozenset({"GRN-C005", "GRN-C006"})
