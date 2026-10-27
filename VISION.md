# Garnet Guard vision

## The problem

Open-source registries now defend well against two kinds of risk. Known malware gets blocked by free tools fed from vendor and OpenSSF advisories. Brand-new packages get held back by the "minimum release age" cooldowns that npm, pnpm, Yarn, Bun, pip, uv, Poetry and Dependabot all ship.

The gap is the **new version of a package you already trust**. Attackers learned that the cheapest path into thousands of environments is to steal one maintainer's account, token or CI pipeline and publish a version that looks routine. The signals that would expose it already exist: PyPI and npm attestations, Trusted Publishing metadata, git tags, and the contents of the release itself. Almost nothing on the consumer side reads them. pip and uv do not verify PEP 740 attestations at install time, and only pnpm refuses a release whose trust level dropped.

## Mission

Garnet Guard exists so that no project takes a dependency update on faith. We compare every new release with the last one it trusted, explain exactly what changed, and give that check away, free and open, until the registries and installers do it themselves.

## Vision

A world where a hijacked release never looks routine, because every installer reads the signals that are already there.

## Who it's for

1. **Python teams that take updates through Dependabot or Renovate.** They review dependency PRs but have nothing to review them *with*.
2. **Open-source maintainers** who want a cheap, auditable guard on their own dependency tree.
3. **People using AI coding agents**, which add dependencies faster than humans read them. A pre-install hook for Claude Code and Codex checks each one before it lands.

The three audiences map to the three surfaces: the GitHub Action, the CLI and the agent hook.

## Principles

Garnet's founding principles are in [PRINCIPLES.md](PRINCIPLES.md). The short version: diff against the last trusted release, stay quiet on clean updates, explain every finding, never execute what we inspect, stay open and neutral, and never paywall detection.

## Non-goals

- Being a malware feed or a malware scanner for whole packages.
- Catching a malicious *first* version of a brand-new package. Cooldowns and feeds cover that.
- Sandboxed or dynamic execution.
- Replacing vulnerability (CVE) scanners such as pip-audit or OSV-Scanner.
- Ecosystems beyond Python and npm before both are solid.

## What success looks like

In one line: "this release looks different from the last one you trusted" becomes a check every project runs on every dependency update.

- **At launch (mid-December 2026, 0.2):** Garnet catches every replayed 2025–26 incident it targets, stays quiet on the large majority of clean updates to top PyPI packages, runs on real repositories, and the launch write-up gets read.
- **Year 1 (1.0 shipped):** Garnet is a default recommendation for securing Dependabot/Renovate flows in Python, has outside maintainers, and has caught at least one real compromise before a feed listed it.
- **Longer term:** the checks Garnet proves out become native in pip, uv and npm, and Garnet becomes the policy and history layer above them.
