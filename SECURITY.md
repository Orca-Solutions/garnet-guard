# Garnet Guard security policy

## Reporting a vulnerability in Garnet

Please use GitHub's **private vulnerability reporting** on this repository (Security tab → "Report a vulnerability"). Do not open a public issue.

Report privately if you find:

- a way to make Garnet execute code from a package it inspects
- a parser bug in archive, lockfile or metadata handling (crash, hang, traversal, resource exhaustion)
- a way to make the Action leak tokens or act with more privilege than documented
- a way to forge a `pass` verdict, or to make Garnet report "pass" when it couldn't check
- a **novel** detection bypass that an attacker could use today

Known evasion ideas that are already public, false positives, and rule ideas are welcome as normal issues.

## What to expect

Garnet is maintained by one person for now, so these are goals rather than guarantees:

- Acknowledgement within 3 business days.
- An initial assessment within 10 business days.
- A fix or mitigation for confirmed high-severity issues as fast as possible, with a GitHub Security Advisory and CVE where it applies.
- Credit in the advisory, unless you'd rather stay anonymous.

Please give us 90 days, or until a fix ships, before public disclosure.

## Supported versions

Before 1.0, only the latest release gets security fixes. After 1.0, the latest minor release of the current major version is supported.

## Reporting a malicious package

A Garnet warning is a reason to look, not proof. Please report privately to the registry and the maintainer, and don't name a release as malicious in public until it's confirmed.

Garnet doesn't run a malware feed. If Garnet helped you find a malicious release, report it to the registry (PyPI: the "Report project as malware" link on the project page; npm: `npm report` or npm support) and to the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) repository so OSV picks it up. We'd love to hear about it too, so we can add it to the backtest corpus.

## How Garnet is released

Every release is published to PyPI with Trusted Publishing from a protected environment and carries PEP 740 attestations. Verify them with `pypi-attestations` or by running Garnet on itself.
