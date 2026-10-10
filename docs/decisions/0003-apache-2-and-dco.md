# 0003. Apache-2.0 with DCO, no CLA

- Status: Accepted
- Date: 2026-10-10

## Context

Impact is the top priority, so companies must be able to adopt Garnet without legal review friction. AGPL would deter cloud clones of a hosted service but slows adoption, and the hosted app's value is its data, not code secrecy. A CLA would allow relicensing but discourages contributors and isn't needed since the hosted app is a separate codebase.

## Decision

Apache-2.0 for all open-source code. Contributors sign off commits under the Developer Certificate of Origin. No CLA.

## Consequences

Anyone, including competitors, can run Garnet commercially. The project competes on trust, neutrality and quality rather than license restrictions. The project can never relicense contributors' code to something more restrictive.
