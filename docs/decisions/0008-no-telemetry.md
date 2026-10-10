# 0008. No telemetry

- Status: Accepted
- Date: 2026-10-10

## Context

Socket Firewall Free sends telemetry that can't be disabled. Security-conscious teams notice. Usage numbers would help prioritization, but they can come from download stats, GitHub dependents and an opt-in interest list.

## Decision

The open-source tool sends nothing except the requests needed to fetch public package data. No usage pings, no crash reporting.

## Consequences

Less insight into usage. "No telemetry" becomes a stated differentiator.
