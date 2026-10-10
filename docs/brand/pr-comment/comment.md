<!-- garnet:report -->
<img src="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/favicon/favicon-16.svg" width="16" height="16" alt=""> **Garnet Guard: 1 of 3 updates needs a look**

> [!WARNING]
> **examplelib 2.6.1 → 2.6.2**
> - [`GRN-T001`](https://garnet-guard.dev/rules/GRN-T001) 2.6.1 had a PyPI provenance attestation from `github.com/example/examplelib` (`release.yml`). 2.6.2 has none.
> - [`GRN-T004`](https://garnet-guard.dev/rules/GRN-T004) No git tag `v2.6.2` exists in `github.com/example/examplelib`.
> - [`GRN-C003`](https://garnet-guard.dev/rules/GRN-C003) New import-time code in `examplelib/__init__.py:12` (subprocess call at module level).

<details><summary>2 updates with nothing worth a look</summary>

| Package | Update | Checks |
|---|---|---|
| `requests` | 2.32.4 → 2.32.5 | provenance ✓ · tag ✓ · content ✓ |
| `idna` | 3.10 → 3.11 | provenance ✓ · tag ✓ · content ✓ |

</details>

<sub>Garnet Guard · [what is this?](https://garnet-guard.dev/what) · [GRN-T001](https://garnet-guard.dev/rules/GRN-T001) · [GRN-T004](https://garnet-guard.dev/rules/GRN-T004) · [GRN-C003](https://garnet-guard.dev/rules/GRN-C003)</sub>
