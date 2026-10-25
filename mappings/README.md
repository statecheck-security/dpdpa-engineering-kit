# Control mappings

How far an existing ISO 27001 or SOC 2 programme gets you towards the DPDPA, obligation by
obligation, with what to add where it falls short.

| File | Rows | Coverage |
|---|---|---|
| `dpdpa-iso-27001-mapping-matrix.csv` / `.xlsx` | 20 DPDPA obligations | 3 full, 8 partial, 9 gaps |
| `soc2-tsc-dpdpa-mapping.csv` / `.xlsx` | 52 SOC 2 TSC controls | 17 full, 34 partial, 1 gap |
| `diagrams/` | ISO control flow, NIST crosswalk, SOC 2 coverage (Mermaid) | — |

The XLSX files add a Summary sheet and Status / Owner columns for tracking your own progress.

Explained in [ISO 27001:2022 and DPDPA](https://statechecksecurity.com/blog/dpdpa-iso-27001-mapping)
and [SOC 2 and DPDPA](https://statechecksecurity.com/blog/soc-2-dpdpa-compliance).

A mapping is a judgement, not text from either standard. "Full" means the control asks for
the same thing as the obligation, not that your implementation of it is enough.

## Licence

[CC BY 4.0](LICENSE): reuse and adapt them, crediting StateCheck Security with a link to
[statechecksecurity.com](https://statechecksecurity.com).

## Tests

`tests/test_mappings.py`: CSV and XLSX hold the same rows, rows are numbered and complete,
every gap has implementation notes, and the Summary counts match the rows.
