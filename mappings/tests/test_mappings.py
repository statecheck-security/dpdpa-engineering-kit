"""The CSV and XLSX crosswalks must say the same thing, and the summary sheet must match the rows."""
import csv
import re
from collections import Counter
from pathlib import Path

import openpyxl
import pytest

HERE = Path(__file__).resolve().parent.parent

PAIRS = [
    ("dpdpa-iso-27001-mapping-matrix.csv", "dpdpa-iso-27001-mapping.xlsx", "DPDPA-ISO Mapping"),
    ("soc2-tsc-dpdpa-mapping.csv", "soc2-tsc-dpdpa-mapping.xlsx", "SOC2-DPDPA Mapping"),
]


def csv_rows(name):
    with open(HERE / name, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def sheet_rows(name, sheet):
    ws = openpyxl.load_workbook(HERE / name, read_only=True)[sheet]
    return [["" if v is None else str(v) for v in row] for row in ws.iter_rows(values_only=True)
            if any(v is not None for v in row)]


def _norm(value: str) -> str:
    value = value.strip()
    return str(int(float(value))) if re.fullmatch(r"\d+(\.0)?", value) else value


@pytest.mark.parametrize("csv_name, xlsx_name, sheet", PAIRS)
def test_csv_and_xlsx_hold_the_same_rows(csv_name, xlsx_name, sheet):
    a = [[_norm(v) for v in r] for r in csv_rows(csv_name)]
    b = [[_norm(v) for v in r][: len(a[0])] for r in sheet_rows(xlsx_name, sheet)]
    assert a == b


@pytest.mark.parametrize("csv_name, _x, _s", PAIRS)
def test_rows_are_complete_and_numbered(csv_name, _x, _s):
    header, *rows = csv_rows(csv_name)
    assert [int(r[0]) for r in rows] == list(range(1, len(rows) + 1))
    cov = header.index("Coverage")
    assert {r[cov] for r in rows} <= {"Full", "Partial", "Gap"}
    obligation = header.index("DPDPA Obligation")
    assert all(r[obligation].strip() for r in rows)


@pytest.mark.parametrize("csv_name, _x, _s", PAIRS)
def test_every_gap_row_has_implementation_notes(csv_name, _x, _s):
    header, *rows = csv_rows(csv_name)
    cov, notes = header.index("Coverage"), header.index("Implementation Notes")
    assert all(r[notes].strip() for r in rows if r[cov] == "Gap")


@pytest.mark.parametrize("csv_name, xlsx_name, _s", PAIRS)
def test_summary_counts_match_the_rows(csv_name, xlsx_name, _s):
    header, *rows = csv_rows(csv_name)
    counts = Counter(r[header.index("Coverage")] for r in rows)
    summary = sheet_rows(xlsx_name, "Summary")
    stated = {}
    for row in summary:
        label = row[0].strip().lower()
        for level in ("full", "partial", "gap"):
            if label.startswith(level) and len(row) > 1 and re.fullmatch(r"\d+(\.0)?", row[1].strip()):
                stated[level.capitalize()] = int(float(row[1]))
    assert stated, "no coverage counts found on the Summary sheet"
    for level, n in stated.items():
        assert counts[level] == n, f"Summary says {n} {level}, rows have {counts[level]}"
