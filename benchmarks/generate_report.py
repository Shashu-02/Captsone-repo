#!/usr/bin/env python3
"""Generate a simple Markdown summary from benchmark CSV files that exist."""
import csv
from pathlib import Path
ROOT=Path(__file__).resolve().parent
RESULTS=ROOT/"results"
names=["crypto","storage","blockchain","e2e"]
lines=["# Capstone Comparative Benchmark Results","",
       "Generated from measured CSV outputs. Empty/missing benchmark files are not inferred.",""]
for name in names:
    p=RESULTS/f"{name}.csv"
    lines += [f"## {name.replace('_',' ').title()}",""]
    if not p.exists():
        lines += ["Not run yet.",""]; continue
    with p.open(newline="") as f:
        rows=list(csv.DictReader(f))
    if not rows:
        lines += ["No rows recorded.",""];continue
    headers=list(rows[0])
    lines += ["| "+" | ".join(headers)+" |","| "+" | ".join(["---"]*len(headers))+" |"]
    for row in rows:
        lines += ["| "+" | ".join(str(row[h]) for h in headers)+" |"]
    lines.append("")
out=RESULTS/"benchmark_summary.md"
out.write_text("\n".join(lines),encoding="utf-8")
print(f"Wrote {out}")
