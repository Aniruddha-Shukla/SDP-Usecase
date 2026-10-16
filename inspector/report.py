"""Print a Markdown summary of Trivy JSON reports, e.g. for a GitHub Actions job summary.

python -m inspector.report data/scans/*.json
python -m inspector.report trivy-image.json >> "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from inspector import analytics as an
from inspector.parser import (
    ReportError,
    ScanReport,
    images_frame,
    latest_per_image,
    load_report,
    vulnerabilities_frame,
)


def _table(df: pd.DataFrame) -> str:
    header = "| " + " | ".join(df.columns) + " |"
    rule = "| " + " | ".join("---" for _ in df.columns) + " |"
    rows = ["| " + " | ".join(str(v).replace("|", "\\|") for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join([header, rule, *rows])


def render(reports: list[ScanReport], top: int = 10) -> str:
    reports = latest_per_image(reports)
    images, vulns = images_frame(reports), vulnerabilities_frame(reports)
    k = an.headline(vulns, images)

    out = [
        "## 🛡️ Container vulnerability summary",
        "",
        f"**{k['images']}** image(s) · **{k['findings']:,}** findings · **{k['unique_vulns']:,}** unique "
        f"vulnerabilities · **{k['critical']:,}** critical · **{k['high']:,}** high · "
        f"**{k['fixable_pct']:.0f}%** have a fix",
        "",
    ]

    risk = an.image_risk(vulns, images)
    risk_table = pd.DataFrame(
        {
            "Image": "`" + risk["image"] + "`",
            "OS": risk["os"],
            "Risk score": risk["risk_score"].round(0).astype(int),
            "Critical": risk["critical"],
            "High": risk["high"],
            "Medium": risk["medium"],
            "Low": risk["low"],
            "Fixable": risk["fixable_pct"].round(0).astype(int).astype(str) + "%",
        }
    )
    out += ["### Images by risk", "", _table(risk_table), ""]

    plan = an.remediation_plan(vulns).head(top)
    if not plan.empty:
        plan_table = pd.DataFrame(
            {
                "Image": "`" + plan["image"] + "`",
                "Package": plan["pkg_name"],
                "Installed": plan["installed_version"],
                "Upgrade to": plan["upgrade_to"],
                "Fixes": plan["fixes"],
                "Worst": plan["worst_severity"].astype(str),
            }
        )
        out += [f"### Top {len(plan)} upgrades", "", _table(plan_table), ""]

    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", nargs="+", type=Path, help="Trivy JSON report files")
    parser.add_argument("--top", type=int, default=10, help="number of upgrades to list")
    args = parser.parse_args(argv)

    reports = []
    for path in args.reports:
        try:
            reports.append(load_report(path))
        except (ReportError, OSError) as exc:
            print(f"skipping {path}: {exc}", file=sys.stderr)
    if not reports:
        print("No readable Trivy reports.", file=sys.stderr)
        return 1

    print(render(reports, top=args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
