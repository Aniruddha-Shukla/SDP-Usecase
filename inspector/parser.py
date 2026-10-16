"""Turn Trivy JSON reports (``trivy image --format json``) into tidy pandas DataFrames.

Trivy's report schema (SchemaVersion 2) is::

    {ArtifactName, CreatedAt, Metadata: {OS, ImageID, ...},
     Results: [{Target, Class, Type, Packages?: [...], Vulnerabilities?: [...]}]}

Three frames come out of it, one row per:
  * image   -- ``images_frame``
  * finding -- ``vulnerabilities_frame`` (vulnerability x package x target)
  * package -- ``packages_frame`` (needs ``--list-all-pkgs`` at scan time)
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

import pandas as pd

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_DTYPE = pd.CategoricalDtype(SEVERITIES, ordered=True)

# Preferred CVSS sources, most authoritative first; any other vendor is a fallback.
_CVSS_SOURCES = ("nvd", "ghsa", "redhat")

IMAGE_COLUMNS = [
    "image",
    "scanned_at",
    "os_family",
    "os_name",
    "image_id",
    "repo_digest",
    "image_created",
    "architecture",
    "layers",
    "source",
]
VULN_COLUMNS = [
    "image",
    "target",
    "pkg_class",
    "pkg_type",
    "vulnerability_id",
    "pkg_name",
    "installed_version",
    "fixed_version",
    "status",
    "fixable",
    "severity",
    "cvss_score",
    "title",
    "cwe_ids",
    "published_date",
    "age_days",
    "primary_url",
    "layer_diff_id",
    "purl",
]
PACKAGE_COLUMNS = [
    "image",
    "target",
    "pkg_class",
    "pkg_type",
    "pkg_name",
    "version",
    "licenses",
    "purl",
    "layer_diff_id",
]


class ReportError(ValueError):
    """Raised when a file is not a Trivy JSON report we can read."""


@dataclass(frozen=True)
class ScanReport:
    """One parsed Trivy report plus where it came from."""

    data: dict[str, Any]
    source: str

    @property
    def image(self) -> str:
        return self.data["ArtifactName"]

    @property
    def scanned_at(self) -> pd.Timestamp:
        return pd.to_datetime(self.data.get("CreatedAt"), utc=True, errors="coerce")

    @property
    def results(self) -> list[dict[str, Any]]:
        return self.data.get("Results") or []


def load_report(source: str | Path | IO | dict, name: str | None = None) -> ScanReport:
    """Load one report from a path, an open file / upload, or an already-decoded dict."""
    if isinstance(source, dict):
        data, label = source, name or "<dict>"
    elif isinstance(source, (str, Path)):
        path = Path(source)
        label = name or path.name
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReportError(f"{label}: not valid JSON ({exc})") from exc
    else:
        label = name or getattr(source, "name", "<upload>")
        try:
            data = json.load(source)
        except json.JSONDecodeError as exc:
            raise ReportError(f"{label}: not valid JSON ({exc})") from exc

    if not isinstance(data, dict):
        raise ReportError(f"{label}: expected a JSON object")
    if "bomFormat" in data or "spdxVersion" in data:
        raise ReportError(f"{label}: this is an SBOM, not a Trivy vulnerability report")
    if "ArtifactName" not in data or "SchemaVersion" not in data:
        raise ReportError(f"{label}: missing ArtifactName/SchemaVersion; run trivy with --format json")
    if data["SchemaVersion"] != 2:
        raise ReportError(f"{label}: unsupported Trivy SchemaVersion {data['SchemaVersion']} (expected 2)")
    return ScanReport(data=data, source=label)


def load_reports_from_dir(directory: str | Path) -> tuple[list[ScanReport], list[str]]:
    """Load every ``*.json`` report in ``directory``; returns (reports, error messages)."""
    reports, errors = [], []
    for path in sorted(Path(directory).glob("*.json")):
        try:
            reports.append(load_report(path))
        except ReportError as exc:
            errors.append(str(exc))
    return reports, errors


def latest_per_image(reports: Iterable[ScanReport]) -> list[ScanReport]:
    """Keep only the most recent scan of each image (by Trivy's CreatedAt)."""
    latest: dict[str, ScanReport] = {}
    for report in reports:
        current = latest.get(report.image)
        if current is None or _later(report.scanned_at, current.scanned_at):
            latest[report.image] = report
    return list(latest.values())


def images_frame(reports: Iterable[ScanReport]) -> pd.DataFrame:
    rows = []
    for r in reports:
        meta = r.data.get("Metadata") or {}
        os_info = meta.get("OS") or {}
        config = meta.get("ImageConfig") or {}
        rows.append(
            {
                "image": r.image,
                "scanned_at": r.scanned_at,
                "os_family": os_info.get("Family"),
                "os_name": os_info.get("Name"),
                "image_id": meta.get("ImageID"),
                "repo_digest": next(iter(meta.get("RepoDigests") or []), None),
                "image_created": pd.to_datetime(config.get("created"), utc=True, errors="coerce"),
                "architecture": config.get("architecture"),
                "layers": len(meta.get("DiffIDs") or []),
                "source": r.source,
            }
        )
    return pd.DataFrame(rows, columns=IMAGE_COLUMNS)


def vulnerabilities_frame(reports: Iterable[ScanReport]) -> pd.DataFrame:
    rows = []
    for r in reports:
        scanned_at = r.scanned_at
        for result in r.results:
            for v in result.get("Vulnerabilities") or []:
                published = pd.to_datetime(v.get("PublishedDate"), utc=True, errors="coerce")
                fixed = (v.get("FixedVersion") or "").strip()
                rows.append(
                    {
                        "image": r.image,
                        "target": result.get("Target"),
                        "pkg_class": result.get("Class"),
                        "pkg_type": result.get("Type"),
                        "vulnerability_id": v.get("VulnerabilityID"),
                        "pkg_name": v.get("PkgName"),
                        "installed_version": v.get("InstalledVersion"),
                        "fixed_version": fixed or None,
                        "status": v.get("Status") or ("fixed" if fixed else "unknown"),
                        "fixable": bool(fixed),
                        "severity": (v.get("Severity") or "UNKNOWN").upper(),
                        "cvss_score": cvss_score(v),
                        "title": v.get("Title") or _first_line(v.get("Description")),
                        "cwe_ids": ", ".join(v.get("CweIDs") or []) or None,
                        "published_date": published,
                        "age_days": _age_days(published, scanned_at),
                        "primary_url": v.get("PrimaryURL"),
                        "layer_diff_id": (v.get("Layer") or {}).get("DiffID"),
                        "purl": (v.get("PkgIdentifier") or {}).get("PURL"),
                    }
                )

    df = pd.DataFrame(rows, columns=VULN_COLUMNS)
    df["severity"] = df["severity"].where(df["severity"].isin(SEVERITIES), "UNKNOWN").astype(SEVERITY_DTYPE)
    df["fixable"] = df["fixable"].astype(bool)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["age_days"] = pd.to_numeric(df["age_days"], errors="coerce")
    # Trivy can list the same finding twice when one package is seen through two paths.
    return df.drop_duplicates(
        subset=["image", "target", "vulnerability_id", "pkg_name", "installed_version"]
    ).reset_index(drop=True)


def packages_frame(reports: Iterable[ScanReport]) -> pd.DataFrame:
    rows = []
    for r in reports:
        for result in r.results:
            for p in result.get("Packages") or []:
                rows.append(
                    {
                        "image": r.image,
                        "target": result.get("Target"),
                        "pkg_class": result.get("Class"),
                        "pkg_type": result.get("Type"),
                        "pkg_name": p.get("Name"),
                        "version": p.get("Version"),
                        "licenses": ", ".join(p.get("Licenses") or []) or None,
                        "purl": (p.get("Identifier") or {}).get("PURL"),
                        "layer_diff_id": (p.get("Layer") or {}).get("DiffID"),
                    }
                )
    return pd.DataFrame(rows, columns=PACKAGE_COLUMNS)


def cvss_score(vuln: dict[str, Any]) -> float | None:
    """Best available CVSS base score: v3 (then v4, then v2) from the most authoritative source."""
    cvss = vuln.get("CVSS") or {}
    sources = [s for s in _CVSS_SOURCES if s in cvss]
    sources += [s for s in cvss if s not in sources]
    for key in ("V3Score", "V40Score", "V2Score"):
        for source in sources:
            score = (cvss.get(source) or {}).get(key)
            if score:
                return float(score)
    return None


def _first_line(text: str | None) -> str | None:
    return text.strip().splitlines()[0][:200] if text and text.strip() else None


def _age_days(published: pd.Timestamp, scanned_at: pd.Timestamp) -> float | None:
    if pd.isna(published) or pd.isna(scanned_at):
        return None
    return float((scanned_at - published).days)


def _later(a: pd.Timestamp, b: pd.Timestamp) -> bool:
    if pd.isna(b):
        return True
    return not pd.isna(a) and a > b
