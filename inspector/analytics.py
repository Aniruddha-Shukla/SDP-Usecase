"""Plain pandas aggregations over the frames built in :mod:`inspector.parser`.

Every function takes DataFrames and returns a DataFrame (or a small dict), so the
dashboard, tests and any CLI/report code share one implementation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import pandas as pd

from inspector.parser import SEVERITIES, SEVERITY_DTYPE

# Weights for a simple, explainable risk score: one CRITICAL ~ two HIGHs ~ five MEDIUMs.
SEVERITY_WEIGHTS = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "UNKNOWN": 0.1}

AGE_BUCKETS = [
    (0, 30, "< 30 days"),
    (30, 90, "30-90 days"),
    (90, 365, "3-12 months"),
    (365, 730, "1-2 years"),
    (730, 1825, "2-5 years"),
    (1825, float("inf"), "5+ years"),
]
AGE_UNKNOWN = "Unknown"
AGE_ORDER = [label for *_, label in AGE_BUCKETS] + [AGE_UNKNOWN]

COMPARE_ORDER = ["Removed", "Added", "In both"]

# Coarse license families. Patterns anchor on a word start so "LGPL-2.1" is not
# mistaken for GPL.
_LICENSE_FAMILIES = [
    ("Strong copyleft", re.compile(r"\b(AGPL|GPL|SSPL)", re.I)),
    ("Weak copyleft", re.compile(r"\b(LGPL|MPL|EPL|CDDL|EUPL|OSL)", re.I)),
    (
        "Permissive",
        re.compile(
            r"\b(MIT|BSD|0BSD|Apache|ISC|Zlib|PSF|Python|Unlicense|CC0|X11|BSL-1\.0|Boost|Artistic"
            r"|public-domain|curl)",
            re.I,
        ),
    ),
]
LICENSE_FAMILY_ORDER = ["Strong copyleft", "Weak copyleft", "Permissive", "Other", "Unknown"]


def filter_findings(
    vulns: pd.DataFrame,
    images: Iterable[str] | None = None,
    severities: Iterable[str] | None = None,
    pkg_classes: Iterable[str] | None = None,
    fixable_only: bool = False,
) -> pd.DataFrame:
    mask = pd.Series(True, index=vulns.index)
    if images is not None:
        mask &= vulns["image"].isin(list(images))
    if severities is not None:
        mask &= vulns["severity"].isin(list(severities))
    if pkg_classes is not None:
        mask &= vulns["pkg_class"].isin(list(pkg_classes))
    if fixable_only:
        mask &= vulns["fixable"]
    return vulns[mask]


def headline(vulns: pd.DataFrame, images: pd.DataFrame) -> dict[str, float]:
    total = len(vulns)
    return {
        "images": int(images["image"].nunique()),
        "findings": total,
        "unique_vulns": int(vulns["vulnerability_id"].nunique()),
        "critical": int((vulns["severity"] == "CRITICAL").sum()),
        "high": int((vulns["severity"] == "HIGH").sum()),
        "fixable_pct": float(vulns["fixable"].mean() * 100) if total else 0.0,
    }


def severity_counts(vulns: pd.DataFrame, by: str = "image") -> pd.DataFrame:
    """Findings per ``by`` value with one column per severity (all five, zero-filled)."""
    counts = (
        vulns.groupby([by, "severity"], observed=False).size().unstack("severity", fill_value=0)
        if not vulns.empty
        else pd.DataFrame(columns=SEVERITIES)
    )
    counts = counts.reindex(columns=SEVERITIES, fill_value=0)
    counts.columns = list(SEVERITIES)
    return counts.astype(int)


def image_risk(vulns: pd.DataFrame, images: pd.DataFrame) -> pd.DataFrame:
    """One row per image, riskiest first. Images with no findings are kept (score 0)."""
    unique = vulns.drop_duplicates(["image", "vulnerability_id", "pkg_name", "installed_version"])
    score = unique["severity"].astype(str).map(SEVERITY_WEIGHTS).groupby(unique["image"]).sum()

    sev = severity_counts(vulns).rename(columns=str.lower)
    per_image = vulns.groupby("image").agg(
        findings=("vulnerability_id", "size"),
        unique_vulns=("vulnerability_id", "nunique"),
        fixable=("fixable", "sum"),
    )
    out = (
        images.set_index("image")[["os_family", "os_name"]]
        .join(per_image)
        .join(sev)
        .assign(risk_score=score)
        .fillna({c: 0 for c in ["findings", "unique_vulns", "fixable", "risk_score", *sev.columns]})
    )
    int_cols = ["findings", "unique_vulns", "fixable", *sev.columns]
    out[int_cols] = out[int_cols].astype(int)
    out["fixable_pct"] = (out["fixable"] / out["findings"].where(out["findings"] > 0)).fillna(0) * 100
    out["os"] = (out["os_family"].fillna("") + " " + out["os_name"].fillna("")).str.strip()
    cols = ["os", "risk_score", "findings", "unique_vulns", *sev.columns, "fixable", "fixable_pct"]
    return out[cols].sort_values(["risk_score", "findings"], ascending=False).rename_axis("image").reset_index()


def fixability(vulns: pd.DataFrame) -> pd.DataFrame:
    """Findings per severity split into fix available / no fix yet."""
    df = vulns.assign(fix=vulns["fixable"].map({True: "Fix available", False: "No fix yet"}))
    return df.groupby(["severity", "fix"], observed=False).size().rename("findings").reset_index().query("findings > 0")


def top_packages(vulns: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    """Packages contributing the most weighted risk, with a per-severity breakdown."""
    if vulns.empty:
        return pd.DataFrame(
            columns=["pkg_name", "pkg_type", "findings", "unique_vulns", "images", "fixable", "risk_score", *SEVERITIES]
        )
    weighted = vulns.assign(weight=vulns["severity"].astype(str).map(SEVERITY_WEIGHTS))
    keys = ["pkg_name", "pkg_type"]
    agg = weighted.groupby(keys).agg(
        findings=("vulnerability_id", "size"),
        unique_vulns=("vulnerability_id", "nunique"),
        images=("image", "nunique"),
        fixable=("fixable", "sum"),
        risk_score=("weight", "sum"),
    )
    sev = vulns.groupby([*keys, "severity"], observed=False).size().unstack("severity", fill_value=0)
    sev.columns = list(sev.columns.astype(str))
    return agg.join(sev).sort_values("risk_score", ascending=False).head(n).reset_index()


def shared_vulnerabilities(vulns: pd.DataFrame, min_images: int = 2) -> pd.DataFrame:
    """Vulnerabilities that show up in at least ``min_images`` different images."""
    if vulns.empty:
        return pd.DataFrame(
            columns=[
                "vulnerability_id",
                "severity",
                "cvss_score",
                "images",
                "image_list",
                "packages",
                "fixable",
                "title",
                "primary_url",
            ]
        )
    out = vulns.groupby("vulnerability_id").agg(
        severity=("severity", "min"),  # ordered categorical: min == most severe
        cvss_score=("cvss_score", "max"),
        images=("image", "nunique"),
        image_list=("image", lambda s: ", ".join(sorted(s.unique()))),
        packages=("pkg_name", lambda s: ", ".join(sorted(s.unique()))),
        fixable=("fixable", "any"),
        title=("title", "first"),
        primary_url=("primary_url", "first"),
    )
    out = out[out["images"] >= min_images]
    return (
        out.reset_index()
        .sort_values(["images", "severity", "cvss_score"], ascending=[False, True, False])
        .reset_index(drop=True)
    )


def remediation_plan(vulns: pd.DataFrame) -> pd.DataFrame:
    """Package upgrades ranked by how much risk each one removes.

    ``upgrade_to`` is the highest fixed version Trivy reported for the package,
    which clears every listed vulnerability. It uses a natural sort, which is
    right for typical deb/apk/semver strings but is not a full per-ecosystem
    version comparison; ``fixed_in`` keeps every reported fixed version.
    """
    fixable = vulns[vulns["fixable"]]
    cols = [
        "image",
        "pkg_name",
        "pkg_type",
        "installed_version",
        "upgrade_to",
        "fixes",
        "worst_severity",
        "critical",
        "high",
        "risk_reduction",
        "vulnerability_ids",
        "fixed_in",
    ]
    if fixable.empty:
        return pd.DataFrame(columns=cols)

    fixable = fixable.assign(weight=fixable["severity"].astype(str).map(SEVERITY_WEIGHTS))
    keys = ["image", "pkg_name", "pkg_type", "installed_version"]
    plan = fixable.groupby(keys).agg(
        upgrade_to=("fixed_version", lambda s: max(_split_versions(s), key=_natural_key)),
        fixed_in=("fixed_version", lambda s: " / ".join(sorted(_split_versions(s), key=_natural_key))),
        fixes=("vulnerability_id", "nunique"),
        worst_severity=("severity", "min"),
        critical=("severity", lambda s: int((s == "CRITICAL").sum())),
        high=("severity", lambda s: int((s == "HIGH").sum())),
        risk_reduction=("weight", "sum"),
        vulnerability_ids=("vulnerability_id", lambda s: ", ".join(sorted(s.unique()))),
    )
    return plan.reset_index().sort_values(["risk_reduction", "fixes"], ascending=False)[cols].reset_index(drop=True)


def age_profile(vulns: pd.DataFrame) -> pd.DataFrame:
    """Findings by how long the vulnerability had been public when the image was scanned."""

    def bucket(days: float) -> str:
        if pd.isna(days):
            return AGE_UNKNOWN
        return next(label for lo, hi, label in AGE_BUCKETS if lo <= days < hi)

    df = vulns.assign(age=pd.Categorical(vulns["age_days"].map(bucket), categories=AGE_ORDER, ordered=True))
    return df.groupby(["age", "severity"], observed=False).size().rename("findings").reset_index()


def compare_images(vulns: pd.DataFrame, base: str, candidate: str) -> tuple[pd.DataFrame, dict[str, int]]:
    """Which vulnerabilities switching from ``base`` to ``candidate`` removes, keeps or adds."""

    def per_vuln(image: str) -> pd.DataFrame:
        sub = vulns[vulns["image"] == image]
        return sub.groupby("vulnerability_id").agg(
            severity=("severity", "min"),
            packages=("pkg_name", lambda s: ", ".join(sorted(s.unique()))),
            title=("title", "first"),
        )

    a, b = per_vuln(base), per_vuln(candidate)
    merged = a.join(b, how="outer", lsuffix="_base", rsuffix="_candidate")
    in_a, in_b = merged["severity_base"].notna(), merged["severity_candidate"].notna()
    change = pd.Series("In both", index=merged.index)
    change[in_a & ~in_b] = "Removed"
    change[~in_a & in_b] = "Added"
    merged["change"] = pd.Categorical(change, categories=COMPARE_ORDER, ordered=True)
    merged["severity"] = (
        merged["severity_candidate"].astype(object).where(in_b, merged["severity_base"].astype(object))
    ).astype(SEVERITY_DTYPE)
    merged["packages"] = merged["packages_candidate"].where(in_b, merged["packages_base"])
    merged["title"] = merged["title_candidate"].where(in_b, merged["title_base"])
    out = (
        merged[["change", "severity", "packages", "title"]]
        .rename_axis("vulnerability_id")
        .reset_index()
        .sort_values(["change", "severity", "vulnerability_id"])
        .reset_index(drop=True)
    )
    summary = out["change"].value_counts().reindex(COMPARE_ORDER, fill_value=0)
    return out, {k: int(v) for k, v in summary.items()}


def package_inventory(packages: pd.DataFrame) -> pd.DataFrame:
    """Package count per image and ecosystem (deb, apk, python-pkg, node-pkg, ...)."""
    return packages.groupby(["image", "pkg_type"]).size().rename("packages").reset_index()


def license_family(license_name: str | None) -> str:
    if not license_name:
        return "Unknown"
    for family, pattern in _LICENSE_FAMILIES:
        if pattern.search(license_name):
            return family
    return "Other"


def package_license_family(licenses: str | None) -> str:
    """Most restrictive family among a package's (comma-separated) licenses."""
    names = [n for n in licenses.split(", ") if n] if isinstance(licenses, str) else []
    if not names:
        return "Unknown"
    families = {license_family(n) for n in names}
    return next(f for f in LICENSE_FAMILY_ORDER if f in families)


def license_families_by_image(packages: pd.DataFrame) -> pd.DataFrame:
    """Packages per image per license family (a package counts once, under its strictest license)."""
    if packages.empty:
        return pd.DataFrame(columns=["image", "family", "packages"])
    unique = packages.drop_duplicates(["image", "pkg_name", "version"])
    family = pd.Categorical(unique["licenses"].map(package_license_family), categories=LICENSE_FAMILY_ORDER)
    return (
        unique.assign(family=family)
        .groupby(["image", "family"], observed=False)
        .size()
        .rename("packages")
        .reset_index()
    )


def license_summary(packages: pd.DataFrame) -> pd.DataFrame:
    """One row per license string found in the SBOM, with its family and spread."""
    if packages.empty:
        return pd.DataFrame(columns=["license", "family", "packages", "images"])
    exploded = packages.assign(license=packages["licenses"].fillna("").str.split(", ")).explode("license")
    exploded["license"] = exploded["license"].replace("", "(none declared)")
    exploded["family"] = exploded["license"].map(lambda x: "Unknown" if x == "(none declared)" else license_family(x))
    return (
        exploded.groupby(["license", "family"])
        .agg(packages=("pkg_name", "nunique"), images=("image", "nunique"))
        .reset_index()
        .sort_values("packages", ascending=False)
        .reset_index(drop=True)
    )


def copyleft_packages(packages: pd.DataFrame) -> pd.DataFrame:
    """Packages under a strong-copyleft license (worth a legal look before redistributing)."""
    if packages.empty:
        return packages
    families = (
        packages["licenses"].fillna("").str.split(", ").map(lambda names: {license_family(n) for n in names if n})
    )
    flagged = packages[families.map(lambda f: "Strong copyleft" in f)]
    return flagged[["image", "pkg_name", "version", "pkg_type", "licenses"]].drop_duplicates().reset_index(drop=True)


def _split_versions(versions: pd.Series) -> set[str]:
    """Trivy's FixedVersion can hold several comma-separated versions (one per release branch)."""
    return {v.strip() for cell in versions.dropna() for v in str(cell).split(",") if v.strip()}


def _natural_key(version: str) -> tuple:
    """Sort key comparing digit runs numerically: 1.6+deb12u10 > 1.6+deb12u3."""
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in re.findall(r"\d+|[^\d]+", version))
