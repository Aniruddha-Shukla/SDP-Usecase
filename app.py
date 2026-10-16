"""Container Vulnerability & Software Supply Chain Inspector -- Streamlit dashboard.

streamlit run app.py
"""

from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
import streamlit as st

from inspector import analytics as an
from inspector import charts
from inspector.parser import (
    SEVERITIES,
    ReportError,
    images_frame,
    latest_per_image,
    load_report,
    load_reports_from_dir,
    packages_frame,
    vulnerabilities_frame,
)

ROOT = Path(__file__).resolve().parent
SCAN_DIR = ROOT / "data" / "scans"
SAMPLE_DIR = ROOT / "data" / "sample"
SBOM_DIR = ROOT / "data" / "sbom"

SOURCES = {
    "Latest scans": SCAN_DIR,
    "Bundled sample": SAMPLE_DIR,
    "Upload": None,
}
CLASS_LABELS = {"os-pkgs": "OS packages", "lang-pkgs": "Language packages"}

st.set_page_config(page_title="Container Vulnerability Inspector", page_icon="🛡️", layout="wide")


# --------------------------------------------------------------------------- data

Frames = tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, list[str]]


def _frames(reports, errors, latest_only: bool) -> Frames:
    if latest_only:
        reports = latest_per_image(reports)
    return images_frame(reports), vulnerabilities_frame(reports), packages_frame(reports), errors


def _fingerprint(directory: Path) -> tuple:
    """Changes whenever a report is added, removed or rewritten, so the cache refreshes."""
    return tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in sorted(directory.glob("*.json")))


@st.cache_data(show_spinner="Parsing Trivy reports…")
def load_folder(directory: str, fingerprint: tuple, latest_only: bool) -> Frames:
    reports, errors = load_reports_from_dir(directory)
    return _frames(reports, errors, latest_only)


@st.cache_data(show_spinner="Parsing uploaded reports…")
def load_uploads(files: tuple[tuple[str, bytes], ...], latest_only: bool) -> Frames:
    reports, errors = [], []
    for name, raw in files:
        try:
            reports.append(load_report(io.BytesIO(raw), name=name))
        except ReportError as exc:
            errors.append(str(exc))
    return _frames(reports, errors, latest_only)


def has_reports(directory: Path) -> bool:
    return directory.is_dir() and any(directory.glob("*.json"))


# --------------------------------------------------------------------------- sidebar

with st.sidebar:
    st.header("Data source")
    default_source = "Latest scans" if has_reports(SCAN_DIR) else "Bundled sample"
    source = st.radio(
        "Reports",
        list(SOURCES),
        index=list(SOURCES).index(default_source),
        label_visibility="collapsed",
        help="Latest scans = data/scans (written by `python -m inspector.scan`); "
        "Bundled sample = data/sample; Upload = any Trivy JSON report.",
    )
    latest_only = st.toggle(
        "Latest scan per image only",
        value=True,
        help="If an image was scanned more than once, keep only its newest report.",
    )

    if source == "Upload":
        uploads = st.file_uploader("Trivy JSON reports", type="json", accept_multiple_files=True)
        images, vulns, packages, errors = load_uploads(
            tuple((f.name, f.getvalue()) for f in uploads or []), latest_only
        )
    else:
        directory = SOURCES[source]
        images, vulns, packages, errors = load_folder(str(directory), _fingerprint(directory), latest_only)

    st.divider()
    with st.expander("Add more scans"):
        st.markdown("Scan the images in `images.txt` (or any you name) into `data/scans`:")
        st.code("python -m inspector.scan\npython -m inspector.scan redis:8 postgres:17 --sbom", language="bash")
        st.markdown("Or run Trivy yourself. `--list-all-pkgs` fills the Supply chain tab:")
        st.code("trivy image --format json --list-all-pkgs \\\n  -o data/scans/redis_8.json redis:8", language="bash")

for message in errors:
    st.warning(message, icon="⚠️")

st.title("🛡️ Container Vulnerability Inspector")

if images.empty:
    st.info(
        "No Trivy reports loaded yet. Run `python -m inspector.scan` to scan the images in "
        "`images.txt`, pick **Bundled sample** in the sidebar, or upload a report.",
        icon="ℹ️",
    )
    st.stop()

scanned = images["scanned_at"].dropna()
if not scanned.empty:
    first, last = scanned.min().strftime("%Y-%m-%d %H:%M"), scanned.max().strftime("%Y-%m-%d %H:%M")
    when = first if first == last else f"{first} → {last}"
    st.caption(f"{len(images)} image(s) · scanned {when} UTC · source: {source}")


# --------------------------------------------------------------------------- filters

all_images = sorted(images["image"])
all_classes = sorted(vulns["pkg_class"].dropna().unique()) or list(CLASS_LABELS)

sel_images = st.multiselect("Images", all_images, default=all_images)
f1, f2, f3 = st.columns([5, 4, 2], vertical_alignment="bottom")
sel_sev = f1.pills("Severity", SEVERITIES, selection_mode="multi", default=SEVERITIES)
sel_classes = f2.pills(
    "Package class",
    all_classes,
    selection_mode="multi",
    default=all_classes,
    format_func=lambda c: CLASS_LABELS.get(c, c),
)
fixable_only = f3.toggle("Only fixable", help="Hide findings that have no fixed version yet.")

# Everything except the image filter: the Compare tab picks its own two images.
scoped = an.filter_findings(vulns, severities=sel_sev, pkg_classes=sel_classes, fixable_only=fixable_only)
view = scoped[scoped["image"].isin(sel_images)]
view_images = images[images["image"].isin(sel_images)]
view_packages = packages[packages["image"].isin(sel_images)]

if view_images.empty:
    st.info("Select at least one image.")
    st.stop()


# --------------------------------------------------------------------------- headline

k = an.headline(view, view_images)
cols = st.columns(6)
cols[0].metric("Images", k["images"], border=True)
cols[1].metric("Findings", f"{k['findings']:,}", border=True, help="Vulnerability × package × location")
cols[2].metric("Unique vulnerabilities", f"{k['unique_vulns']:,}", border=True)
cols[3].metric("Critical", f"{k['critical']:,}", border=True)
cols[4].metric("High", f"{k['high']:,}", border=True)
cols[5].metric(
    "Fix available",
    f"{k['fixable_pct']:.0f}%",
    border=True,
    help="Share of findings with a fixed version published upstream.",
)

tab_overview, tab_fix, tab_pkgs, tab_vulns, tab_compare, tab_supply = st.tabs(
    ["Overview", "Fix first", "Packages", "Vulnerabilities", "Compare images", "Supply chain"]
)


# --------------------------------------------------------------------------- overview

risk = an.image_risk(view, view_images)
image_order = list(risk["image"])  # riskiest first, shared by every per-image chart

with tab_overview:
    left, right = st.columns([3, 2], gap="large")
    with left:
        st.subheader("Findings by severity")
        if view.empty:
            st.success("No findings match the current filters.", icon="✅")
        else:
            st.plotly_chart(charts.severity_by_image(an.severity_counts(view), image_order))
    with right:
        st.subheader("Risk ranking")
        st.caption(
            "Risk score = Σ severity weights over unique findings "
            f"({', '.join(f'{s.title()} {w:g}' for s, w in an.SEVERITY_WEIGHTS.items())})."
        )
        st.dataframe(
            risk[["image", "os", "risk_score", "critical", "high", "medium", "fixable_pct"]],
            hide_index=True,
            column_config={
                "image": "Image",
                "os": "OS",
                "risk_score": st.column_config.ProgressColumn(
                    "Risk score", format="%.0f", min_value=0, max_value=float(max(risk["risk_score"].max(), 1))
                ),
                "critical": "Crit.",
                "high": "High",
                "medium": "Med.",
                "fixable_pct": st.column_config.NumberColumn("Fixable", format="%.0f%%"),
            },
        )

    if not view.empty:
        left, right = st.columns(2, gap="large")
        with left:
            st.subheader("Can it be fixed today?")
            st.plotly_chart(charts.fixability_bar(an.fixability(view)))
        with right:
            st.subheader("How long have these been public?")
            st.plotly_chart(charts.age_bar(an.age_profile(view)))


# --------------------------------------------------------------------------- fix first

with tab_fix:
    st.subheader("Upgrades that remove the most risk")
    st.caption(
        "Each row is one package upgrade inside one image. *Upgrade to* is the highest fixed version "
        "Trivy reported, which clears every vulnerability listed; *All fixed versions* shows the rest."
    )
    plan = an.remediation_plan(view)
    if plan.empty:
        st.info("No fixable findings under the current filters.")
    else:
        st.dataframe(
            plan,
            hide_index=True,
            column_config={
                "image": "Image",
                "pkg_name": "Package",
                "pkg_type": "Type",
                "installed_version": "Installed",
                "upgrade_to": "Upgrade to",
                "fixed_in": "All fixed versions",
                "fixes": st.column_config.NumberColumn("Fixes", help="Unique vulnerabilities removed"),
                "worst_severity": "Worst",
                "critical": "Crit.",
                "high": "High",
                "risk_reduction": st.column_config.NumberColumn("Risk removed", format="%.1f"),
                "vulnerability_ids": st.column_config.TextColumn("Vulnerabilities", width="large"),
            },
        )
        st.download_button("Download plan (CSV)", plan.to_csv(index=False), "remediation_plan.csv", "text/csv")

    unfixable = view[~view["fixable"] & view["severity"].isin(["CRITICAL", "HIGH"])]
    if not unfixable.empty:
        st.warning(
            f"{unfixable['vulnerability_id'].nunique():,} critical/high vulnerabilities have **no fix yet**. "
            "Upgrading packages won't clear them; a different base image might (see *Compare images*).",
            icon="⚠️",
        )


# --------------------------------------------------------------------------- packages

with tab_pkgs:
    top = an.top_packages(view, n=15)
    if top.empty:
        st.info("No findings under the current filters.")
    else:
        st.subheader("Most vulnerable packages")
        st.caption("Ranked by summed severity weight across the selected images.")
        st.plotly_chart(charts.top_packages_bar(top))
        st.dataframe(
            top[["pkg_name", "pkg_type", "risk_score", "findings", "unique_vulns", "images", "fixable"]],
            hide_index=True,
            column_config={
                "pkg_name": "Package",
                "pkg_type": "Type",
                "risk_score": st.column_config.NumberColumn("Risk score", format="%.1f"),
                "findings": "Findings",
                "unique_vulns": "Unique vulns",
                "images": "Images affected",
                "fixable": "Fixable findings",
            },
        )


# --------------------------------------------------------------------------- vulnerabilities

with tab_vulns:
    query = st.text_input("Search", placeholder="CVE ID, package or keyword", label_visibility="collapsed")
    table = view.sort_values(["severity", "cvss_score"], ascending=[True, False])
    if query:
        q = query.lower()
        hay = (
            table["vulnerability_id"].fillna("") + " " + table["pkg_name"].fillna("") + " " + table["title"].fillna("")
        ).str.lower()
        table = table[hay.str.contains(q, regex=False)]
    st.caption(f"{len(table):,} findings")
    st.dataframe(
        table[
            [
                "severity",
                "vulnerability_id",
                "pkg_name",
                "installed_version",
                "fixed_version",
                "status",
                "cvss_score",
                "image",
                "title",
                "published_date",
                "primary_url",
            ]
        ],
        hide_index=True,
        height=420,
        column_config={
            "severity": "Severity",
            "vulnerability_id": "ID",
            "pkg_name": "Package",
            "installed_version": "Installed",
            "fixed_version": "Fixed in",
            "status": "Status",
            "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "image": "Image",
            "title": st.column_config.TextColumn("Title", width="large"),
            "published_date": st.column_config.DateColumn("Published"),
            "primary_url": st.column_config.LinkColumn("Advisory", display_text="open ↗"),
        },
    )
    st.download_button("Download findings (CSV)", table.to_csv(index=False), "findings.csv", "text/csv")

    shared = an.shared_vulnerabilities(view)
    if not shared.empty:
        st.subheader("Shared across images")
        st.caption("Usually inherited from a common base layer: fixing the base fixes them everywhere.")
        st.dataframe(
            shared.drop(columns=["fixable"]),
            hide_index=True,
            column_config={
                "vulnerability_id": "ID",
                "severity": "Severity",
                "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
                "images": "Images",
                "image_list": "Found in",
                "packages": "Packages",
                "title": st.column_config.TextColumn("Title", width="large"),
                "primary_url": st.column_config.LinkColumn("Advisory", display_text="open ↗"),
            },
        )


# --------------------------------------------------------------------------- compare

with tab_compare:
    if len(all_images) < 2:
        st.info("Load at least two images to compare them.")
    else:
        st.caption(
            "What changes if you switch from one image to another, e.g. a slimmer or newer base. "
            "Uses the severity, package and fixable filters, ignoring the image filter."
        )
        c1, c2 = st.columns(2)
        base = c1.selectbox("Current image", all_images, index=0)
        candidate = c2.selectbox("Candidate image", [i for i in all_images if i != base], index=0)

        diff, summary = an.compare_images(scoped, base, candidate)
        base_risk = an.image_risk(scoped, images).set_index("image")["risk_score"]
        m = st.columns(4)
        m[0].metric("Removed", summary["Removed"], border=True)
        m[1].metric("Added", summary["Added"], border=True)
        m[2].metric("In both", summary["In both"], border=True)
        m[3].metric(
            "Risk score",
            f"{base_risk.get(candidate, 0):.0f}",
            delta=f"{base_risk.get(candidate, 0) - base_risk.get(base, 0):+.0f} vs current",
            delta_color="inverse",
            border=True,
        )

        unique_counts = an.severity_counts(
            scoped[scoped["image"].isin([base, candidate])].drop_duplicates(["image", "vulnerability_id"])
        ).reindex([base, candidate], fill_value=0)
        st.plotly_chart(charts.compare_bar(unique_counts, base, candidate))
        st.dataframe(
            diff,
            hide_index=True,
            column_config={
                "vulnerability_id": "ID",
                "change": "Change",
                "severity": "Severity",
                "packages": "Packages",
                "title": st.column_config.TextColumn("Title", width="large"),
            },
        )


# --------------------------------------------------------------------------- supply chain

with tab_supply:
    if view_packages.empty:
        st.info(
            "No package inventory in these reports. Re-scan with `--list-all-pkgs` "
            "(`python -m inspector.scan` does this by default) to see the SBOM view."
        )
    else:
        families = an.license_families_by_image(view_packages)
        copyleft = an.copyleft_packages(view_packages)
        unique_pkgs = view_packages.drop_duplicates(["image", "pkg_name", "version"])
        no_license = unique_pkgs["licenses"].isna().sum()

        m = st.columns(4)
        m[0].metric("Packages", f"{len(unique_pkgs):,}", border=True, help="Unique name+version per image")
        m[1].metric("Ecosystems", view_packages["pkg_type"].nunique(), border=True)
        m[2].metric(
            "Strong copyleft",
            f"{copyleft['pkg_name'].nunique():,}",
            border=True,
            help="GPL/AGPL/SSPL packages; check obligations before redistributing the image.",
        )
        m[3].metric("No license declared", f"{no_license:,}", border=True)

        left, right = st.columns(2, gap="large")
        with left:
            st.subheader("Package inventory")
            type_colors = charts.categorical_colors(packages["pkg_type"].dropna())
            st.plotly_chart(charts.inventory_bar(an.package_inventory(view_packages), type_colors, image_order))
        with right:
            st.subheader("License families")
            st.plotly_chart(charts.license_family_bar(families, image_order))

        with st.expander("Licenses", expanded=False):
            st.dataframe(an.license_summary(view_packages), hide_index=True)
        if not copyleft.empty:
            with st.expander(f"Strong-copyleft packages ({copyleft['pkg_name'].nunique():,})"):
                st.dataframe(copyleft, hide_index=True)
        with st.expander("Full package inventory (SBOM)"):
            st.dataframe(view_packages.drop(columns=["layer_diff_id"]), hide_index=True, height=360)
            st.download_button(
                "Download inventory (CSV)", view_packages.to_csv(index=False), "package_inventory.csv", "text/csv"
            )

    sboms = sorted(SBOM_DIR.glob("*.cdx.json")) if SBOM_DIR.is_dir() else []
    if sboms:
        st.subheader("CycloneDX SBOMs")
        for path in sboms:
            st.download_button(f"⬇ {path.name}", path.read_bytes(), path.name, "application/json", key=path.name)
