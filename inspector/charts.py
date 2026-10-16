"""Plotly figures for the dashboard. Colors are fixed per entity, never per rank."""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from inspector.analytics import AGE_ORDER, LICENSE_FAMILY_ORDER
from inspector.parser import SEVERITIES

# Ordinal severity scale (checked for colour-vision-deficiency separation between
# neighbours). Severity is always labelled too, so colour never carries it alone.
SEVERITY_COLORS = {
    "CRITICAL": "#b52f2f",
    "HIGH": "#ec835a",
    "MEDIUM": "#f8c537",
    "LOW": "#2a78d6",
    "UNKNOWN": "#898781",
}
# Categorical slots, assigned in this order and never cycled; a 9th category folds into "Other".
CATEGORICAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
OTHER_COLOR = "#898781"
FIX_COLORS = {"Fix available": "#2a78d6", "No fix yet": "#898781"}
LICENSE_COLORS = dict(zip(LICENSE_FAMILY_ORDER, ["#e34948", "#eda100", "#1baf7a", "#4a3aa7", OTHER_COLOR], strict=True))


def categorical_colors(values: Iterable[str]) -> dict[str, str]:
    """Stable value -> colour map. Pass the *unfiltered* value list so filtering never repaints."""
    ordered = sorted(set(values))
    colors = dict(zip(ordered, CATEGORICAL, strict=False))  # values past the 8th become "Other"
    colors["Other"] = OTHER_COLOR
    return colors


def fold_to_known(series: pd.Series, colors: dict[str, str]) -> pd.Series:
    return series.where(series.isin(colors), "Other")


def _style(fig: go.Figure, height: int = 360, horizontal: bool = False) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=0, r=8, t=8, b=0),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, title_text=""),
        barcornerradius=4,
        bargap=0.35,
        hovermode="closest",
    )
    value_axis = fig.update_xaxes if horizontal else fig.update_yaxes
    category_axis = fig.update_yaxes if horizontal else fig.update_xaxes
    value_axis(showgrid=True, zeroline=False, title_text="")
    category_axis(showgrid=False, title_text="")
    return fig


def severity_by_image(counts: pd.DataFrame, image_order: list[str]) -> go.Figure:
    """Horizontal stacked bars, riskiest image on top. ``counts``: index=image, columns=severities."""
    long = counts.reset_index(names="image").melt("image", var_name="severity", value_name="findings")
    fig = px.bar(
        long[long["findings"] > 0],
        x="findings",
        y="image",
        color="severity",
        orientation="h",
        category_orders={"severity": SEVERITIES, "image": image_order},
        color_discrete_map=SEVERITY_COLORS,
    )
    fig.update_traces(hovertemplate="<b>%{y}</b><br>%{fullData.name}: %{x:,} findings<extra></extra>")
    return _style(fig, height=max(220, 70 + 48 * len(image_order)), horizontal=True)


def fixability_bar(fix: pd.DataFrame) -> go.Figure:
    fig = px.bar(
        fix,
        x="severity",
        y="findings",
        color="fix",
        category_orders={"severity": SEVERITIES, "fix": list(FIX_COLORS)},
        color_discrete_map=FIX_COLORS,
    )
    fig.update_traces(hovertemplate="<b>%{x}</b><br>%{fullData.name}: %{y:,}<extra></extra>")
    return _style(fig, height=320)


def age_bar(age: pd.DataFrame) -> go.Figure:
    fig = px.bar(
        age[age["findings"] > 0],
        x="age",
        y="findings",
        color="severity",
        category_orders={"age": AGE_ORDER, "severity": SEVERITIES},
        color_discrete_map=SEVERITY_COLORS,
    )
    fig.update_traces(hovertemplate="<b>Public for %{x}</b><br>%{fullData.name}: %{y:,}<extra></extra>")
    return _style(fig, height=320)


def top_packages_bar(top: pd.DataFrame) -> go.Figure:
    label = top["pkg_name"] + " (" + top["pkg_type"].fillna("?") + ")"
    severity_cols = [s for s in SEVERITIES if s in top]
    long = top.assign(package=label)[["package", *severity_cols]].melt(
        "package", var_name="severity", value_name="findings"
    )
    fig = px.bar(
        long[long["findings"] > 0],
        x="findings",
        y="package",
        color="severity",
        orientation="h",
        category_orders={"severity": SEVERITIES, "package": list(label)},
        color_discrete_map=SEVERITY_COLORS,
    )
    fig.update_traces(hovertemplate="<b>%{y}</b><br>%{fullData.name}: %{x:,} findings<extra></extra>")
    return _style(fig, height=max(260, 60 + 26 * len(top)), horizontal=True)


def compare_bar(counts: pd.DataFrame, base: str, candidate: str) -> go.Figure:
    """Grouped bars: unique vulnerabilities per severity for two images."""
    long = (
        counts.loc[[base, candidate]]
        .reset_index(names="image")
        .melt("image", var_name="severity", value_name="vulnerabilities")
    )
    fig = px.bar(
        long,
        x="severity",
        y="vulnerabilities",
        color="image",
        barmode="group",
        category_orders={"severity": SEVERITIES, "image": [base, candidate]},
        color_discrete_map={base: CATEGORICAL[0], candidate: CATEGORICAL[1]},
    )
    fig.update_traces(hovertemplate="<b>%{fullData.name}</b><br>%{x}: %{y:,}<extra></extra>")
    return _style(fig, height=300)


def inventory_bar(inventory: pd.DataFrame, colors: dict[str, str], image_order: list[str]) -> go.Figure:
    df = inventory.assign(pkg_type=fold_to_known(inventory["pkg_type"], colors))
    df = df.groupby(["image", "pkg_type"], as_index=False)["packages"].sum()
    fig = px.bar(
        df,
        x="packages",
        y="image",
        color="pkg_type",
        orientation="h",
        category_orders={"pkg_type": [t for t in colors if t in set(df["pkg_type"])], "image": image_order},
        color_discrete_map=colors,
    )
    fig.update_traces(hovertemplate="<b>%{y}</b><br>%{fullData.name}: %{x:,} packages<extra></extra>")
    return _style(fig, height=max(220, 70 + 48 * df["image"].nunique()), horizontal=True)


def license_family_bar(families: pd.DataFrame, image_order: list[str]) -> go.Figure:
    fig = px.bar(
        families[families["packages"] > 0],
        x="packages",
        y="image",
        color="family",
        orientation="h",
        category_orders={"family": LICENSE_FAMILY_ORDER, "image": image_order},
        color_discrete_map=LICENSE_COLORS,
    )
    fig.update_traces(hovertemplate="<b>%{y}</b><br>%{fullData.name}: %{x:,} packages<extra></extra>")
    return _style(fig, height=max(220, 70 + 48 * families["image"].nunique()), horizontal=True)
