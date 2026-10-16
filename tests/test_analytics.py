import pytest

from inspector import analytics as an
from inspector.parser import SEVERITIES, images_frame, packages_frame, vulnerabilities_frame


@pytest.fixture
def frames(reports):
    return images_frame(reports), vulnerabilities_frame(reports), packages_frame(reports)


def test_headline(frames):
    images, vulns, _ = frames
    k = an.headline(vulns, images)
    assert k == {
        "images": 3,
        "findings": 7,
        "unique_vulns": 6,
        "critical": 1,
        "high": 2,
        "fixable_pct": pytest.approx(4 / 7 * 100),
    }


def test_severity_counts_has_every_severity(frames):
    _, vulns, _ = frames
    counts = an.severity_counts(vulns)
    assert list(counts.columns) == SEVERITIES
    assert counts.loc["app:new"].tolist() == [0, 1, 1, 0, 0]


def test_image_risk_ranks_and_keeps_clean_images(frames):
    images, vulns, _ = frames
    risk = an.image_risk(vulns, images)
    assert list(risk["image"]) == ["app:old", "app:new", "app:distroless"]
    old = risk.iloc[0]
    assert old["risk_score"] == 10 + 5 + 2 + 2 + 0.5
    assert old["fixable"] == 3 and old["fixable_pct"] == pytest.approx(60)
    clean = risk.iloc[-1]
    assert clean["risk_score"] == 0 and clean["findings"] == 0


def test_filter_findings(frames):
    _, vulns, _ = frames
    only = an.filter_findings(vulns, images=["app:old"], severities=["CRITICAL", "HIGH"], fixable_only=True)
    assert sorted(only["vulnerability_id"]) == ["CVE-2026-0001", "CVE-2026-0002"]
    assert an.filter_findings(vulns, pkg_classes=["lang-pkgs"])["pkg_name"].tolist() == ["pip"]


def test_remediation_plan_groups_by_package_and_picks_highest_fix(frames):
    _, vulns, _ = frames
    plan = an.remediation_plan(vulns)
    top = plan.iloc[0]
    assert (top["image"], top["pkg_name"]) == ("app:old", "openssl")
    assert top["fixes"] == 2 and top["critical"] == 1 and top["high"] == 1
    assert top["upgrade_to"] == "3.0.10"  # natural sort: 3.0.10 > 3.0.2
    assert top["fixed_in"] == "3.0.1 / 3.0.2 / 3.0.10"
    assert "zlib" not in set(plan["pkg_name"])  # no fix available


def test_shared_vulnerabilities(frames):
    _, vulns, _ = frames
    shared = an.shared_vulnerabilities(vulns)
    assert shared["vulnerability_id"].tolist() == ["CVE-2026-0003"]
    assert shared.loc[0, "image_list"] == "app:new, app:old"


def test_age_profile_buckets(frames):
    _, vulns, _ = frames
    age = an.age_profile(vulns).groupby("age", observed=False)["findings"].sum()
    assert age["1-2 years"] == 6 and age["5+ years"] == 1


def test_compare_images(frames):
    _, vulns, _ = frames
    diff, summary = an.compare_images(vulns, "app:old", "app:new")
    assert summary == {"Removed": 4, "Added": 1, "In both": 1}
    assert diff.loc[diff["change"] == "Added", "vulnerability_id"].tolist() == ["CVE-2026-0006"]


@pytest.mark.parametrize(
    "name, family",
    [
        ("GPL-2.0-only", "Strong copyleft"),
        ("AGPL-3.0-or-later", "Strong copyleft"),
        ("LGPL-2.1-only", "Weak copyleft"),
        ("MPL-2.0", "Weak copyleft"),
        ("MIT", "Permissive"),
        ("Apache-2.0", "Permissive"),
        ("verbatim", "Other"),
        (None, "Unknown"),
    ],
)
def test_license_family(name, family):
    assert an.license_family(name) == family


def test_supply_chain_views(frames):
    _, _, pkgs = frames
    families = an.license_families_by_image(pkgs).set_index(["image", "family"])["packages"]
    # libgcc is LGPL + GPL: counted once, under the stricter family.
    assert families[("app:old", "Strong copyleft")] == 2
    assert families[("app:old", "Unknown")] == 1

    copyleft = an.copyleft_packages(pkgs)
    assert sorted(copyleft["pkg_name"]) == ["bash", "libgcc"]

    inventory = an.package_inventory(pkgs).set_index("image")["packages"]
    assert inventory["app:old"] == 5
