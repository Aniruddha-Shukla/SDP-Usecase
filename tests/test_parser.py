import io
import json
from pathlib import Path

import pytest

from inspector.parser import (
    SEVERITIES,
    ReportError,
    cvss_score,
    images_frame,
    latest_per_image,
    load_report,
    load_reports_from_dir,
    packages_frame,
    vulnerabilities_frame,
)
from tests.conftest import report, vuln

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data" / "sample"


def test_load_report_from_path_and_file(tmp_path):
    data = report("nginx:1.29", vulns=[vuln("CVE-1", "openssl")])
    path = tmp_path / "nginx.json"
    path.write_text(json.dumps(data))

    assert load_report(path).image == "nginx:1.29"
    assert load_report(io.BytesIO(path.read_bytes()), name="upload.json").source == "upload.json"


@pytest.mark.parametrize(
    "data, message",
    [
        ({"bomFormat": "CycloneDX", "specVersion": "1.6"}, "SBOM"),
        ({"hello": "world"}, "ArtifactName"),
        ({"SchemaVersion": 1, "ArtifactName": "x"}, "SchemaVersion 1"),
        ([1, 2, 3], "JSON object"),
    ],
)
def test_load_report_rejects_non_trivy_json(data, message):
    with pytest.raises(ReportError, match=message):
        load_report(data if isinstance(data, dict) else io.StringIO(json.dumps(data)))


def test_load_reports_from_dir_collects_errors(tmp_path):
    (tmp_path / "good.json").write_text(json.dumps(report("a:1")))
    (tmp_path / "broken.json").write_text("{not json")
    reports, errors = load_reports_from_dir(tmp_path)
    assert [r.image for r in reports] == ["a:1"]
    assert len(errors) == 1 and "broken.json" in errors[0]


def test_vulnerabilities_frame_flattens_and_dedupes(reports):
    df = vulnerabilities_frame(reports)

    risky = df[df["image"] == "app:old"]
    assert len(risky) == 5  # 6 findings in the report, one exact duplicate
    assert set(risky["pkg_class"]) == {"os-pkgs", "lang-pkgs"}
    assert list(df["severity"].cat.categories) == SEVERITIES
    assert df["fixable"].dtype == bool

    openssl = risky.set_index("vulnerability_id").loc["CVE-2026-0001"]
    assert openssl["fixable"] and openssl["fixed_version"] == "3.0.2"
    assert openssl["cvss_score"] == 9.8
    assert openssl["age_days"] == pytest.approx(638)  # 2025-01-01 -> 2026-10-01


def test_unknown_severity_is_normalised():
    data = report("x:1", vulns=[vuln("CVE-1", "p", severity="weird")])
    df = vulnerabilities_frame([load_report(data)])
    assert df.loc[0, "severity"] == "UNKNOWN"


def test_empty_reports_give_typed_empty_frames():
    df = vulnerabilities_frame([load_report(report("clean:1"))])
    assert df.empty and "severity" in df.columns


def test_packages_and_images_frames(reports):
    pkgs = packages_frame(reports)
    assert len(pkgs[pkgs["image"] == "app:old"]) == 5
    assert pkgs.set_index("pkg_name").loc["libgcc", "licenses"] == "LGPL-2.1-only, GPL-3.0-only"

    images = images_frame(reports)
    assert list(images["image"]) == ["app:old", "app:new", "app:distroless"]
    assert images.loc[0, "layers"] == 2 and images.loc[0, "os_family"] == "debian"


def test_latest_per_image_keeps_newest_scan():
    old = load_report(report("a:1", created="2026-01-01T00:00:00Z"))
    new = load_report(report("a:1", created="2026-06-01T00:00:00Z"))
    other = load_report(report("b:1"))
    kept = latest_per_image([old, other, new])
    assert {r.image: r.scanned_at.month for r in kept} == {"a:1": 6, "b:1": 10}


@pytest.mark.parametrize(
    "cvss, expected",
    [
        ({"redhat": {"V3Score": 7.0}, "nvd": {"V3Score": 9.1}}, 9.1),  # nvd preferred
        ({"redhat": {"V3Score": 7.0}}, 7.0),
        ({"nvd": {"V2Score": 5.0}, "ghsa": {"V40Score": 8.7}}, 8.7),  # any v4 beats v2
        ({}, None),
    ],
)
def test_cvss_score_preference(cvss, expected):
    assert cvss_score({"CVSS": cvss}) == expected


@pytest.mark.skipif(not any(SAMPLE_DIR.glob("*.json")), reason="no bundled sample reports")
def test_bundled_sample_reports_parse():
    """The real Trivy output shipped in data/sample must always load cleanly."""
    reports, errors = load_reports_from_dir(SAMPLE_DIR)
    assert not errors
    df = vulnerabilities_frame(reports)
    assert not df.empty
    assert df["vulnerability_id"].notna().all()
    assert not packages_frame(reports).empty
