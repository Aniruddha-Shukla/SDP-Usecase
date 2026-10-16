from __future__ import annotations

from typing import Any

import pytest

from inspector.parser import load_report


def vuln(
    vid: str,
    pkg: str,
    severity: str = "HIGH",
    installed: str = "1.0",
    fixed: str | None = None,
    published: str | None = "2025-01-01T00:00:00Z",
    cvss: dict[str, Any] | None = None,
) -> dict[str, Any]:
    v = {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "PkgIdentifier": {"PURL": f"pkg:deb/debian/{pkg}@{installed}"},
        "InstalledVersion": installed,
        "Status": "fixed" if fixed else "affected",
        "Severity": severity,
        "Title": f"{pkg}: example issue {vid}",
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{vid.lower()}",
        "PublishedDate": published,
        "CVSS": cvss or {},
    }
    if fixed:
        v["FixedVersion"] = fixed
    return v


def report(
    image: str,
    vulns: list[dict] = (),
    packages: list[dict] = (),
    lang_vulns: list[dict] = (),
    created: str = "2026-10-01T00:00:00Z",
) -> dict[str, Any]:
    results = [
        {
            "Target": f"{image} (debian 13.1)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Packages": list(packages),
            "Vulnerabilities": list(vulns),
        }
    ]
    if lang_vulns:
        results.append(
            {
                "Target": "usr/local/lib/python3.12/site-packages",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": list(lang_vulns),
            }
        )
    return {
        "SchemaVersion": 2,
        "CreatedAt": created,
        "ArtifactName": image,
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "debian", "Name": "13.1"},
            "ImageID": f"sha256:{abs(hash(image)):x}",
            "DiffIDs": ["sha256:aaa", "sha256:bbb"],
            "RepoDigests": [f"{image.split(':')[0]}@sha256:abc"],
            "ImageConfig": {"architecture": "amd64", "created": "2026-09-01T00:00:00Z"},
        },
        "Results": results,
    }


@pytest.fixture
def reports():
    """Three images: one risky, one smaller, one clean."""
    risky = report(
        "app:old",
        vulns=[
            vuln("CVE-2026-0001", "openssl", "CRITICAL", fixed="3.0.2", cvss={"nvd": {"V3Score": 9.8}}),
            vuln("CVE-2026-0002", "openssl", "HIGH", fixed="3.0.1, 3.0.10"),
            vuln("CVE-2026-0003", "zlib", "MEDIUM"),
            vuln("CVE-2026-0003", "zlib", "MEDIUM"),  # duplicate finding Trivy can emit
            vuln("CVE-2019-0004", "bash", "LOW", published="2019-01-01T00:00:00Z"),
        ],
        lang_vulns=[vuln("CVE-2026-0005", "pip", "MEDIUM", installed="24.0", fixed="25.3")],
        packages=[
            {"Name": "openssl", "Version": "3.0.0", "Licenses": ["Apache-2.0"]},
            {"Name": "bash", "Version": "5.2", "Licenses": ["GPL-3.0-or-later"]},
            {"Name": "libgcc", "Version": "12", "Licenses": ["LGPL-2.1-only", "GPL-3.0-only"]},
            {"Name": "zlib", "Version": "1.3", "Licenses": ["Zlib"]},
            {"Name": "tzdata", "Version": "2026a"},
        ],
    )
    smaller = report(
        "app:new",
        vulns=[vuln("CVE-2026-0003", "zlib", "MEDIUM"), vuln("CVE-2026-0006", "curl", "HIGH", fixed="8.1")],
        packages=[{"Name": "zlib", "Version": "1.3", "Licenses": ["Zlib"]}],
    )
    clean = report("app:distroless")
    return [load_report(r) for r in (risky, smaller, clean)]
