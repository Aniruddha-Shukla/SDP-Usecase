import json

from inspector import report, scan
from tests.conftest import report as make_report
from tests.conftest import vuln


def test_slugify():
    assert scan.slugify("nginx:1.29") == "nginx_1.29"
    assert scan.slugify("ghcr.io/org/app@sha256:abc") == "ghcr.io_org_app_sha256_abc"


def test_read_images_file(tmp_path):
    f = tmp_path / "images.txt"
    f.write_text("# comment\npython:3.12-slim\n\n  nginx:latest   # trailing\n")
    assert scan.read_images_file(f) == ["python:3.12-slim", "nginx:latest"]


def test_report_cli_renders_markdown(tmp_path, capsys):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(make_report("app:1", vulns=[vuln("CVE-1", "openssl", "CRITICAL", fixed="3.1")])))

    assert report.main([str(path)]) == 0
    out = capsys.readouterr().out
    assert "## 🛡️ Container vulnerability summary" in out
    assert "| `app:1` |" in out
    assert "| `app:1` | openssl | 1.0 | 3.1 | 1 | CRITICAL |" in out


def test_report_cli_fails_without_reports(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert report.main([str(bad)]) == 1
