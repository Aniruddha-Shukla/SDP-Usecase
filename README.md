# Container Vulnerability & Software Supply Chain Inspector

Scan public (or your own) container images with [Trivy](https://github.com/aquasecurity/trivy), turn the JSON
reports into pandas DataFrames, and explore them in a Streamlit dashboard: severity breakdowns, a ranked upgrade
plan, image-vs-image comparison, and an SBOM / license view. The same Trivy scan also runs in GitHub Actions as a
quality gate on this project's own image.

You don't need a cloud account, API keys or synthetic data. Trivy produces real vulnerability data in seconds.

```
.
├── app.py                      Streamlit dashboard
├── inspector/
│   ├── scan.py                 python -m inspector.scan    -> runs Trivy, writes data/scans/*.json
│   ├── parser.py               Trivy JSON  -> images / vulnerabilities / packages DataFrames
│   ├── analytics.py            pandas groupings: risk score, remediation plan, compare, licenses …
│   ├── charts.py               Plotly figures (fixed, colour-blind-checked palettes)
│   └── report.py               python -m inspector.report  -> Markdown summary (CI job summary)
├── data/
│   ├── sample/                 real Trivy reports, committed so the dashboard works out of the box
│   ├── scans/                  your scans (git-ignored)
│   └── sbom/                   CycloneDX SBOMs (git-ignored)
├── images.txt                  images to scan locally and in the weekly workflow
├── tests/                      pytest suite (fixtures + the real sample reports)
├── Dockerfile                  the dashboard image (CI scans this)
├── .devcontainer/              VS Code Dev Container (Python 3.12 + checksum-verified Trivy + Docker)
├── .github/
│   ├── workflows/ci.yml        lint, test, build, Trivy scan -> SARIF + SBOM + gate
│   ├── workflows/scan-images.yml  weekly scan of images.txt -> "trivy-scans" artifact
│   └── dependabot.yml          keeps pinned actions / deps / base image current (7-day cooldown)
├── .trivyignore                accepted risks for the CI gate
└── Makefile                    shortcuts: make scan, make dashboard, make test …
```

## Quick start

### Option A: Dev Container (VS Code + Docker Desktop / WSL2)

1. Open the folder in VS Code and choose **Dev Containers: Reopen in Container**.
2. `post-create.sh` installs the Python deps and Trivy (checked against pinned SHA-256 sums).
3. Run:

```bash
make scan && make dashboard
```

Port 8501 is forwarded and opens in your browser.

### Option B: Local Python

Needs Python 3.11+, plus either the `trivy` CLI or Docker. The scanner falls back to the digest-pinned
`aquasec/trivy` image when `trivy` isn't installed.

```bash
python -m venv .venv && source .venv/bin/activate
```

```bash
pip install -r requirements-dev.txt
```

```bash
python -m inspector.scan --sbom
```

```bash
streamlit run app.py
```

If you haven't scanned anything yet, the dashboard falls back to **Bundled sample** (`data/sample`), real reports for
`python:3.11-slim`, `python:3.12-alpine` and `nginx:latest`.

## Scanning

```bash
python -m inspector.scan                        # everything in images.txt
python -m inspector.scan redis:8 postgres:17    # specific images
python -m inspector.scan --sbom                 # also write CycloneDX SBOMs to data/sbom
python -m inspector.scan myapp:dev --docker-socket   # an image that only exists in your local Docker
```

Reports are ordinary `trivy image --format json --list-all-pkgs` output, so you can also produce them by hand or
upload them in the dashboard. `--list-all-pkgs` matters: without it the **Supply chain** tab has no package inventory.

## Dashboard

| Tab | What it answers |
|---|---|
| **Overview** | Which image is riskiest? Severity mix per image, how much is fixable today, how old the vulnerabilities are |
| **Fix first** | Which package upgrades remove the most risk? (exportable CSV) |
| **Packages** | Which packages contribute the most risk across images? |
| **Vulnerabilities** | Searchable list of every finding with advisory links; vulnerabilities shared across images |
| **Compare images** | What changes if I switch base image? (removed / added / unchanged vulnerabilities, risk delta) |
| **Supply chain** | Package inventory by ecosystem, license families, strong-copyleft packages, SBOM downloads |

**Risk score**: the sum of severity weights over the unique findings in an image (Critical 10, High 5, Medium 2,
Low 0.5, Unknown 0.1). It's deliberately simple and explainable. Change `SEVERITY_WEIGHTS` in
`inspector/analytics.py` to tune it.

**Upgrade to**: the highest fixed version Trivy reported for a package. Versions are compared with a natural sort,
which handles typical deb/apk/semver strings but isn't a full per-ecosystem comparison. The full list is in
*All fixed versions*.

## CI/CD (the "Key DevOps Integration")

**`ci.yml`** runs on every push and PR:

1. **Lint & test**: `ruff check` and `pytest`.
2. **Repo scan**: `trivy fs` over the repository for vulnerable dependencies (`requirements.txt`), committed
   secrets, and Dockerfile misconfigurations, uploaded as SARIF to **Security → Code scanning**.
3. **Build & scan image**: builds the dashboard image, then:
   - writes a JSON report (with full package list) and a **CycloneDX SBOM** as the `trivy-image-report` artifact;
   - uploads SARIF to the Security tab;
   - writes a Markdown summary (risk table plus top upgrades) to the run page via `inspector.report`;
   - **gates** the build: the job fails on any CRITICAL vulnerability that has a fix. Add reviewed exceptions to
     `.trivyignore`.

**`scan-images.yml`** runs weekly and on demand. It scans every image in `images.txt` in parallel and publishes one
`trivy-scans` artifact. Unzip it into `data/` and the dashboard picks it up.

### Supply-chain hygiene in this repo

In March 2026 attackers used stolen credentials to publish a malicious Trivy v0.69.4 and force-push most
`aquasecurity/trivy-action` tags to credential-stealing code ([CVE-2026-33634][cve]). This project is built so that
kind of attack can't silently reach it:

- **Every GitHub Action is pinned to a full commit SHA** (with the version in a comment). Tags can be moved; SHAs
  can't.
- **Trivy itself is pinned**: `v0.75.0` in the workflows, the `aquasec/trivy` image **by digest** in
  `inspector/scan.py`, and the dev-container download is verified against **SHA-256 sums written into**
  `post-create.sh`, not taken from the release's own checksum file.
- **Python deps are exact-pinned**, and the Docker base image is digest-pinned.
- **Dependabot** proposes updates for all of the above, with a **7-day cooldown** so brand-new (possibly hijacked)
  releases aren't picked up immediately.
- Workflows default to `contents: read`, and checkout doesn't persist credentials. Matrix values reach shell steps
  only through `env:`, never by inline interpolation.

**Upgrading Trivy** means changing it in three places: `TRIVY_VERSION` in both workflows, `TRIVY_VERSION` and
`TRIVY_IMAGE` (digest) in `inspector/scan.py`, and `TRIVY_VERSION` plus the two SHA-256 sums in
`.devcontainer/devcontainer.json` / `post-create.sh`. Take the digest from `docker buildx imagetools inspect
aquasec/trivy:<ver>` and the sums from the release's asset list on GitHub.

[cve]: https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know

## Development

```bash
make test        # pytest
make lint        # ruff check + format check
make report      # Markdown summary of data/scans in the terminal
make docker-run  # build and run the dashboard container with your scans mounted
make scan-self   # scan the dashboard image the way CI does
```

## Things you'll notice in real data

- Full Debian-based images (`node:18`, `python:3.x`) report many **"no fix yet"** findings. Debian often marks
  low-impact issues as *will not fix*/*deferred*. That's why the *Only fixable* toggle and *Fix first* tab exist.
- `linux-libc-dev` (kernel headers) often dominates full images with thousands of kernel CVEs that don't apply
  inside a container. It's a good candidate for `.trivyignore` or for a slimmer base.
- End-of-life images (e.g. `node:18`) are dramatically worse than current slim/alpine ones. Use **Compare images**
  to put a number on it.

## Ideas for next steps

- Commit weekly scans (remove `data/scans/*.json` from `.gitignore`) and add a trend-over-time chart.
- Add EPSS / CISA KEV enrichment to rank "actually exploited" vulnerabilities first.
- Feed the CycloneDX SBOMs into Dependency-Track, or attest them with `cosign attest`.
