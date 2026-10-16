#!/usr/bin/env bash
# Runs once when the dev container is created: Python deps + a verified Trivy binary.
set -euo pipefail

pip install --user --no-cache-dir -r requirements-dev.txt

# The named cache volume is created root-owned; hand it to the dev user.
if [[ -n "${TRIVY_CACHE_DIR:-}" ]]; then
  sudo mkdir -p "$TRIVY_CACHE_DIR"
  sudo chown "$(id -u):$(id -g)" "$TRIVY_CACHE_DIR"
fi

TRIVY_VERSION="${TRIVY_VERSION:-0.75.0}"

# SHA-256 of the official release tarballs, pinned here rather than read from the
# release's own checksums file, so a tampered release cannot vouch for itself
# (see the March 2026 Trivy compromise, CVE-2026-33634). Update both together.
declare -A TRIVY_SHA256=(
  [0.75.0-64bit]=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
  [0.75.0-ARM64]=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
)

case "$(dpkg --print-architecture)" in
  amd64) arch=64bit ;;
  arm64) arch=ARM64 ;;
  *) echo "Unsupported architecture for Trivy install: $(dpkg --print-architecture)" >&2; exit 1 ;;
esac

expected="${TRIVY_SHA256[${TRIVY_VERSION}-${arch}]:-}"
if [[ -z "$expected" ]]; then
  echo "No pinned checksum for Trivy ${TRIVY_VERSION} (${arch}); add it to .devcontainer/post-create.sh" >&2
  exit 1
fi

tarball="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$tarball" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tarball}"
echo "${expected}  $tmp/$tarball" | sha256sum -c -
tar -xzf "$tmp/$tarball" -C "$tmp" trivy
sudo install -m 0755 "$tmp/trivy" /usr/local/bin/trivy

trivy --version
echo "Dev container ready. Try: python -m inspector.scan && streamlit run app.py"
