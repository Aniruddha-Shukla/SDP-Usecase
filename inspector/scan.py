"""Run Trivy against container images and save the JSON reports the dashboard reads.

Uses a local ``trivy`` binary when one is on PATH, otherwise the pinned
``aquasec/trivy`` container image through Docker.

    python -m inspector.scan                       # every image listed in images.txt
    python -m inspector.scan nginx:1.29 node:18    # just these images
    python -m inspector.scan --sbom                # also write CycloneDX SBOMs
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TRIVY_VERSION = "0.75.0"
# Pinned by digest, not just tag: aquasec/trivy tags were overwritten with
# malware during the March 2026 supply-chain compromise (CVE-2026-33634).
TRIVY_IMAGE = f"aquasec/trivy:{TRIVY_VERSION}@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa"

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGES_FILE = ROOT / "images.txt"
DEFAULT_SCAN_DIR = ROOT / "data" / "scans"
DEFAULT_SBOM_DIR = ROOT / "data" / "sbom"
CACHE_DIR = Path(os.environ.get("TRIVY_CACHE_DIR", Path.home() / ".cache" / "trivy"))
DOCKER_SOCKET = Path("/var/run/docker.sock")


def slugify(image: str) -> str:
    """Turn an image reference into a safe file stem: ``nginx:1.29`` -> ``nginx_1.29``."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", image).strip("_")


def read_images_file(path: Path) -> list[str]:
    """One image per line; blank lines and ``#`` comments are ignored."""
    images = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            images.append(line)
    return images


def trivy_base_command(mount_dirs: list[Path], use_docker_socket: bool) -> list[str]:
    """Command prefix that runs ``trivy``, natively or in Docker with ``mount_dirs`` shared."""
    if shutil.which("trivy"):
        return ["trivy"]
    if not shutil.which("docker"):
        sys.exit("Neither `trivy` nor `docker` is on PATH. Install one of them (see README).")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{CACHE_DIR}:/cache"]
    if hasattr(os, "getuid"):
        # Write reports as the calling user rather than root.
        cmd += ["--user", f"{os.getuid()}:{os.getgid()}"]
    for d in mount_dirs:
        cmd += ["-v", f"{d}:{d}"]
    if use_docker_socket:
        # Only needed for images that exist solely in the local daemon (e.g. one
        # you just built). Grants the container control of Docker, so it is opt-in.
        cmd += ["-v", f"{DOCKER_SOCKET}:{DOCKER_SOCKET}"]
        if hasattr(os, "getuid"):
            # The socket is root:docker on Linux hosts but root:root inside the
            # Docker Desktop VM (macOS/Windows), so join whichever group owns it.
            groups = {"0"}
            if DOCKER_SOCKET.exists():
                groups.add(str(DOCKER_SOCKET.stat().st_gid))
            for gid in sorted(groups):
                cmd += ["--group-add", gid]
    return [*cmd, TRIVY_IMAGE, "--cache-dir", "/cache"]


def scan_image(base: list[str], image: str, scan_dir: Path, sbom_dir: Path | None) -> Path:
    """Scan one image; returns the JSON report path. Raises CalledProcessError on failure."""
    report = scan_dir / f"{slugify(image)}.json"
    subprocess.run(
        [
            *base,
            "image",
            "--quiet",
            "--scanners",
            "vuln",
            "--list-all-pkgs",  # keeps the full package inventory for the supply-chain view
            "--format",
            "json",
            "--output",
            str(report),
            image,
        ],
        check=True,
    )
    if sbom_dir is not None:
        subprocess.run(
            [
                *base,
                "image",
                "--quiet",
                "--format",
                "cyclonedx",
                "--output",
                str(sbom_dir / f"{slugify(image)}.cdx.json"),
                image,
            ],
            check=True,
        )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("images", nargs="*", help="image references; defaults to the images file")
    parser.add_argument("--images-file", type=Path, default=DEFAULT_IMAGES_FILE)
    parser.add_argument("--out", type=Path, default=DEFAULT_SCAN_DIR, help="where JSON reports go")
    parser.add_argument("--sbom", action="store_true", help="also write CycloneDX SBOMs")
    parser.add_argument("--sbom-out", type=Path, default=DEFAULT_SBOM_DIR)
    parser.add_argument(
        "--docker-socket",
        action="store_true",
        help="when running Trivy in Docker, mount the Docker socket so locally built images can be scanned",
    )
    args = parser.parse_args(argv)

    images = args.images or read_images_file(args.images_file)
    if not images:
        parser.error(f"no images given and {args.images_file} lists none")

    scan_dir = args.out.resolve()
    scan_dir.mkdir(parents=True, exist_ok=True)
    sbom_dir = args.sbom_out.resolve() if args.sbom else None
    if sbom_dir is not None:
        sbom_dir.mkdir(parents=True, exist_ok=True)

    base = trivy_base_command([d for d in (scan_dir, sbom_dir) if d], args.docker_socket)

    failed = []
    for i, image in enumerate(images, 1):
        print(f"[{i}/{len(images)}] scanning {image} ...", flush=True)
        try:
            report = scan_image(base, image, scan_dir, sbom_dir)
        except subprocess.CalledProcessError as exc:
            print(f"    failed (exit {exc.returncode})", file=sys.stderr)
            failed.append(image)
        else:
            print(f"    wrote {report.relative_to(ROOT) if report.is_relative_to(ROOT) else report}")

    if failed:
        print(f"\n{len(failed)} image(s) failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
