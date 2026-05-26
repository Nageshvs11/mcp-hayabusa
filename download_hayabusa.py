#!/usr/bin/env python3
"""Download the latest Hayabusa release for this platform and extract to ./hayabusa/"""

import json
import os
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

RELEASES_API = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
DEST = Path("hayabusa")


def pick_asset(assets: list[dict]) -> dict | None:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in ("x86_64", "amd64"):
            pattern = "lin-x64-gnu"
        elif machine in ("aarch64", "arm64"):
            pattern = "lin-aarch64-gnu"
        else:
            sys.exit(f"Unsupported Linux architecture: {machine}")
    elif system == "darwin":
        pattern = "mac-aarch64" if machine in ("arm64", "aarch64") else "mac-x64"
    elif system == "windows":
        pattern = "win-x64"
    else:
        sys.exit(f"Unsupported platform: {system}")

    for asset in assets:
        name = asset["name"]
        if pattern in name and (name.endswith(".zip") or name.endswith(".tar.gz")):
            return asset
    return None


def extract(archive: Path, dest: Path) -> None:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest)


def flatten_if_single_subdir(dest: Path) -> None:
    """If the archive dropped everything into one subdirectory, lift it up."""
    children = list(dest.iterdir())
    if len(children) == 1 and children[0].is_dir():
        subdir = children[0]
        for item in subdir.iterdir():
            shutil.move(str(item), dest / item.name)
        subdir.rmdir()


def main() -> None:
    print("Fetching latest Hayabusa release info...")
    req = urllib.request.Request(RELEASES_API, headers={"User-Agent": "mcp-hayabusa"})
    with urllib.request.urlopen(req) as resp:
        release = json.loads(resp.read())

    version = release["tag_name"]
    print(f"Latest release: {version}")

    asset = pick_asset(release["assets"])
    if not asset:
        sys.exit("No suitable release asset found for this platform.")

    print(f"Downloading {asset['name']} ...")
    tmp = Path(f"/tmp/{asset['name']}")
    urllib.request.urlretrieve(asset["browser_download_url"], tmp)

    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir()

    print(f"Extracting to {DEST}/ ...")
    extract(tmp, DEST)
    tmp.unlink()

    flatten_if_single_subdir(DEST)

    # Hayabusa releases name the binary with version+platform (e.g. hayabusa-3.9.0-lin-x64-gnu)
    binary = DEST / "hayabusa"
    if not binary.exists():
        skip_exts = {".zip", ".exe", ".pdf", ".txt", ".md", ".json", ".yaml", ".yml"}
        candidates = [
            f for f in DEST.iterdir()
            if f.is_file()
            and f.name.startswith("hayabusa")
            and Path(f.name).suffix not in skip_exts
        ]
        if not candidates:
            sys.exit(f"Could not find hayabusa binary in {DEST}/")
        candidates[0].rename(binary)

    binary.chmod(binary.stat().st_mode | 0o111)
    print(f"Binary ready: {binary}")

    print("Done.")


if __name__ == "__main__":
    main()
