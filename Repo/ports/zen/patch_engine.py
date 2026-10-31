#!/usr/bin/env python3
"""Apply tracked Alix patches to the pinned Gecko source without resetting it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PATCHES = Path(__file__).with_name("patches")


def digest(path):
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(mode):
        raise RuntimeError(f"refusing symlink patch input: {path}")
    if not stat.S_ISREG(mode):
        raise RuntimeError(f"refusing non-regular patch input: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def apply_patches(engine, package=PATCHES):
    upstream = json.loads((ROOT / "ports/zen/upstream.json").read_text())
    series = json.loads((package / "series.json").read_text())
    if (series["firefox_revision"] != upstream["firefox_revision"] or
            series["firefox_version"] != upstream["firefox_version"]):
        raise RuntimeError("patch series does not match the pinned Firefox source")
    if (engine / "browser/config/version.txt").read_text().strip() != series["firefox_version"]:
        raise RuntimeError("engine release does not match the patch series")
    repository = Path(subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip())
    try:
        prefix = str(engine.resolve().relative_to(repository.resolve()))
    except ValueError as error:
        raise RuntimeError("patched engine must be inside the Alix checkout") from error
    # Validate every affected file before any mutation. Unrelated source files
    # are deliberately untouched; unexpected edits in an affected file stop us.
    decisions = []
    for entry in series["patches"]:
        patch = package / entry["file"]
        if not valid_digest(entry["sha256"]) or digest(patch) != entry["sha256"]:
            raise RuntimeError(f"tracked patch digest changed: {patch.name}")
        states = []
        for item in entry["files"]:
            # An absent base file explicitly authorizes a tracked addition.
            # Its result must still have a concrete, verified content digest.
            if ((item["before"] is not None and not valid_digest(item["before"])) or
                    not valid_digest(item["after"])):
                raise RuntimeError(f"invalid source digest in patch manifest: {item['path']}")
            path = engine / item["path"]
            actual = digest(path)
            if actual == item["before"]:
                states.append("base")
            elif actual == item["after"]:
                states.append("applied")
            else:
                raise RuntimeError(f"unrecognized edits in {item['path']}; source left untouched")
        if len(set(states)) != 1:
            raise RuntimeError(f"partially applied patch {patch.name}; source left untouched")
        command = ["git", "apply", "--directory=" + prefix]
        if states[0] == "applied":
            command.append("--reverse")
        subprocess.run(command + ["--check", str(patch)], cwd=repository, check=True)
        decisions.append((entry, patch, states[0]))
    for entry, patch, state in decisions:
        if state == "base":
            subprocess.run(["git", "apply", "--directory=" + prefix, str(patch)],
                           cwd=repository, check=True)
        for item in entry["files"]:
            if digest(engine / item["path"]) != item["after"]:
                raise RuntimeError(f"post-apply digest mismatch in {item['path']}")
        print(f"Verified Alix patch: {patch.name} ({'applied' if state == 'base' else 'already present'})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-dir", type=Path, default=ROOT / "ports/zen/upstream/firefox-159.0")
    args = parser.parse_args()
    apply_patches(args.engine_dir)


if __name__ == "__main__":
    main()
