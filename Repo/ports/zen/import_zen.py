#!/usr/bin/env python3
"""Import the pinned Zen application onto the native Alix Gecko source."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "build/ports/zen"
STATE = ".alix-zen-overlay.json"


def digest(path):
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink overlay input: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError(f"not a regular overlay file: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise RuntimeError(f"invalid overlay path: {value}")
    return value


def verify_active_overlay(engine):
    state = json.loads((engine / STATE).read_text())
    upstream = json.loads((ROOT / "ports/zen/upstream.json").read_text())
    if state["zen_revision"] != upstream["revision"]:
        raise RuntimeError("active Zen overlay has a different source revision")
    for name, record in state["files"].items():
        if digest(engine / relative(name)) != record["after"]:
            raise RuntimeError(f"unrecognized edits in active Zen overlay: {name}")
    print(f"Verified active Zen {state['release']} overlay: {len(state['files'])} changed files")
    return state


def alix_icon_manifest(text):
    # Zen groups its standard icon set under XP_LINUX. Alix uses that same
    # theme without claiming to be Linux in the rest of the application.
    marker = "#if defined(XP_LINUX) || defined(MOZ_WIDGET_ALIX)\n"
    if marker not in text:
        if text.count("#ifdef XP_LINUX\n") != 1:
            raise RuntimeError("unrecognized Zen platform icon manifest")
        text = text.replace("#ifdef XP_LINUX\n", marker, 1)
    # Existing Zen styles still request this legacy name; the pinned icon set
    # supplies the same small chevron as arrow-right.svg.
    if "skin/classic/browser/zen-icons/arrow-right-small.svg" not in text:
        text = text.replace(marker, marker +
            "*  skin/classic/browser/zen-icons/arrow-right-small.svg (../shared/zen-icons/nucleo/arrow-right.svg)\n", 1)
    return text


def refresh_alix_resources(engine, state):
    name = "browser/themes/shared/zen-icons/jar.inc.mn"
    target = engine / name
    original = target.read_text()
    updated = alix_icon_manifest(original)
    if updated == original:
        return state
    if digest(target) != state["files"][name]["after"]:
        raise RuntimeError("concurrent edit in Zen icon manifest")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = OUTPUT / ("zen-alix-resources-" + stamp)
    backup.mkdir()
    shutil.copy2(target, backup / "jar.inc.mn")
    shutil.copy2(engine / STATE, backup / STATE)
    state["files"][name]["after"] = hashlib.sha256(updated.encode()).hexdigest()
    state["alix_resource_revision"] = 1
    pending = target.with_name(target.name + ".alix-pending")
    pending_state = engine / (STATE + ".alix-pending")
    try:
        pending.write_text(updated)
        pending_state.write_text(json.dumps(state, indent=2) + "\n")
        pending.replace(target)
        pending_state.replace(engine / STATE)
    except BaseException:
        shutil.copy2(backup / "jar.inc.mn", target)
        shutil.copy2(backup / STATE, engine / STATE)
        raise
    finally:
        pending.unlink(missing_ok=True)
        pending_state.unlink(missing_ok=True)
    print("Enabled native Alix Zen icon resources; previous manifest preserved at " + str(backup))
    return state


def restore_overlay(engine):
    state = verify_active_overlay(engine)
    backup = Path(state["backup"])
    for name, record in state["files"].items():
        if record["before"] is not None and digest(backup / "before" / name) != record["before"]:
            raise RuntimeError(f"original overlay file missing or changed: {name}")
    for name, record in state["files"].items():
        if record["after"] is not None:
            target = backup / "after" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(engine / name, target)
    restored = []
    try:
        for name, record in state["files"].items():
            target = engine / name
            restored.append(name)
            if record["before"] is None:
                target.unlink(missing_ok=True)
            else:
                shutil.copy2(backup / "before" / name, target)
                os.utime(target, None)
        (engine / STATE).unlink()
    except BaseException:
        for name in reversed(restored):
            target = engine / name
            if state["files"][name]["after"] is None:
                target.unlink(missing_ok=True)
            else:
                shutil.copy2(backup / "after" / name, target)
        raise
    print(f"Restored original source from {backup}")


def import_overlay(engine, source, generated):
    if (engine / STATE).exists():
        return refresh_alix_resources(engine, verify_active_overlay(engine))
    from patch_engine import apply_patches
    from prepare import load_manifest, verify_source

    upstream = load_manifest()
    verify_source(source, upstream)
    apply_patches(engine)
    preflight = json.loads((OUTPUT / "zen-overlay-preflight.json").read_text())
    composition = json.loads((OUTPUT / "zen-overlay-composition-preflight.json").read_text())
    series = json.loads((ROOT / "ports/zen/patches/series.json").read_text())
    if (preflight["zen_revision"] != upstream["revision"] or
            composition["managed_alix_patch_count"] != len(series["patches"]) or
            not composition["all_alix_patches_preserved"]):
        raise RuntimeError("refresh the Zen/native source composition before importing")
    paths = {item["path"] for patch in series["patches"] for item in patch["files"]}
    copies = {}

    def add_copy(target, origin, expected):
        relative(target)
        if digest(origin) != expected:
            raise RuntimeError(f"generated/pinned Zen input changed: {origin}")
        if target in copies and digest(copies[target]) != expected:
            raise RuntimeError(f"conflicting Zen input: {target}")
        copies[target] = origin
        paths.add(target)

    for patch in preflight["patches"]:
        if digest(source / relative(patch["patch"])) != patch["sha256"]:
            raise RuntimeError(f"pinned Zen patch changed: {patch['patch']}")
        for name, expected in patch["current_target_sha256"].items():
            if digest(engine / relative(name)) != expected:
                raise RuntimeError(f"Zen patch target changed since composition: {name}")
            paths.add(name)
    for item in preflight["copies"]:
        if digest(engine / relative(item["target"])) != item["current_target_sha256"]:
            raise RuntimeError(f"Zen copy target changed since composition: {item['target']}")
        add_copy(item["target"], source / relative(item["source"]), item["source_sha256"])

    receipts = {}
    for label, directory in generated.items():
        receipt = json.loads((directory / "receipt.json").read_text())
        if receipt["zen_revision"] != upstream["revision"]:
            raise RuntimeError(f"generated {label} uses a different Zen revision")
        receipts[label] = receipt
    preferences = receipts["preferences"]
    if digest(engine / "browser/app/profile/firefox.js") != preferences["base_profile_sha256"]:
        raise RuntimeError("Firefox preference baseline changed; regenerate Zen preferences")
    for name, record in preferences["outputs"].items():
        add_copy(name, generated["preferences"] / "engine" / name, record["sha256"])
    branding = receipts["branding"]
    for name, record in branding["outputs"].items():
        target = "browser/branding/release/" + name
        if (engine / target).exists():
            raise RuntimeError(f"existing release branding preserved: {target}")
        add_copy(target, generated["branding"] / "engine" / target, record["sha256"])
    for name, record in branding["extra_engine_outputs"].items():
        add_copy(name, generated["branding"] / "engine" / name, record["sha256"])
    resources = receipts["resources"]
    for name, record in resources["locale_overlay_files"].items():
        add_copy(name, generated["resources"] / "engine" / name, record["sha256"])
    for name, expected in resources["dump_outputs_sha256"].items():
        target = "services/settings/dumps/main/" + name
        if digest(engine / target) != resources["dump_engine_base_sha256"][name]:
            raise RuntimeError(f"settings dump baseline changed: {target}")
        add_copy(target, generated["resources"] / "engine" / target, expected)

    versions = {"browser/config/version.txt": upstream["release"],
                "browser/config/version_display.txt": upstream["release"]}
    paths.update(versions)
    before = {name: digest(engine / relative(name)) for name in paths}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = OUTPUT / ("zen-import-" + stamp)
    backup.mkdir()
    # git apply ignores paths outside the current subdirectory when it finds
    # an enclosing repository. Compose outside Alix's checkout.
    with tempfile.TemporaryDirectory(prefix="alix-zen-compose-") as temporary:
        stage = Path(temporary)
        for name in sorted(paths):
            if before[name] is not None:
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(engine / name, target)
        for name, origin in copies.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, target)
        for name, version in versions.items():
            (stage / name).write_text(version)
        for name in composition["patch_order"]:
            patch = next(item for item in preflight["patches"] if item["patch"] == name)
            prior = {target: digest(stage / target) for target in patch["targets"]}
            subprocess.run(["git", "apply", "--whitespace=nowarn", str(source / name)],
                           cwd=stage, check=True)
            if all(digest(stage / target) == value for target, value in prior.items()):
                raise RuntimeError(f"Zen patch produced no source changes: {name}")
        for patch in series["patches"]:
            subprocess.run(["git", "apply", "--reverse", "--check",
                            str(ROOT / "ports/zen/patches" / patch["file"])], cwd=stage, check=True)
        icon_manifest = stage / "browser/themes/shared/zen-icons/jar.inc.mn"
        icon_manifest.write_text(alix_icon_manifest(icon_manifest.read_text()))
        changed = {name: {"before": before[name], "after": digest(stage / name)}
                   for name in sorted(paths) if before[name] != digest(stage / name)}
        overrides = {}
        for patch in series["patches"]:
            for item in patch["files"]:
                name = item["path"]
                if name in changed:
                    overrides[name] = {"native_after": item["after"],
                                       "composed_after": changed[name]["after"]}
        state = {"zen_revision": upstream["revision"], "release": upstream["release"],
                 "firefox_revision": upstream["firefox_revision"],
                 "source_patches": len(composition["patch_order"]),
                 "backup": str(backup), "native_overrides": overrides, "files": changed}
        (backup / "overlay.json").write_text(json.dumps(state, indent=2) + "\n")
        for name, record in changed.items():
            if record["before"] is not None:
                target = backup / "before" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(engine / name, target)
        for name, expected in before.items():
            if digest(engine / name) != expected:
                raise RuntimeError(f"concurrent source edit; import stopped before publication: {name}")
        published = []
        try:
            for name, record in changed.items():
                target = engine / name
                published.append(name)
                if record["after"] is None:
                    target.unlink()
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    pending = target.with_name(target.name + ".alix-import")
                    shutil.copy2(stage / name, pending)
                    os.utime(pending, None)
                    pending.replace(target)
            pending = engine / (STATE + ".tmp")
            pending.write_text(json.dumps(state, indent=2) + "\n")
            pending.replace(engine / STATE)
        except BaseException:
            for name in reversed(published):
                target = engine / name
                if changed[name]["before"] is None:
                    target.unlink(missing_ok=True)
                else:
                    shutil.copy2(backup / "before" / name, target)
            raise
    verify_active_overlay(engine)
    print(f"Imported Zen {upstream['release']}; original source files preserved at {backup}")
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-dir", type=Path, default=ROOT / "ports/zen/upstream/firefox-159.0")
    parser.add_argument("--source", type=Path, default=ROOT / "ports/zen/upstream/desktop")
    parser.add_argument("--restore", action="store_true", help="Restore the verified pre-import source snapshot")
    args = parser.parse_args()
    if args.restore:
        restore_overlay(args.engine_dir.resolve())
        return
    import_overlay(args.engine_dir.resolve(), args.source.resolve(), {
        "preferences": OUTPUT / "zen-release-preferences",
        "branding": OUTPUT / "zen-branding-project",
        "resources": OUTPUT / "zen-release-resources",
    })


if __name__ == "__main__":
    main()
