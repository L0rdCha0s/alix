#!/usr/bin/env python3
"""Structural regressions for ATK background I/O and video lock ordering."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    while start >= 0:
        opening = text.find("{", start + len(signature))
        semicolon = text.find(";", start + len(signature))
        if opening >= 0 and (semicolon < 0 or opening < semicolon):
            break
        start = text.find(signature, start + len(signature))
    if start < 0 or opening < 0:
        raise AssertionError(f"missing function definition: {signature}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated body: {signature}")


def before(body: str, first: str, second: str) -> None:
    first_at = body.find(first)
    second_at = body.find(second)
    if first_at < 0 or second_at < 0 or first_at >= second_at:
        raise AssertionError(f"expected {first!r} before {second!r}")


def absent(body: str, tokens: tuple[str, ...], scope: str) -> None:
    for token in tokens:
        if token in body:
            raise AssertionError(f"{scope} must not contain {token!r}")


def main() -> int:
    atk = source("src/atk/atk.c")
    video = source("src/drivers/video.c")

    render = function_body(atk, "void atk_render(void)")
    render_without = function_body(
        atk,
        "static __attribute__((unused)) void atk_render_scene_without",
    )
    forbidden_render_work = (
        "atk_background_refresh(",
        "atk_background_read_",
        "atk_background_stage_",
        "vfs_",
        "png_decode_rgba32(",
    )
    absent(render, forbidden_render_work, "atk_render")
    absent(render_without, forbidden_render_work, "atk_render_scene_without")

    config_read = function_body(
        atk,
        "static bool atk_background_read_config_path(char path[256])",
    )
    stage = function_body(
        atk,
        "static bool atk_background_stage_path",
    )
    for body, scope in ((config_read, "background config read"), (stage, "background image stage")):
        if "vfs_stat(" not in body:
            raise AssertionError(f"{scope} must snapshot file size/type with vfs_stat")
        if "vfs_data(" in body:
            raise AssertionError(f"{scope} must not retain a VFS data alias")
        absent(body, ("atk_state_lock_acquire(", "spinlock_lock("), scope)
    if "atk_background_read_exact(" not in config_read or "atk_background_read_exact(" not in stage:
        raise AssertionError("background VFS reads must copy through vfs_read_at")
    exact_read = function_body(atk, "static bool atk_background_read_exact")
    if "vfs_read_at(" not in exact_read or "vfs_data(" in exact_read:
        raise AssertionError("background byte copies must use vfs_read_at, never vfs_data")
    if "png_decode_rgba32(" not in stage:
        raise AssertionError("PNG decode must happen in the unlocked staging phase")

    refresh = function_body(atk, "void atk_background_refresh(void)")
    before(refresh, "atk_background_stage_path(path, &staged)", "atk_background_commit(&staged)")
    commit = function_body(atk, "static void atk_background_commit")
    before(commit, "atk_state_lock_acquire()", "g_atk_background = *staged")
    before(commit, "g_atk_background = *staged", "atk_state_lock_release(irq_state)")
    before(commit, "atk_state_lock_release(irq_state)", "free(old_pixels)")
    absent(commit, ("vfs_", "png_decode_rgba32("), "background commit")

    refresh_locked = function_body(
        video,
        "static bool video_perform_refresh_locked(bool full_refresh_prepared)",
    )
    absent(refresh_locked, ("atk_background_refresh(", "vfs_"), "locked video refresh")
    before(
        refresh_locked,
        "refresh_requested_full && !full_refresh_prepared",
        "target = refresh_window",
    )
    before(refresh_locked, "if (do_full)", "if (target)")

    refresh_caller = function_body(video, "static void video_perform_refresh(void)")
    before(
        refresh_caller,
        "full_refresh_prepared = video_full_refresh_pending()",
        "if (full_refresh_prepared)",
    )
    before(refresh_caller, "if (full_refresh_prepared)", "atk_background_refresh()")
    before(refresh_caller, "atk_background_refresh()", "spinlock_lock(&g_video_render_lock)")

    enter_mode = function_body(video, "bool video_enter_mode(void)")
    before(enter_mode, "atk_background_refresh()", "atk_render()")

    if video.count("atk_background_refresh();") != 2:
        raise AssertionError("background refresh must run only for initial/full render cadence")

    mouse = function_body(video, "void video_on_mouse_event")
    mouse_retry = """bool retry = video_perform_refresh_locked(false);
        spinlock_unlock(&g_video_render_lock);
        if (retry)"""
    if mouse_retry not in mouse:
        raise AssertionError("mouse full refresh must leave the render lock before staging")
    before(mouse, mouse_retry, "video_perform_refresh()")

    print("ATK background locking contract test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"ATK background locking contract test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
