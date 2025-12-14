# ATK

ATK is Alix’s retained-mode UI toolkit. It runs in kernel space for the desktop/window manager and can also be used in userland via “remote windows”.

If you are specifically working on userland remote windows, start with `docs/user_atk.md` for the architecture overview.

## Contents

- `docs/atk/principles.md` – core concepts (state, rendering, events, layout, performance).
- `docs/atk/tutorials/quick_start_kernel.md` – minimal kernel-side integration.
- `docs/atk/tutorials/quick_start_userland.md` – minimal userland app using a remote window.
- `docs/atk/reference/README.md` – per-module and per-widget API notes.

## Where APIs live

- Core entry points: `include/atk.h`
- Public widget APIs: `include/atk/*.h`
- Window manager / desktop / menu bar: `src/atk/*.h` (internal but commonly used)
- Userland wrappers: `user/atk_user.h`, `user/atk_app.h`
