#!/usr/bin/env python3
"""Stage bounded legacy-input polling without changing active drivers."""
from pathlib import Path
import difflib,hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];STAGE=HERE/'pending'
changes={}
for name in ['src/drivers/mouse.c','src/drivers/keyboard.c']:
    old=(ROOT/name).read_text();new='#include "build_features.h"\n'+old
    if name.endswith('/mouse.c'):
        new=new.replace('#define KBD_DATA 0x60','#define KBD_DATA 0x60\n#define MOUSE_POLL_BYTE_BUDGET 32u')
        new=new.replace('if (!g_mouse_ps2_enabled)','if (!mouse_ps2_active())')
        old_poll='''    while (1)
    {
        uint64_t irq_state = mouse_irq_save();
        uint8_t status = inb(KBD_STATUS);
        if ((status & 0x01) == 0)'''
        new_poll='''    /* A missing controller reads 0xff; a stuck or continuously producing
     * device must also return control to serial/keyboard input and scheduling.
     * USB binding on another CPU can disable this loop after it has entered. */
    for (unsigned bytes = 0; bytes < MOUSE_POLL_BYTE_BUDGET && mouse_ps2_active(); ++bytes)
    {
        uint64_t irq_state = mouse_irq_save();
        uint8_t status = inb(KBD_STATUS);
        if (status == 0xff || (status & 0x01) == 0)'''
        assert new.count(old_poll)==1;new=new.replace(old_poll,new_poll)
        new=new.replace('    g_mouse_ps2_enabled = false;','    __atomic_store_n(&g_mouse_ps2_enabled, false, __ATOMIC_RELEASE);')
        new=new.replace('    return g_mouse_ps2_enabled;','    return __atomic_load_n(&g_mouse_ps2_enabled, __ATOMIC_ACQUIRE);')
    else:
        new=new.replace('if (!ps2_enabled)','if (!keyboard_ps2_enabled())')
        new=new.replace('    ps2_enabled = false;','    __atomic_store_n(&ps2_enabled, false, __ATOMIC_RELEASE);')
        new=new.replace('    ps2_enabled = true;','    __atomic_store_n(&ps2_enabled, true, __ATOMIC_RELEASE);')
        new=new.replace('    return ps2_enabled;','    return __atomic_load_n(&ps2_enabled, __ATOMIC_ACQUIRE);')
        new=new.replace('static void ps2_controller_init(void);','static void __attribute__((unused)) ps2_controller_init(void);')
        new=new.replace('    ps2_controller_init();\n    keyboard_reset_state();','    ps2_controller_init();\n#endif /* ENABLE_USB: software state is shared by both input backends. */\n    keyboard_reset_state();')
        new=new.replace('#endif /* ENABLE_USB */\n}', '}')
    changes[name]=(old,new);dest=STAGE/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(new)
for path in (STAGE/'tests').glob('*.py'):
    name=path.relative_to(STAGE).as_posix();changes[name]=((ROOT/name).read_text() if (ROOT/name).exists() else '',path.read_text())
patch=[];manifest=[]
for name,(old,new) in sorted(changes.items()):
    patch.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/Repo/'+name if (ROOT/name).exists() else '/dev/null',tofile='b/Repo/'+name))
    manifest.append({'path':name,'before':hashlib.sha256(old.encode()).hexdigest() if (ROOT/name).exists() else None,'after':hashlib.sha256(new.encode()).hexdigest()})
(HERE/'input-boot.pending.patch').write_text(''.join(patch));(HERE/'pending.json').write_text(json.dumps({'applied':False,'files':manifest},indent=2)+'\n')
print('Staged legacy-input fix; active files unchanged')
