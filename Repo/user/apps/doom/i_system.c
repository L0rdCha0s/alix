// AlixOS usermode system glue for DOOM.

#include <stdarg.h>

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "doomdef.h"
#include "doomstat.h"
#include "d_net.h"
#include "g_game.h"
#include "i_system.h"
#include "i_video.h"
#include "i_sound.h"
#include "m_misc.h"
#include "serial.h"
#include "types.h"
#include "usyscall.h"

int mb_used = 16;

static uint64_t g_base_millis = 0;
ticcmd_t emptycmd;

void I_Tactile(int on, int off, int total)
{
    (void)on;
    (void)off;
    (void)total;
}

ticcmd_t *I_BaseTiccmd(void)
{
    return &emptycmd;
}

int I_GetHeapSize(void)
{
    return mb_used * 1024 * 1024;
}

byte *I_ZoneBase(int *size)
{
    size_t bytes = (size_t)mb_used * 1024 * 1024;
    if (size)
    {
        *size = (int)bytes;
    }
    byte *base = (byte *)malloc(bytes);
    if (base)
    {
        memset(base, 0, bytes);
    }
    return base;
}

int I_GetTime(void)
{
    uint64_t now = sys_time_millis();
    if (g_base_millis == 0)
    {
        g_base_millis = now;
    }
    uint64_t delta_ms = now - g_base_millis;
    return (int)((delta_ms * TICRATE) / 1000ULL);
}

void I_Init(void)
{
    I_InitSound();
}

void I_Quit(void)
{
    serial_printf("[doom][I_Quit] exiting cleanly\n");
    D_QuitNetGame();
    I_ShutdownSound();
    I_ShutdownMusic();
    M_SaveDefaults();
    I_ShutdownGraphics();
    exit(0);
}

void I_WaitVBL(int count)
{
    uint64_t wait_ms = (uint64_t)count * 1000ULL / 70ULL;
    uint64_t start = sys_time_millis();
    while ((sys_time_millis() - start) < wait_ms)
    {
        sys_yield();
    }
}

void I_BeginRead(void) {}
void I_EndRead(void) {}

byte *I_AllocLow(int length)
{
    byte *mem = (byte *)malloc((size_t)length);
    if (mem)
    {
        memset(mem, 0, (size_t)length);
    }
    return mem;
}

void I_Error(char *error, ...)
{
    va_list args;

    va_start(args, error);

    char buf[256];
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(buf, sizeof(buf), error ? error : "<null>", args_copy);
    va_end(args_copy);
    serial_printf("[doom][I_Error] %s\n", buf);

    fprintf(stderr, "Error: ");
    vfprintf(stderr, error, args);
    fprintf(stderr, "\n");
    va_end(args);
    fflush(stderr);

    if (demorecording)
    {
        G_CheckDemoStatus();
    }

    D_QuitNetGame();
    I_ShutdownGraphics();
    exit(-1);
}

void I_StartFrame(void) {}
