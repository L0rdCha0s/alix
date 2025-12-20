// AlixOS usermode system glue for Quake (WinQuake software renderer).

#include <stdarg.h>
#include <string.h>

#include "quakedef.h"
#include "sys.h"

#include "stdio.h"
#include "stdlib.h"
#include "usyscall.h"

enum
{
    QUAKE_DEFAULT_MEM_MB = 32,
    MAX_HANDLES = 16,
};

static FILE *g_handles[MAX_HANDLES];

qboolean isDedicated;

static int sys_find_handle(void)
{
    for (int i = 1; i < MAX_HANDLES; ++i)
    {
        if (!g_handles[i])
        {
            return i;
        }
    }
    Sys_Error("out of handles");
    return -1;
}

static int sys_file_length(FILE *f)
{
    int pos = ftell(f);
    fseek(f, 0, SEEK_END);
    int end = ftell(f);
    fseek(f, pos, SEEK_SET);
    return end;
}

int Sys_FileOpenRead(char *path, int *hndl)
{
    if (hndl)
    {
        *hndl = -1;
    }
    if (!path || !hndl)
    {
        return -1;
    }

    int handle = sys_find_handle();
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        *hndl = -1;
        return -1;
    }

    g_handles[handle] = f;
    *hndl = handle;
    return sys_file_length(f);
}

int Sys_FileOpenWrite(char *path)
{
    if (!path)
    {
        return -1;
    }

    int handle = sys_find_handle();
    FILE *f = fopen(path, "wb");
    if (!f)
    {
        Sys_Error("Error opening %s", path);
    }
    g_handles[handle] = f;
    return handle;
}

void Sys_FileClose(int handle)
{
    if (handle <= 0 || handle >= MAX_HANDLES || !g_handles[handle])
    {
        return;
    }
    fclose(g_handles[handle]);
    g_handles[handle] = NULL;
}

void Sys_FileSeek(int handle, int position)
{
    if (handle <= 0 || handle >= MAX_HANDLES || !g_handles[handle])
    {
        return;
    }
    fseek(g_handles[handle], position, SEEK_SET);
}

int Sys_FileRead(int handle, void *dest, int count)
{
    if (handle <= 0 || handle >= MAX_HANDLES || !g_handles[handle] || !dest || count < 0)
    {
        return -1;
    }
    return (int)fread(dest, 1, (size_t)count, g_handles[handle]);
}

int Sys_FileWrite(int handle, void *data, int count)
{
    if (handle <= 0 || handle >= MAX_HANDLES || !g_handles[handle] || !data || count < 0)
    {
        return -1;
    }
    return (int)fwrite(data, 1, (size_t)count, g_handles[handle]);
}

int Sys_FileTime(char *path)
{
    if (!path)
    {
        return -1;
    }
    FILE *f = fopen(path, "rb");
    if (f)
    {
        fclose(f);
        return 1;
    }
    return -1;
}

void Sys_mkdir(char *path)
{
    (void)path;
}

void Sys_MakeCodeWriteable(unsigned long startaddr, unsigned long length)
{
    (void)startaddr;
    (void)length;
}

void Sys_DebugLog(char *file, char *fmt, ...)
{
    (void)file;
    (void)fmt;
}

void Sys_Error(char *error, ...)
{
    va_list argptr;
    va_start(argptr, error);

    fprintf(stderr, "Sys_Error: ");
    vfprintf(stderr, error ? error : "<null>", argptr);
    fprintf(stderr, "\n");
    va_end(argptr);

    Host_Shutdown();
    exit(1);
}

void Sys_Printf(char *fmt, ...)
{
    va_list argptr;
    va_start(argptr, fmt);
    vfprintf(stdout, fmt ? fmt : "<null>", argptr);
    va_end(argptr);
}

void Sys_Quit(void)
{
    Host_Shutdown();
    exit(0);
}

double Sys_FloatTime(void)
{
    static uint64_t base_ms = 0;
    uint64_t now_ms = sys_time_millis();
    if (base_ms == 0)
    {
        base_ms = now_ms;
    }
    return (double)(now_ms - base_ms) / 1000.0;
}

char *Sys_ConsoleInput(void)
{
    return NULL;
}

void Sys_Sleep(void)
{
    sys_yield();
}

void Sys_LowFPPrecision(void) {}
void Sys_HighFPPrecision(void) {}
void Sys_SetFPCW(void) {}

void Sys_Init(void) {}

static void quake_setup_input_defaults(void)
{
    Cbuf_AddText("bind w +forward\n");
    Cbuf_AddText("bind s +back\n");
    Cbuf_AddText("bind a +moveleft\n");
    Cbuf_AddText("bind d +moveright\n");
    Cbuf_AddText("+mlook\n");
}

int main(int argc, char **argv)
{
    quakeparms_t parms;
    memset(&parms, 0, sizeof(parms));

    COM_InitArgv(argc, argv);
    parms.argc = com_argc;
    parms.argv = com_argv;

    isDedicated = (COM_CheckParm("-dedicated") != 0);

    parms.memsize = QUAKE_DEFAULT_MEM_MB * 1024 * 1024;
    int mem_arg = COM_CheckParm("-mem");
    if (mem_arg && mem_arg + 1 < com_argc)
    {
        parms.memsize = (int)(Q_atof(com_argv[mem_arg + 1]) * 1024.0 * 1024.0);
    }
    if (parms.memsize < MINIMUM_MEMORY)
    {
        parms.memsize = MINIMUM_MEMORY;
    }

    parms.membase = malloc((size_t)parms.memsize);
    if (!parms.membase)
    {
        Sys_Error("unable to allocate %d bytes for hunk", parms.memsize);
    }

    parms.basedir = "/usr/share/games/quake";

    Host_Init(&parms);
    quake_setup_input_defaults();
    Cbuf_Execute();
    Sys_Init();

    const double frame_min = 1.0 / 72.0;
    double oldtime = Sys_FloatTime() - 0.1;
    while (1)
    {
        double newtime = Sys_FloatTime();
        double time = newtime - oldtime;
        if (time < 0)
        {
            time = 0;
        }
        Host_Frame((float)time);
        oldtime = newtime;
        if (time < frame_min)
        {
            sys_yield();
        }
    }
}
