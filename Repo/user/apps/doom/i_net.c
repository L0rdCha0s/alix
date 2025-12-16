// Minimal single-player networking shim for AlixOS.

#include "i_net.h"

#include "doomdef.h"
#include "doomstat.h"
#include "d_net.h"
#include "m_argv.h"
#include "string.h"

void I_InitNetwork(void)
{
    static doomcom_t local_doomcom;

    memset(&local_doomcom, 0, sizeof(local_doomcom));
    doomcom = &local_doomcom;

    doomcom->id = DOOMCOM_ID;
    doomcom->ticdup = 1;
    doomcom->extratics = 0;
    doomcom->numnodes = 1;
    doomcom->numplayers = 1;
    doomcom->consoleplayer = 0;
    doomcom->deathmatch = 0;
    doomcom->savegame = -1;
    doomcom->angleoffset = 0;
    doomcom->drone = 0;
    doomcom->remotenode = -1;

    netgame = false;
}

void I_NetCmd(void)
{
    if (doomcom)
    {
        doomcom->remotenode = -1;
        doomcom->datalength = 0;
    }
}
