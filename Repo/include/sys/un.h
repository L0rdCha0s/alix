#ifndef ALIX_SYS_UN_H
#define ALIX_SYS_UN_H
#include "sys/socket.h"
/* Native local-address representation. Local socket transport and descriptor
 * passing are separate capabilities; their current entry points return errors. */
struct sockaddr_un { sa_family_t sun_family; char sun_path[108]; };
#endif
