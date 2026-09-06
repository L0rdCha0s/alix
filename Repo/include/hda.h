#ifndef HDA_H
#define HDA_H

#include "types.h"

typedef struct
{
    uint64_t queued_bytes;
    uint64_t empty_events;
    uint64_t reprime_events;
    uint64_t stream_errors;
    uint64_t rejected_writers;
    uint64_t writer_pid;
    bool running;
} hda_status_t;

void hda_init(void);
bool hda_get_status(hda_status_t *status);

#endif
