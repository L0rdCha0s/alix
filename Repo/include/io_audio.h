#ifndef ALIX_IO_AUDIO_H
#define ALIX_IO_AUDIO_H
#include "io_event_service.h"
#include "hda.h"

typedef enum { IO_AUDIO_READ, IO_AUDIO_WRITE, IO_AUDIO_STATUS, IO_AUDIO_DRAIN } io_audio_opcode_t;
typedef struct
{
    uint32_t opcode, reserved;
    uint64_t count;
    hda_pcm_status_t status;
    unsigned char data[];
} io_audio_operation_t;

/* Bounded preparation guard or protected worker. The returned description owns
 * its PCM account; queued DMA independently keeps that account alive. */
int io_audio_create(fd_retirement_queue_t *retirement, uint64_t owner_pid,
                      fd_description_t **output);
bool io_audio_description_valid(const fd_description_t *description);
int io_audio_stat(const fd_description_t *description, syscall_stat_t *output);
/* One readiness step, never a sleep. PCM/output is owned by the request. */
bool io_audio_execute(io_request_t *request, io_service_result_t *result);
#endif
