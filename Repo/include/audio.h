#ifndef AUDIO_H
#define AUDIO_H

#include "types.h"

void audio_sys_controls_init(void);

uint32_t audio_volume_get_percent(void);
void audio_volume_set_percent(uint32_t percent);

#endif
