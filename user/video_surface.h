#ifndef USER_VIDEO_SURFACE_H
#define USER_VIDEO_SURFACE_H

#include "types.h"
#include <stdbool.h>

void video_surface_attach(uint16_t *buffer, uint32_t width, uint32_t height);
void video_surface_detach(void);
bool video_surface_has_dirty(void);
bool video_surface_consume_dirty(void);
void video_surface_force_dirty(void);

#endif /* USER_VIDEO_SURFACE_H */
