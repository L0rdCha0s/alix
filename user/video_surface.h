#ifndef USER_VIDEO_SURFACE_H
#define USER_VIDEO_SURFACE_H

#include "types.h"
#include "video.h"
void video_surface_attach(video_color_t *buffer, uint32_t width, uint32_t height);
void video_surface_detach(void);
bool video_surface_has_dirty(void);
bool video_surface_consume_dirty(void);
void video_surface_force_dirty(void);
void video_surface_set_tracking(bool enable);
bool video_surface_tracking_enabled(void);

#endif /* USER_VIDEO_SURFACE_H */
