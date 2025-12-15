#ifndef USER_VIDEO_SURFACE_H
#define USER_VIDEO_SURFACE_H

#include "types.h"
#include "video.h"
void video_surface_attach(video_color_t *buffer, uint32_t width, uint32_t height, size_t buffer_bytes);
void video_surface_detach(void);
bool video_surface_has_dirty(void);
bool video_surface_consume_dirty(void);
void video_surface_force_dirty(void);
void video_surface_set_tracking(bool enable);
bool video_surface_tracking_enabled(void);
void video_surface_convert8_to_rgba32(const uint8_t *src,
                                      const video_color_t *palette,
                                      video_color_t *dst,
                                      size_t pixel_count);

#endif /* USER_VIDEO_SURFACE_H */
