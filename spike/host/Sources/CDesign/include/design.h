#pragma once
#include <stdint.h>
typedef struct Engine Engine;
Engine *ds_new(const char *font);
void ds_free(Engine *e);
double ds_open_ms(Engine *e);
double ds_layout_ms(Engine *e);
void ds_counts(Engine *e, uint32_t *out3);
void ds_set_view(Engine *e, float w, float h, float scale);
float ds_fit_zoom(Engine *e);
void ds_set_camera(Engine *e, float zoom, float px, float py);
void ds_get_camera(Engine *e, float *out3);
void ds_pan(Engine *e, float dx, float dy);
void ds_zoom_at(Engine *e, float factor, float cx, float cy);
void ds_set_lod(Engine *e, int on);
void ds_set_bars_max_w(Engine *e, float w);
void ds_set_blur_min_w(Engine *e, float w);
int ds_drag_begin(Engine *e, float x, float y);
void ds_drag_move(Engine *e, float x, float y);
void ds_drag_end(Engine *e);
double ds_last_rerecord_ms(Engine *e);
void ds_card_center(Engine *e, int g, float *out2);
double ds_render_cpu_png(Engine *e, int w, int h, const char *path);
double ds_render_metal(Engine *e, void *device, void *queue, void *texture, int w, int h, const char *png);
