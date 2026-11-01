#include "cubeb/cubeb.h"
#include <alix_audio.h>
#include <cmath>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "serial.h"
#include "usyscall.h"
#ifdef ALIX_TEST_LINKED_PROFILER
#include "MicroGeckoProfiler.h"
extern "C" bool alix_test_profiler_verify();
#endif

#define CHECK(value, label) do { if (!(value)) { serial_printf("CUBEB_ALIX_TEST: FAIL %s errno=%d\n", label, errno); return 1; } } while (0)
struct fixture {
  cubeb_stream * stream;
  cubeb * self_context;
  cubeb_stream_params params;
  uint64_t produced, goal, calls;
  uint32_t started, stopped, drained, errors;
  bool self_destroy;
  double frequency;
};
struct group {
  cubeb * first;
  cubeb * second;
  fixture one, two, three, self;
  cubeb_device_collection devices;
};
static long data(cubeb_stream *, void * pointer, const void *, void * output, long requested) {
  fixture * value = static_cast<fixture *>(pointer);
  uint64_t produced = __atomic_load_n(&value->produced, __ATOMIC_RELAXED);
  uint64_t goal = __atomic_load_n(&value->goal, __ATOMIC_ACQUIRE);
  uint64_t remaining = goal > produced ? goal - produced : 0;
  unsigned frames = remaining < static_cast<uint64_t>(requested) ? static_cast<unsigned>(remaining) :
                    static_cast<unsigned>(requested);
  for (unsigned frame = 0; frame < frames; ++frame) {
    double phase = 6.2831853071795864769 * value->frequency * (produced + frame) / value->params.rate;
    float sample = static_cast<float>(0.2 * std::sin(phase));
    for (unsigned channel = 0; channel < value->params.channels; ++channel) {
      unsigned index = frame * value->params.channels + channel;
      if (value->params.format == CUBEB_SAMPLE_FLOAT32NE) static_cast<float *>(output)[index] = sample;
      else static_cast<int16_t *>(output)[index] = static_cast<int16_t>(sample * 32767.0f);
    }
  }
  __atomic_store_n(&value->produced, produced + frames, __ATOMIC_RELEASE);
  __atomic_add_fetch(&value->calls, UINT64_C(1), __ATOMIC_RELEASE);
  return frames;
}
static void state(cubeb_stream * stream, void * pointer, cubeb_state event) {
  fixture * value = static_cast<fixture *>(pointer);
  if (event == CUBEB_STATE_STARTED) __atomic_add_fetch(&value->started, 1u, __ATOMIC_RELEASE);
  if (event == CUBEB_STATE_STOPPED) __atomic_add_fetch(&value->stopped, 1u, __ATOMIC_RELEASE);
  if (event == CUBEB_STATE_ERROR) __atomic_add_fetch(&value->errors, 1u, __ATOMIC_RELEASE);
  if (event == CUBEB_STATE_DRAINED) {
    if (value->self_destroy) {
      cubeb_stream_destroy(stream);
      cubeb_destroy(value->self_context);
    }
    // Last user-data access: a self-destroying callback must not touch this
    // record after notifying its owner that destruction has completed.
    __atomic_add_fetch(&value->drained, 1u, __ATOMIC_RELEASE);
  }
}
static bool wait_for(fixture * value, uint32_t drains, uint64_t calls = 0) {
  uint64_t deadline = sys_monotonic_millis() + 5000;
  while (sys_monotonic_millis() < deadline) {
    if (__atomic_load_n(&value->errors, __ATOMIC_ACQUIRE)) return false;
    if (__atomic_load_n(&value->drained, __ATOMIC_ACQUIRE) >= drains &&
        __atomic_load_n(&value->calls, __ATOMIC_ACQUIRE) >= calls) return true;
    sys_sleep_ms(1);
  }
  return false;
}
static int init_context(cubeb ** context) {
  uint64_t deadline = sys_monotonic_millis() + 10000;
  int result;
  do {
    result = cubeb_init(context, "Alix native cubeb acceptance", "alix");
    if (result == CUBEB_OK || errno != ENODEV) return result;
    sys_sleep_ms(10);
  } while (sys_monotonic_millis() < deadline);
  return result;
}
static int init_stream(cubeb * context, fixture * value, uint32_t sample_rate,
                       unsigned channels, cubeb_sample_format format, double frequency,
                       uint64_t frames) {
  value->params.format = format; value->params.rate = sample_rate; value->params.channels = channels;
  value->params.layout = channels == 1 ? CUBEB_LAYOUT_MONO : CUBEB_LAYOUT_STEREO;
  value->frequency = frequency; value->goal = frames;
  uint32_t latency = 0;
  if (cubeb_get_min_latency(context, &value->params, &latency) != CUBEB_OK) return CUBEB_ERROR;
  return cubeb_stream_init(context, &value->stream, "Native acceptance tone", nullptr, nullptr, nullptr,
                            &value->params, latency, data, state, value);
}
int main() {
  group * test = static_cast<group *>(calloc(1, sizeof(*test)));
  CHECK(test && init_context(&test->first) == CUBEB_OK &&
        init_context(&test->second) == CUBEB_OK, "real native backend contexts");
  CHECK(!strcmp(cubeb_get_backend_id(test->first), "alix") &&
        !strcmp(cubeb_get_backend_id(test->second), "alix"), "backend identity");
  uint32_t channels = 0, preferred = 0;
  CHECK(cubeb_get_max_channel_count(test->first, &channels) == CUBEB_OK && channels == 2 &&
        cubeb_get_preferred_sample_rate(test->first, &preferred) == CUBEB_OK && preferred == 48000,
        "actual native hardware capabilities");
  CHECK(cubeb_enumerate_devices(test->first, CUBEB_DEVICE_TYPE_OUTPUT, &test->devices) == CUBEB_OK &&
        test->devices.count == 1 && test->devices.device[0].default_rate == 48000 &&
        cubeb_device_collection_destroy(test->first, &test->devices) == CUBEB_OK, "output enumeration");
  CHECK(cubeb_enumerate_devices(test->first, CUBEB_DEVICE_TYPE_INPUT, &test->devices) == CUBEB_OK &&
        !test->devices.count && cubeb_device_collection_destroy(test->first, &test->devices) == CUBEB_OK,
        "absent capture hardware is not fabricated");
  CHECK(init_stream(test->first, &test->one, 44100, 1, CUBEB_SAMPLE_FLOAT32NE, 997, 11025) == CUBEB_OK &&
        init_stream(test->second, &test->two, 48000, 2, CUBEB_SAMPLE_S16NE, 503, 12000) == CUBEB_OK,
        "mono float and stereo integer streams");
  CHECK(cubeb_stream_set_volume(test->one.stream, 0.75f) == CUBEB_OK &&
        cubeb_stream_set_volume(test->two.stream, 0.5f) == CUBEB_OK &&
        cubeb_stream_start(test->one.stream) == CUBEB_OK &&
        cubeb_stream_start(test->two.stream) == CUBEB_OK, "simultaneous stream start");
  CHECK(wait_for(&test->one, 1) && wait_for(&test->two, 1), "mixed streams reach hardware drain");
  uint64_t position = 0;
  CHECK(cubeb_stream_get_position(test->one.stream, &position) == CUBEB_OK && position == 11025 &&
        cubeb_stream_get_position(test->two.stream, &position) == CUBEB_OK && position == 12000,
        "resampled and native-rate hardware positions");
  serial_printf("CUBEB_ALIX_TEST: MIX PASS resample44100=11025 stereo48000=12000\n");
  __atomic_store_n(&test->one.produced, UINT64_C(0), __ATOMIC_RELEASE);
  CHECK(cubeb_stream_start(test->one.stream) == CUBEB_OK && wait_for(&test->one, 2) &&
        cubeb_stream_get_position(test->one.stream, &position) == CUBEB_OK && position == 22050,
        "restart after drain preserves cumulative position");
  CHECK(init_stream(test->second, &test->three, 32000, 1, CUBEB_SAMPLE_S16NE, 701, 320000) == CUBEB_OK &&
        cubeb_stream_start(test->three.stream) == CUBEB_OK && wait_for(&test->three, 0, 3),
        "pause/resume stream start");
  CHECK(cubeb_stream_stop(test->three.stream) == CUBEB_OK, "stop quiesces data callbacks");
  uint64_t calls = __atomic_load_n(&test->three.calls, __ATOMIC_ACQUIRE);
  sys_sleep_ms(50);
  CHECK(__atomic_load_n(&test->three.calls, __ATOMIC_ACQUIRE) == calls, "no data callback after stop");
  uint64_t goal = __atomic_load_n(&test->three.produced, __ATOMIC_ACQUIRE) + 3200;
  __atomic_store_n(&test->three.goal, goal, __ATOMIC_RELEASE);
  CHECK(cubeb_stream_start(test->three.stream) == CUBEB_OK && wait_for(&test->three, 1) &&
        cubeb_stream_get_position(test->three.stream, &position) == CUBEB_OK && position == goal,
        "resume and final client-rate drain");
  cubeb_stream_destroy(test->one.stream); cubeb_stream_destroy(test->two.stream);
  cubeb_stream_destroy(test->three.stream);
  cubeb_destroy(test->first); cubeb_destroy(test->second);
  CHECK(init_context(&test->first) == CUBEB_OK, "context reinitialization");
  test->self.self_context = test->first; test->self.self_destroy = true;
  CHECK(init_stream(test->first, &test->self, 48000, 2, CUBEB_SAMPLE_FLOAT32NE, 997, 2400) == CUBEB_OK &&
        cubeb_stream_start(test->self.stream) == CUBEB_OK && wait_for(&test->self, 1),
        "state callback destroys its stream and final context");
  CHECK(init_context(&test->second) == CUBEB_OK, "old worker leaves a reusable device");
  cubeb_destroy(test->second);
  CHECK(!test->one.errors && !test->two.errors && !test->three.errors && !test->self.errors,
        "no backend errors");
#ifdef ALIX_TEST_LINKED_PROFILER
  UPROFILER_GET(get_profiler);
  UprofilerFuncPtrs * hooks = static_cast<UprofilerFuncPtrs *>(calloc(1, sizeof(*hooks)));
  CHECK(get_profiler && hooks && get_profiler(hooks) && hooks->is_active && hooks->is_active() &&
        hooks->feature_active && hooks->feature_active(42) && !hooks->feature_active(0) &&
        alix_test_profiler_verify(), "static profiler hooks and provider lookup");
  free(hooks);
  serial_printf("CUBEB_ALIX_TEST: PROFILER PASS linked=1 thread_lifetimes=3\n");
#endif
  free(test);
  serial_printf("CUBEB_ALIX_TEST: PASS contexts=2 streams=3 resample=1 restart=1 pause=1 self_destroy=1\n");
  return 0;
}
