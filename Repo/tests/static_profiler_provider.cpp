// A strong provider exercises the real static-client hooks, including lookup.
#define MOZ_UPROFILER_IMPLEMENTATION 1
#include "MicroGeckoProfiler.h"
#include <stdint.h>
#include <string.h>

static uint32_t registrations, unregistrations, invalid_registration;
extern "C" void uprofiler_register_thread(const char * name, void * stack) {
  if (!name || strcmp(name, "cubeb-alix") || stack)
    __atomic_add_fetch(&invalid_registration, 1u, __ATOMIC_RELAXED);
  __atomic_add_fetch(&registrations, 1u, __ATOMIC_RELEASE);
}
extern "C" void uprofiler_unregister_thread() {
  __atomic_add_fetch(&unregistrations, 1u, __ATOMIC_RELEASE);
}
extern "C" void uprofiler_simple_event_marker(const char *, char, char, int,
    const char **, const unsigned char *, const unsigned long long *) {}
extern "C" void uprofiler_simple_event_marker_capture_stack(const char *, char, char, int,
    const char **, const unsigned char *, const unsigned long long *) {}
extern "C" void uprofiler_simple_event_marker_with_stack(const char *, char, char, int,
    const char **, const unsigned char *, const unsigned long long *, void *) {}
extern "C" bool uprofiler_backtrace_into_buffer(NativeStack *, void *) { return false; }
extern "C" void uprofiler_native_backtrace(const void *, NativeStack *) {}
extern "C" bool uprofiler_is_active() { return true; }
extern "C" bool uprofiler_feature_active(int32_t feature) { return feature == 42; }
extern "C" bool uprofiler_get(UprofilerFuncPtrs * output) {
  if (!output) return false;
  output->register_thread = uprofiler_register_thread;
  output->unregister_thread = uprofiler_unregister_thread;
  output->simple_event_marker = uprofiler_simple_event_marker;
  output->simple_event_marker_capture_stack = uprofiler_simple_event_marker_capture_stack;
  output->simple_event_marker_with_stack = uprofiler_simple_event_marker_with_stack;
  output->backtrace_into_buffer = uprofiler_backtrace_into_buffer;
  output->native_backtrace = uprofiler_native_backtrace;
  output->is_active = uprofiler_is_active;
  output->feature_active = uprofiler_feature_active;
  return true;
}
extern "C" bool alix_test_profiler_verify() {
  return !__atomic_load_n(&invalid_registration, __ATOMIC_ACQUIRE) &&
    __atomic_load_n(&registrations, __ATOMIC_ACQUIRE) >= 3 &&
    __atomic_load_n(&registrations, __ATOMIC_ACQUIRE) ==
    __atomic_load_n(&unregistrations, __ATOMIC_ACQUIRE);
}
