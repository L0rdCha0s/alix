#include "__external_threading"
#include "usyscall.h"
#include <errno.h>
#include <stdlib.h>

_LIBCPP_BEGIN_NAMESPACE_STD

static int as_error(int result) { return result < 0 ? -result : result; }

int __libcpp_recursive_mutex_init(__libcpp_recursive_mutex_t* mutex) {
  if (!mutex) return EINVAL;
  alix_recursive_mutex_init(mutex);
  return 0;
}
int __libcpp_recursive_mutex_lock(__libcpp_recursive_mutex_t* mutex) {
  return as_error(alix_recursive_mutex_lock(mutex));
}
bool __libcpp_recursive_mutex_trylock(__libcpp_recursive_mutex_t* mutex) {
  return alix_recursive_mutex_trylock(mutex);
}
int __libcpp_recursive_mutex_unlock(__libcpp_recursive_mutex_t* mutex) {
  return as_error(alix_recursive_mutex_unlock(mutex));
}
int __libcpp_recursive_mutex_destroy(__libcpp_recursive_mutex_t* mutex) {
  if (!mutex) return EINVAL;
  return __atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) == 0 ? 0 : EBUSY;
}
int __libcpp_mutex_lock(__libcpp_mutex_t* mutex) {
  if (!mutex) return EINVAL;
  alix_mutex_lock(mutex);
  return 0;
}
bool __libcpp_mutex_trylock(__libcpp_mutex_t* mutex) { return alix_mutex_trylock(mutex); }
int __libcpp_mutex_unlock(__libcpp_mutex_t* mutex) {
  if (!mutex) return EINVAL;
  alix_mutex_unlock(mutex);
  return 0;
}
int __libcpp_mutex_destroy(__libcpp_mutex_t* mutex) {
  if (!mutex) return EINVAL;
  return __atomic_load_n(&mutex->state, __ATOMIC_ACQUIRE) == 0 ? 0 : EBUSY;
}
int __libcpp_condvar_signal(__libcpp_condvar_t* cv) { return as_error(alix_cond_signal(cv)); }
int __libcpp_condvar_broadcast(__libcpp_condvar_t* cv) { return as_error(alix_cond_broadcast(cv)); }
int __libcpp_condvar_wait(__libcpp_condvar_t* cv, __libcpp_mutex_t* mutex) {
  return as_error(alix_cond_wait(cv, mutex));
}
int __libcpp_condvar_timedwait(__libcpp_condvar_t* cv, __libcpp_mutex_t* mutex, __libcpp_timespec_t* end) {
  if (!cv || !mutex || !end || end->tv_nsec < 0 || end->tv_nsec >= 1000000000L) return EINVAL;
  timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0) return errno;
  if (end->tv_sec < now.tv_sec || (end->tv_sec == now.tv_sec && end->tv_nsec <= now.tv_nsec))
    return as_error(alix_cond_timedwait(cv, mutex, 0));
  // Re-evaluate wall-clock deadlines at least once a second after timeout.
  // Alix's kernel waits are monotonic relative durations.
  uint32_t milliseconds = 1000;
  if (end->tv_sec <= now.tv_sec + 1) {
    int64_t nanoseconds = (end->tv_sec - now.tv_sec) * 1000000000LL + end->tv_nsec - now.tv_nsec;
    uint64_t rounded = (static_cast<uint64_t>(nanoseconds) + 999999u) / 1000000u;
    if (rounded < milliseconds) milliseconds = static_cast<uint32_t>(rounded);
  }
  int result = alix_cond_timedwait(cv, mutex, milliseconds);
  if (result != SYSCALL_FUTEX_TIMED_OUT) return as_error(result);
  if (clock_gettime(CLOCK_REALTIME, &now) != 0) return errno;
  // The predicate may have changed after timeout but before mutex reacquisition.
  // Return a permitted spurious wake instead of hiding that notification by
  // beginning another wait without allowing the caller to check its predicate.
  return end->tv_sec < now.tv_sec || (end->tv_sec == now.tv_sec && end->tv_nsec <= now.tv_nsec)
             ? as_error(SYSCALL_FUTEX_TIMED_OUT) : 0;
}
int __libcpp_condvar_destroy(__libcpp_condvar_t* cv) { return cv ? 0 : EINVAL; }
int __libcpp_execute_once(__libcpp_exec_once_flag* flag, void (*initialize)()) {
  return as_error(alix_call_once(flag, initialize));
}
bool __libcpp_thread_id_equal(__libcpp_thread_id lhs, __libcpp_thread_id rhs) { return lhs == rhs; }
bool __libcpp_thread_id_less(__libcpp_thread_id lhs, __libcpp_thread_id rhs) { return lhs < rhs; }
bool __libcpp_thread_isnull(const __libcpp_thread_t* thread) { return !thread || *thread == 0; }

struct alix_cxx_start { void* (*function)(void*); void* argument; };
static void alix_cxx_thread_start(void* opaque) {
  auto* start = static_cast<alix_cxx_start*>(opaque);
  auto function = start->function;
  void* argument = start->argument;
  free(start);
  // libc++'s join interface has no return-value channel. Its own trampoline
  // returns nullptr; never cast a pointer result to Alix's integer exit status.
  (void)function(argument);
}
int __libcpp_thread_create(__libcpp_thread_t* thread, void* (*function)(void*), void* argument) {
  if (!thread || !function) return EINVAL;
  auto* start = static_cast<alix_cxx_start*>(malloc(sizeof(alix_cxx_start)));
  if (!start) return ENOMEM;
  start->function = function;
  start->argument = argument;
  int result = alix_thread_create(thread, "cxx_thread", alix_cxx_thread_start, start);
  if (result != 0) { free(start); return EAGAIN; }
  return 0;
}
__libcpp_thread_id __libcpp_thread_get_current_id() { return alix_thread_self(); }
__libcpp_thread_id __libcpp_thread_get_id(const __libcpp_thread_t* thread) { return thread ? *thread : 0; }
int __libcpp_thread_join(__libcpp_thread_t* thread) {
  if (!thread || !*thread) return EINVAL;
  int result = alix_thread_join(*thread, nullptr);
  if (result != 0) return EINVAL;
  *thread = 0;
  return 0;
}
int __libcpp_thread_detach(__libcpp_thread_t* thread) {
  if (!thread || !*thread) return EINVAL;
  if (alix_thread_detach(*thread) != 0) return EINVAL;
  *thread = 0;
  return 0;
}
void __libcpp_thread_yield() { (void)sys_yield(); }
void __libcpp_thread_sleep_for(const chrono::nanoseconds& duration) {
  if (duration.count() <= 0) return;
  timespec request;
  request.tv_sec = duration.count() / 1000000000;
  request.tv_nsec = duration.count() % 1000000000;
  (void)nanosleep(&request, nullptr);
}
int __libcpp_tls_create(__libcpp_tls_key* key, void (*destroy)(void*)) {
  return as_error(alix_tls_key_create(key, destroy));
}
void* __libcpp_tls_get(__libcpp_tls_key key) { return alix_tls_get(key); }
int __libcpp_tls_set(__libcpp_tls_key key, void* value) { return as_error(alix_tls_set(key, value)); }

_LIBCPP_END_NAMESPACE_STD
