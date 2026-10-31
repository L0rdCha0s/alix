#!/usr/bin/env python3
"""Exercise the production libc++ timed-wait adapter with controlled scheduling."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from audio_stream_contract_test import function_definition

source = (ROOT / "ports/zen/libcxx/alix_threading.cpp").read_text()
code = r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

// Target error values are deliberately independent of the host's libc ABI.
#define EINVAL 22
#define EIO 5
#define SYSCALL_FUTEX_TIMED_OUT (-110)
#define CLOCK_REALTIME 0
static int target_errno;
#define errno target_errno
#define timespec mock_timespec
#define clock_gettime mock_clock_gettime
struct mock_timespec { int64_t tv_sec; long tv_nsec; };
using __libcpp_timespec_t = mock_timespec;
struct __libcpp_condvar_t {};
struct __libcpp_mutex_t { bool held = true; };
static int as_error(int result) { return result < 0 ? -result : result; }

static mock_timespec clock_before, clock_after;
static unsigned clock_calls, fail_clock_call, waits;
static uint32_t waited_milliseconds;
static int wait_result;
static bool notify_during_reacquire, predicate;

static void reset(mock_timespec before, mock_timespec after, int result = SYSCALL_FUTEX_TIMED_OUT) {
  clock_before = before; clock_after = after;
  clock_calls = fail_clock_call = waits = 0;
  waited_milliseconds = UINT32_MAX;
  wait_result = result;
  notify_during_reacquire = predicate = false;
  target_errno = 0;
}
static int mock_clock_gettime(int clock, mock_timespec* now) {
  assert(clock == CLOCK_REALTIME);
  ++clock_calls;
  if (clock_calls == fail_clock_call) { target_errno = EIO; return -1; }
  *now = clock_calls == 1 ? clock_before : clock_after;
  return 0;
}
static int alix_cond_timedwait(__libcpp_condvar_t*, __libcpp_mutex_t* mutex, uint32_t milliseconds) {
  assert(mutex->held);
  mutex->held = false;
  ++waits;
  assert(waits == 1); // A single adapter call must expose every internal timeout.
  waited_milliseconds = milliseconds;
  // A timed kernel wait has expired, but this waiter does not own its mutex
  // yet. A producer locks it, changes the predicate, signals, then unlocks.
  // No futex waiter remains to receive that signal. The caller must get a
  // chance to see the predicate before the adapter waits again.
  if (notify_during_reacquire) predicate = true;
  mutex->held = true;
  return wait_result;
}
'''
code += function_definition(source, "int __libcpp_condvar_timedwait(")
code += r'''
int main() {
  __libcpp_condvar_t cv;
  __libcpp_mutex_t mutex;
  __libcpp_timespec_t end{5, 0};

  reset({0, 0}, {1, 0});
  notify_during_reacquire = true;
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 0);
  assert(predicate && waits == 1 && waited_milliseconds == 1000 && mutex.held);

  // Even without a notification, an internal timeout is a permitted spurious
  // wake. The caller owns predicate checking and any subsequent wait.
  reset({0, 0}, {1, 0});
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 0 && waits == 1);

  // The actual absolute deadline, including nanoseconds, determines timeout.
  end = {1, 500000001};
  reset({1, 499000000}, end);
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 110);
  assert(waited_milliseconds == 2 && waits == 1 && mutex.held);
  reset({1, 499000000}, {1, 500000000});
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 0 && waits == 1);

  // Expired waits still release/reacquire the mutex through the native API.
  reset(end, end);
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 110);
  assert(waited_milliseconds == 0 && waits == 1 && mutex.held);

  // Clock changes are checked after the bounded monotonic wait.
  end = {5, 0};
  reset({0, 0}, {20, 0});
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 110 && waits == 1);
  reset({0, 0}, {-20, 0});
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 0 && waits == 1);

  reset({0, 0}, {0, 0}, 0);
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == 0 && clock_calls == 1);
  reset({0, 0}, {0, 0}, -EINVAL);
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == EINVAL && mutex.held);
  reset({0, 0}, {1, 0}); fail_clock_call = 2;
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == EIO && mutex.held && waits == 1);
  reset({0, 0}, {1, 0}); fail_clock_call = 1;
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == EIO && mutex.held && waits == 0);
  reset({0, 0}, {1, 0}); end.tv_nsec = 1000000000;
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == EINVAL && waits == 0);
  end.tv_nsec = -1;
  assert(__libcpp_condvar_timedwait(&cv, &mutex, &end) == EINVAL && waits == 0);
  end.tv_nsec = 0;
  assert(__libcpp_condvar_timedwait(nullptr, &mutex, &end) == EINVAL);
  assert(__libcpp_condvar_timedwait(&cv, nullptr, &end) == EINVAL);
  assert(__libcpp_condvar_timedwait(&cv, &mutex, nullptr) == EINVAL);
  puts("LIBCXX_THREADING_CONTRACT: PASS timed-wait notification race, deadlines, clock changes, errors");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-libcxx-threading-") as temporary:
    program = Path(temporary) / "test.cpp"
    binary = Path(temporary) / "test"
    program.write_text(code)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-g", str(program), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
