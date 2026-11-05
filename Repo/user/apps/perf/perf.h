#ifndef ALIX_PERF_H
#define ALIX_PERF_H
#include "pthread.h"
#include "types.h"
#define PERF_MAX_RESULTS 128
#define PERF_MAX_ROUNDS 15

typedef struct
{
    char name[64], group[16], detail[96];
    uint64_t operations, bytes, elapsed_ns, p50_ns, p95_ns, max_ns;
    uint64_t user_us, system_us, minor_faults, major_faults;
    unsigned samples, workers;
    int error;
} perf_result_t;
typedef struct
{
    pthread_mutex_t lock;
    volatile uint32_t stop, running, done;
    unsigned count, failed, skipped;
    char current[80];
    perf_result_t results[PERF_MAX_RESULTS];
} perf_state_t;
typedef struct
{
    unsigned rounds, duration_ms, threads, cpus, present_mode, present_batch;
    bool gui, autorun, exit_when_done;
    const char *group, *case_name, *workdir, *net_host, *dns_host;
    unsigned port;
    char executable[4096];
    perf_state_t *state;
} perf_config_t;
uint64_t perf_now_ns(void);
void perf_log(const char *format, ...);
const char *perf_status(int error);
void perf_record(perf_state_t *state, const perf_result_t *result);
int perf_run(perf_config_t *config);
int perf_gui(perf_config_t *config);
#endif
