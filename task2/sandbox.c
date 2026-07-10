#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define MAX_WALL_SECONDS   10
#define MAX_CPU_SECONDS    5
#define MAX_RSS_KB         (64 * 1024)   /* 64 MB */
#define POLL_INTERVAL_US   200000        /* 200 ms */

typedef struct {
    pid_t child_pid;
    atomic_int should_terminate;   /* 0 = run, 1 = terminate requested   */
    atomic_int termination_reason; /* bitmask / enum, see enum below     */
    struct timespec start_time;
    pthread_mutex_t log_lock;
} sandbox_state_t;

enum { REASON_NONE = 0, REASON_WALL_TIMEOUT = 1, REASON_CPU_LIMIT = 2,
       REASON_MEM_LIMIT = 3, REASON_CHILD_EXITED = 4 };

static sandbox_state_t g_state;

static void log_line(const char *fmt, ...) {
    pthread_mutex_lock(&g_state.log_lock);
    va_list ap;
    va_start(ap, fmt);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - g_state.start_time.tv_sec) +
                      (now.tv_nsec - g_state.start_time.tv_nsec) / 1e9;
    fprintf(stderr, "[sandbox +%.3fs] ", elapsed);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    pthread_mutex_unlock(&g_state.log_lock);
}
