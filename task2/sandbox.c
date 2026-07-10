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

/* ---- read /proc/<pid>/stat for utime+stime (in clock ticks) ---- */
static long read_cpu_ticks(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    /* Field 2 (comm) can contain spaces/parens, so find the last ')' */
    char *rparen = strrchr(buf, ')');
    if (!rparen) return -1;

    long utime = 0, stime = 0;
    /* After ')', fields are space separated starting at field 3 (state).
       utime is field 14, stime is field 15 relative to field 1. */
    int field = 2;
    char *p = rparen + 2; /* skip ") " */
    char *tok = strtok(p, " ");
    while (tok) {
        field++;
        if (field == 14) utime = atol(tok);
        if (field == 15) { stime = atol(tok); break; }
        tok = strtok(NULL, " ");
    }
    return utime + stime;
}

/* ---- read /proc/<pid>/status for VmRSS (kB) ---- */
static long read_rss_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    long rss = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

/* ---- Thread 1: wall-clock timeout watcher ---- */
static void *timer_watcher(void *arg) {
    (void)arg;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += MAX_WALL_SECONDS;

    while (!atomic_load(&g_state.should_terminate)) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            log_line("TIMER: wall-clock limit of %ds exceeded", MAX_WALL_SECONDS);
            int expected = 0;
            atomic_compare_exchange_strong(&g_state.termination_reason, &expected, REASON_WALL_TIMEOUT);
            atomic_store(&g_state.should_terminate, 1);
            break;
        }
        usleep(POLL_INTERVAL_US);
    }
    return NULL;
}

/* ---- Thread 2: external resource watcher (CPU time + memory) ---- */
static void *resource_watcher(void *arg) {
    (void)arg;
    long clk_tck = sysconf(_SC_CLK_TCK);

    while (!atomic_load(&g_state.should_terminate)) {
        pid_t pid = g_state.child_pid;
        if (pid <= 0) break;

        long ticks = read_cpu_ticks(pid);
        long rss_kb = read_rss_kb(pid);

        if (ticks < 0 || rss_kb < 0) {
            /* /proc entry vanished: child has already exited. */
            break;
        }

        double cpu_seconds = (double)ticks / (double)clk_tck;
        if ((int)cpu_seconds % 1 == 0) {
            log_line("MONITOR: cpu=%.2fs rss=%ldKB (limits: cpu=%ds rss=%dKB)",
                      cpu_seconds, rss_kb, MAX_CPU_SECONDS, MAX_RSS_KB);
        }

        if (cpu_seconds >= MAX_CPU_SECONDS) {
            log_line("MONITOR: CPU-time limit exceeded (%.2fs >= %ds)",
                      cpu_seconds, MAX_CPU_SECONDS);
            int expected = 0;
            atomic_compare_exchange_strong(&g_state.termination_reason, &expected, REASON_CPU_LIMIT);
            atomic_store(&g_state.should_terminate, 1);
            break;
        }
        if (rss_kb >= MAX_RSS_KB) {
            log_line("MONITOR: memory limit exceeded (%ldKB >= %dKB)",
                      rss_kb, MAX_RSS_KB);
            int expected = 0;
            atomic_compare_exchange_strong(&g_state.termination_reason, &expected, REASON_MEM_LIMIT);
            atomic_store(&g_state.should_terminate, 1);
            break;
        }
        usleep(POLL_INTERVAL_US);
    }
    return NULL;
}
