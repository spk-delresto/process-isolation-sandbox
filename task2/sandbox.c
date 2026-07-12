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

/* ---- Thread 3: enforcement thread - actually delivers the kill ---- */
static void *enforcement_watcher(void *arg) {
    (void)arg;
    while (1) {
        if (atomic_load(&g_state.should_terminate)) {
            if (atomic_load(&g_state.termination_reason) == REASON_CHILD_EXITED) {
                return NULL; /* child already gone on its own - nothing to enforce */
            }
            pid_t pid = g_state.child_pid;
            if (pid > 0 && kill(pid, 0) != 0) {
                /* Process is already gone (e.g. it exited right as the
                   deadline fired) - nothing left to enforce against. */
                return NULL;
            }
            if (pid > 0) {
                log_line("ENFORCEMENT: sending SIGSTOP then SIGKILL to pid %d", pid);
                /* SIGSTOP first: freezes the process so it cannot fork,
                   spawn helpers, or otherwise race the kill. Then SIGKILL,
                   which - unlike SIGTERM - cannot be caught, blocked or
                   ignored by the target (Investigation Q6). */
                kill(pid, SIGSTOP);
                usleep(50000);
                kill(pid, SIGKILL);
            }
            return NULL;
        }
        /* Also exit this thread if the child already exited on its own. */
        int status;
        pid_t r = waitpid(g_state.child_pid, &status, WNOHANG | WUNTRACED);
        if (r == g_state.child_pid && !WIFSTOPPED(status)) {
            int expected = 0;
            atomic_compare_exchange_strong(&g_state.termination_reason, &expected, REASON_CHILD_EXITED);
            return NULL;
        }
        usleep(POLL_INTERVAL_US);
    }
}

static void set_child_resource_limits(void) {
    /* Belt-and-braces kernel-enforced limits, in addition to the
       userspace watchers above, so the sandbox is defence-in-depth
       rather than relying solely on the polling threads. */
    struct rlimit rl;

    rl.rlim_cur = MAX_CPU_SECONDS + 1;
    rl.rlim_max = MAX_CPU_SECONDS + 2;
    setrlimit(RLIMIT_CPU, &rl);

    /* Kernel-enforced backstop set noticeably above the userspace
       watcher's threshold, so the polling watcher (which produces an
       auditable log entry and a controlled SIGSTOP/SIGKILL sequence)
       is normally the one that catches the violation first; RLIMIT_AS
       only fires if the watcher's poll interval is somehow missed. */
    rl.rlim_cur = (rlim_t)MAX_RSS_KB * 1024 * 2;
    rl.rlim_max = (rlim_t)MAX_RSS_KB * 1024 * 2;
    setrlimit(RLIMIT_AS, &rl);

    rl.rlim_cur = 64;
    rl.rlim_max = 64;
    setrlimit(RLIMIT_NPROC, &rl); /* limit fork-bomb style behaviour */
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <untrusted-binary> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    memset(&g_state, 0, sizeof(g_state));
    pthread_mutex_init(&g_state.log_lock, NULL);
    clock_gettime(CLOCK_MONOTONIC, &g_state.start_time);
    atomic_store(&g_state.should_terminate, 0);
    atomic_store(&g_state.termination_reason, REASON_NONE);

    log_line("Launching sandboxed target: %s", argv[1]);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        /* ---- CHILD: becomes the untrusted binary, nothing more ---- */
        set_child_resource_limits();
        /* The child never runs any sandbox logic beyond this point,
           satisfying "the untrusted binary must not take part in its
           own monitoring or termination" - after execve() this address
           space is entirely replaced by the target program. */
        execve(argv[1], &argv[1], NULL);
        perror("execve"); /* only reached if execve fails */
        _exit(127);
    }

    /* ---- PARENT: supervisor ---- */
    g_state.child_pid = pid;
    log_line("Child pid=%d started, supervising...", pid);

    pthread_t t_timer, t_resource, t_enforce;
    pthread_create(&t_timer, NULL, timer_watcher, NULL);
    pthread_create(&t_resource, NULL, resource_watcher, NULL);
    pthread_create(&t_enforce, NULL, enforcement_watcher, NULL);

    int status = 0;
    pid_t r = waitpid(pid, &status, 0);

    /* Child has terminated one way or another: signal all watcher
       threads to stop and join them before reporting the result. */
    atomic_store(&g_state.should_terminate, 1);
    pthread_join(t_timer, NULL);
    pthread_join(t_resource, NULL);
    pthread_join(t_enforce, NULL);

    if (r < 0) {
        perror("waitpid");
        return EXIT_FAILURE;
    }

    int reason = atomic_load(&g_state.termination_reason);
    const char *reason_str =
        reason == REASON_WALL_TIMEOUT ? "WALL_CLOCK_TIMEOUT" :
        reason == REASON_CPU_LIMIT    ? "CPU_LIMIT_EXCEEDED" :
        reason == REASON_MEM_LIMIT    ? "MEMORY_LIMIT_EXCEEDED" :
        "CHILD_SELF_TERMINATED";

    if (WIFEXITED(status)) {
        log_line("RESULT: child exited normally with code %d (reason=%s)",
                  WEXITSTATUS(status), reason_str);
    } else if (WIFSIGNALED(status)) {
        log_line("RESULT: child terminated by signal %d (%s) (reason=%s)",
                  WTERMSIG(status), strsignal(WTERMSIG(status)), reason_str);
    } else {
        log_line("RESULT: child ended with unexpected status 0x%x (reason=%s)",
                  status, reason_str);
    }

    pthread_mutex_destroy(&g_state.log_lock);
    return 0;
}
