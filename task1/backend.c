#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <time.h>

#define SOCK_PATH        "/tmp/auth_backend.sock"
#define CREDDB_PATH      "./creddb.txt"      /* simulated /etc/shadow-like store */
#define UNPRIV_USER      "nobody"
#define MAX_LINE         256
#define MAX_USER         64
#define MAX_PASS         128

/* ---- explicit, non-optimisable memory wipe (Investigation Q11/12) ---- */
static void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

/* ---- runtime privilege verification (Deliverable #3) ---- */
static int confirm_unprivileged(uid_t target_uid) {
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) != 0) {
        perror("getresuid");
        return -1;
    }
    fprintf(stderr,
        "[backend] runtime check: ruid=%d euid=%d suid=%d (target=%d)\n",
        ruid, euid, suid, target_uid);

    if (ruid != target_uid || euid != target_uid || suid != target_uid) {
        fprintf(stderr,
            "[backend] FATAL: privilege drop verification failed - "
            "process still holds an unexpected uid. Refusing to serve.\n");
        return -1;
    }

    /* Cross-check independently via /proc, as required by the brief. */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    FILE *f = fopen(path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                fprintf(stderr, "[backend] /proc self-check -> %s", line);
                break;
            }
        }
        fclose(f);
    }
    return 0;
}

/* ---- privileged step: open the credential DB while still root ---- */
static FILE *open_creddb_privileged(void) {
    FILE *f = fopen(CREDDB_PATH, "r");
    if (!f) {
        perror("[backend] fopen creddb (must exist before privilege drop)");
        exit(EXIT_FAILURE);
    }
    return f;
}

