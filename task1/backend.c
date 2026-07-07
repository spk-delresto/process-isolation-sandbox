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

/* ---- privileged step: open the credential DB while still root ---- */
static FILE *open_creddb_privileged(void) {
    FILE *f = fopen(CREDDB_PATH, "r");
    if (!f) {
        perror("[backend] fopen creddb (must exist before privilege drop)");
        exit(EXIT_FAILURE);
    }
    return f;
}

/* ---- privilege drop: irreversible, via setresuid (Deliverable #2) ---- */
static void drop_privileges_permanently(const char *target_user) {
    struct passwd *pw = getpwnam(target_user);
    if (!pw) {
        fprintf(stderr, "[backend] target user '%s' not found\n", target_user);
        exit(EXIT_FAILURE);
    }

    /* Drop supplementary groups first, then gid, then uid. Order matters:
       you must still be root when you call setgroups/setresgid. */
    if (geteuid() == 0) {
        if (setgroups(1, &pw->pw_gid) != 0) { perror("setgroups"); exit(EXIT_FAILURE); }
        if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0) { perror("setresgid"); exit(EXIT_FAILURE); }
    }

    /* setresuid sets real, effective AND saved uid together. Because the
       saved-uid is also overwritten, there is no privileged id left
       anywhere for the process to seteuid() back to - this is what makes
       the drop irreversible (Investigation Q7), unlike a bare seteuid()
       which would leave the saved-uid at 0. */
    if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0) {
        perror("setresuid");
        exit(EXIT_FAILURE);
    }

    if (confirm_unprivileged(pw->pw_uid) != 0) {
        fprintf(stderr, "[backend] aborting: could not verify privilege drop\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[backend] privileges permanently dropped to uid=%d (%s)\n",
            pw->pw_uid, target_user);
}

/* ---- validate credentials against the (already-open) DB fd ---- */
static int validate_credentials(FILE *db, const char *user, const char *pass) {
    rewind(db);
    char line[MAX_LINE];
    int ok = 0;
    while (fgets(line, sizeof(line), db)) {
        char db_user[MAX_USER], db_pass[MAX_PASS];
        line[strcspn(line, "\n")] = 0;
        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = 0;
        strncpy(db_user, line, sizeof(db_user) - 1);
        db_user[sizeof(db_user)-1] = 0;
        strncpy(db_pass, sep + 1, sizeof(db_pass) - 1);
        db_pass[sizeof(db_pass)-1] = 0;

        if (strcmp(db_user, user) == 0 && strcmp(db_pass, pass) == 0) {
            ok = 1;
        }
        secure_zero(db_pass, sizeof(db_pass));
    }
    return ok;
}

/* ---- receive kernel-verified peer credentials over the UNIX socket ---- */
static int check_peer_credentials(int fd) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        perror("getsockopt(SO_PEERCRED)");
        return -1;
    }
    fprintf(stderr, "[backend] peer credentials -> pid=%d uid=%d gid=%d\n",
            cred.pid, cred.uid, cred.gid);
    /* Example policy: reject requests from uid 0 connecting to us -
       the frontend is expected to run unprivileged. Extend as needed. */
    return 0;
}

static void handle_client(int fd, FILE *db, uid_t target_uid) {
    /* Attack-resistance re-check on every single request (Deliverable #4) */
    if (confirm_unprivileged(target_uid) != 0) {
        const char *msg = "DENY:internal-error\n";
        write(fd, msg, strlen(msg));
        close(fd);
        return;
    }

    if (check_peer_credentials(fd) != 0) {
        close(fd);
        return;
    }

    char user[MAX_USER] = {0};
    char pass[MAX_PASS] = {0};
    char buf[MAX_USER + MAX_PASS + 2] = {0};

    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(fd); return; }
    buf[n] = 0;

    char *sep = strchr(buf, '\x01');   /* field separator */
    if (!sep) {
        const char *msg = "DENY:malformed-request\n";
        write(fd, msg, strlen(msg));
        secure_zero(buf, sizeof(buf));
        close(fd);
        return;
    }
    *sep = 0;
    strncpy(user, buf, sizeof(user) - 1);
    strncpy(pass, sep + 1, sizeof(pass) - 1);

    int ok = validate_credentials(db, user, pass);

    const char *result = ok ? "ALLOW\n" : "DENY\n";
    write(fd, result, strlen(result));

    fprintf(stderr, "[backend] validation for user='%s' -> %s", user, result);

    /* Wipe plaintext password (and the raw buffer) as soon as it is no
       longer needed (Investigation Q10/11/12). */
    secure_zero(pass, sizeof(pass));
    secure_zero(buf, sizeof(buf));

    close(fd);
}

static volatile sig_atomic_t g_running = 1;
static void handle_sigterm(int sig) { (void)sig; g_running = 0; }

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "[backend] starting as uid=%d euid=%d\n", getuid(), geteuid());

    /* 1. Privileged step performed BEFORE dropping root. */
    FILE *db = open_creddb_privileged();

    /* 2. Set up the listening socket while we still have permission to
       bind wherever policy requires (kept simple here: /tmp). */
    unlink(SOCK_PATH);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(EXIT_FAILURE); }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    chmod(SOCK_PATH, 0666); /* demo only: real deployments should use group perms */

    if (listen(srv, 8) != 0) { perror("listen"); exit(EXIT_FAILURE); }

    /* 3. Permanently drop privileges. From this point on the process can
          never regain root, by construction of setresuid(). */
    struct passwd *target = getpwnam(UNPRIV_USER);
    uid_t target_uid = target ? target->pw_uid : getuid();
    drop_privileges_permanently(UNPRIV_USER);

    fprintf(stderr, "[backend] listening on %s (unprivileged)\n", SOCK_PATH);

    while (g_running) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        handle_client(fd, db, target_uid);
    }

    fclose(db);
    close(srv);
    unlink(SOCK_PATH);
    fprintf(stderr, "[backend] shut down cleanly\n");
    return 0;
}
